package migrate_test

import (
	"context"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/ArjunRachithcf/homeward/internal/host"
	"github.com/ArjunRachithcf/homeward/internal/migrate"
	"github.com/ArjunRachithcf/homeward/internal/testenv"
)

// The users step with the real shadow tools, on this machine's own /etc: as root, in CI's throwaway container only
// (HOMEWARD_TEST_SHADOW=1), on users of the test's own. A renamed user keeps its uid, takes its new home, and stays in
// its supplementary groups under its new name; a new user that sysusers made first with another uid goes, its group
// with it, and the old one takes its name and keeps the fixed id. An old user of another id (main's) takes the fixed
// id, its group too, or goes when sysusers made the new one first with it. systemctl and systemd-tmpfiles aren't there: stubbed.
// UsersOnly: no folder or unit of this machine's is touched.
func TestTheShadowToolsRenameUsersInPlace(t *testing.T) {
	testenv.Isolate(t)
	if os.Geteuid() != 0 || os.Getenv("HOMEWARD_TEST_SHADOW") != "1" {
		t.Skip("as root, in a throwaway container only (HOMEWARD_TEST_SHADOW=1)")
	}
	if !inContainer() {
		t.Fatal("HOMEWARD_TEST_SHADOW=1 outside a container: this test changes /etc's users")
	}
	must := func(name string, args ...string) {
		t.Helper()
		if out, err := exec.Command(name, args...).CombinedOutput(); err != nil {
			t.Fatalf("%s %q: %v: %s", name, args, err, out)
		}
	}
	add := func(name, id string) {
		must("groupadd", "--system", "--gid", id, name)
		must("useradd", "--system", "--uid", id, "--gid", name, "--no-create-home", "--home-dir", "/var/lib/"+name, "--shell", "/usr/sbin/nologin", name)
	}
	add("hltest-old-a", "61190")
	add("hltest-old-b", "61191")
	add("hltest-new-b", "61195") // sysusers' fallback: the fixed id was the old user's
	add("hltest-old-c", "61197") // main's: an id sysusers picked, not the fixed one; no new user yet
	add("hltest-old-d", "61198") // main's, and sysusers made the new user first with the fixed id
	add("hltest-new-d", "61193")
	must("usermod", "--append", "--groups", "hltest-old-b", "hltest-old-a")
	t.Cleanup(func() {
		for _, u := range []string{"hltest-new-a", "hltest-new-b", "hltest-new-c", "hltest-new-d", "hltest-old-a", "hltest-old-b", "hltest-old-c", "hltest-old-d"} {
			_ = exec.Command("userdel", u).Run()
			_ = exec.Command("groupdel", u).Run()
		}
		_ = os.Remove(filepath.Join("/", migrate.AgentState, migrate.Mark))
	})
	run := func(ctx context.Context, c host.Cmd) ([]byte, error) {
		if c.Name == "systemctl" || c.Name == "systemd-tmpfiles" {
			return nil, nil
		}
		return host.Exec(ctx, c)
	}
	users := []migrate.User{{"hltest-old-a", "hltest-new-a", 61190, "/var/lib/hltest-new-a"}, {"hltest-old-b", "hltest-new-b", 61191, "/"},
		{"hltest-old-c", "hltest-new-c", 61192, "/var/lib/hltest-new-c"}, {"hltest-old-d", "hltest-new-d", 61193, "/var/lib/hltest-new-d"}}
	if _, err := migrate.Run(context.Background(), migrate.Host{Root: "/", Run: run, Users: users, UsersOnly: true}); err != nil {
		t.Fatal(err)
	}
	for _, u := range users {
		got, err := user.Lookup(u.New)
		if err != nil || got.Uid != strconv.Itoa(u.ID) || got.Gid != strconv.Itoa(u.ID) || got.HomeDir != u.Home {
			t.Errorf("%s: %+v %v, want uid and gid %d, home %s", u.New, got, err, u.ID, u.Home)
		}
		if _, err := user.Lookup(u.Old); err == nil {
			t.Errorf("%s is still there", u.Old)
		}
		if g, err := user.LookupGroup(u.New); err != nil || g.Gid != strconv.Itoa(u.ID) {
			t.Errorf("group %s: %+v %v", u.New, g, err)
		}
	}
	for _, id := range []string{"61195", "61197", "61198"} {
		if _, err := user.LookupId(id); err == nil {
			t.Errorf("a user of id %s, not the fixed one, is still there", id)
		}
		if _, err := user.LookupGroupId(id); err == nil {
			t.Errorf("a group of id %s, not the fixed one, is still there", id)
		}
	}
	b, _ := os.ReadFile("/etc/group")
	for line := range strings.SplitSeq(string(b), "\n") {
		if strings.HasPrefix(line, "hltest-new-b:") && !slices.Contains(strings.Split(line[strings.LastIndex(line, ":")+1:], ","), "hltest-new-a") {
			t.Errorf("the renamed user left its supplementary group: %s", line)
		}
	}
}

// inContainer says whether the test runs in a container (Docker's, Podman's), never on a machine of its own.
func inContainer() bool {
	for _, p := range []string{"/.dockerenv", "/run/.containerenv"} {
		if _, err := os.Stat(p); err == nil {
			return true
		}
	}
	return false
}
