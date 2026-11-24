package agent_test

import (
	"bytes"
	"context"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ArjunRachithcf/homeward/internal/agent"
	"github.com/ArjunRachithcf/homeward/internal/agent/agenttest"
	"github.com/ArjunRachithcf/homeward/internal/testenv"
)

// An install's compose read that ends for its own reasons says so, as the plan's read does (TestAReadsEndingIsSaid),
// not that the file is invalid: out of time is 504 read-timeout, out of memory 422 read-too-big; checking or
// installing, nothing is written (#295).
func TestAnInstallsReadSaysWhyItEnded(t *testing.T) {
	testenv.Isolate(t)
	for name, c := range map[string]struct {
		script string
		status int
		code   string
	}{
		"its CPU limit":     {"cat >/dev/null; kill -XCPU $$", http.StatusGatewayTimeout, "read-timeout"},
		"its own deadline":  {`cat >/dev/null; echo '{"error":"deadline"}'; exit 1`, http.StatusGatewayTimeout, "read-timeout"},
		"the kernel's kill": {"cat >/dev/null; kill -KILL $$", http.StatusUnprocessableEntity, "read-too-big"},
		"Go out of memory":  {"cat >/dev/null; echo 'fatal error: runtime: out of memory' >&2; exit 2", http.StatusUnprocessableEntity, "read-too-big"},
	} {
		t.Run(name, func(t *testing.T) {
			testenv.Isolate(t)
			sock, h, state := signedIn(t, agent.Config{})
			agent.ShellReads(t, 5*time.Second, c.script)
			for _, path := range []string{"/v1/apps/ledger?check=true", "/v1/apps/ledger"} {
				if code, body := call(t, sock, "PUT", path, withSecrets()); code != c.status || string(body) != `{"error":"`+c.code+`"}`+"\n" {
					t.Errorf("PUT %s: %d %s, want %d and only %s", path, code, body, c.status, c.code)
				}
			}
			nothingFor(t, sock, h, state)
		})
	}
}

// An install whose read waits out its deadline for the one read slot, another read holding it, is busy (503): try
// again, not a bad file (#295).
func TestAnInstallsReadWhileAnotherHoldsTheSlotIsBusy(t *testing.T) {
	testenv.Isolate(t)
	sock, h, state := signedIn(t, agent.Config{})
	started, release := agent.HeldReads(t, 300*time.Millisecond)
	held := make(chan int, 1)
	go func() { // not post: no t.Fatal off the test's goroutine
		c := http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", sock)
		}}}
		resp, err := c.Post("http://agent/v1/projects/read", "application/json", strings.NewReader(`{"project":"homerslab-web","compose":"services: {web: {image: x}}\n"}`))
		if err != nil {
			held <- 0
			return
		}
		resp.Body.Close()
		held <- resp.StatusCode
	}()
	<-started // the holder has the slot, until released
	if code, body := call(t, sock, "PUT", "/v1/apps/ledger?check=true", withSecrets()); code != http.StatusServiceUnavailable || string(body) != `{"error":"busy"}`+"\n" {
		t.Errorf("an install while another read holds the slot: %d %s, want 503 and only busy", code, body)
	}
	release()
	if code := <-held; code != http.StatusInternalServerError {
		t.Errorf("the read that held the slot, let go without a child: %d, want 500", code)
	}
	nothingFor(t, sock, h, state)
}

func nothingFor(t *testing.T, sock string, h *agenttest.Host, state string) {
	t.Helper()
	if _, err := os.Stat(filepath.Join(state, "apps", "ledger")); err == nil || h.Ran("systemctl enable /"+agent.UnitsDir) >= 0 || len(apps(t, sock).Apps) != 0 {
		t.Error("something was written for it")
	}
}

// A reader that panics on a file is the file's trouble to the household, invalid-compose, as any read that fails, not a
// reader that didn't start (no-reader, which points at the machine). The child says so itself, and the panic and its
// stack go to the agent's log, the journal, never into the answer (#295).
func TestAReaderThatPanicsIsAnInvalidFile(t *testing.T) {
	testenv.Isolate(t)
	// The child itself answers.
	child := exec.Command(os.Args[0], "agent", "read-project-panic", "--", "homerslab-web")
	child.Stdin = strings.NewReader("services: {web: {image: x}}\n")
	child.Dir = t.TempDir()
	child.Env = []string{"PATH=/usr/bin:/bin"}
	var stderr bytes.Buffer
	child.Stderr = &stderr
	said, err := child.Output()
	if err != nil || !strings.Contains(string(said), `"error":"invalid-compose"`) || !strings.Contains(string(said), "the reader fell over on line 7") {
		t.Errorf("a child whose reader panics: %v, said %q; want it to answer invalid-compose with the panic", err, said)
	}

	var logs bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	sock, _, _ := signedIn(t, agent.Config{Log: log})
	agent.ChildReads(t, agenttest.Executable(t), "read-project-panic", 20*time.Second, 10)
	resp, out := post(t, sock, "/v1/projects/read", map[string]string{"project": "homerslab-web", "compose": "services: {web: {image: x}}\n"})
	if resp.StatusCode != http.StatusUnprocessableEntity || !strings.Contains(string(out), `"error":"invalid-compose"`) {
		t.Errorf("a read whose reader panics: %d %s, want 422 invalid-compose", resp.StatusCode, out)
	}
	if strings.Contains(string(out), "fell over") || strings.Contains(string(out), "goroutine") {
		t.Errorf("the answer carries the panic: %s", out)
	}
	if code, body := call(t, sock, "PUT", "/v1/apps/ledger?check=true", withSecrets()); code != http.StatusUnprocessableEntity || string(body) != `{"error":"invalid-compose"}`+"\n" {
		t.Errorf("an install whose reader panics: %d %s, want 422 and only invalid-compose", code, body)
	}
	if got := logs.String(); strings.Count(got, "the reader fell over on line 7") < 2 || !strings.Contains(got, "goroutine") {
		t.Errorf("the agent's log doesn't keep each panic with its stack:\n%s", got)
	}
}

// A crash in the reader that no recover reaches, a panic in a goroutine of its own or a fatal runtime error (a stack
// overflow, say), once the child said it is reading the file (agent.ReadingMarker), is the reader's bug on this file
// too: invalid-compose, its words in the agent's log; a child that ends with anything else is still a reader that broke
// (no-reader, TestAReadsEndingIsSaid) (#295).
func TestAReaderThatCrashesIsAnInvalidFile(t *testing.T) {
	testenv.Isolate(t)
	reading := "printf '" + strings.TrimSuffix(agent.ReadingMarker, "\n") + "\\n' >&2; "
	for name, c := range map[string]struct {
		child, said string // a mode of this test binary, or a script for sh
	}{
		"a real Go child, panicking in another goroutine": {"read-project-panic-elsewhere", "the reader's helper fell over on line 9"},
		"a fatal runtime error":                           {"cat >/dev/null; " + reading + "printf 'runtime: goroutine stack exceeds 1000000000-byte limit\\nfatal error: stack overflow\\n' >&2; exit 2", "fatal error: stack overflow"},
		"an unrecovered panic":                            {"cat >/dev/null; " + reading + "printf 'panic: the reader fell over\\n\\ngoroutine 1 [running]:\\n' >&2; exit 2", "panic: the reader fell over"},
	} {
		t.Run(name, func(t *testing.T) {
			testenv.Isolate(t)
			sock, logs := crashingReads(t, c.child)
			resp, out := post(t, sock, "/v1/projects/read", map[string]string{"project": "homerslab-web", "compose": "services: {web: {image: x}}\n"})
			if resp.StatusCode != http.StatusUnprocessableEntity || !strings.Contains(string(out), `"error":"invalid-compose"`) || strings.Contains(string(out), c.said) {
				t.Errorf("%d %s, want 422 invalid-compose without the crash", resp.StatusCode, out)
			}
			if !strings.Contains(logs.String(), "crashed on an app's compose file") || !strings.Contains(logs.String(), c.said) {
				t.Errorf("the agent's log doesn't keep the crash:\n%s", logs.String())
			}
		})
	}
}

// A child that crashes before it says it is reading the file (a panic as it confines itself, or Go unable to start a
// thread under the unit's TasksMax) is the machine's fault, never the file's: 500 reader-crashed, not invalid-compose,
// for a plan's read and an install's alike, with the crash in the agent's log (#295).
func TestAReaderThatCrashesBeforeReadingIsTheMachines(t *testing.T) {
	testenv.Isolate(t)
	for name, c := range map[string]struct{ child, said string }{
		"a real Go child, panicking before it reads": {"read-project-panic-early", "confining fell over"},
		"Go unable to start a thread":                {"cat >/dev/null; printf 'runtime: failed to create new OS thread\\nfatal error: newosproc\\n' >&2; exit 2", "fatal error: newosproc"},
		"a crash with only part of the marker": {"cat >/dev/null; printf 'panic: confine\\n' >&2; " +
			"printf 'reading the fi' >&2; exit 2", "panic: confine"},
	} {
		t.Run(name, func(t *testing.T) {
			testenv.Isolate(t)
			sock, logs := crashingReads(t, c.child)
			resp, out := post(t, sock, "/v1/projects/read", map[string]string{"project": "homerslab-web", "compose": "services: {web: {image: x}}\n"})
			if resp.StatusCode != http.StatusInternalServerError || string(out) != `{"error":"reader-crashed"}`+"\n" {
				t.Errorf("a plan's read: %d %s, want 500 and only reader-crashed", resp.StatusCode, out)
			}
			if !strings.Contains(logs.String(), "before it read") || !strings.Contains(logs.String(), c.said) {
				t.Errorf("the agent's log doesn't keep the crash:\n%s", logs.String())
			}
		})
	}
	t.Run("an install's read", func(t *testing.T) {
		testenv.Isolate(t)
		sock, h, state := signedIn(t, agent.Config{})
		agent.ShellReads(t, 5*time.Second, "cat >/dev/null; printf 'fatal error: newosproc\\n' >&2; exit 2")
		for _, path := range []string{"/v1/apps/ledger?check=true", "/v1/apps/ledger"} {
			if code, body := call(t, sock, "PUT", path, withSecrets()); code != http.StatusInternalServerError || string(body) != `{"error":"reader-crashed"}`+"\n" {
				t.Errorf("PUT %s: %d %s, want 500 and only reader-crashed", path, code, body)
			}
		}
		nothingFor(t, sock, h, state)
	})
}

// crashingReads starts an agent whose reads' children are child, a mode of this test binary or a script for sh, and
// returns its socket and its log.
func crashingReads(t *testing.T, child string) (string, *bytes.Buffer) {
	t.Helper()
	if strings.HasPrefix(child, "read-project") {
		agent.ChildReads(t, agenttest.Executable(t), child, 20*time.Second, 10)
	} else {
		agent.ShellReads(t, 5*time.Second, child)
	}
	var logs bytes.Buffer
	sock, _ := agenttest.StartWith(t, agent.Config{Log: slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))})
	return sock, &logs
}
