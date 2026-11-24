package cli_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/ArjunRachithcf/homeward/internal/testenv"
)

func TestTheCLIListsTheCatalog(t *testing.T) {
	testenv.Isolate(t)
	ctl := running(t)
	code, out, errOut := run(t, "catalog", "--control-socket", ctl)
	if code != 0 {
		t.Fatalf("homeward catalog: %d %s", code, errOut)
	}
	for _, want := range []string{"The official catalog, from HomersLab", "BentoPDF", "PDF tools", "Community, guarded at the edge", "Immich", "Photos", "Verified, native sign-in"} {
		if !strings.Contains(out, want) {
			t.Errorf("no %q in\n%s", want, out)
		}
	}
}

// The CLI makes a plan and shows it by its id, the one object Admin shows too (the manager's tests compare the two).
func TestTheCLIShowsAPlanByItsID(t *testing.T) {
	testenv.Isolate(t)
	ctl := running(t, true)
	code, out, errOut := run(t, "plan", "immich", "--json", "--control-socket", ctl)
	if code != 0 {
		t.Fatalf("homeward plan immich --json: %d %s", code, errOut)
	}
	var p struct{ ID string }
	if err := json.Unmarshal([]byte(out), &p); err != nil || !strings.HasPrefix(p.ID, "p-") {
		t.Fatalf("%v: %s", err, out)
	}
	if _, byID, _ := run(t, "plan", "show", p.ID, "--json", "--control-socket", ctl); !bytes.Equal(bytes.TrimSpace([]byte(byID)), bytes.TrimSpace([]byte(out))) {
		t.Errorf("plan show %s --json:\n%s\nwant\n%s", p.ID, byID, out)
	}

	code, words, errOut := run(t, "plan", "show", p.ID, "--control-socket", ctl)
	if code != 0 {
		t.Fatalf("homeward plan show: %d %s", code, errOut)
	}
	for _, want := range []string{"Install Immich v3.3.5, from the official catalog", "Verified, published by HomersLab", "Plan " + p.ID,
		"photos.ferreira.family", "on NetBird", "Adults: \u2068Inês Ferreira\u2069", "an OIDC client in Authentik",
		"Every hour: the photo library, its database (a dump)", "A restore test every week",
		"Not the database's own files: the dump holds them", "Not machine-learning models: Immich downloads them again", "study-pc", "4 containers", "None",
		"sealed to study-pc's TPM: the database password", "Memory: needs 6 GB", "Nothing happens until"} {
		if !strings.Contains(words, want) {
			t.Errorf("no %q in\n%s", want, words)
		}
	}
	code, again, _ := run(t, "plan", "immich", "--control-socket", ctl)
	if code != 0 || again != words {
		t.Errorf("homeward plan immich shows another plan than plan show:\n%s", again)
	}
}

func TestTheCLISaysWhyThereIsNoPlan(t *testing.T) {
	testenv.Isolate(t)
	ctl := running(t)
	if code, _, errOut := run(t, "plan", "immich", "--control-socket", ctl); code != 1 || !strings.Contains(errOut, "first-time setup") {
		t.Errorf("before setup: %d %q", code, errOut)
	}
	if code, _, errOut := run(t, "plan", "nope", "--control-socket", ctl); code != 1 || !strings.Contains(errOut, "no app nope") {
		t.Errorf("an unknown app: %d %q", code, errOut)
	}
	if code, _, errOut := run(t, "plan", "show", "p-0", "--control-socket", ctl); code != 1 || !strings.Contains(errOut, "no plan p-0") {
		t.Errorf("an unknown plan: %d %q", code, errOut)
	}
	if code, _, _ := run(t, "plan"); code != 2 {
		t.Errorf("plan with no app: %d, want 2", code)
	}
}

// When the primary can't read the app's definition, the CLI says why in the words Admin uses, not the manager's code
// (#293, #295).
func TestTheCLISaysWhyThePrimaryCantReadAnApp(t *testing.T) {
	testenv.Isolate(t)
	for code, c := range map[string]struct{ status, want string }{
		"agent-unreachable":  {"503", "the primary didn't answer. Try again in a moment"},
		"agent-refused-read": {"500", "the primary answered, but wouldn't read the app's definition. The network is fine: the primary needs mending, and sudo journalctl -u homeward-agent there says why"},
		"agent-busy":         {"503", "the primary was busy: it was reading another app's definition, or too many reads were running at once. Try again in a moment"},
		"agent-read-crashed": {"500", "the primary's reader crashed before it read the app's definition, so the definition isn't the cause. The primary needs mending, and sudo journalctl -u homeward-agent there says why (most often too many processes or too little memory)"},
		"read-timeout":       {"422", "its definition took too long to read, so the primary stopped. Try again later; if it happens again, tell the catalog's publisher"},
		"read-too-big":       {"422", "its definition needs more memory to read than Homeward allows, so the primary stopped. Try again later; if it happens again, tell the catalog's publisher"},
	} {
		sock, _ := routedControl(t, map[string][2]string{"POST /api/v1/plans": {c.status, `{"error":"` + code + `"}`}})
		exit, _, errOut := run(t, "plan", "immich", "--control-socket", sock)
		if exit != 1 || !strings.Contains(errOut, "Homeward can't plan this app: "+c.want) || strings.Contains(errOut, code) {
			t.Errorf("%s: exit %d, %q", code, exit, errOut)
		}
	}
}
