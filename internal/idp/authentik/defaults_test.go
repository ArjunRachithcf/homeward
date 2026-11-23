package authentik

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ArjunRachithcf/homeward/internal/idp"
	"github.com/ArjunRachithcf/homeward/internal/testenv"
)

// Authentik is ready for Prepare once its default and system blueprints have applied, and every default flow is
// there. A blueprint whose file an upgrade removed is orphaned: there is nothing left to apply, so it doesn't stop
// Prepare; one that hasn't applied yet, or failed, does. One in warning, or in a state Authentik doesn't have, fails at
// once, naming the blueprint (#269): Authentik at Version never sets warning (its apply is all or nothing, and the
// status is read-only over the API), so Homeward can't know what of it applied and doesn't wait for it to change.
func TestDefaultsAreReadyOnceTheBlueprintsHaveApplied(t *testing.T) {
	testenv.Isolate(t)
	var blueprints []map[string]any
	var applied []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var results []any
		switch {
		case r.Method == http.MethodPost:
			applied = append(applied, r.URL.Path)
			_, _ = w.Write([]byte("{}"))
			return
		case r.URL.Path == "/api/v3/flows/instances/":
			results = []any{map[string]string{"pk": "f", "slug": r.URL.Query().Get("slug")}}
		case r.URL.Path == "/api/v3/crypto/certificatekeypairs/":
			results = []any{map[string]string{"pk": "c", "name": selfSignedCert}}
		case r.URL.Path == "/api/v3/managed/blueprints/":
			for _, b := range blueprints {
				results = append(results, b)
			}
		default:
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"pagination": map[string]any{"next": 0}, "results": results})
	}))
	defer srv.Close()
	a, err := newAPI(srv.URL, idp.Household{Name: "x", Domain: "example.test"}, "token-PLACEHOLDER")
	if err != nil {
		t.Fatal(err)
	}
	bp := func(path, status string, enabled bool) map[string]any {
		return map[string]any{"pk": "pk-" + path, "path": path, "status": status, "enabled": enabled}
	}
	const ready, notYet, failed = "ready", "not ready yet", "failed"
	for _, c := range []struct {
		name  string
		bps   []map[string]any
		want  string
		names string // the blueprint a failure names
	}{
		{"all applied", []map[string]any{bp("default/flow-a.yaml", "successful", true), bp("system/b.yaml", "successful", true)}, ready, ""},
		{"one removed by an upgrade (orphaned)", []map[string]any{bp("default/flow-a.yaml", "successful", true), bp("default/flow-gone.yaml", "orphaned", true)}, ready, ""},
		{"one not applied yet", []map[string]any{bp("default/flow-a.yaml", "successful", true), bp("default/flow-b.yaml", "unknown", true)}, notYet, ""},
		{"one failed", []map[string]any{bp("default/flow-a.yaml", "error", true)}, notYet, ""},
		{"an example, disabled", []map[string]any{bp("default/flow-a.yaml", "successful", true), bp("example/x.yaml", "unknown", false)}, ready, ""},
		{"none found yet", nil, notYet, ""},
		{"only orphaned ones", []map[string]any{bp("default/flow-gone.yaml", "orphaned", true)}, notYet, ""},
		{"one in warning", []map[string]any{bp("default/flow-a.yaml", "successful", true), bp("system/w.yaml", "warning", true)}, failed, "system/w.yaml"},
		{"one in warning, another not applied yet", []map[string]any{bp("default/flow-b.yaml", "unknown", true), bp("default/flow-w.yaml", "warning", true)}, failed, "default/flow-w.yaml"},
		{"one in a state Authentik doesn't have", []map[string]any{bp("default/flow-a.yaml", "half-done", true)}, failed, "default/flow-a.yaml"},
		{"an example in warning, disabled", []map[string]any{bp("default/flow-a.yaml", "successful", true), bp("example/x.yaml", "warning", false)}, ready, ""},
	} {
		blueprints, applied = c.bps, nil
		err := defaultsReady(context.Background(), a)
		got := ready
		switch {
		case errors.Is(err, idp.ErrNotReady):
			got = notYet
		case err != nil:
			got = failed
		}
		if got != c.want {
			t.Errorf("%s: %s (%v), want %s", c.name, got, err, c.want)
		}
		if c.want == failed && err != nil && !strings.Contains(err.Error(), c.names) {
			t.Errorf("%s: %v doesn't name %s", c.name, err, c.names)
		}
		// Only one in error is applied again; Homeward leaves one in a state it doesn't know as it found it.
		if c.want == failed && len(applied) > 0 {
			t.Errorf("%s: applied %q again", c.name, applied)
		}
		if err != nil && strings.Contains(err.Error(), "token-PLACEHOLDER") {
			t.Errorf("%s: the error holds the token", c.name)
		}
	}
}

// A default blueprint that failed (Authentik's worker applies them in no set order at its first start, and one may come
// before what it builds on) is applied again while the caller waits, at most every so often; one applied just now is
// left to finish.
func TestAFailedDefaultBlueprintIsAppliedAgain(t *testing.T) {
	testenv.Isolate(t)
	var applied []string
	var lastApplied string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var results []any
		switch {
		case r.Method == http.MethodPost:
			applied = append(applied, r.URL.Path)
			_, _ = w.Write([]byte("{}"))
			return
		case r.URL.Path == "/api/v3/flows/instances/":
			results = []any{map[string]string{"pk": "f", "slug": r.URL.Query().Get("slug")}}
		case r.URL.Path == "/api/v3/managed/blueprints/":
			results = []any{map[string]any{"pk": "b-ok", "path": "default/flow-a.yaml", "status": "successful", "enabled": true},
				map[string]any{"pk": "b-oobe", "path": "default/flow-oobe.yaml", "status": "error", "enabled": true, "last_applied": lastApplied}}
		default:
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"pagination": map[string]any{"next": 0}, "results": results})
	}))
	defer srv.Close()
	a, err := newAPI(srv.URL, idp.Household{Name: "x", Domain: "example.test"}, "token-PLACEHOLDER")
	if err != nil {
		t.Fatal(err)
	}
	lastApplied = time.Now().Add(-time.Minute).UTC().Format(time.RFC3339Nano)
	if err := defaultsReady(context.Background(), a); !errors.Is(err, idp.ErrNotReady) {
		t.Fatalf("with a failed blueprint: %v", err)
	}
	if len(applied) != 1 || applied[0] != "/api/v3/managed/blueprints/b-oobe/apply/" {
		t.Errorf("applied again: %q", applied)
	}
	applied = nil
	lastApplied = time.Now().UTC().Format(time.RFC3339Nano)
	_ = defaultsReady(context.Background(), a)
	if len(applied) != 0 {
		t.Errorf("applied again right after it was: %q", applied)
	}
}
