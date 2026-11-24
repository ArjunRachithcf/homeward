package manager_test

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ArjunRachithcf/homeward/internal/agent"
	"github.com/ArjunRachithcf/homeward/internal/agent/agenttest"
	"github.com/ArjunRachithcf/homeward/internal/testenv"
)

// A primary whose agent answers but refuses its compose reads (#293): as root, its read user missing, a permission
// refused, or the check that a read's child can't start dumpable failing. Here, the program it would start for a
// read isn't there, which the agent refuses the same way (500 no-reader).
func refusingReads(t *testing.T) option {
	return func(p *primary) { p.agentConfig.Executable = filepath.Join(t.TempDir(), "no-reader") }
}

// noAgent points the manager at a socket nothing answers on, from then on.
func noAgent(t *testing.T, p *primary) {
	t.Helper()
	p.agent = filepath.Join(t.TempDir(), "nobody.sock")
	p.restart()
}

// wantOnly checks that r is status with only the error code, and nothing of the machine's: no path, user or uid.
func wantOnly(t *testing.T, what string, r response, status int, code string) {
	t.Helper()
	if r.Code != status || string(r.Body) != `{"error":"`+code+`"}`+"\n" {
		t.Errorf("%s: %d %s, want %d and only {\"error\":%q}", what, r.Code, r.Body, status, code)
	}
}

// A plan the primary can't make says why: its agent didn't answer (503 agent-unreachable), or it answered and refused
// to read the app's compose file (500 agent-refused-read), which no network fix mends. Neither says more than its
// code, on Admin and on the control socket alike.
func TestAPlanSaysWhetherTheAgentIsUnreachableOrRefusedItsRead(t *testing.T) {
	testenv.Isolate(t)
	t.Run("refused", func(t *testing.T) {
		testenv.Isolate(t)
		p := newPrimary(t, refusingReads(t))
		p.setUp()
		body := map[string]string{"app": "immich"}
		wantOnly(t, "Admin", p.admin("POST", "/api/v1/plans", body), http.StatusInternalServerError, "agent-refused-read")
		wantOnly(t, "the control socket", p.control("POST", "/api/v1/plans", body), http.StatusInternalServerError, "agent-refused-read")
	})
	t.Run("unreachable", func(t *testing.T) {
		testenv.Isolate(t)
		p := newPrimary(t)
		p.setUp()
		noAgent(t, p)
		body := map[string]string{"app": "immich"}
		wantOnly(t, "Admin", p.admin("POST", "/api/v1/plans", body), http.StatusServiceUnavailable, "agent-unreachable")
		wantOnly(t, "the control socket", p.control("POST", "/api/v1/plans", body), http.StatusServiceUnavailable, "agent-unreachable")
	})
}

// Applying a plan reads the app's compose file again (the plan must still be the household's), and the agent reads it
// once more to install it: a refusal at either read is agent-refused-read, and an agent that doesn't answer is
// agent-unreachable. Nothing is installed.
func TestApplyingSaysWhetherTheAgentIsUnreachableOrRefusedItsRead(t *testing.T) {
	testenv.Isolate(t)
	t.Run("refused, making the plan again", func(t *testing.T) {
		testenv.Isolate(t)
		p, _ := installable(t, nil)
		made := planFor(t, p, "bentopdf")
		// Another agent, one that refuses its reads: the plan is read again before anything of the agent's state is
		// asked, so its empty state doesn't matter.
		p.agent, _ = agenttest.StartWith(t, agent.Config{Executable: filepath.Join(t.TempDir(), "no-reader")})
		p.restart()
		wantOnly(t, "applying", p.control("POST", "/api/v1/plans/"+made.ID+"/apply", nil), http.StatusInternalServerError, "agent-refused-read")
	})
	t.Run("refused, checking the install", func(t *testing.T) {
		testenv.Isolate(t)
		p, _ := installable(t, nil)
		made := planFor(t, p, "bentopdf")
		refused := refuseInstalls(t, p, true)
		wantOnly(t, "applying", p.control("POST", "/api/v1/plans/"+made.ID+"/apply", nil), http.StatusInternalServerError, "agent-refused-read")
		if refused.Load() == 0 {
			t.Error("the agent was never asked")
		}
		if apps := agentApps(t, p).Apps; len(apps) != 0 {
			t.Errorf("installed: %+v", apps)
		}
	})
	t.Run("refused, installing", func(t *testing.T) {
		testenv.Isolate(t)
		p, _ := installable(t, nil)
		made := planFor(t, p, "bentopdf")
		refused := refuseInstalls(t, p, false)
		wantOnly(t, "applying", p.control("POST", "/api/v1/plans/"+made.ID+"/apply", nil), http.StatusInternalServerError, "agent-refused-read")
		if refused.Load() == 0 {
			t.Error("the agent was never asked")
		}
		if apps := agentApps(t, p).Apps; len(apps) != 0 {
			t.Errorf("installed: %+v", apps)
		}
	})
	t.Run("unreachable", func(t *testing.T) {
		testenv.Isolate(t)
		p, _ := installable(t, nil)
		made := planFor(t, p, "bentopdf")
		real := p.agent
		noAgent(t, p)
		wantOnly(t, "applying", p.control("POST", "/api/v1/plans/"+made.ID+"/apply", nil), http.StatusServiceUnavailable, "agent-unreachable")
		if apps := agentApps(t, &primary{t: t, agent: real}).Apps; len(apps) != 0 {
			t.Errorf("installed: %+v", apps)
		}
	})
}

// refuseInstalls puts a socket in front of p's agent that passes everything to it but its installs (with check, only
// the check that comes first; without, only the install after it), which it answers as the agent answers an install
// whose compose read it refuses (agent: TestAnInstallWhoseReadIsRefusedSaysSo). It counts them.
func refuseInstalls(t *testing.T, p *primary, check bool) *atomic.Int32 {
	t.Helper()
	return answerInstead(t, p, installs(check), http.StatusInternalServerError, "no-reader")
}

// installs matches the agent's installs: with check, only the check that comes first; without, only the install after.
func installs(check bool) func(*http.Request) bool {
	return func(r *http.Request) bool {
		return r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/v1/apps/") && (r.URL.Query().Get("check") == "true") == check
	}
}

// reads matches the agent's compose reads.
func reads(r *http.Request) bool { return r.Method == http.MethodPost && r.URL.Path == "/v1/projects/read" }

// answerInstead puts a socket in front of p's agent that passes everything to it but the requests match picks, which it
// answers status with only the error code, as the agent does. It counts them.
func answerInstead(t *testing.T, p *primary, match func(*http.Request) bool, status int, code string) *atomic.Int32 {
	t.Helper()
	real := p.agent
	sock := filepath.Join(t.TempDir(), "front.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	proxy := httputil.NewSingleHostReverseProxy(&url.URL{Scheme: "http", Host: "agent"})
	proxy.Transport = &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", real)
	}}
	var n atomic.Int32
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if match(r) {
			n.Add(1)
			_, _ = io.Copy(io.Discard, r.Body)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			_, _ = w.Write([]byte(`{"error":"` + code + `"}` + "\n"))
			return
		}
		proxy.ServeHTTP(w, r)
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	p.agent = sock
	p.restart()
	return &n
}
