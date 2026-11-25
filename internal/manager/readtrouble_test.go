package manager_test

import (
	"net/http"
	"testing"

	"github.com/ArjunRachithcf/homeward/internal/testenv"
)

// readTroubles are the agent's answers when a compose read ends for a reason other than the file's contents (agent:
// TestAReadsEndingIsSaid, TestAnInstallsReadSaysWhyItEnded, TestAnInstallsReadWhileAnotherHoldsTheSlotIsBusy), and
// the manager's to the household for each: busy is the primary's, try again; out of time or memory is the app
// definition's, too slow or too large to read; a child that crashed before reading is the primary's to mend (#295).
var readTroubles = map[string]struct {
	status     int
	code       string
	wantStatus int
	wantCode   string
}{
	"busy":         {http.StatusServiceUnavailable, "busy", http.StatusServiceUnavailable, "agent-busy"},
	"read-timeout": {http.StatusGatewayTimeout, "read-timeout", http.StatusUnprocessableEntity, "read-timeout"},
	"read-too-big": {http.StatusUnprocessableEntity, "read-too-big", http.StatusUnprocessableEntity, "read-too-big"},
	// The read's child crashed before it read the file: the primary's (agent: TestAReaderThatCrashesBeforeReadingIsTheMachines).
	"reader-crashed": {http.StatusInternalServerError, "reader-crashed", http.StatusInternalServerError, "agent-read-crashed"},
}

// A plan, an apply's plan made again, an install's check and the install itself each say which trouble the read had,
// with only its code, on Admin and on the control socket alike; nothing is installed.
func TestAReadsTroubleIsSaidAtEveryStep(t *testing.T) {
	testenv.Isolate(t)
	for name, c := range readTroubles {
		t.Run(name+", planning", func(t *testing.T) {
			testenv.Isolate(t)
			p := newPrimary(t)
			p.setUp()
			n := answerInstead(t, p, reads, c.status, c.code)
			body := map[string]string{"app": "immich"}
			wantOnly(t, "Admin", p.admin("POST", "/api/v1/plans", body), c.wantStatus, c.wantCode)
			wantOnly(t, "the control socket", p.control("POST", "/api/v1/plans", body), c.wantStatus, c.wantCode)
			if n.Load() != 2 {
				t.Errorf("the agent was asked %d times, want 2", n.Load())
			}
		})
		for stage, match := range map[string]func(*http.Request) bool{"making the plan again": reads, "checking the install": installs(true), "installing": installs(false)} {
			t.Run(name+", applying: "+stage, func(t *testing.T) {
				testenv.Isolate(t)
				p, _ := installable(t, nil)
				made := planFor(t, p, "bentopdf")
				real := p.agent
				n := answerInstead(t, p, match, c.status, c.code)
				wantOnly(t, "applying", p.control("POST", "/api/v1/plans/"+made.ID+"/apply", nil), c.wantStatus, c.wantCode)
				if n.Load() == 0 {
					t.Error("the agent was never asked")
				}
				if apps := agentApps(t, &primary{t: t, agent: real}).Apps; len(apps) != 0 {
					t.Errorf("installed: %+v", apps)
				}
			})
		}
	}
}
