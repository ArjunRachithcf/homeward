package migrate

import (
	"io/fs"
	"testing"
)

// WithFail makes h's run fail at the step fail says, before that step changes anything: a crash there.
func WithFail(h Host, fail func(step string) error) Host {
	h.fail = fail
	return h
}

// WithOwners gives h's run other file owners, for a test that can't chown: owner reads a path's (not following a link),
// chown sets them.
func WithOwners(h Host, owner func(string) (int, int, error), chown func(string, int, int) error) Host {
	h.owner, h.chown = owner, chown
	return h
}

// SetLstat gives Pending another lstat for the test.
func SetLstat(t *testing.T, f func(string) (fs.FileInfo, error)) {
	old := lstat
	lstat = f
	t.Cleanup(func() { lstat = old })
}
