package manager

import (
	"fmt"
	"testing"

	"github.com/ArjunRachithcf/homeward/internal/testenv"
)

// An LDAP app's directory opens to its audience's roles but Admin (#298); an app for admins alone keeps it, so the
// directory refuses that app by name.
func TestAnLDAPAppsDirectoryOpensToItsAudienceButAdmins(t *testing.T) {
	testenv.Isolate(t)
	for audience, want := range map[string]string{"everyone": "[adult kid]", "adults": "[adult]", "admins": "[admin]"} {
		if got := fmt.Sprint(ldapRoles(audience)); got != want {
			t.Errorf("%s: %s, want %s", audience, got, want)
		}
	}
	if fmt.Sprint(roles("everyone")) != "[admin adult kid]" {
		t.Errorf("the audience's own roles changed: %v", roles("everyone"))
	}
}
