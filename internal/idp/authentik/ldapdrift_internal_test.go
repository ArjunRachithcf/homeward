package authentik

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ArjunRachithcf/homeward/internal/idp"
	"github.com/ArjunRachithcf/homeward/internal/testenv"
)

// #298, on the fake: the moments in between and each rule alone. The contract suite checks the same against the real
// Authentik.

// A policy binding that passes when its policy fails would let a failing policy through (#298): one drifted so is put
// back, and every binding Homeward makes says it fails closed.
func TestAPolicyBindingNeverPassesOnFailure(t *testing.T) {
	testenv.Isolate(t)
	f := newFake()
	a := f.open(t)
	f.objs["/policies/bindings/"] = []map[string]any{{"pk": "pb-own", "target": "pbm-login", "policy": "policy-own", "order": 0,
		"enabled": true, "negate": false, "failure_result": true}}
	if err := a.bindPolicies(context.Background(), target{PBM: "pbm-login", PK: "pbm-login"},
		[]binding{{Policy: "policy-own"}, {Policy: "policy-no-admin"}}); err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, b := range f.objs["/policies/bindings/"] {
		got = append(got, fmt.Sprintf("%v@%v failure=%v", b["policy"], b["order"], b["failure_result"]))
	}
	if fmt.Sprint(got) != "[policy-own@0 failure=false policy-no-admin@10 failure=false]" {
		t.Errorf("the bindings, put back: %v", got)
	}
}

// A password set within a second of the account's making counts (#298): its event says so, for that account alone.
func TestAPasswordSetAtOnceCounts(t *testing.T) {
	testenv.Isolate(t)
	joined := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	event := func(user int) map[string]any {
		return map[string]any{"pk": fmt.Sprint("event-", user), "action": "password_set", "user": map[string]any{"pk": user, "username": "lena"}}
	}
	for _, c := range []struct {
		name   string
		events []map[string]any
		want   bool
	}{
		{"no event", nil, false},
		{"her own event", []map[string]any{event(1)}, true},
		{"another account's event, of the same name before", []map[string]any{event(9)}, false},
		{"another action", []map[string]any{{"pk": "e", "action": "login", "user": map[string]any{"pk": 1}}}, false},
	} {
		f := withPeople()
		f.objs["/core/users/"][0]["date_joined"] = joined
		f.objs["/core/users/"][0]["password_change_date"] = joined.Add(10 * time.Millisecond)
		f.objs["/events/events/"] = c.events
		a := f.open(t)
		got, err := a.Credentials(context.Background(), "lena")
		if err != nil {
			t.Fatal(err)
		}
		if slices.Contains(got.Others, idp.CredPassword) != c.want {
			t.Errorf("%s: %+v, want a password: %v", c.name, got, c.want)
		}
	}
}

// An LDAP app's audience never has the Admin role (#298), and the refusal changes nothing.
func TestAnLDAPAppNeverOpensToAdmins(t *testing.T) {
	testenv.Isolate(t)
	for _, roles := range [][]idp.Role{{idp.Admin}, {idp.Adult, idp.Admin}} {
		f := newFake()
		a := f.open(t)
		if _, err := a.EnsureLDAP(context.Background(), idp.LDAPApp{Slug: "homerslab-notes", Name: "Notes", Roles: roles}); !errors.Is(err, idp.ErrLDAPAdminAudience) {
			t.Errorf("%v: %v, want ErrLDAPAdminAudience", roles, err)
		}
		if len(f.changes) != 0 {
			t.Errorf("%v: refused, yet changed %v", roles, f.changes)
		}
	}
}

// An LDAP application opened to the admins' group, as Homeward made it before #298, loses that binding and keeps the
// rest; one the admins' group alone opened gets the policy that refuses everyone first, and is never left without a
// binding, which would open it to everyone.
func TestAnLDAPApplicationLosesTheAdminsGroup(t *testing.T) {
	testenv.Isolate(t)
	app := &ldapAppState{}
	app.PK, app.PBM = "app-notes", "app-notes"
	for _, c := range []struct {
		name string
		have []string
		want string
	}{
		{"with adults", []string{"group-admin", "group-adult"}, "[group-adult]"},
		{"alone", []string{"group-admin"}, "[policy-never]"},
		{"none", []string{"group-adult"}, "[group-adult]"},
		// A binding that is off opens nothing, and keeps nothing closed.
		{"beside one that is off", []string{"group-admin", "!group-adult"}, "[group-adult policy-never]"},
		// Negated, it is no audience of Homeward's: the console's, left for the tidy to judge.
		{"negated", []string{"-group-admin", "group-adult"}, "[group-admin group-adult]"},
	} {
		f := newFake()
		f.objs["/policies/expression/"] = append(f.objs["/policies/expression/"], map[string]any{"pk": "policy-never", "name": policyNever})
		for i, g := range c.have {
			on, negate := !strings.HasPrefix(g, "!"), strings.HasPrefix(g, "-")
			g = strings.TrimLeft(g, "!-")
			f.objs["/policies/bindings/"] = append(f.objs["/policies/bindings/"], map[string]any{"pk": "pb-" + g, "target": "app-notes",
				"group": g, "order": i * 10, "enabled": on, "negate": negate})
		}
		a := f.open(t)
		f.after = func() {
			if !slices.ContainsFunc(f.objs["/policies/bindings/"], func(b map[string]any) bool { return b["enabled"] == true }) {
				t.Errorf("%s: after %s, the application has no binding: open to everyone", c.name, f.changes[len(f.changes)-1])
			}
		}
		for _, repair := range []bool{false, true} {
			had, err := a.ldapDropAdmins(context.Background(), app, "group-admin", repair)
			if err != nil || had != slices.Contains(c.have, "group-admin") {
				t.Errorf("%s, repair %v: %v %v", c.name, repair, had, err)
			}
			if !repair && len(f.changes) != 0 {
				t.Errorf("%s: only reading, yet changed %v", c.name, f.changes)
			}
		}
		var got []string
		for _, b := range f.objs["/policies/bindings/"] {
			if g, ok := b["group"].(string); ok && g != "" {
				got = append(got, g)
			} else {
				got = append(got, fmt.Sprint(b["policy"]))
			}
		}
		if fmt.Sprint(got) != c.want {
			t.Errorf("%s: the bindings left: %v, want %s", c.name, got, c.want)
		}
	}
}
