package authentik

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/ArjunRachithcf/homeward/internal/idp"
	"github.com/ArjunRachithcf/homeward/internal/testenv"
)

// No app password for an admin (#281), on an Authentik that ignores every list filter: the adapter checks what comes
// back. The contract suite checks the same against the real one; these check the moments in between.

// withPeople is a fake holding an LDAP app's directory, and people: lena an adult, olga an admin.
func withPeople() *fakeAuthentik {
	f := newFake()
	f.objs["/providers/ldap/"] = []map[string]any{{"pk": 7, "name": "homerslab-media-ldap", "assigned_application_slug": "homerslab-media-ldap"}}
	f.objs["/core/users/"] = []map[string]any{
		{"pk": 1, "username": "lena", "type": "internal", "path": userPath, "is_active": true, "groups": []any{"group-adult"}},
		{"pk": 2, "username": "olga", "type": "internal", "path": userPath, "is_active": true, "groups": []any{"group-admin"}},
	}
	f.objs["/core/tokens/"] = []map[string]any{}
	return f
}

func token(id string, user int, expires *time.Time) map[string]any {
	return map[string]any{"pk": id, "identifier": id, "intent": "app_password", "user": user, "expiring": expires != nil, "expires": expires}
}

// tokens are the identifiers of the fake's tokens, in order.
func (f *fakeAuthentik) tokens() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, t := range f.objs["/core/tokens/"] {
		out = append(out, t["identifier"].(string))
	}
	return out
}

func TestAnAdminGetsNoAppPassword(t *testing.T) {
	testenv.Isolate(t)
	f := withPeople()
	a := f.open(t)
	if _, err := a.AppPassword(context.Background(), "homerslab-media", "olga"); !errors.Is(err, idp.ErrAdminAppPassword) {
		t.Errorf("an app password for an admin: %v, want ErrAdminAppPassword", err)
	}
	if len(f.tokens()) != 0 || len(f.changes) != 0 {
		t.Errorf("refused, yet changed: %v, tokens %v", f.changes, f.tokens())
	}
	if pw, err := a.AppPassword(context.Background(), "homerslab-media", "lena"); err != nil || pw == "" {
		t.Errorf("an adult's: %v", err)
	}
}

// Made an admin while the app password was being made: it reads the role again after making it, and ends it.
func TestAnAppPasswordMadeAsItsPersonBecomesAnAdminEnds(t *testing.T) {
	testenv.Isolate(t)
	f := withPeople()
	a := f.open(t)
	f.after = func() {
		if f.changes[len(f.changes)-1] == "POST /core/tokens/" {
			f.objs["/core/users/"][0]["groups"] = []any{"group-admin"}
		}
	}
	if _, err := a.AppPassword(context.Background(), "homerslab-media", "lena"); !errors.Is(err, idp.ErrAdminAppPassword) {
		t.Errorf("made an admin meanwhile: %v, want ErrAdminAppPassword", err)
	}
	if ts := f.tokens(); len(ts) != 0 {
		t.Errorf("the app password made meanwhile is still there: %v", ts)
	}
}

func TestSomeoneHoldingAnAppPasswordIsntMadeAnAdmin(t *testing.T) {
	testenv.Isolate(t)
	f := withPeople()
	a := f.open(t)
	ctx := context.Background()
	past := time.Now().Add(-time.Hour)
	// Another's token, which a filter Authentik ignored hands back too, and an expired one of her own: neither counts.
	f.objs["/core/tokens/"] = append(f.objs["/core/tokens/"], token("olgas", 2, nil), token("lenas-old", 1, &past))
	lena := idp.Person{Username: "lena", Name: "Lena", Mail: "lena@ferreira.family", Role: idp.Admin}
	if err := a.EnsurePerson(ctx, lena); err != nil {
		t.Fatalf("with no live app password of her own: %v", err)
	}
	f.objs["/core/users/"][0]["groups"] = []any{"group-adult"}
	f.objs["/core/tokens/"] = append(f.objs["/core/tokens/"], token("lenas", 1, nil))
	f.changes = nil
	err := a.EnsurePerson(ctx, lena)
	if !errors.Is(err, idp.ErrAdminAppPassword) {
		t.Fatalf("made an admin with an app password: %v, want ErrAdminAppPassword", err)
	}
	if len(f.changes) != 0 || !slices.Contains(f.tokens(), "lenas") {
		t.Errorf("refused, yet changed: %v, tokens %v", f.changes, f.tokens())
	}
	// An admin already, whose name changes: nothing refused, and the app password she holds ends.
	if err := a.EnsurePerson(ctx, idp.Person{Username: "olga", Name: "Olga F.", Role: idp.Admin}); err != nil {
		t.Errorf("an admin's name: %v", err)
	}
	if ts := f.tokens(); !slices.Equal(ts, []string{"lenas"}) {
		t.Errorf("after the admin's change: %v, want hers ended, lena's kept", ts)
	}
	// Removed, then made an admin.
	if err := a.RevokeAppPasswords(ctx, "lena"); err != nil {
		t.Fatal(err)
	}
	if ts := f.tokens(); len(ts) != 0 {
		t.Errorf("after revoking hers: %v, want none left", ts)
	}
	if err := a.EnsurePerson(ctx, lena); err != nil {
		t.Errorf("made an admin once hers are gone: %v", err)
	}
}

// One made at the same moment as the promotion: it reads the app passwords again after the change, and ends them.
func TestAnAppPasswordMadeAsItsPersonIsPromotedEnds(t *testing.T) {
	testenv.Isolate(t)
	f := withPeople()
	a := f.open(t)
	f.after = func() {
		if f.changes[len(f.changes)-1] == "PATCH /core/users/1/" {
			f.objs["/core/tokens/"] = append(f.objs["/core/tokens/"], token("lenas", 1, nil))
		}
	}
	if err := a.EnsurePerson(context.Background(), idp.Person{Username: "lena", Role: idp.Admin}); err != nil {
		t.Fatal(err)
	}
	if ts := f.tokens(); len(ts) != 0 {
		t.Errorf("the app password made at the promotion is still there: %v", ts)
	}
}

// names are the admins found, each "name" or "name (failed)".
func names(found []idp.AdminAppPasswords) []string {
	out := []string{}
	for _, f := range found {
		if f.Err != nil {
			out = append(out, f.Username+" (failed)")
		} else {
			out = append(out, f.Username)
		}
	}
	return out
}

func TestTheAdminsAppPasswordsEnd(t *testing.T) {
	testenv.Isolate(t)
	f := withPeople()
	a := f.open(t)
	past := time.Now().Add(-time.Hour)
	f.objs["/core/users/"] = append(f.objs["/core/users/"],
		map[string]any{"pk": 3, "username": "bea", "type": "internal", "path": userPath, "is_active": true, "groups": []any{"group-admin"}},
		// Admins the console made, outside Homeward's path, one inactive (it can be made active again); a service account
		// in the group, which signs in to nothing; someone of the console's in another group only.
		map[string]any{"pk": 4, "username": "carla", "type": "internal", "path": "users", "is_active": true, "groups": []any{"group-admin"}},
		map[string]any{"pk": 5, "username": "dora", "type": "internal", "path": "users", "is_active": false, "groups": []any{"group-admin"}},
		map[string]any{"pk": 6, "username": "svc", "type": "service_account", "path": "users", "is_active": true, "groups": []any{"group-admin"}},
		map[string]any{"pk": 7, "username": "eva", "type": "internal", "path": "users", "is_active": true, "groups": []any{"group-authentik-admins"}})
	f.objs["/core/tokens/"] = []map[string]any{token("lenas", 1, nil), token("olgas", 2, nil), token("olgas-2", 2, nil),
		token("beas-old", 3, &past), {"pk": "olgas-api", "identifier": "olgas-api", "intent": "api", "user": 2},
		token("carlas", 4, nil), token("doras", 5, nil), token("svcs", 6, nil), token("evas", 7, nil)}
	got, err := a.EndAdminAppPasswords(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if n := names(got); !slices.Equal(n, []string{"carla", "dora", "olga"}) {
		t.Errorf("ended: %v, want the admins' (the console's on any path, inactive included; bea's is expired, lena isn't one)", n)
	}
	if ts := f.tokens(); !slices.Equal(ts, []string{"lenas", "beas-old", "olgas-api", "svcs", "evas"}) {
		t.Errorf("left: %v, want the adult's, the expired one, the API token, the service account's and the non-admin's", ts)
	}
	if got, err := a.EndAdminAppPasswords(context.Background()); err != nil || len(got) != 0 {
		t.Errorf("again: %v %v, want nobody", got, err)
	}
}

// An admin whose app passwords couldn't be deleted is found all the same, with the failure: the manager says so, and
// the next pass tries again.
func TestAnAdminsAppPasswordsThatDidntEndAreSaidSo(t *testing.T) {
	testenv.Isolate(t)
	f := withPeople()
	a := f.open(t)
	f.objs["/core/tokens/"] = []map[string]any{token("olgas", 2, nil)}
	f.refuse = "DELETE /core/tokens/"
	got, err := a.EndAdminAppPasswords(context.Background())
	if n := names(got); err != nil || !slices.Equal(n, []string{"olga (failed)"}) {
		t.Errorf("with the delete refused: %v %v, want olga, failed", n, err)
	}
	f.refuse = ""
	if got, err := a.EndAdminAppPasswords(context.Background()); err != nil || !slices.Equal(names(got), []string{"olga"}) {
		t.Errorf("the next pass: %v %v, want olga's ended", names(got), err)
	}
}

// The role read again after making an app password fails: the password is deleted, and the error is that failure, not
// a refusal of an admin nobody saw.
func TestAnAppPasswordWhoseRoleCantBeReadAgainIsDeleted(t *testing.T) {
	testenv.Isolate(t)
	f := withPeople()
	a := f.open(t)
	f.after = func() {
		if f.changes[len(f.changes)-1] == "POST /core/tokens/" {
			f.refuse = "GET /core/users/"
		}
	}
	_, err := a.AppPassword(context.Background(), "homerslab-media", "lena")
	if err == nil || errors.Is(err, idp.ErrAdminAppPassword) {
		t.Errorf("the role unreadable afterwards: %v, want that error, not ErrAdminAppPassword", err)
	}
	if ts := f.tokens(); len(ts) != 0 {
		t.Errorf("the app password made is still there: %v", ts)
	}
}
