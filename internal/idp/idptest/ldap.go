package idptest

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ArjunRachithcf/homeward/internal/idp"
	"github.com/ArjunRachithcf/homeward/internal/ldaps/ldaptest"
)

// LDAPWorld is a provider that serves apps over LDAP, with its outpost in containers (#204).
type LDAPWorld interface {
	World
	// LDAP is the adapter's LDAP side.
	LDAP() idp.LDAP
	// StartOutpost runs the provider's LDAP outpost with its token, as the sign-in's unit does.
	StartOutpost(t *testing.T, token idp.Secret)
	// Bind binds at the outpost as dn with password. It returns nil only when the outpost said yes.
	Bind(t *testing.T, dn, password string) error
	// Search binds at the outpost as dn with password, then searches base's whole subtree for every object.
	Search(t *testing.T, dn, password, base string) ([]ldaptest.Entry, error)
	// OwnAppPassword has the person make themselves an app password for an LDAP app, by its slug, in the provider's own
	// settings, and returns it: Kanidm has everyone make their own, and Authentik's settings let anyone. Homeward's
	// refusals aren't in the way there, so an admin can make one too (#281).
	OwnAppPassword(t *testing.T, slug, username string) string
}

// RunLDAP runs the LDAP contract: an app's provider opens to its roles only, a person sees nobody but themselves, and
// nothing a person has but an app password made for that app binds them (#204). The sign-in is prepared already (Run).
func RunLDAP(t *testing.T, w LDAPWorld) {
	ctx := context.Background()
	p, l := w.Provider(), w.LDAP()
	people := []idp.Person{
		{Username: "lena", Name: "Lena", Mail: "lena@ferreira.family", Role: idp.Adult},
		{Username: "maria", Name: "Maria", Mail: "maria@ferreira.family", Role: idp.Adult},
		{Username: "kiko", Name: "Kiko", Mail: "kiko@ferreira.family", Role: idp.Kid},
		{Username: "olga", Name: "Olga", Mail: "olga@ferreira.family", Role: idp.Admin},
	}
	for _, x := range people {
		if err := p.EnsurePerson(ctx, x); err != nil {
			t.Fatal(err)
		}
	}

	var token idp.Secret
	t.Run("the LDAP outpost: one, its token kept", func(t *testing.T) {
		var err error
		if token, err = l.LDAPOutpost(ctx); err != nil || token == "" {
			t.Fatalf("the outpost: %v", err)
		}
		again, err := l.LDAPOutpost(ctx)
		if err != nil || again != token {
			t.Errorf("again: a new token, or %v", err)
		}
	})
	if token == "" {
		t.Fatal("no outpost: nothing else can be checked")
	}
	w.StartOutpost(t, token)

	media := idp.LDAPApp{Slug: "homerslab-jellyfin", Name: "Jellyfin", Roles: []idp.Role{idp.Adult}}
	var creds idp.LDAPCredentials
	t.Run("an app's LDAP provider: made for its roles, its base DN kept, and no account of its own", func(t *testing.T) {
		var err error
		if creds, err = l.EnsureLDAP(ctx, media); err != nil {
			t.Fatal(err)
		}
		if !creds.Created || creds.BaseDN == "" || !strings.Contains(creds.UserDN, "%s") || strings.Count(creds.UserDN, "%") != 1 ||
			!strings.HasSuffix(creds.UserDN, ","+creds.BaseDN) {
			t.Fatalf("credentials: %+v", creds)
		}
		again, err := l.EnsureLDAP(ctx, media)
		if err != nil || again.Created || again != (idp.LDAPCredentials{BaseDN: creds.BaseDN, UserDN: creds.UserDN}) {
			t.Errorf("again: %+v %v, want the same, not made", again, err)
		}
		for _, bad := range []idp.LDAPApp{{Slug: "jellyfin", Roles: media.Roles}, {Slug: "homerslab-outpost", Roles: media.Roles},
			{Slug: "homerslab-admin", Roles: media.Roles}, {Slug: "homerslab-Jelly fin", Roles: media.Roles}, {Slug: "homerslab-books"}} {
			if _, err := l.EnsureLDAP(ctx, bad); err == nil {
				t.Errorf("made the provider %+v", bad)
			}
		}
	})
	if creds.BaseDN == "" {
		t.Fatal("no provider: nothing else can be checked")
	}
	dn := func(c idp.LDAPCredentials, username string) string { return fmt.Sprintf(c.UserDN, username) }
	// password is a new app password of a person's for one app, as Home will make one for them.
	password := func(app idp.LDAPApp, username string) string {
		t.Helper()
		pw, err := l.AppPassword(ctx, app.Slug, username)
		if err != nil || pw == "" {
			t.Fatalf("an app password for %s at %s: %v", username, app.Slug, err)
		}
		return pw.Reveal()
	}
	lena, maria, kiko := password(media, "lena"), password(media, "maria"), password(media, "kiko")
	// Homeward makes no app password for an admin (#274, #281); olga, the admin, makes her own, as she can.
	if pw, err := l.AppPassword(ctx, media.Slug, "olga"); !errors.Is(err, idp.ErrAdminAppPassword) || pw != "" {
		t.Errorf("an app password for an admin: %v, want ErrAdminAppPassword (#281)", err)
	}
	if c, err := p.Credentials(ctx, "olga"); err != nil || slices.Contains(c.Others, idp.CredToken) {
		t.Errorf("the admin's credentials after the refusal: %+v %v, want no app password left behind", c, err)
	}
	olga := w.OwnAppPassword(t, media.Slug, "olga")
	if _, err := l.AppPassword(ctx, "jellyfin", "lena"); err == nil {
		t.Error("an app password for something that isn't an app's slug")
	}
	if _, err := l.AppPassword(ctx, media.Slug, "nobody-of-ours"); err == nil {
		t.Error("an app password for someone the household doesn't have")
	}
	if _, err := l.AppPassword(ctx, media.Slug+"-yet-to-come", "lena"); err == nil {
		t.Error("an app password for an app with no directory, ahead of one of that slug")
	}
	// The outpost takes a new provider in a while: until it does, nobody binds there.
	ready := func(c idp.LDAPCredentials, username, password string) error {
		var err error
		for deadline := time.Now().Add(90 * time.Second); ; time.Sleep(3 * time.Second) {
			if err = w.Bind(t, dn(c, username), password); err == nil || time.Now().After(deadline) {
				return err
			}
		}
	}

	t.Run("a person of the audience binds with an app password, and only with it", func(t *testing.T) {
		if err := ready(creds, "lena", lena); err != nil {
			t.Fatalf("an adult, in an adults' app: %v", err)
		}
		if err := w.Bind(t, dn(creds, "lena"), lena[:len(lena)-1]); err == nil {
			t.Error("a wrong app password bound")
		}
		f := w.GiveFactors(t, "lena")
		if err := w.Bind(t, dn(creds, "lena"), f.Password); err == nil {
			t.Error("a password from the provider's console bound: only app passwords may")
		}
		if err := w.Bind(t, dn(creds, "lena"), f.Password+";"+f.TOTP()); err == nil {
			t.Error("a password and TOTP bound: only app passwords may")
		}
	})
	t.Run("a person outside the audience can't bind: a kid, an admin", func(t *testing.T) {
		if err := w.Bind(t, dn(creds, "kiko"), kiko); err == nil {
			t.Error("a kid bound to an adults' app")
		}
		if err := w.Bind(t, dn(creds, "olga"), olga); err == nil {
			t.Error("an admin bound to an adults' app")
		}
		if err := w.Bind(t, dn(creds, "kiko"), lena); err == nil {
			t.Error("a kid bound with an adult's app password")
		}
	})
	t.Run("a person sees only their own entry and their own groups: nobody else of the household, nor any account (#204)", func(t *testing.T) {
		own := strings.ToLower(dn(creds, "lena"))
		for _, base := range []string{creds.BaseDN, "ou=users," + creds.BaseDN, "ou=groups," + creds.BaseDN} {
			es, err := w.Search(t, dn(creds, "lena"), lena, base)
			if err != nil {
				t.Errorf("searching %s: %v", base, err)
				continue
			}
			t.Logf("lena, searching %s: %d entries", base, len(es))
			for _, e := range es {
				d := strings.ToLower(e.DN)
				switch {
				case d == own:
					if !slices.ContainsFunc(e.Attrs["memberOf"], func(g string) bool { return strings.HasPrefix(strings.ToLower(g), "cn="+idp.RoleGroup(idp.Adult)+",") }) {
						t.Errorf("her own entry without her role's group: %v", e.Attrs["memberOf"])
					}
				case strings.HasPrefix(d, "cn="+idp.RoleGroup(idp.Adult)+",ou=groups,"):
					// her own role's group, with her alone in it: maria, the other adult, never shows
					for _, m := range e.Attrs["member"] {
						if strings.ToLower(m) != own {
							t.Errorf("her role's group lists %s", m)
						}
					}
				case strings.HasPrefix(d, "cn=lena,ou=virtual-groups,"):
					// her own group of one, as Authentik's LDAP gives every person
				case d == strings.ToLower(creds.BaseDN), slices.ContainsFunc([]string{"users", "groups", "virtual-groups"},
					func(ou string) bool { return d == "ou="+ou+","+strings.ToLower(creds.BaseDN) }):
					// the tree itself
				default:
					t.Errorf("lena sees %s", e.DN)
				}
				for _, other := range []string{"maria", "bea", "ines", "kiko", "olga", "akadmin", "homerslab", "ak-outpost"} {
					for k, vs := range e.Attrs {
						for _, v := range vs {
							if strings.Contains(strings.ToLower(v), "cn="+other) && !strings.Contains(strings.ToLower(v), "cn=homerslab-") {
								t.Errorf("lena sees %s in %s's %s: %s", other, e.DN, k, v)
							}
						}
					}
				}
			}
		}
		// Another app's base DN, and the tree above them all: nothing.
		for _, base := range []string{"dc=homerslab", "dc=kids-books,dc=homerslab", "ou=outpost,dc=homerslab"} {
			if es, err := w.Search(t, dn(creds, "lena"), lena, base); err == nil && len(es) > 0 {
				t.Errorf("lena, searching %s: %v", base, es)
			}
		}
	})
	t.Run("each app's provider is its own: an adult can't bind where only kids may", func(t *testing.T) {
		books := idp.LDAPApp{Slug: "homerslab-kids-books", Name: "Kids' books", Roles: []idp.Role{idp.Kid}}
		other, err := l.EnsureLDAP(ctx, books)
		if err != nil {
			t.Fatal(err)
		}
		if other.BaseDN == creds.BaseDN {
			t.Fatalf("two apps share a base DN: %s", other.BaseDN)
		}
		if err := ready(other, "kiko", password(books, "kiko")); err != nil {
			t.Errorf("a kid, in a kids' app: %v", err)
		}
		if err := w.Bind(t, dn(other, "lena"), password(books, "lena")); err == nil {
			t.Error("an adult bound to a kids' app")
		}
		if err := w.Bind(t, dn(creds, "lena"), lena); err != nil {
			t.Errorf("the adult, still, in the first app: %v", err)
		}
		if err := l.DeleteLDAP(ctx, books.Slug); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("an app password binds at its own app alone: another app that is handed it can't replay it (#204)", func(t *testing.T) {
		// A second adults' app, whose slug starts as the first's does.
		notes := idp.LDAPApp{Slug: media.Slug + "-notes", Name: "Notes", Roles: []idp.Role{idp.Adult}}
		other, err := l.EnsureLDAP(ctx, notes)
		if err != nil {
			t.Fatal(err)
		}
		own := password(notes, "lena")
		if err := ready(other, "lena", own); err != nil {
			t.Fatalf("an adult, in a second adults' app, with its own app password: %v", err)
		}
		for _, x := range []struct{ at, with, what string }{
			{other.UserDN, lena, "the first app's app password, at the second"},
			{creds.UserDN, own, "the second app's app password, at the first"},
			{other.UserDN, maria, "another adult's, for the first app, at the second"},
		} {
			if err := w.Bind(t, fmt.Sprintf(x.at, "lena"), x.with); err == nil {
				t.Errorf("bound with %s", x.what)
			}
		}
		if err := w.Bind(t, dn(creds, "lena"), lena); err != nil {
			t.Errorf("the adult, still, in the first app with its own: %v", err)
		}
		if err := l.DeleteLDAP(ctx, notes.Slug); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("a change of role holds at the next bind", func(t *testing.T) {
		kid := people[0] // lena
		kid.Role = idp.Kid
		if err := p.EnsurePerson(ctx, kid); err != nil {
			t.Fatal(err)
		}
		if err := w.Bind(t, dn(creds, "lena"), lena); err == nil {
			t.Error("an adult who became a kid still binds to an adults' app")
		}
		kid.Role = idp.Adult
		if err := p.EnsurePerson(ctx, kid); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("the audience changes, and the app is never open to everyone on the way (#219)", func(t *testing.T) {
		media.Roles = []idp.Role{idp.Kid}
		if _, err := l.EnsureLDAP(ctx, media); err != nil {
			t.Fatal(err)
		}
		if err := w.Bind(t, dn(creds, "lena"), lena); err == nil {
			t.Error("an adult binds to an app that is the kids' now")
		}
		if err := w.Bind(t, dn(creds, "kiko"), kiko); err != nil {
			t.Errorf("a kid, in an app that is the kids' now: %v", err)
		}
		media.Roles = []idp.Role{idp.Adult}
		if _, err := l.EnsureLDAP(ctx, media); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("a deleted provider: from the moment it is deleted, nobody binds there, and deleting again is done", func(t *testing.T) {
		type try struct{ who, password string }
		for _, x := range []try{{"lena", lena}, {"maria", maria}} {
			if err := w.Bind(t, dn(creds, x.who), x.password); err != nil {
				t.Fatalf("%s, of the audience, before the delete: %v", x.who, err)
			}
		}
		// Those outside the audience try all along, from before the delete, three clients each; once it returns, the
		// audience too, until 15 s after. A window of a moment would show.
		var (
			wg     sync.WaitGroup
			mu     sync.Mutex
			seen   = map[string]int{}
			after  = make(chan struct{})
			finish = make(chan struct{})
		)
		trying := func(x try, from <-chan struct{}, when string) {
			defer wg.Done()
			if from != nil {
				select {
				case <-from:
				case <-finish:
					return
				}
			}
			for {
				select {
				case <-finish:
					return
				default:
				}
				if w.Bind(t, dn(creds, x.who), x.password) == nil {
					mu.Lock()
					seen[x.who+" "+when]++
					mu.Unlock()
				}
			}
		}
		for range 3 {
			for _, x := range []try{{"kiko", kiko}, {"olga", olga}} {
				wg.Add(2)
				go trying(x, nil, "(outside the audience)")
				go trying(x, after, "(outside the audience, after the delete returned)")
			}
			for _, x := range []try{{"lena", lena}, {"maria", maria}} {
				wg.Add(1)
				go trying(x, after, "(after the delete returned)")
			}
		}
		err := l.DeleteLDAP(ctx, media.Slug)
		close(after)
		time.Sleep(15 * time.Second)
		close(finish)
		wg.Wait()
		if err != nil {
			t.Fatal(err)
		}
		for who, n := range seen {
			t.Errorf("%s bound to a deleted app, %d times", who, n)
		}
		if err := l.DeleteLDAP(ctx, media.Slug); err != nil {
			t.Errorf("again: %v", err)
		}
		for _, bad := range []string{"jellyfin", "homerslab-outpost", "homerslab-admin", ""} {
			if err := l.DeleteLDAP(ctx, bad); err == nil {
				t.Errorf("deleted %q", bad)
			}
		}
	})
	notes := idp.LDAPApp{Slug: "homerslab-family-notes", Name: "Family notes", Roles: []idp.Role{idp.Adult, idp.Admin}}
	var shared idp.LDAPCredentials
	t.Run("someone holding app passwords isn't made an admin until they're removed (#281)", func(t *testing.T) {
		var err error
		if shared, err = l.EnsureLDAP(ctx, notes); err != nil {
			t.Fatal(err)
		}
		bea := idp.Person{Username: "bea", Name: "Bea", Mail: "bea@ferreira.family", Role: idp.Adult}
		if err := p.EnsurePerson(ctx, bea); err != nil {
			t.Fatal(err)
		}
		made, own := password(notes, "bea"), w.OwnAppPassword(t, notes.Slug, "bea")
		if err := ready(shared, "bea", made); err != nil {
			t.Fatalf("an adult, with the app password Homeward made: %v", err)
		}
		bea.Role = idp.Admin
		if err := p.EnsurePerson(ctx, bea); !errors.Is(err, idp.ErrAdminAppPassword) {
			t.Errorf("made an admin while holding app passwords: %v, want ErrAdminAppPassword", err)
		}
		if admins, err := p.People(ctx, idp.Admin); err != nil || slices.ContainsFunc(admins, func(x idp.Person) bool { return x.Username == "bea" }) {
			t.Errorf("the admins after the refusal: %+v %v, want no bea", admins, err)
		}
		for _, pw := range []string{made, own} {
			if err := w.Bind(t, dn(shared, "bea"), pw); err != nil {
				t.Errorf("refused, yet her app passwords changed: %v", err)
			}
		}
		if err := l.RevokeAppPasswords(ctx, "bea"); err != nil {
			t.Fatal(err)
		}
		for _, pw := range []string{made, own} {
			if err := w.Bind(t, dn(shared, "bea"), pw); err == nil {
				t.Error("a revoked app password bound")
			}
		}
		if c, err := p.Credentials(ctx, "bea"); err != nil || slices.Contains(c.Others, idp.CredToken) {
			t.Errorf("her credentials once revoked: %+v %v, want no app password", c, err)
		}
		if err := l.RevokeAppPasswords(ctx, "nobody-of-ours"); err == nil {
			t.Error("revoked the app passwords of someone the household doesn't have")
		}
		if err := p.EnsurePerson(ctx, bea); err != nil {
			t.Errorf("made an admin once they're removed: %v", err)
		}
		if admins, err := p.People(ctx, idp.Admin); err != nil || !slices.ContainsFunc(admins, func(x idp.Person) bool { return x.Username == "bea" }) {
			t.Errorf("the admins: %+v %v, want bea among them", admins, err)
		}
	})
	t.Run("admins who made themselves app passwords: every one ends, and the check says whose (#281)", func(t *testing.T) {
		if shared.BaseDN == "" {
			t.Skip("no app for it")
		}
		bea, olga, maria := w.OwnAppPassword(t, notes.Slug, "bea"), w.OwnAppPassword(t, notes.Slug, "olga"), password(notes, "maria")
		if err := ready(shared, "bea", bea); err != nil {
			t.Fatalf("an admin, with the app password she made herself: %v", err)
		}
		ended, err := l.EndAdminAppPasswords(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, who := range []string{"bea", "olga"} {
			if !slices.Contains(ended, who) {
				t.Errorf("ended %v: no %s", ended, who)
			}
		}
		for _, who := range []string{"lena", "maria", "kiko"} {
			if slices.Contains(ended, who) {
				t.Errorf("ended %v: %s isn't an admin", ended, who)
			}
		}
		for who, pw := range map[string]string{"bea": bea, "olga": olga} {
			if err := w.Bind(t, dn(shared, who), pw); err == nil {
				t.Errorf("%s's app password, ended, still bound", who)
			}
			if c, err := p.Credentials(ctx, who); err != nil || slices.Contains(c.Others, idp.CredToken) {
				t.Errorf("%s's credentials once ended: %+v %v", who, c, err)
			}
		}
		if err := w.Bind(t, dn(shared, "maria"), maria); err != nil {
			t.Errorf("an adult's app password, after the admins' ended: %v", err)
		}
		if again, err := l.EndAdminAppPasswords(ctx); err != nil || len(again) != 0 {
			t.Errorf("again: %v %v, want nobody", again, err)
		}
		if err := l.DeleteLDAP(ctx, notes.Slug); err != nil {
			t.Fatal(err)
		}
	})
}
