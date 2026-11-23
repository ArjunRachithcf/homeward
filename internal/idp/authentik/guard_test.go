package authentik_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ArjunRachithcf/homeward/internal/edge"
	"github.com/ArjunRachithcf/homeward/internal/idp"
	"github.com/ArjunRachithcf/homeward/internal/idp/authentik"
	"github.com/ArjunRachithcf/homeward/internal/idp/idptest"
)

// scopeMapping is a scope mapping as the suite reads it behind the adapter's back.
type scopeMapping struct {
	PK         string  `json:"pk"`
	Name       string  `json:"name"`
	Managed    *string `json:"managed"`
	Scope      string  `json:"scope_name"`
	Expression string  `json:"expression"`
}

// guardProvider is a guard's proxy provider as the suite reads it.
type guardProvider struct {
	PK       int      `json:"pk"`
	Name     string   `json:"name"`
	Mappings []string `json:"property_mappings"`
}

func (w *world) roleMapping(t *testing.T) scopeMapping {
	t.Helper()
	var ms struct{ Results []scopeMapping }
	w.raw(t, w.own, "GET", "/api/v3/propertymappings/provider/scope/?page_size=500", nil, &ms)
	var mine []scopeMapping
	for _, m := range ms.Results {
		if m.Name == authentik.RoleMapping {
			mine = append(mine, m)
		}
	}
	if len(mine) != 1 {
		t.Fatalf("role mappings: %+v, want one", mine)
	}
	return mine[0]
}

func (w *world) guardProvider(t *testing.T, slug string) guardProvider {
	t.Helper()
	var ps struct{ Results []guardProvider }
	w.raw(t, w.own, "GET", "/api/v3/providers/proxy/?name__iexact="+slug, nil, &ps)
	if len(ps.Results) != 1 || ps.Results[0].Name != slug {
		t.Fatalf("the provider %s: %+v", slug, ps.Results)
	}
	return ps.Results[0]
}

// evaluate runs the role mapping for a person through Authentik's own test of a mapping, which evaluates it as a
// token for them would, and returns the headers its answer gives the outpost. It never goes through the outpost,
// so the order in which the outpost writes headers can't decide what it shows.
func (w *world) evaluate(t *testing.T, username string) map[string]string {
	t.Helper()
	var res struct {
		Successful bool   `json:"successful"`
		Result     string `json:"result"`
	}
	w.raw(t, w.own, "POST", "/api/v3/propertymappings/all/"+w.roleMapping(t).PK+"/test/", map[string]any{"user": w.userPK(t, username)}, &res)
	var out struct {
		Proxy struct {
			Attrs struct {
				Headers map[string]string `json:"additionalHeaders"`
			} `json:"user_attributes"`
		} `json:"ak_proxy"`
	}
	if !res.Successful || json.Unmarshal([]byte(res.Result), &out) != nil {
		t.Fatalf("the role mapping for %s: %+v", username, res)
	}
	return out.Proxy.Attrs.Headers
}

// roleMappingFailsClosed (#244's nit): with attributes that would set a header of Authentik's or Homeward's under
// another spelling, the mapping names no role at all, whichever spelling the outpost would write last, and empties
// each of them. Theo is a kid throughout, so a mapping that only emptied the forged keys would still name "kid".
func roleMappingFailsClosed(w *world) func(*testing.T) {
	return func(t *testing.T) {
		theo := w.userPK(t, "theo")
		if h := w.evaluate(t, "theo"); h[authentik.RoleHeader] != string(idp.Kid) {
			t.Fatalf("theo, with no attributes: %v, want a kid", h)
		}
		forged := map[string]any{"x-authentik-homerslab-role": "admin", "X-AUTHENTIK-HOMERSLAB-ROLE": "admin",
			"X-Authentik-Uid": "forged-uid", "x_authentik_name": "forged", "X-HomersLab-Role": "admin"}
		check := func(how string) {
			t.Helper()
			h := w.evaluate(t, "theo")
			if role, ok := h[authentik.RoleHeader]; !ok || role != "" {
				t.Errorf("%s: the role header %q (there: %v), want there and empty", how, role, ok)
			}
			for k := range forged {
				if v, ok := h[k]; !ok || v != "" {
					t.Errorf("%s: %s is %q (there: %v), want emptied", how, k, v, ok)
				}
			}
		}
		w.raw(t, w.own, "PATCH", fmt.Sprintf("/api/v3/core/users/%d/", theo), map[string]any{"attributes": map[string]any{"additionalHeaders": forged}}, nil)
		check("in the person's attributes")
		w.raw(t, w.own, "PATCH", fmt.Sprintf("/api/v3/core/users/%d/", theo), map[string]any{"attributes": map[string]any{}}, nil)
		var house struct {
			PK string `json:"pk"`
		}
		w.raw(t, w.own, "POST", "/api/v3/core/groups/", map[string]any{"name": "the-house-244", "users": []int{theo},
			"attributes": map[string]any{"additionalHeaders": forged}}, &house)
		check("in a group's attributes")
		w.raw(t, w.own, "DELETE", "/api/v3/core/groups/"+house.PK+"/", nil, nil)
		if h := w.evaluate(t, "theo"); h[authentik.RoleHeader] != string(idp.Kid) {
			t.Errorf("theo, with the attributes gone: %v, want a kid again", h)
		}
	}
}

// guardDrift (#244): a scope mapping on a guard's provider other than Authentik's own and Homeward's, which could name
// the role after Homeward's does, or Homeward's role mapping changed, shows in the report (ForwardAuth false), and
// Prepare puts the guard back.
func guardDrift(w *world, a *authentik.Authentik) func(*testing.T) {
	return func(t *testing.T) {
		ctx, slug := context.Background(), "homerslab-chores"
		intact := func(how string, want bool) {
			t.Helper()
			r, err := a.Report(ctx)
			if err != nil || r.ForwardAuth != want {
				t.Errorf("%s: the report %+v %v, want ForwardAuth %v", how, r, err, want)
				var ps, ms struct{ Results []map[string]any }
				w.raw(t, w.own, "GET", "/api/v3/providers/proxy/?page_size=500", nil, &ps)
				w.raw(t, w.own, "GET", "/api/v3/propertymappings/provider/scope/?page_size=500", nil, &ms)
				for _, p := range ps.Results {
					t.Logf("provider %v of %v: %v", p["name"], p["assigned_application_slug"], p["property_mappings"])
				}
				for _, m := range ms.Results {
					t.Logf("mapping %v %q managed %v scope %v", m["pk"], m["name"], m["managed"], m["scope_name"])
				}
				t.Logf("the role mapping's expression: %q", w.roleMapping(t).Expression)
			}
		}
		prepare := func() {
			t.Helper()
			if err := idptest.Prepare(ctx, a, household); err != nil {
				t.Fatal(err)
			}
		}
		intact("as Homeward made it", true)
		before := w.guardProvider(t, slug).Mappings
		mine := w.roleMapping(t)

		// An admin's mapping that sorts after Homeward's, naming the role admin.
		var zzz scopeMapping
		w.raw(t, w.own, "POST", "/api/v3/propertymappings/provider/scope/", map[string]any{"name": "zzz", "scope_name": "zzz",
			"expression": fmt.Sprintf("return {\"ak_proxy\": {\"user_attributes\": {\"additionalHeaders\": {%q: \"admin\"}}}}", authentik.RoleHeader)}, &zzz)
		defer w.raw(t, w.own, "DELETE", "/api/v3/propertymappings/provider/scope/"+zzz.PK+"/", nil, nil)
		p := w.guardProvider(t, slug)
		w.setMappings(t, p.PK, append(p.Mappings, zzz.PK))
		if !slices.Contains(w.guardProvider(t, slug).Mappings, zzz.PK) {
			t.Fatal("the foreign mapping didn't stay on the provider")
		}
		intact("a foreign mapping on a guard", false)
		prepare()
		if got := w.guardProvider(t, slug).Mappings; slices.Contains(got, zzz.PK) || !sameSet(got, before) {
			t.Errorf("after Prepare, the provider carries %v, want %v", got, before)
		}
		intact("after Prepare", true)

		// A foreign mapping in the role mapping's own scope, whose order beside it Authentik doesn't fix.
		w.raw(t, w.own, "PATCH", "/api/v3/propertymappings/provider/scope/"+zzz.PK+"/", map[string]any{"scope_name": "homerslab"}, nil)
		w.setMappings(t, p.PK, append(before, zzz.PK))
		intact("a foreign mapping in Homeward's scope", false)
		prepare()
		intact("after Prepare", true)

		// Homeward's role mapping taken off the guard: the edge would refuse everyone, and the report says so.
		var without []string
		for _, m := range before {
			if m != mine.PK {
				without = append(without, m)
			}
		}
		w.setMappings(t, p.PK, without)
		intact("the role mapping off a guard", false)
		prepare()
		intact("after Prepare", true)
		if got := w.guardProvider(t, slug).Mappings; !sameSet(got, before) {
			t.Errorf("after Prepare, the provider carries %v, want %v", got, before)
		}

		// The guard switched to the whole domain (#83: never forward_domain), its mappings left alone.
		w.raw(t, w.own, "PATCH", fmt.Sprintf("/api/v3/providers/proxy/%d/", p.PK), map[string]any{"mode": "forward_domain",
			"cookie_domain": household.Domain}, nil)
		intact("a guard for the whole domain", false)
		prepare()
		intact("after Prepare", true)
		var mode struct {
			Mode   string `json:"mode"`
			Cookie string `json:"cookie_domain"`
		}
		w.raw(t, w.own, "GET", fmt.Sprintf("/api/v3/providers/proxy/%d/", p.PK), nil, &mode)
		if mode.Mode != "forward_single" || mode.Cookie != "" {
			t.Errorf("after Prepare, the guard is %+v, want forward_single with no cookie domain", mode)
		}

		// Homeward's role mapping changed: its expression, then its scope (one before ak_proxy's would lose to the
		// person's attributes).
		for _, change := range []map[string]any{
			{"expression": strings.Replace(mine.Expression, `and not forged`, ``, 1)},
			{"expression": fmt.Sprintf("return {\"ak_proxy\": {\"user_attributes\": {\"additionalHeaders\": {%q: \"admin\"}}}}", authentik.RoleHeader)},
			{"scope_name": "aaa"},
		} {
			w.raw(t, w.own, "PATCH", "/api/v3/propertymappings/provider/scope/"+mine.PK+"/", change, nil)
			intact(fmt.Sprintf("the role mapping changed (%v)", change), false)
			prepare()
			intact("after Prepare", true)
			if got := w.roleMapping(t); got.Expression != mine.Expression || got.Scope != mine.Scope {
				t.Errorf("after Prepare, the role mapping is %+v, want %+v", got, mine)
			}
		}
	}
}

// setMappings puts a guard's provider's scope mappings, as an admin in the console could. Authentik checks a proxy
// provider's mode on each change, so the change names it too.
func (w *world) setMappings(t *testing.T, pk int, mappings []string) {
	t.Helper()
	w.raw(t, w.own, "PATCH", fmt.Sprintf("/api/v3/providers/proxy/%d/", pk), map[string]any{"mode": "forward_single", "property_mappings": mappings}, nil)
}

func sameSet(a, b []string) bool {
	a, b = slices.Clone(a), slices.Clone(b)
	slices.Sort(a)
	slices.Sort(b)
	return slices.Equal(a, b)
}

// guardSettingsDrift (#273): a guard's provider changed in the console where it decides who gets past it, its mappings
// left alone. Each change alone shows in the report (ForwardAuth false); Prepare puts every one back. Header auth on is
// the way in it would open: the outpost takes Authorization: Basic with a person's LDAP app password for a session,
// through the provider's client_credentials grant, with no passkey; after Prepare, the guard refuses that request.
func guardSettingsDrift(w *world, a *authentik.Authentik) func(*testing.T) {
	return func(t *testing.T) {
		ctx, slug, host := context.Background(), "homerslab-chores", "chores."+household.Domain
		report := func(how string, want bool) {
			t.Helper()
			if r, err := a.Report(ctx); err != nil || r.ForwardAuth != want {
				t.Errorf("%s: the report %+v %v, want ForwardAuth %v", how, r, err, want)
			}
		}
		pk := w.guardProvider(t, slug).PK
		at := fmt.Sprintf("/api/v3/providers/proxy/%d/", pk)
		read := func() map[string]any {
			t.Helper()
			var p map[string]any
			w.raw(t, w.own, "GET", at, nil, &p)
			return p
		}
		patch := func(change map[string]any) {
			t.Helper()
			body := map[string]any{"mode": "forward_single"} // Authentik validates a partial update as proxy mode otherwise
			for k, v := range change {
				body[k] = v
			}
			w.raw(t, w.own, "PATCH", at, body, nil)
		}
		flowPK := func(slug string) string {
			t.Helper()
			var fs struct {
				Results []struct {
					PK   string `json:"pk"`
					Slug string `json:"slug"`
				}
			}
			w.raw(t, w.own, "GET", "/api/v3/flows/instances/?slug="+slug, nil, &fs)
			if len(fs.Results) != 1 || fs.Results[0].Slug != slug {
				t.Fatalf("the flow %s: %+v", slug, fs.Results)
			}
			return fs.Results[0].PK
		}
		var admin struct {
			Results []struct {
				PK int `json:"pk"`
			}
		}
		w.raw(t, w.own, "GET", "/api/v3/providers/oauth2/?name=homerslab-admin", nil, &admin)
		if len(admin.Results) != 1 {
			t.Fatalf("Admin's provider: %+v", admin.Results)
		}
		report("as Homeward made it", true)
		before := read()
		changes := []map[string]any{
			{"intercept_header_auth": true},
			{"basic_auth_enabled": true, "basic_auth_user_attribute": "username", "basic_auth_password_attribute": "password"},
			{"authentication_flow": flowPK("default-authentication-flow")},
			{"authorization_flow": flowPK("default-provider-authorization-explicit-consent")},
			{"invalidation_flow": flowPK("default-invalidation-flow")},
			{"skip_path_regex": "^/.*$"},
			{"jwt_federation_providers": []int{admin.Results[0].PK}},
			{"cookie_domain": household.Domain},
			{"access_token_validity": "weeks=52"},
		}
		// Whatever stops the case midway, the guard goes back as it was for the cases after it.
		defer func() {
			undo := map[string]any{}
			for _, change := range changes {
				for k := range change {
					undo[k] = before[k]
				}
			}
			patch(undo)
		}()
		for _, change := range changes {
			patch(change)
			report(fmt.Sprintf("changed: %v", change), false)
			undo := map[string]any{}
			for k := range change {
				undo[k] = before[k]
			}
			patch(undo)
			report(fmt.Sprintf("changed back by hand: %v", undo), true)
		}

		// Off the embedded outpost, which the edge asks.
		type outpost struct {
			PK        string `json:"pk"`
			Managed   string `json:"managed"`
			Providers []int  `json:"providers"`
		}
		embedded := func() outpost {
			t.Helper()
			var os struct{ Results []outpost }
			w.raw(t, w.own, "GET", "/api/v3/outposts/instances/?managed__iexact=goauthentik.io/outposts/embedded", nil, &os)
			if len(os.Results) != 1 || os.Results[0].Managed != "goauthentik.io/outposts/embedded" {
				t.Fatalf("the embedded outpost: %+v", os.Results)
			}
			return os.Results[0]
		}
		o := embedded()
		defer func() {
			if now := embedded(); !slices.Contains(now.Providers, pk) {
				w.raw(t, w.own, "PATCH", "/api/v3/outposts/instances/"+now.PK+"/", map[string]any{"providers": append(now.Providers, pk)}, nil)
			}
		}()
		w.raw(t, w.own, "PATCH", "/api/v3/outposts/instances/"+o.PK+"/", map[string]any{"providers": slices.DeleteFunc(slices.Clone(o.Providers),
			func(p int) bool { return p == pk })}, nil)
		report("off the embedded outpost", false)
		w.raw(t, w.own, "PATCH", "/api/v3/outposts/instances/"+o.PK+"/", map[string]any{"providers": o.Providers}, nil)
		report("back on the embedded outpost by hand", true)

		// The way in: theo, a kid, has an app password for a kids' LDAP app, and chores is the kids' guarded app.
		books := idp.LDAPApp{Slug: "homerslab-kids-books-273", Name: "Kids' books", Roles: []idp.Role{idp.Kid}}
		if _, err := a.EnsureLDAP(ctx, books); err != nil {
			t.Fatal(err)
		}
		defer func() { _ = a.DeleteLDAP(context.Background(), books.Slug) }()
		basic := "Basic " + base64.StdEncoding.EncodeToString([]byte("theo:"+appPassword(t, a, books.Slug, "theo")))
		ask := func() (int, string) {
			t.Helper()
			req, _ := http.NewRequest("GET", upstream+"/outpost.goauthentik.io/auth/caddy", nil)
			for k, v := range map[string]string{"X-Forwarded-Host": host, "X-Forwarded-Proto": "https", "X-Forwarded-Uri": "/", "X-Forwarded-Method": "GET",
				"Authorization": basic} {
				req.Header.Set(k, v)
			}
			c := &http.Client{Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
			resp, err := c.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			return resp.StatusCode, resp.Header.Get(edge.AuthentikGuard("").Person)
		}
		let := func(status int, uid string) bool { return status/100 == 2 && uid != "" }
		// The outpost takes a provider's change a while after Authentik saves it.
		until := func(how string, want bool) {
			t.Helper()
			status, uid := ask()
			for deadline := time.Now().Add(3 * time.Minute); let(status, uid) != want && time.Now().Before(deadline); status, uid = ask() {
				time.Sleep(2 * time.Second)
			}
			if let(status, uid) != want {
				t.Errorf("%s: Basic with theo's app password at %s: %d, uid %q; want let in %v", how, host, status, uid, want)
			}
		}
		until("as Homeward made it", false)
		patch(changes[0])
		until("header auth on", true)

		// Every change at once, then Prepare: each is put back, and the request is refused again.
		for _, change := range changes[1:] {
			patch(change)
		}
		o = embedded()
		w.raw(t, w.own, "PATCH", "/api/v3/outposts/instances/"+o.PK+"/", map[string]any{"providers": slices.DeleteFunc(slices.Clone(o.Providers),
			func(p int) bool { return p == pk })}, nil)
		report("every change at once", false)
		if err := idptest.Prepare(ctx, a, household); err != nil {
			t.Fatal(err)
		}
		report("after Prepare", true)
		after := read()
		for _, change := range changes {
			for k := range change {
				if k == "basic_auth_user_attribute" || k == "basic_auth_password_attribute" {
					continue // Prepare empties them, which Basic auth off never reads
				}
				if fmt.Sprint(after[k]) != fmt.Sprint(before[k]) {
					t.Errorf("after Prepare, %s is %v, want %v", k, after[k], before[k])
				}
			}
		}
		if !slices.Contains(embedded().Providers, pk) {
			t.Errorf("after Prepare, the embedded outpost serves %v, want the guard %d too", embedded().Providers, pk)
		}
		until("after Prepare", false)
	}
}
