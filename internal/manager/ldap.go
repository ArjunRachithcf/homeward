package manager

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/ArjunRachithcf/homeward/internal/catalog"
	"github.com/ArjunRachithcf/homeward/internal/idp"
	"github.com/ArjunRachithcf/homeward/internal/manager/plan"
)

// ensureLDAPApps puts each LDAP app's directory back as its plan says, at every pass of the schedule (#204): its
// audience alone, and whatever the outpost's tidying took off (a binding added in the console, its bind flow changed:
// the provider leaves the outpost, and comes back here). The outpost's token goes back to the agent too, which keeps the
// outpost running as it is when nothing changed. An app's failure doesn't keep the others from theirs.
func (m *Manager) ensureLDAPApps(ctx context.Context) error {
	// One at a time with applies: an apply that fails deletes the directory it made, which must be no pass's.
	m.applying.Lock()
	defer m.applying.Unlock()
	apps, err := m.db.Apps(ctx)
	if err != nil {
		return err
	}
	var want []idp.LDAPApp
	var errs []error
	for _, a := range apps {
		b, err := m.db.Plan(ctx, a.Plan)
		var p plan.Plan
		if err == nil {
			err = json.Unmarshal(b, &p)
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("%s's plan: %w", a.ID, err))
			continue
		}
		if p.SignIn.Method == catalog.LDAP {
			want = append(want, idp.LDAPApp{Slug: "homerslab-" + a.ID, Name: p.App.Name, Roles: roles(p.Audience.Default)})
		}
	}
	if len(want) == 0 {
		return errors.Join(errs...)
	}
	ans, err := m.db.Answers(ctx)
	if err != nil {
		return errors.Join(append(errs, err)...)
	}
	provider, err := m.provider(ctx, ans)
	if err != nil {
		return errors.Join(append(errs, err)...)
	}
	directory, ok := provider.(idp.LDAP)
	if !ok {
		return errors.Join(append(errs, errors.New("the household account serves no LDAP"))...)
	}
	token, err := directory.LDAPOutpost(ctx)
	if err != nil {
		return errors.Join(append(errs, fmt.Errorf("the LDAP outpost: %w", err))...)
	}
	if err := m.agent.ldapOutpost(ctx, token); err != nil {
		errs = append(errs, fmt.Errorf("the LDAP outpost's token: %w", err))
	}
	if err := directory.EnsureLDAPApps(ctx, want); err != nil {
		errs = append(errs, fmt.Errorf("the LDAP directories: %w", err))
	}
	return errors.Join(errs...)
}

// warnAppPasswords is the security event's source, per admin, when one held app passwords (#281).
const warnAppPasswords = "security:app-passwords:"

// endAdminAppPasswords ends every admin's app passwords, at every pass of the schedule (#281): Homeward makes none for
// an admin, but with Kanidm a person makes their own, an admin too, and a console can. Each admin found is a security
// event. It runs whether or not the household has an LDAP app: an app password is a credential either way.
func (m *Manager) endAdminAppPasswords(ctx context.Context) error {
	ans, err := m.db.Answers(ctx)
	if err != nil || ans[ansSignInBootstrapped] == "" {
		return err // no household account yet: nobody holds anything
	}
	provider, err := m.provider(ctx, ans)
	if err != nil {
		return err
	}
	directory, ok := provider.(idp.LDAP)
	if !ok {
		return nil
	}
	found, err := directory.EndAdminAppPasswords(ctx)
	for _, f := range found {
		what := "security: " + f.Username + " held app passwords, which an admin never does, so Homeward ended them."
		if f.Err != nil {
			m.log.Error("couldn't end an admin's app passwords", "username", f.Username, "err", f.Err)
			what = "security: " + f.Username + " holds app passwords, which an admin never does, and Homeward couldn't end " +
				"them; it tries again at every pass."
		} else {
			m.log.Error("ended an admin's app passwords", "username", f.Username)
		}
		m.warnOnce(ctx, warnAppPasswords+f.Username, what+" An admin uses LDAP apps with a separate account that isn't an "+
			"admin; if "+f.Username+" didn't make them, check what else changed on their account.")
	}
	return err
}
