package authentik

import "time"

// SetLDAPRetire sets how long a closed LDAP application and its provider stay off the outpost before they go.
func SetLDAPRetire(a *Authentik, d time.Duration) { a.ldapRetire = d }

// RoleMapping is the name of Homeward's role mapping, which every guard's provider carries.
const RoleMapping = roleMapping

// LDAPPasswordPrefix is what the identifier of an app password for an LDAP app starts with, by the app's slug.
func LDAPPasswordPrefix(slug string) string { return ldapPasswordOf(ldapObj(slug)) }

// UserPath is the path of Homeward's people in Authentik.
const UserPath = userPath

// LDAPNoAdminExpr is the expression of the policy that refuses admins at every LDAP bind, for the admins' group's pk.
func LDAPNoAdminExpr(admins string) string { return ldapNoAdminExpr(admins) }
