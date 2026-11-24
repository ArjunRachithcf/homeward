package authentik_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"unicode"

	"go.yaml.in/yaml/v3"

	"github.com/ArjunRachithcf/homeward/internal/testenv"
)

// The contract suite runs split over CI's identity runners, each with -run and -skip patterns of its own (#303): its
// LDAP section alone would pass go test's timeout on one. A pattern that missed a subtest would leave it run nowhere,
// and one that took it twice would spend a runner's time on it again. This reads the patterns from ci.yml and the
// subtests' names from the suite's source, and matches them as go test does: every subtest on exactly one runner; the
// bootstrap, which every section needs, on every runner; the outpost and the first app's provider, which the rest of
// the LDAP section needs, on every runner that runs any of it.
func TestTheContractSubtestsRunOnceAcrossTheIdentityRunners(t *testing.T) {
	testenv.Isolate(t)
	runners := identityRunners(t)
	if len(runners) < 2 {
		t.Fatalf("the identity job's matrix: %+v, want the suite split", runners)
	}
	const top = "TestTheIdentityProviderContractOnAuthentik"
	contract := parseGo(t, "contract_test.go")
	suite := funcBody(t, contract, top)
	ldapBlock, level2 := (*ast.BlockStmt)(nil), subtests(t, suite)
	for _, s := range level2 {
		if strings.HasPrefix(s.name, "LDAP: ") {
			ldapBlock = s.body
		}
	}
	if ldapBlock == nil {
		t.Fatal("no LDAP section in the suite")
	}
	idptest := parseGo(t, "../idptest/idptest.go")
	idptestLDAP := parseGo(t, "../idptest/ldap.go")
	level2 = append(level2, subtests(t, funcBody(t, idptest, "Run"))...)
	level3 := append(subtests(t, ldapBlock), subtests(t, funcBody(t, idptestLDAP, "RunLDAP"))...)

	var paths [][]string
	section := ""
	for _, s := range level2 {
		if s.body == ldapBlock {
			section = goName(t, s.name)
			continue // a section, not a subtest: its own are counted
		}
		paths = append(paths, []string{top, goName(t, s.name)})
	}
	for _, s := range level3 {
		paths = append(paths, []string{top, section, goName(t, s.name)})
	}
	if len(paths) < 40 {
		t.Fatalf("found %d subtests in the suite's source: the parse missed them", len(paths))
	}

	everywhere := func(p []string) bool { return len(p) == 2 && strings.HasPrefix(p[1], "bootstrap:") }
	ldapNeeds := func(p []string) bool {
		return len(p) == 3 && (strings.HasPrefix(p[2], "the_LDAP_outpost:") || strings.HasPrefix(p[2], "an_app's_LDAP_provider:"))
	}
	runsLDAP := make([]bool, len(runners))
	for i, r := range runners {
		for _, p := range paths {
			if len(p) == 3 && !ldapNeeds(p) && r.selects(p) {
				runsLDAP[i] = true
			}
		}
	}
	for _, p := range paths {
		var on []string
		for i, r := range runners {
			sel := r.selects(p)
			if sel {
				on = append(on, strconv.Quote(r.Label))
			}
			switch {
			case everywhere(p) && !sel:
				t.Errorf("%s: not on the runner %q, which needs it", strings.Join(p, "/"), r.Label)
			case ldapNeeds(p) && runsLDAP[i] && !sel:
				t.Errorf("%s: not on the runner %q, whose LDAP subtests need it", strings.Join(p, "/"), r.Label)
			}
		}
		if len(on) == 0 || !everywhere(p) && !ldapNeeds(p) && len(on) != 1 {
			t.Errorf("%s: on the runners %v, want exactly one", strings.Join(p, "/"), on)
		}
	}
	// A runner that runs the LDAP setup runs something of the section's beside it: a subtest renamed out of its
	// runner's pattern would otherwise leave that runner running the setup alone.
	for i, r := range runners {
		for _, p := range paths {
			if ldapNeeds(p) && r.selects(p) && !runsLDAP[i] {
				t.Errorf("the runner %q runs the LDAP setup and nothing of the section beside it", r.Label)
				break
			}
		}
	}
	// Every alternative of every pattern names a subtest that is there: one renamed away from its alternative would
	// otherwise fall to another runner unseen (into ", LDAP", which runs what nothing else takes), or stop being skipped.
	// One alternative may name a subtest still to come, in expectedSoon, until it is there.
	expectedSoon := map[string]bool{
		// #300 (#298): its admins'-audience drift goes to ", LDAP drift" rather than to the impostors' runner, which
		// its other drifts fill. Remove it here once #300 is merged: the check then holds it to the subtest.
		"drift:_providers_of_the_console's,_or_of_an_older": true,
	}
	for _, r := range runners {
		for _, pat := range []string{r.Run, r.Skip} {
			if pat == "" {
				continue
			}
			for _, levels := range splitPattern(pat) {
				for depth, elem := range levels {
					for _, alt := range groupAlternatives(elem) {
						found := false
						for _, p := range paths {
							if len(p) > depth {
								if m, err := regexp.MatchString(alt, p[depth]); err == nil && m {
									found = true
									break
								}
							}
						}
						switch {
						case !found && !expectedSoon[alt]:
							t.Errorf("the runner %q: %q in %q names no subtest of the suite", r.Label, alt, pat)
						case found && expectedSoon[alt]:
							t.Errorf("the runner %q: %q names a subtest now: take it out of expectedSoon", r.Label, alt)
						}
					}
				}
			}
		}
	}
	// The patterns themselves, against names they must tell apart (the go test matching itself).
	if !(runner{Run: "A/(b|c)", Skip: "A/c/d"}).selects([]string{"A", "c", "e"}) ||
		(runner{Run: "A/(b|c)", Skip: "A/c/d"}).selects([]string{"A", "c", "d_x"}) ||
		(runner{Run: "A/b/(x|y)"}).selects([]string{"A", "b", "z"}) || !(runner{Run: "A/b/(x|y)"}).selects([]string{"A", "b"}) {
		t.Error("the matching isn't go test's")
	}
}

// runner is one entry of the identity job's matrix: the patterns its go test runs with.
type runner struct {
	Label string `yaml:"label"`
	Run   string `yaml:"run"`
	Skip  string `yaml:"skip"`
}

func identityRunners(t *testing.T) []runner {
	t.Helper()
	b, err := os.ReadFile("../../../.github/workflows/ci.yml")
	if err != nil {
		t.Fatal(err)
	}
	var ci struct {
		Jobs map[string]struct {
			Strategy struct {
				Matrix struct {
					Include []runner `yaml:"include"`
				} `yaml:"matrix"`
			} `yaml:"strategy"`
			Steps []struct {
				Run string `yaml:"run"`
			} `yaml:"steps"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal(b, &ci); err != nil {
		t.Fatal(err)
	}
	job := ci.Jobs["identity"]
	uses := false
	for _, s := range job.Steps {
		uses = uses || strings.Contains(s.Run, `go test`) && strings.Contains(s.Run, `-run "$RUN" -skip "$SKIP"`)
	}
	if !uses {
		t.Fatal("the identity job's go test doesn't take its matrix's patterns as -run and -skip")
	}
	return job.Strategy.Matrix.Include
}

// selects says whether go test, given the runner's -run and -skip, runs the subtest at path (its name at each level,
// as go test writes it), and every subtest above it, as a subtest runs only inside its parent.
func (r runner) selects(path []string) bool {
	run, skip := splitPattern(r.Run), splitPattern(r.Skip)
	for n := 1; n <= len(path); n++ {
		elem := path[:n]
		if r.Run != "" {
			if ok, _ := run.matches(elem); !ok {
				return false
			}
		}
		if r.Skip != "" {
			if ok, partial := skip.matches(elem); ok && !partial {
				return false
			}
		}
	}
	return true
}

// alternatives is a pattern as go test reads it (testing/match.go): alternatives at the top level's |, each a regexp
// for each level, split at the top level's /.
type alternatives [][]string

func splitPattern(s string) alternatives {
	var out alternatives
	var a []string
	brackets, parens := 0, 0
	for i := 0; i < len(s); {
		switch s[i] {
		case '[':
			brackets++
		case ']':
			if brackets--; brackets < 0 {
				brackets = 0
			}
		case '(':
			if brackets == 0 {
				parens++
			}
		case ')':
			if brackets == 0 {
				parens--
			}
		case '\\':
			i++
		case '/', '|':
			if brackets == 0 && parens == 0 {
				a = append(a, s[:i])
				if s[i] == '|' {
					out, a = append(out, a), nil
				}
				s, i = s[i+1:], 0
				continue
			}
		}
		i++
	}
	return append(out, append(a, s))
}

// groupAlternatives are the alternatives of one level's regexp written as one group, (a|b|c), or the regexp itself.
func groupAlternatives(elem string) []string {
	if !strings.HasPrefix(elem, "(") || !strings.HasSuffix(elem, ")") {
		return []string{elem}
	}
	inner := elem[1 : len(elem)-1]
	var out []string
	depth, start := 0, 0
	for i := 0; i < len(inner); i++ {
		switch inner[i] {
		case '\\':
			i++
		case '(':
			depth++
		case ')':
			if depth--; depth < 0 {
				return []string{elem} // the first ( closes before the last ): not one group
			}
		case '|':
			if depth == 0 {
				out = append(out, inner[start:i])
				start = i + 1
			}
		}
	}
	return append(out, inner[start:])
}

// matches is go test's: one alternative matches every level it has a regexp for; partial when the name is shorter.
func (m alternatives) matches(name []string) (ok, partial bool) {
	for _, levels := range m {
		ok = true
		for i, s := range name {
			if i >= len(levels) {
				break
			}
			if matched, err := regexp.MatchString(levels[i], s); err != nil || !matched {
				ok = false
				break
			}
		}
		if ok {
			return true, len(name) < len(levels)
		}
	}
	return false, false
}

// goName is a subtest's name as go test writes it: spaces as underscores. Names with anything else go test rewrites
// aren't in the suite.
func goName(t *testing.T, s string) string {
	t.Helper()
	for _, r := range s {
		if !unicode.IsPrint(r) {
			t.Fatalf("the subtest %q: a name go test would rewrite", s)
		}
	}
	return strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return '_'
		}
		return r
	}, s)
}

func parseGo(t *testing.T, file string) *ast.File {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), file, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func funcBody(t *testing.T, f *ast.File, name string) *ast.BlockStmt {
	t.Helper()
	for _, d := range f.Decls {
		if fd, ok := d.(*ast.FuncDecl); ok && fd.Name.Name == name && fd.Recv == nil {
			return fd.Body
		}
	}
	t.Fatalf("no func %s", name)
	return nil
}

type subtest struct {
	name string
	body *ast.BlockStmt // the subtest's own function, when it is written in place
}

// subtests are the t.Run calls of a function's own level: in its body, not inside another t.Run's function. Every one
// must be named by a constant string, so no subtest's name is unknown here.
func subtests(t *testing.T, body *ast.BlockStmt) []subtest {
	t.Helper()
	var out []subtest
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Run" || len(call.Args) != 2 {
			return true
		}
		if id, ok := sel.X.(*ast.Ident); !ok || id.Name != "t" {
			return true
		}
		lit, ok := call.Args[0].(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			t.Errorf("a subtest named by %T, not a constant string: its runner can't be checked", call.Args[0])
			return false
		}
		name, err := strconv.Unquote(lit.Value)
		if err != nil {
			t.Fatal(err)
		}
		s := subtest{name: name}
		if fn, ok := call.Args[1].(*ast.FuncLit); ok {
			s.body = fn.Body
		}
		out = append(out, s)
		return false
	})
	return out
}
