package vault

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	pathpkg "path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// The safety claim in kek_darwin.go is that this binary can only ever ask the
// keychain for one specific item: it never enumerates, and never issues a query
// missing either identifying attribute. macOS enforces the rest via item ACLs,
// but that only helps if we don't hand it a broad query in the first place.
//
// These tests keep that property from regressing silently. They parse source
// rather than test behavior deliberately — the failure mode being guarded
// against is someone adding a new call site, which no runtime test would cover.
// Parsing, not grepping, so an import alias cannot hide a call.

const (
	keychainImport = "github.com/keybase/go-keychain"
	keychainPkg    = "keychain"                     // the name that import declares
	keychainFile   = "internal/vault/kek_darwin.go" // the one file allowed to import it
)

// forbiddenKeychainAPIs widen a query beyond the single known item, or reach
// items without going through the NewItem path checked below.
var forbiddenKeychainAPIs = map[string]string{
	"MatchLimitAll":              "returns every matching item",
	"QueryItemRef":               "returns a live reference, bypassing our accessors",
	"GetGenericPasswordAccounts": "enumerates every account of a service",
	"GetAccountsForService":      "enumerates every account of a service",
	"NewGenericPassword":         "builds an item outside the checked NewItem path",
	"GetGenericPassword":         "queries outside the checked NewItem path",
	"DeleteGenericPasswordItem":  "deletes outside the checked NewItem path",
	"DeleteItem":                 "deletes keychain items",
	"DeleteItemRef":              "deletes keychain items",
	"UpdateItem":                 "rewrites every item a query matches",
	"SynchronizableAny":          "matches iCloud-synced items as well",
	"SecClassInternetPassword":   "a class this binary never creates",
}

// rawSetters write an attribute by key, which would dodge the pins below, e.g.
// q.SetString("m_Limit", "m_LimitAll").
var rawSetters = map[string]bool{"SetString": true, "SetInt32": true}

// pinnedArgs is the only argument each item setter may receive. Forbidding
// names is not enough on its own: SetMatchLimit(2) is MatchLimitAll.
var pinnedArgs = map[string]string{
	"SetSecClass":       keychainPkg + ".SecClassGenericPassword",
	"SetMatchLimit":     keychainPkg + ".MatchLimitOne",
	"SetSynchronizable": keychainPkg + ".SynchronizableNo",
	"SetService":        "KeychainService",
	"SetAccount":        "KeychainAccount",
}

// qualifyingSetters must both be called on every item NewItem builds.
var qualifyingSetters = []string{"SetService", "SetAccount"}

// checkKeychainUse lists every way the Go file at path (repo-relative, slash
// separated) could reach the keychain beyond the one exact-match item.
func checkKeychainUse(path, src string) []string {
	file, err := parser.ParseFile(token.NewFileSet(), path, src, parser.SkipObjectResolution)
	if err != nil {
		// Source we cannot parse is source we cannot vouch for.
		return []string{"cannot parse: " + err.Error()}
	}

	problems, local := checkImports(path, file)

	// Method names are only meaningful where a keychain.Item can exist: the
	// package that owns the allowed file. Elsewhere SetString is reflect's.
	if pathpkg.Dir(path) == pathpkg.Dir(keychainFile) {
		problems = append(problems, checkSetters(file, local)...)
	}
	if local != "" {
		problems = append(problems, checkForbidden(file, local)...)
		problems = append(problems, checkItemsQualified(file, local)...)
	}
	return problems
}

// checkImports confines go-keychain to keychainFile and returns the name it is
// imported under there ("" when absent), so an alias is followed, not missed.
func checkImports(path string, file *ast.File) (problems []string, local string) {
	for _, imp := range file.Imports {
		importPath, _ := strconv.Unquote(imp.Path.Value)
		if importPath == "C" {
			problems = append(problems, `imports "C": cgo can call the Security framework directly, past every check here`)
			continue
		}
		if importPath != keychainImport {
			continue
		}
		if path != keychainFile {
			problems = append(problems, "imports "+keychainImport+"; only "+keychainFile+" may")
		}

		name := keychainPkg
		if imp.Name != nil {
			name = imp.Name.Name
		}
		switch name {
		case ".":
			problems = append(problems, "dot import of "+keychainImport+" hides which calls are keychain calls")
		case "_":
			problems = append(problems, "blank import of "+keychainImport+" serves no purpose here")
		default:
			local = name
		}
	}
	return problems, local
}

// checkForbidden rejects any use of a forbidden API — called or not, since a
// function value is as good as a call.
func checkForbidden(file *ast.File, local string) []string {
	var problems []string
	ast.Inspect(file, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok || !isPkgSelector(sel, local) {
			return true
		}
		if reason, bad := forbiddenKeychainAPIs[sel.Sel.Name]; bad {
			problems = append(problems, fmt.Sprintf("uses %s.%s: %s", keychainPkg, sel.Sel.Name, reason))
		}
		return true
	})
	return problems
}

// checkSetters rejects raw setters, and any pinned setter that is not called
// directly with its pinned argument — a method value would dodge the pin.
func checkSetters(file *ast.File, local string) []string {
	callOf := map[ast.Expr]*ast.CallExpr{}
	ast.Inspect(file, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			callOf[call.Fun] = call
		}
		return true
	})

	var problems []string
	ast.Inspect(file, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		name := sel.Sel.Name
		if rawSetters[name] {
			problems = append(problems, "uses "+name+", which sets any attribute and skips every pin")
			return true
		}
		want, pinned := pinnedArgs[name]
		if !pinned {
			return true
		}
		call := callOf[sel]
		if call == nil || len(call.Args) != 1 || canonical(call.Args[0], local) != want {
			problems = append(problems, fmt.Sprintf("%s must be called directly as %s(%s)", name, name, want))
		}
		return true
	})
	return problems
}

// checkItemsQualified requires every NewItem() to be assigned to a variable
// that the same function gives both a service and an account, so no query can
// match an item this binary did not create. Pins fix those values.
func checkItemsQualified(file *ast.File, local string) []string {
	var problems []string
	tracked := map[*ast.SelectorExpr]bool{}

	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		var items []string
		called := map[string]bool{} // "q.SetService"
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.AssignStmt:
				if len(n.Lhs) != 1 || len(n.Rhs) != 1 {
					return true
				}
				variable, isIdent := n.Lhs[0].(*ast.Ident)
				call, isCall := n.Rhs[0].(*ast.CallExpr)
				if !isIdent || !isCall {
					return true
				}
				if sel, ok := call.Fun.(*ast.SelectorExpr); ok && isPkgSelector(sel, local) && sel.Sel.Name == "NewItem" {
					items = append(items, variable.Name)
					tracked[sel] = true
				}
			case *ast.CallExpr:
				sel, isSel := n.Fun.(*ast.SelectorExpr)
				if !isSel {
					return true
				}
				if receiver, ok := sel.X.(*ast.Ident); ok {
					called[receiver.Name+"."+sel.Sel.Name] = true
				}
			}
			return true
		})

		for _, item := range items {
			for _, setter := range qualifyingSetters {
				if !called[item+"."+setter] {
					problems = append(problems, fmt.Sprintf("%s builds keychain item %s but never calls %s.%s",
						fn.Name.Name, item, item, setter))
				}
			}
		}
	}

	// Anything else — inline, package level, a function value — cannot be followed.
	ast.Inspect(file, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if ok && isPkgSelector(sel, local) && sel.Sel.Name == "NewItem" && !tracked[sel] {
			problems = append(problems, "NewItem must be assigned to a variable inside a function, so its setters can be checked")
		}
		return true
	})
	return problems
}

// isPkgSelector reports whether sel is local.Something, i.e. a package member.
func isPkgSelector(sel *ast.SelectorExpr, local string) bool {
	x, ok := sel.X.(*ast.Ident)
	return ok && local != "" && x.Name == local
}

// canonical renders a setter argument with the import alias normalized, e.g.
// kc.MatchLimitOne -> keychain.MatchLimitOne. Literals, conversions and calls
// render as "" and so never match a pin.
func canonical(arg ast.Expr, local string) string {
	switch arg := arg.(type) {
	case *ast.Ident:
		return arg.Name
	case *ast.SelectorExpr:
		if isPkgSelector(arg, local) {
			return keychainPkg + "." + arg.Sel.Name
		}
	}
	return ""
}

func goSourceFiles(t *testing.T) map[string]string {
	t.Helper()

	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	sources, err := goSources(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(sources) == 0 {
		t.Fatal("found no Go source to scan; the guard would pass vacuously")
	}
	return sources
}

// goSources reads every non-test Go file of the module at root, keyed by
// slash-separated relative path. Dot-directories and nested modules are
// skipped: neither is built into this binary, and .claude/worktrees holds whole
// copies of the repo that would otherwise count kek_darwin.go once per copy.
func goSources(root string) (map[string]string, error) {
	sources := map[string]string{}
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if path == root {
				return nil
			}
			if name := entry.Name(); strings.HasPrefix(name, ".") || name == "vendor" {
				return filepath.SkipDir
			}
			if _, err := os.Stat(filepath.Join(path, "go.mod")); err == nil {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		sources[filepath.ToSlash(rel)] = string(data)
		return nil
	})
	return sources, err
}

// The walk must see exactly this module's own sources: not test files, not a
// nested module, not a copy of the repo under a dot-directory.
func TestGoSourcesSkipsNestedModulesAndDotDirs(t *testing.T) {
	root := t.TempDir()
	for _, file := range []string{
		"go.mod", "a.go", "sub/b.go", "sub/b_test.go",
		"nested/go.mod", "nested/c.go",
		".claude/worktrees/copy/go.mod", ".claude/worktrees/copy/internal/vault/kek_darwin.go",
		".hidden/d.go",
	} {
		path := filepath.Join(root, filepath.FromSlash(file))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("package x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	sources, err := goSources(root)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for path := range sources {
		got = append(got, path)
	}
	slices.Sort(got)
	if want := []string{"a.go", "sub/b.go"}; !slices.Equal(got, want) {
		t.Errorf("scanned %v, want %v", got, want)
	}
}

func TestKeychainAccessIsLimitedToOneItem(t *testing.T) {
	for path, src := range goSourceFiles(t) {
		for _, problem := range checkKeychainUse(path, src) {
			t.Errorf("%s: %s (keychain access must stay one exact-match item; see %s)",
				path, problem, keychainFile)
		}
	}
}

// fakeSource is a Go file in package vault with one import.
func fakeSource(imp, body string) string {
	return "package vault\n\nimport " + imp + "\n\n" + body + "\n"
}

// fullyQualified builds an item the way kek_darwin.go does, so each case below
// differs from a passing file by exactly the attack it names.
const fullyQualified = `q := keychain.NewItem()
	q.SetService(KeychainService)
	q.SetAccount(KeychainAccount)
`

// The guard is itself security code: each case is a way to widen keychain
// access that it must catch. The first two are a bypass the old text-matching
// guard let through.
func TestKeychainGuardCatchesBypasses(t *testing.T) {
	const aliasedBypass = `func enumerate(service string) ([]string, error) { return kc.GetGenericPasswordAccounts(service) }
func broad() ([]kc.QueryResult, error) { return kc.QueryItem(kc.NewGenericPassword("", "", "", nil, "")) }`

	cases := []struct {
		name, path, src string
		want            []string // each must appear in some reported problem
	}{
		{
			name: "aliased enumeration in a new file",
			path: "internal/vault/enumerate_darwin.go",
			src:  fakeSource(`kc "github.com/keybase/go-keychain"`, aliasedBypass),
			want: []string{"only " + keychainFile},
		},
		{
			name: "aliased enumeration in the allowed file",
			path: keychainFile,
			src:  fakeSource(`kc "github.com/keybase/go-keychain"`, aliasedBypass),
			want: []string{"GetGenericPasswordAccounts", "NewGenericPassword"},
		},
		{
			name: "dot import hides the package name",
			path: keychainFile,
			src:  fakeSource(`. "github.com/keybase/go-keychain"`, `var accounts = GetGenericPasswordAccounts`),
			want: []string{"dot import"},
		},
		{
			name: "blank import",
			path: keychainFile,
			src:  fakeSource(`_ "github.com/keybase/go-keychain"`, ""),
			want: []string{"blank import"},
		},
		{
			name: "untyped constant for MatchLimitAll",
			path: keychainFile,
			src: fakeSource(`"github.com/keybase/go-keychain"`,
				"func load() {\n\t"+fullyQualified+"\tq.SetMatchLimit(2)\n}"),
			want: []string{"SetMatchLimit"},
		},
		{
			name: "pinned setter taken as a method value",
			path: keychainFile,
			src: fakeSource(`"github.com/keybase/go-keychain"`,
				"func load() {\n\t"+fullyQualified+"\tlimit := q.SetMatchLimit\n\tlimit(2)\n}"),
			want: []string{"SetMatchLimit"},
		},
		{
			name: "raw attribute setter",
			path: keychainFile,
			src: fakeSource(`"github.com/keybase/go-keychain"`,
				"func load() {\n\t"+fullyQualified+"\tq.SetString(\"m_Limit\", \"m_LimitAll\")\n}"),
			want: []string{"SetString"},
		},
		{
			name: "query missing the account beside one that sets it",
			path: keychainFile,
			src: fakeSource(`"github.com/keybase/go-keychain"`,
				"func store() {\n\t"+fullyQualified+"}\n\n"+
					"func load() {\n\tq := keychain.NewItem()\n\tq.SetService(KeychainService)\n\tkeychain.QueryItem(q)\n}"),
			want: []string{"SetAccount"},
		},
		{
			name: "item built inline where it cannot be tracked",
			path: keychainFile,
			src: fakeSource(`"github.com/keybase/go-keychain"`,
				"func load() { keychain.QueryItem(keychain.NewItem()) }"),
			want: []string{"NewItem"},
		},
		{
			name: "query including iCloud-synced items",
			path: keychainFile,
			src: fakeSource(`"github.com/keybase/go-keychain"`,
				"func load() {\n\t"+fullyQualified+"\tq.SetSynchronizable(keychain.SynchronizableAny)\n}"),
			want: []string{"SynchronizableAny"},
		},
		{
			name: "cgo reaching the Security framework directly",
			path: "internal/vault/raw_darwin.go",
			src:  fakeSource(`"C"`, ""),
			want: []string{`"C"`},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			problems := strings.Join(checkKeychainUse(tc.path, tc.src), "\n")
			for _, want := range tc.want {
				if !strings.Contains(problems, want) {
					t.Errorf("guard missed %q; reported:\n%s", want, problems)
				}
			}
		})
	}
}
