package vault

import (
	"go/ast"
	"go/parser"
	"go/token"
	"maps"
	"strconv"
	"strings"
	"testing"
)

// The Linux counterpart of keychain_guard_test.go. kek_linux.go claims it only
// ever looks up one Secret Service item by two exact attributes, and never
// enumerates, deletes or rewrites anything. These checks keep that claim true
// as the file changes: they parse source, because the regression guarded
// against is a new call site that no runtime test would exercise.

const (
	dbusImport        = "github.com/godbus/dbus/v5"
	secretServiceFile = "internal/vault/kek_linux.go" // the one file allowed to import it
)

// allowedDBusNames is every D-Bus name kek_linux.go may spell out. A new one —
// Item.Delete, Service.Lock, a Properties.Get that lists a collection's
// items — fails until it is reviewed and added here.
var allowedDBusNames = map[string]bool{
	"org.freedesktop.secrets":                                              true,
	"/org/freedesktop/secrets":                                             true,
	"org.freedesktop.Secret.Service.OpenSession":                           true,
	"org.freedesktop.Secret.Service.SearchItems":                           true,
	"org.freedesktop.Secret.Service.Unlock":                                true,
	"org.freedesktop.Secret.Service.ReadAlias":                             true,
	"org.freedesktop.Secret.Collection.CreateItem":                         true,
	"org.freedesktop.Secret.Item.GetSecret":                                true,
	"org.freedesktop.Secret.Prompt.Prompt":                                 true,
	"org.freedesktop.Secret.Prompt":                                        true,
	"org.freedesktop.Secret.Item.Label":                                    true,
	"org.freedesktop.Secret.Item.Attributes":                               true,
	"busctl --user call org.freedesktop.secrets /org/freedesktop/secrets ": true, // KeychainInspect
	"org.freedesktop.Secret.Service SearchItems a{ss} 2 service ":          true, // KeychainInspect
}

// wantKeyAttributes is the exact search; dropping either attribute would
// match items this binary did not create.
var wantKeyAttributes = map[string]string{`"service"`: "KeychainService", `"account"`: "KeychainAccount"}

// checkSecretServiceUse lists every way the Go file at path could reach the
// Secret Service beyond the one exact-match item.
func checkSecretServiceUse(path, src string) []string {
	file, err := parser.ParseFile(token.NewFileSet(), path, src, parser.SkipObjectResolution)
	if err != nil {
		return []string{"cannot parse: " + err.Error()}
	}

	var problems []string
	for _, imp := range file.Imports {
		if importPath, _ := strconv.Unquote(imp.Path.Value); importPath == dbusImport && path != secretServiceFile {
			problems = append(problems, "imports "+dbusImport+"; only "+secretServiceFile+" may")
		}
	}
	if path != secretServiceFile {
		return problems
	}

	ast.Inspect(file, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.BasicLit:
			value, err := strconv.Unquote(n.Value)
			if n.Kind == token.STRING && err == nil && strings.Contains(value, "freedesktop") && !allowedDBusNames[value] {
				problems = append(problems, "names D-Bus member "+strconv.Quote(value)+", which is not allowed")
			}
		case *ast.CallExpr:
			problems = append(problems, checkSearchArgs(n)...)
		case *ast.FuncDecl:
			if n.Name.Name == "keyAttributes" {
				problems = append(problems, checkKeyAttributes(n)...)
			}
		}
		return true
	})
	return problems
}

// checkSearchArgs requires SearchItems to be sent keyAttributes() and nothing
// else, e.g. call(secretsPath, methodSearchItems, []any{keyAttributes()}, ...).
func checkSearchArgs(call *ast.CallExpr) []string {
	for i, arg := range call.Args {
		if ident, ok := arg.(*ast.Ident); !ok || ident.Name != "methodSearchItems" {
			continue
		}
		if i+1 < len(call.Args) && isKeyAttributesOnly(call.Args[i+1]) {
			return nil
		}
		return []string{"SearchItems must be called with []any{keyAttributes()}"}
	}
	return nil
}

func isKeyAttributesOnly(arg ast.Expr) bool {
	list, ok := arg.(*ast.CompositeLit)
	if !ok || len(list.Elts) != 1 {
		return false
	}
	call, ok := list.Elts[0].(*ast.CallExpr)
	if !ok || len(call.Args) != 0 {
		return false
	}
	ident, ok := call.Fun.(*ast.Ident)
	return ok && ident.Name == "keyAttributes"
}

// checkKeyAttributes pins the attribute map to exactly service and account.
func checkKeyAttributes(fn *ast.FuncDecl) []string {
	got := map[string]string{}
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		kv, ok := n.(*ast.KeyValueExpr)
		if !ok {
			return true
		}
		key, _ := kv.Key.(*ast.BasicLit)
		value, _ := kv.Value.(*ast.Ident)
		if key == nil || value == nil {
			got["?"] = "?"
			return true
		}
		got[key.Value] = value.Name
		return true
	})
	if !maps.Equal(got, wantKeyAttributes) {
		return []string{"keyAttributes must be exactly service=KeychainService, account=KeychainAccount"}
	}
	return nil
}

func TestSecretServiceAccessIsLimitedToOneItem(t *testing.T) {
	sources := goSourceFiles(t)
	if _, ok := sources[secretServiceFile]; !ok {
		t.Fatalf("%s not found; the guard would pass vacuously", secretServiceFile)
	}
	for path, src := range sources {
		for _, problem := range checkSecretServiceUse(path, src) {
			t.Errorf("%s: %s (Secret Service access must stay one exact-match item; see %s)",
				path, problem, secretServiceFile)
		}
	}
}

// Each case widens Secret Service access in a way the guard must catch.
func TestSecretServiceGuardCatchesBypasses(t *testing.T) {
	const header = "package vault\n\nimport \"github.com/godbus/dbus/v5\"\n\n"
	const exact = `func keyAttributes() map[string]string {
	return map[string]string{"service": KeychainService, "account": KeychainAccount}
}
`
	cases := []struct {
		name, path, src, want string
	}{
		{
			name: "D-Bus imported elsewhere",
			path: "internal/vault/other_linux.go",
			src:  header,
			want: "only " + secretServiceFile,
		},
		{
			name: "deleting an item",
			path: secretServiceFile,
			src:  header + exact + `const del = "org.freedesktop.Secret.Item.Delete"`,
			want: "Item.Delete",
		},
		{
			name: "listing a collection's items",
			path: secretServiceFile,
			src:  header + exact + `const get = "org.freedesktop.DBus.Properties.Get"`,
			want: "Properties.Get",
		},
		{
			name: "searching with a wider attribute set",
			path: secretServiceFile,
			src:  header + exact + `func f(s *secretService) { s.call(secretsPath, methodSearchItems, []any{map[string]string{}}) }`,
			want: "SearchItems",
		},
		{
			name: "attributes missing the account",
			path: secretServiceFile,
			src: header + `func keyAttributes() map[string]string {
	return map[string]string{"service": KeychainService}
}`,
			want: "keyAttributes",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			problems := strings.Join(checkSecretServiceUse(tc.path, tc.src), "\n")
			if !strings.Contains(problems, tc.want) {
				t.Errorf("guard missed %q; reported:\n%s", tc.want, problems)
			}
		})
	}
}
