package boxsync

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	pathpkg "path"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// The claim in ssh.go is that a sync session is the one reason blindfold runs
// ssh, and that it always runs it the same way: the fixed arguments first, then
// the encrypted channel on its stdin and stdout. A second call site — a handy
// exec.Command("ssh", box, "blindfold get …") in the CLI, say — would carry
// plaintext past both, and no runtime test would notice it. Parsing, not
// grepping, so an import alias cannot hide a call.

const (
	sshFile      = "internal/boxsync/ssh.go" // the one file allowed to start ssh
	sshBinary    = "ssh"
	sshIdent     = "sshCommand" // what sshFile runs
	sshArgsIdent = "sshArgs"    // the fixed arguments it always passes first
)

// processStarters are the functions, by import path, that run another program.
var processStarters = map[string][]string{
	"os/exec":               {"Command", "CommandContext"},
	"os":                    {"StartProcess"},
	"syscall":               {"Exec", "ForkExec", "StartProcess"},
	"golang.org/x/sys/unix": {"Exec"},
}

// pinnedVars are set only where ssh.go declares them: reassigning either
// changes what every session runs.
var pinnedVars = map[string]bool{sshIdent: true, sshArgsIdent: true}

// checkSSHUse lists every way the Go file at path (repo-relative, slash
// separated) could run ssh other than ssh.go's one call.
func checkSSHUse(path, src string) []string {
	file, err := parser.ParseFile(token.NewFileSet(), path, src, parser.SkipObjectResolution)
	if err != nil {
		// Source we cannot parse is source we cannot vouch for.
		return []string{"cannot parse: " + err.Error()}
	}

	starts, problems := processStarts(file)
	if path != sshFile {
		problems = append(problems, sshLiterals(file)...)
	}
	// sshCommand and sshArgs are unexported: only this package can reach them.
	inPackage := pathpkg.Dir(path) == pathpkg.Dir(sshFile)
	switch {
	case path == sshFile:
		problems = append(problems, checkTheOneStart(file, starts)...)
	case inPackage && len(starts) > 0:
		problems = append(problems, "starts a process; in this package only "+sshFile+" may")
	}
	if inPackage {
		problems = append(problems, reassigned(file)...)
	}
	return problems
}

// processStarts returns every use of a process-starting function, following
// import aliases — called or not, since a function value is as good as a call.
func processStarts(file *ast.File) (uses []*ast.SelectorExpr, problems []string) {
	starters := map[string]map[string]bool{} // local package name → function names
	for _, imp := range file.Imports {
		importPath, _ := strconv.Unquote(imp.Path.Value)
		funcs, ok := processStarters[importPath]
		if !ok {
			continue
		}
		name := pathpkg.Base(importPath)
		if imp.Name != nil {
			name = imp.Name.Name
		}
		if name == "." {
			problems = append(problems, "dot import of "+importPath+" hides which calls start processes")
			continue
		}
		starters[name] = map[string]bool{}
		for _, f := range funcs {
			starters[name][f] = true
		}
	}
	ast.Inspect(file, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if pkg, ok := sel.X.(*ast.Ident); ok && starters[pkg.Name][sel.Sel.Name] {
			uses = append(uses, sel)
		}
		return true
	})
	return uses, problems
}

// sshLiterals finds strings naming ssh, e.g. "ssh", "/usr/bin/ssh", or the
// import path of an ssh client of its own.
func sshLiterals(file *ast.File) []string {
	var problems []string
	ast.Inspect(file, func(n ast.Node) bool {
		lit, ok := n.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		if value, err := strconv.Unquote(lit.Value); err == nil && pathpkg.Base(value) == sshBinary {
			problems = append(problems, fmt.Sprintf("names ssh (%s); only %s may run it", lit.Value, sshFile))
		}
		return true
	})
	return problems
}

// checkTheOneStart requires sshFile to start exactly one process, called
// directly as exec.CommandContext(ctx, sshCommand, append(sshArgs, …)...), so
// the fixed arguments always come first.
func checkTheOneStart(file *ast.File, starts []*ast.SelectorExpr) []string {
	if len(starts) != 1 {
		return []string{fmt.Sprintf("starts %d processes; it must start exactly one, ssh", len(starts))}
	}
	const want = "must start ssh as exec.CommandContext(ctx, " + sshIdent + ", append(" + sshArgsIdent + ", …)...)"
	var call *ast.CallExpr
	ast.Inspect(file, func(n ast.Node) bool {
		if c, ok := n.(*ast.CallExpr); ok && c.Fun == starts[0] {
			call = c
		}
		return true
	})
	if call == nil || starts[0].Sel.Name != "CommandContext" || len(call.Args) != 3 || !call.Ellipsis.IsValid() {
		return []string{want}
	}
	command, isIdent := call.Args[1].(*ast.Ident)
	args, isCall := call.Args[2].(*ast.CallExpr)
	if !isIdent || command.Name != sshIdent || !isCall || len(args.Args) == 0 {
		return []string{want}
	}
	appendFn, isAppend := args.Fun.(*ast.Ident)
	first, isFirst := args.Args[0].(*ast.Ident)
	if !isAppend || appendFn.Name != "append" || !isFirst || first.Name != sshArgsIdent {
		return []string{want}
	}
	return nil
}

// reassigned finds assignments to a pinned variable, or to one of its elements.
func reassigned(file *ast.File) []string {
	var problems []string
	ast.Inspect(file, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok {
			return true
		}
		for _, lhs := range assign.Lhs {
			for lhs != nil {
				switch x := lhs.(type) {
				case *ast.Ident:
					if pinnedVars[x.Name] {
						problems = append(problems, "assigns "+x.Name+"; it is set once, where "+sshFile+" declares it")
					}
					lhs = nil
				case *ast.IndexExpr:
					lhs = x.X
				default:
					lhs = nil
				}
			}
		}
		return true
	})
	return problems
}

// moduleSources reads every non-test Go file of this module, keyed by
// slash-separated path from its root. Dot-directories, vendor and nested
// modules are skipped, as in internal/vault's guards: none is built into this
// binary.
func moduleSources(t *testing.T) map[string]string {
	t.Helper()
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	sources := map[string]string{}
	err = filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
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
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := sources[sshFile]; !ok {
		t.Fatalf("%s not found; the guard would pass vacuously", sshFile)
	}
	return sources
}

func TestSSHRunsFromOneCall(t *testing.T) {
	for path, src := range moduleSources(t) {
		for _, problem := range checkSSHUse(path, src) {
			t.Errorf("%s: %s (ssh runs only from %s, inside the encrypted channel)", path, problem, sshFile)
		}
	}
}

// goFile is a Go source file in package pkg.
func goFile(pkg string, imports []string, body string) string {
	src := "package " + pkg + "\n\n"
	if len(imports) > 0 {
		src += "import (\n\t" + strings.Join(imports, "\n\t") + "\n)\n\n"
	}
	return src + body + "\n"
}

// The guard is itself security code: each case is a way to run ssh outside the
// one call that it must catch.
func TestSSHGuardCatchesBypasses(t *testing.T) {
	const theOneStart = "func dial(ctx context.Context) *exec.Cmd {\n" +
		"\treturn exec.CommandContext(ctx, sshCommand, append(sshArgs, \"box\")...)\n}"
	exec := []string{`"context"`, `"os/exec"`}

	cases := []struct {
		name, path, src string
		want            []string // each must appear in some reported problem
	}{
		{
			name: "ssh from the CLI",
			path: "internal/cli/peek.go",
			src:  goFile("cli", exec, `func peek() { exec.Command("ssh", "box", "blindfold get X") }`),
			want: []string{`"ssh"`},
		},
		{
			name: "aliased exec with a full path",
			path: "internal/cli/peek.go",
			src:  goFile("cli", []string{`run "os/exec"`}, `var peek = run.Command("/usr/bin/ssh")`),
			want: []string{"/usr/bin/ssh"},
		},
		{
			name: "an ssh client of its own",
			path: "internal/cli/peek.go",
			src:  goFile("cli", []string{`"golang.org/x/crypto/ssh"`}, `var peek = ssh.Dial`),
			want: []string{"golang.org/x/crypto/ssh"},
		},
		{
			name: "dot import hides the call",
			path: "internal/cli/peek.go",
			src:  goFile("cli", []string{`. "os/exec"`}, `var peek = Command`),
			want: []string{"dot import"},
		},
		{
			name: "another process start in the package",
			path: "internal/boxsync/peek.go",
			src:  goFile("boxsync", exec, `func peek() { exec.Command(sshCommand, "box") }`),
			want: []string{"only " + sshFile},
		},
		{
			name: "syscall.Exec in the package, as a value",
			path: "internal/boxsync/peek.go",
			src:  goFile("boxsync", []string{`"syscall"`}, `var peek = syscall.Exec`),
			want: []string{"only " + sshFile},
		},
		{
			name: "the fixed arguments rewritten",
			path: "internal/boxsync/peek.go",
			src:  goFile("boxsync", nil, `func init() { sshArgs = append(sshArgs, "-oProxyCommand=sh") }`),
			want: []string{"assigns " + sshArgsIdent},
		},
		{
			name: "one fixed argument replaced",
			path: "internal/boxsync/peek.go",
			src:  goFile("boxsync", nil, `func init() { sshArgs[0] = "-A" }`),
			want: []string{"assigns " + sshArgsIdent},
		},
		{
			name: "ssh without the fixed arguments",
			path: sshFile,
			src:  goFile("boxsync", exec, `func dial() *exec.Cmd { return exec.Command(sshCommand, "box") }`),
			want: []string{"must start ssh as"},
		},
		{
			name: "a second process in ssh.go",
			path: sshFile,
			src:  goFile("boxsync", exec, theOneStart+"\n\nfunc again() { exec.Command(\"sh\") }"),
			want: []string{"exactly one"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			problems := strings.Join(checkSSHUse(tc.path, tc.src), "\n")
			for _, want := range tc.want {
				if !strings.Contains(problems, want) {
					t.Errorf("guard missed %q; reported:\n%s", want, problems)
				}
			}
		})
	}

	// The shape ssh.go must keep passes: the guard is not simply always failing.
	if problems := checkSSHUse(sshFile, goFile("boxsync", exec, theOneStart)); len(problems) > 0 {
		t.Errorf("the one allowed call was refused: %v", problems)
	}
}
