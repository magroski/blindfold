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
//
// The guard is a tripwire, not a proof. Inside the files allowed to start
// programs, `sh -c "ssh …"` or a name built at run time still gets past it;
// those files are few, and each change to them is read by a person.

const (
	sshFile      = "internal/boxsync/ssh.go" // the one file allowed to start ssh
	sshIdent     = "sshCommand"              // what sshFile runs
	sshArgsIdent = "sshArgs"                 // the fixed arguments, first in every session
)

// sshBinaries are programs that speak ssh. A string naming one, outside
// sshFile, is a call site in the making.
var sshBinaries = map[string]bool{"ssh": true, "scp": true, "sftp": true}

// processFiles may start other programs: ssh for a sync session, and the
// command `blindfold exec` runs. Another file importing a package that starts
// programs is a new call site, and must be added here by hand.
var processFiles = map[string]bool{
	sshFile:                      true,
	"internal/cli/exec.go":       true,
	"internal/cli/exec_other.go": true,
	"internal/cli/exec_unix.go":  true,
}

// processImports start programs, or reach code that can ("C" calls execvp
// as readily as anything else).
var processImports = map[string]bool{"os/exec": true, "syscall": true, "golang.org/x/sys/unix": true, "C": true}

// processStarters are the functions, by import path, that run another program.
// An exec.Cmd literal counts too: it runs whatever Path it is given.
var processStarters = map[string][]string{
	"os/exec":               {"Command", "CommandContext"},
	"os":                    {"StartProcess"},
	"syscall":               {"Exec", "ForkExec", "StartProcess"},
	"golang.org/x/sys/unix": {"Exec"},
}

// pinned are set once, where ssh.go declares them. Assigning, shadowing or
// taking the address of either would change what a session runs.
var pinned = map[string]bool{sshIdent: true, sshArgsIdent: true}

// checkSSHUse lists every way the Go file at path (repo-relative, slash
// separated) could run ssh other than ssh.go's one call.
func checkSSHUse(path, src string) []string {
	file, err := parser.ParseFile(token.NewFileSet(), path, src, parser.SkipObjectResolution)
	if err != nil {
		// Source we cannot parse is source we cannot vouch for.
		return []string{"cannot parse: " + err.Error()}
	}

	var problems []string
	if !processFiles[path] {
		problems = append(problems, processImportsIn(file)...)
	}
	starts, more := processStarts(file)
	problems = append(problems, more...)
	switch {
	case path == sshFile:
		problems = append(problems, checkTheOneStart(file, starts)...)
	case !processFiles[path] && len(starts) > 0:
		problems = append(problems, "starts a program; only the files in processFiles may")
	}
	if path != sshFile {
		problems = append(problems, sshLiterals(file)...)
	}
	// The pinned names are unexported: only this package can reach them.
	if pathpkg.Dir(path) == pathpkg.Dir(sshFile) {
		problems = append(problems, touchesPinned(file, path == sshFile)...)
	}
	return problems
}

// processImportsIn reports each import of a package that starts programs.
func processImportsIn(file *ast.File) []string {
	var problems []string
	for _, imp := range file.Imports {
		if importPath, _ := strconv.Unquote(imp.Path.Value); processImports[importPath] {
			problems = append(problems, fmt.Sprintf("imports %q, which starts programs; only the files in processFiles may", importPath))
		}
	}
	return problems
}

// processStarts returns every use of a process-starting function, following
// import aliases — called or not, since a function value is as good as a call
// — and every exec.Cmd literal.
func processStarts(file *ast.File) (uses []ast.Expr, problems []string) {
	starters := map[string]map[string]bool{} // local package name → function names
	execName := ""
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
			problems = append(problems, "dot import of "+importPath+" hides which calls start programs")
			continue
		}
		if importPath == "os/exec" {
			execName = name
		}
		starters[name] = map[string]bool{}
		for _, f := range funcs {
			starters[name][f] = true
		}
	}
	ast.Inspect(file, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.SelectorExpr:
			if pkg, ok := n.X.(*ast.Ident); ok && starters[pkg.Name][n.Sel.Name] {
				uses = append(uses, n)
			}
		case *ast.CompositeLit:
			if sel, ok := n.Type.(*ast.SelectorExpr); ok && execName != "" && sel.Sel.Name == "Cmd" {
				if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == execName {
					uses = append(uses, n)
				}
			}
		}
		return true
	})
	return uses, problems
}

// sshLiterals finds strings naming an ssh program, e.g. "ssh", "/usr/bin/scp",
// or the import path of an ssh client of its own.
func sshLiterals(file *ast.File) []string {
	var problems []string
	ast.Inspect(file, func(n ast.Node) bool {
		lit, ok := n.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		if value, err := strconv.Unquote(lit.Value); err == nil && sshBinaries[pathpkg.Base(value)] {
			problems = append(problems, fmt.Sprintf("names ssh (%s); only %s may run it", lit.Value, sshFile))
		}
		return true
	})
	return problems
}

// checkTheOneStart requires sshFile to start exactly one program, called
// directly as exec.CommandContext(ctx, sshCommand, append(sshArgs(), …)...),
// so the fixed arguments always come first.
func checkTheOneStart(file *ast.File, starts []ast.Expr) []string {
	if len(starts) != 1 {
		return []string{fmt.Sprintf("starts %d programs; it must start exactly one, ssh", len(starts))}
	}
	const want = "must start ssh as exec.CommandContext(ctx, " + sshIdent + ", append(" + sshArgsIdent + "(), …)...)"
	sel, isSel := starts[0].(*ast.SelectorExpr)
	var call *ast.CallExpr
	ast.Inspect(file, func(n ast.Node) bool {
		if c, ok := n.(*ast.CallExpr); ok && isSel && c.Fun == sel {
			call = c
		}
		return true
	})
	if call == nil || sel.Sel.Name != "CommandContext" || len(call.Args) != 3 || !call.Ellipsis.IsValid() {
		return []string{want}
	}
	command, isIdent := call.Args[1].(*ast.Ident)
	args, isCall := call.Args[2].(*ast.CallExpr)
	if !isIdent || command.Name != sshIdent || !isCall || len(args.Args) == 0 {
		return []string{want}
	}
	appendFn, isAppend := args.Fun.(*ast.Ident)
	first, isFirstCall := args.Args[0].(*ast.CallExpr)
	if !isAppend || appendFn.Name != "append" || !isFirstCall || len(first.Args) != 0 {
		return []string{want}
	}
	if fn, ok := first.Fun.(*ast.Ident); !ok || fn.Name != sshArgsIdent {
		return []string{want}
	}
	return nil
}

// touchesPinned finds every assignment to a pinned name or its elements,
// every declaration of one but sshFile's own at package level, and every
// address taken of one.
func touchesPinned(file *ast.File, isSSHFile bool) []string {
	var problems []string
	report := func(what, name string) {
		problems = append(problems, fmt.Sprintf("%s %s; it is set once, where %s declares it", what, name, sshFile))
	}
	topLevel := map[*ast.Ident]bool{}
	for _, decl := range file.Decls {
		switch d := decl.(type) {
		case *ast.GenDecl:
			for _, spec := range d.Specs {
				if vs, ok := spec.(*ast.ValueSpec); ok {
					for _, name := range vs.Names {
						topLevel[name] = isSSHFile
					}
				}
			}
		case *ast.FuncDecl:
			if d.Recv == nil {
				topLevel[d.Name] = isSSHFile
			}
		}
	}
	ast.Inspect(file, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.AssignStmt:
			for _, lhs := range n.Lhs {
				if name := rootIdent(lhs); pinned[name] {
					if n.Tok == token.DEFINE {
						report("declares", name)
					} else {
						report("assigns", name)
					}
				}
			}
		case *ast.ValueSpec:
			for _, name := range n.Names {
				if pinned[name.Name] && !topLevel[name] {
					report("declares", name.Name)
				}
			}
		case *ast.FuncDecl:
			if pinned[n.Name.Name] && !topLevel[n.Name] {
				report("declares", n.Name.Name)
			}
		case *ast.Field:
			for _, name := range n.Names {
				if pinned[name.Name] {
					report("declares", name.Name)
				}
			}
		case *ast.RangeStmt:
			for _, x := range []ast.Expr{n.Key, n.Value} {
				if id, ok := x.(*ast.Ident); ok && pinned[id.Name] {
					report("declares", id.Name)
				}
			}
		case *ast.UnaryExpr:
			if id, ok := n.X.(*ast.Ident); ok && n.Op == token.AND && pinned[id.Name] {
				report("takes the address of", id.Name)
			}
		}
		return true
	})
	return problems
}

// rootIdent is the variable an assignment target writes through:
// sshArgs[0] writes sshArgs.
func rootIdent(e ast.Expr) string {
	for {
		switch x := e.(type) {
		case *ast.Ident:
			return x.Name
		case *ast.IndexExpr:
			e = x.X
		default:
			return ""
		}
	}
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
		"\treturn exec.CommandContext(ctx, sshCommand, append(sshArgs(), \"box\")...)\n}"
	exec := []string{`"context"`, `"os/exec"`}

	cases := []struct {
		name, path, src string
		want            []string // each must appear in some reported problem
	}{
		{
			name: "ssh from the CLI",
			path: "internal/cli/peek.go",
			src:  goFile("cli", exec, `func peek() { exec.Command("ssh", "box", "blindfold get X") }`),
			want: []string{`"ssh"`, `imports "os/exec"`},
		},
		{
			name: "aliased exec with a full path, in an allowed file",
			path: "internal/cli/exec.go",
			src:  goFile("cli", []string{`run "os/exec"`}, `var peek = run.Command("/usr/bin/ssh")`),
			want: []string{"/usr/bin/ssh"},
		},
		{
			name: "scp named in an allowed file",
			path: "internal/cli/exec_unix.go",
			src:  goFile("cli", nil, `const copier = "scp"`),
			want: []string{`"scp"`},
		},
		{
			name: "a shell that runs ssh, from a new file",
			path: "internal/cli/peek.go",
			src:  goFile("cli", exec, `func peek() { exec.Command("sh", "-c", "s"+"sh box blindfold get X") }`),
			want: []string{`imports "os/exec"`, "starts a program"},
		},
		{
			name: "an ssh client of its own",
			path: "internal/cli/peek.go",
			src:  goFile("cli", []string{`"golang.org/x/crypto/ssh"`}, `var peek = ssh.Dial`),
			want: []string{"golang.org/x/crypto/ssh"},
		},
		{
			name: "cgo, which can call execvp",
			path: "internal/cli/peek.go",
			src:  goFile("cli", []string{`"C"`}, ""),
			want: []string{`imports "C"`},
		},
		{
			name: "os.StartProcess, whose package every file imports",
			path: "internal/cli/peek.go",
			src:  goFile("cli", []string{`"os"`}, `var peek = os.StartProcess`),
			want: []string{"starts a program"},
		},
		{
			name: "dot import hides the call",
			path: "internal/cli/exec.go",
			src:  goFile("cli", []string{`. "os/exec"`}, `var peek = Command`),
			want: []string{"dot import"},
		},
		{
			name: "another start in the package",
			path: "internal/boxsync/peek.go",
			src:  goFile("boxsync", exec, `func peek() { exec.Command(sshCommand, "box") }`),
			want: []string{`imports "os/exec"`, "starts a program"},
		},
		{
			name: "the command rewritten",
			path: "internal/boxsync/peek.go",
			src:  goFile("boxsync", nil, `func init() { sshCommand = "/tmp/evil" }`),
			want: []string{"assigns " + sshIdent},
		},
		{
			name: "the command's address taken",
			path: "internal/boxsync/peek.go",
			src:  goFile("boxsync", nil, `var p = &sshCommand`),
			want: []string{"takes the address of " + sshIdent},
		},
		{
			name: "the command shadowed by a parameter",
			path: sshFile,
			src: goFile("boxsync", exec, "func dial(ctx context.Context, sshCommand string) *exec.Cmd {\n"+
				"\treturn exec.CommandContext(ctx, sshCommand, append(sshArgs(), \"box\")...)\n}"),
			want: []string{"declares " + sshIdent},
		},
		{
			name: "the arguments shadowed by a local",
			path: sshFile,
			src: goFile("boxsync", exec, "func dial(ctx context.Context) *exec.Cmd {\n"+
				"\tsshArgs := func() []string { return []string{\"-A\"} }\n"+
				"\treturn exec.CommandContext(ctx, sshCommand, append(sshArgs(), \"box\")...)\n}"),
			want: []string{"declares " + sshArgsIdent},
		},
		{
			name: "ssh without the fixed arguments",
			path: sshFile,
			src:  goFile("boxsync", exec, `func dial() *exec.Cmd { return exec.Command(sshCommand, "box") }`),
			want: []string{"must start ssh as"},
		},
		{
			name: "an exec.Cmd literal beside the one call",
			path: sshFile,
			src:  goFile("boxsync", exec, theOneStart+"\n\nvar other = &exec.Cmd{Path: \"/bin/sh\"}"),
			want: []string{"exactly one"},
		},
		{
			name: "a second program in ssh.go",
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
	allowed := goFile("boxsync", exec, "var sshCommand = \"ssh\"\n\n"+
		"func sshArgs() []string { return []string{\"-T\"} }\n\n"+theOneStart)
	if problems := checkSSHUse(sshFile, allowed); len(problems) > 0 {
		t.Errorf("the one allowed call was refused: %v", problems)
	}
}
