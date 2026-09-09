package cmd

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// TestEveryRegisteredFlagIsConsumed walks the cobra tree at runtime and the
// package source with go/ast, and fails for every flag that a command
// registers but never reads. "Reads" means: the variable bound through a *Var
// registration, or the flag name as a string literal, appears in the command's
// Run function or in any package function reachable from it.
//
// This is the guard for H2 (remote check registering trust flags it never
// used) and for every future copy of that mistake.
func TestEveryRegisteredFlagIsConsumed(t *testing.T) {
	src := parseCmdPackage(t)
	src.resolveHelperRegistrations()

	var problems []string
	walkCommands(rootCmd, func(c *cobra.Command) {
		varName, ok := src.varForPath(commandPath(c))
		if !ok {
			problems = append(problems, commandPath(c)+": no source declaration found for this command")
			return
		}
		reach := src.reachableFrom(varName)
		// Persistent flags are consumed by descendants as well.
		descReach := reach
		if c.HasSubCommands() {
			descReach = src.reachableFromTree(c)
		}
		check := func(f *pflag.Flag, r reachSet) {
			if f.Name == "help" || f.Name == "version" {
				return
			}
			b, found := src.binding(varName, f.Name)
			if !found {
				problems = append(problems, commandPath(c)+" --"+f.Name+": registration not found in source (unsupported registration style)")
				return
			}
			if b.boundVar != "" && r.idents[b.boundVar] {
				return
			}
			if r.strings[f.Name] {
				return
			}
			for _, fn := range externalFlagReaders[f.Name] {
				if r.idents[fn] {
					return
				}
			}
			problems = append(problems, commandPath(c)+" --"+f.Name+": registered (var "+b.boundVar+") but never read by this command")
		}
		c.LocalNonPersistentFlags().VisitAll(func(f *pflag.Flag) { check(f, reach) })
		c.PersistentFlags().VisitAll(func(f *pflag.Flag) { check(f, descReach) })
	})

	sort.Strings(problems)
	for _, p := range problems {
		t.Error(p)
	}
}

// externalFlagReaders lists flags that a helper in another package reads on
// the command's behalf (the flag name literal lives in cmdutil, out of this
// analyzer's sight). A command counts as reading the flag when its reachable
// code calls one of the named wrappers.
var externalFlagReaders = map[string][]string{
	"output-password": {"mustOutputPassword", "OutputPassword"},
}

// --- runtime side ---

func walkCommands(c *cobra.Command, fn func(*cobra.Command)) {
	fn(c)
	for _, sub := range c.Commands() {
		walkCommands(sub, fn)
	}
}

// commandPath is the command's path without the binary name: "" for root,
// "store list" for the store list subcommand.
func commandPath(c *cobra.Command) string {
	parts := strings.Fields(c.CommandPath())
	if len(parts) <= 1 {
		return ""
	}
	return strings.Join(parts[1:], " ")
}

// --- source side ---

type flagBinding struct {
	name     string
	boundVar string
}

type reachSet struct {
	idents  map[string]bool
	strings map[string]bool
}

type cmdSource struct {
	funcs    map[string]*ast.FuncDecl
	cmdRun   map[string][]ast.Node    // command var -> Run/RunE/PersistentPreRunE nodes
	cmdUse   map[string]string        // command var -> first word of Use
	children map[string][]string      // parent var -> child vars (AddCommand)
	regs     map[string][]flagBinding // "cmdVar" or "func\x00param" -> registrations
	helpers  map[string][]helperCall  // caller key -> helper calls made with a command argument
	groups   map[string][]string      // cmdVar -> flag-group vars registered via x.Register(cmd, ...)
	reachMem map[string]reachSet
}

// helperCall is fn(cmdArg) inside caller; argKey is the registration key the
// argument maps to (a command var or the caller's own "func\x00param").
type helperCall struct {
	callee string
	param  string
	argKey string
}

var registrationMethods = map[string]bool{
	"StringVar": true, "StringVarP": true, "BoolVar": true, "BoolVarP": true,
	"IntVar": true, "IntVarP": true, "StringArrayVar": true, "StringArrayVarP": true,
	"StringSliceVar": true, "StringSliceVarP": true, "CountVar": true, "CountVarP": true,
	"DurationVar": true, "DurationVarP": true, "Var": true, "VarP": true,
	"Uint16Var": true, "Uint16VarP": true, "Float64Var": true, "Float64VarP": true,
	"String": true, "StringP": true, "Bool": true, "BoolP": true, "Int": true, "IntP": true,
	"StringArray": true, "StringArrayP": true, "StringSlice": true, "StringSliceP": true,
	"Count": true, "CountP": true, "Duration": true, "DurationP": true,
}

func helperKey(fn, param string) string { return fn + "\x00" + param }

func parseCmdPackage(t *testing.T) *cmdSource {
	t.Helper()
	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	var files []*ast.File
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		files = append(files, f)
	}
	src := &cmdSource{
		funcs:    map[string]*ast.FuncDecl{},
		cmdRun:   map[string][]ast.Node{},
		cmdUse:   map[string]string{},
		children: map[string][]string{},
		regs:     map[string][]flagBinding{},
		helpers:  map[string][]helperCall{},
		groups:   map[string][]string{},
		reachMem: map[string]reachSet{},
	}
	inits := 0
	for _, f := range files {
		for _, d := range f.Decls {
			switch d := d.(type) {
			case *ast.FuncDecl:
				if d.Recv == nil {
					name := d.Name.Name
					if name == "init" {
						// every file may have its own init; keep them all apart
						inits++
						name = fmt.Sprintf("init#%d", inits)
					}
					src.funcs[name] = d
				}
			case *ast.GenDecl:
				for _, sp := range d.Specs {
					vs, ok := sp.(*ast.ValueSpec)
					if !ok {
						continue
					}
					for i, name := range vs.Names {
						if i < len(vs.Values) {
							src.recordCommandLiteral(name.Name, vs.Values[i])
						}
					}
				}
			}
		}
	}
	for name, fd := range src.funcs {
		src.scanFunction(name, fd)
	}
	return src
}

// recordCommandLiteral handles `var xCmd = &cobra.Command{...}`.
func (s *cmdSource) recordCommandLiteral(varName string, v ast.Expr) {
	u, ok := v.(*ast.UnaryExpr)
	if !ok || u.Op != token.AND {
		return
	}
	cl, ok := u.X.(*ast.CompositeLit)
	if !ok {
		return
	}
	sel, ok := cl.Type.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Command" {
		return
	}
	for _, el := range cl.Elts {
		kv, ok := el.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		key, ok := kv.Key.(*ast.Ident)
		if !ok {
			continue
		}
		switch key.Name {
		case "Use":
			if lit, ok := kv.Value.(*ast.BasicLit); ok {
				use := strings.Trim(lit.Value, "`\"")
				s.cmdUse[varName] = strings.Fields(use)[0]
			}
		case "Run", "RunE", "PersistentPreRunE", "PersistentPreRun", "PreRunE", "PreRun":
			s.cmdRun[varName] = append(s.cmdRun[varName], kv.Value)
		}
	}
}

// scanFunction records flag registrations, AddCommand calls and helper calls
// found in one package-level function.
func (s *cmdSource) scanFunction(fnName string, fd *ast.FuncDecl) {
	if fd.Body == nil {
		return
	}
	params := map[string]bool{}
	if fd.Type.Params != nil {
		for _, p := range fd.Type.Params.List {
			for _, n := range p.Names {
				params[n.Name] = true
			}
		}
	}
	// local alias -> command ident (pf := remoteCmd.PersistentFlags())
	aliases := map[string]string{}
	keyFor := func(recv string) string {
		if params[recv] {
			return helperKey(fnName, recv)
		}
		return recv
	}
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.AssignStmt:
			if len(n.Lhs) == 1 && len(n.Rhs) == 1 {
				if lhs, ok := n.Lhs[0].(*ast.Ident); ok {
					if recv, ok := flagSetReceiver(n.Rhs[0]); ok {
						aliases[lhs.Name] = recv
					}
				}
			}
		case *ast.CallExpr:
			sel, ok := n.Fun.(*ast.SelectorExpr)
			if ok {
				switch {
				case registrationMethods[sel.Sel.Name]:
					recv := ""
					if r, ok := flagSetReceiver(sel.X); ok {
						recv = r
					} else if id, ok := sel.X.(*ast.Ident); ok {
						if params[id.Name] {
							// a *pflag.FlagSet parameter: attributed at the call site
							recv = id.Name
						} else {
							recv = aliases[id.Name]
						}
					}
					if recv == "" {
						return true
					}
					if b, ok := parseBinding(sel.Sel.Name, n.Args); ok {
						s.regs[keyFor(recv)] = append(s.regs[keyFor(recv)], b)
					}
				case sel.Sel.Name == "Register" && len(n.Args) > 0:
					// flag group from another package: group.Register(cmd, ...)
					group, ok := sel.X.(*ast.Ident)
					if !ok {
						return true
					}
					if arg, ok := n.Args[0].(*ast.Ident); ok {
						s.groups[keyFor(arg.Name)] = append(s.groups[keyFor(arg.Name)], group.Name)
					}
				case sel.Sel.Name == "AddCommand":
					parent, ok := sel.X.(*ast.Ident)
					if !ok {
						return true
					}
					for _, a := range n.Args {
						if id, ok := a.(*ast.Ident); ok {
							s.children[parent.Name] = append(s.children[parent.Name], id.Name)
						}
					}
				}
				return true
			}
			// helper(cmdVar) or helper(param)
			id, ok := n.Fun.(*ast.Ident)
			if !ok {
				return true
			}
			callee, ok := s.funcs[id.Name]
			if !ok || callee.Type.Params == nil {
				return true
			}
			pi := 0
			for _, p := range callee.Type.Params.List {
				for _, pn := range p.Names {
					if pi < len(n.Args) {
						argKey := ""
						if arg, ok := n.Args[pi].(*ast.Ident); ok && isCommandType(p.Type) {
							argKey = keyFor(arg.Name)
						} else if recv, ok := flagSetReceiver(n.Args[pi]); ok && isFlagSetType(p.Type) {
							// helper(cmd.Flags()) / helper(cmd.PersistentFlags())
							argKey = keyFor(recv)
						} else if arg, ok := n.Args[pi].(*ast.Ident); ok && isFlagSetType(p.Type) {
							// helper(pf) where pf := cmd.PersistentFlags() above
							if recv, ok := aliases[arg.Name]; ok {
								argKey = keyFor(recv)
							}
						}
						if argKey != "" {
							s.helpers[fnName] = append(s.helpers[fnName], helperCall{
								callee: id.Name, param: pn.Name, argKey: argKey,
							})
						}
					}
					pi++
				}
			}
		}
		return true
	})
}

func isFlagSetType(e ast.Expr) bool {
	star, ok := e.(*ast.StarExpr)
	if !ok {
		return false
	}
	sel, ok := star.X.(*ast.SelectorExpr)
	return ok && sel.Sel.Name == "FlagSet"
}

func isCommandType(e ast.Expr) bool {
	star, ok := e.(*ast.StarExpr)
	if !ok {
		return false
	}
	sel, ok := star.X.(*ast.SelectorExpr)
	return ok && sel.Sel.Name == "Command"
}

// flagSetReceiver recognises `x.Flags()` / `x.PersistentFlags()` and returns x.
func flagSetReceiver(e ast.Expr) (string, bool) {
	call, ok := e.(*ast.CallExpr)
	if !ok {
		return "", false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || (sel.Sel.Name != "Flags" && sel.Sel.Name != "PersistentFlags") {
		return "", false
	}
	id, ok := sel.X.(*ast.Ident)
	if !ok {
		return "", false
	}
	return id.Name, true
}

func parseBinding(method string, args []ast.Expr) (flagBinding, bool) {
	nameAt := 0
	bound := ""
	if strings.Contains(method, "Var") {
		nameAt = 1
		if len(args) > 0 {
			if u, ok := args[0].(*ast.UnaryExpr); ok && u.Op == token.AND {
				if id, ok := u.X.(*ast.Ident); ok {
					bound = id.Name
				}
			} else if id, ok := args[0].(*ast.Ident); ok {
				bound = id.Name
			}
		}
	}
	if len(args) <= nameAt {
		return flagBinding{}, false
	}
	lit, ok := args[nameAt].(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return flagBinding{}, false
	}
	return flagBinding{name: strings.Trim(lit.Value, "\""), boundVar: bound}, true
}

// resolveHelperRegistrations copies registrations made inside helper functions
// (registerX(cmd)) onto the command variables they were called with. Iterates
// so helpers calling helpers resolve too.
func (s *cmdSource) resolveHelperRegistrations() {
	for iter := 0; iter < 5; iter++ {
		changed := false
		for _, calls := range s.helpers {
			for _, hc := range calls {
				from := helperKey(hc.callee, hc.param)
				for _, b := range s.regs[from] {
					if !containsBinding(s.regs[hc.argKey], b) {
						s.regs[hc.argKey] = append(s.regs[hc.argKey], b)
						changed = true
					}
				}
			}
		}
		if !changed {
			return
		}
	}
}

func containsBinding(list []flagBinding, b flagBinding) bool {
	for _, x := range list {
		if x == b {
			return true
		}
	}
	return false
}

// binding finds the registration of one flag on one command. A flag that no
// in-package registration covers is attributed to the flag group registered on
// that command, when there is exactly one; the group variable then has to be
// read by the command (for example createKeyFlags.ApplyChanged(...)).
func (s *cmdSource) binding(cmdVar, flag string) (flagBinding, bool) {
	for _, b := range s.regs[cmdVar] {
		if b.name == flag {
			return b, true
		}
	}
	if groups := s.groups[cmdVar]; len(groups) == 1 {
		return flagBinding{name: flag, boundVar: groups[0]}, true
	}
	return flagBinding{}, false
}

// varForPath maps a runtime command path to the source variable by walking
// the AddCommand tree from rootCmd and matching the first word of Use.
func (s *cmdSource) varForPath(path string) (string, bool) {
	cur := "rootCmd"
	if path == "" {
		return cur, true
	}
	for _, word := range strings.Fields(path) {
		next := ""
		for _, child := range s.children[cur] {
			if s.cmdUse[child] == word {
				next = child
				break
			}
		}
		if next == "" {
			return "", false
		}
		cur = next
	}
	return cur, true
}

// reachableFrom collects identifiers and string literals in the command's
// Run functions and in every package function reachable from them.
func (s *cmdSource) reachableFrom(cmdVar string) reachSet {
	if r, ok := s.reachMem[cmdVar]; ok {
		return r
	}
	r := reachSet{idents: map[string]bool{}, strings: map[string]bool{}}
	visited := map[string]bool{}
	var visit func(n ast.Node)
	visit = func(n ast.Node) {
		ast.Inspect(n, func(x ast.Node) bool {
			switch x := x.(type) {
			case *ast.Ident:
				r.idents[x.Name] = true
				if fd, ok := s.funcs[x.Name]; ok && !visited[x.Name] {
					visited[x.Name] = true
					if fd.Body != nil {
						visit(fd.Body)
					}
				}
			case *ast.BasicLit:
				if x.Kind == token.STRING {
					r.strings[strings.Trim(x.Value, "\"`")] = true
				}
			}
			return true
		})
	}
	for _, run := range s.cmdRun[cmdVar] {
		visit(run)
	}
	s.reachMem[cmdVar] = r
	return r
}

func (s *cmdSource) reachableFromTree(c *cobra.Command) reachSet {
	r := reachSet{idents: map[string]bool{}, strings: map[string]bool{}}
	walkCommands(c, func(sub *cobra.Command) {
		v, ok := s.varForPath(commandPath(sub))
		if !ok {
			return
		}
		sr := s.reachableFrom(v)
		for k := range sr.idents {
			r.idents[k] = true
		}
		for k := range sr.strings {
			r.strings[k] = true
		}
	})
	return r
}
