// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package parser

import (
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unsafe"

	"github.com/ajitpratap0/GoSQLX/internal/renderhint"
	sqlast "github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

// The guard resolves types rather than relying on the spelling of an import alias.
func TestRenderHintConstructionGuard(t *testing.T) {
	fset := token.NewFileSet()
	groups := map[string][]*ast.File{}
	err := filepath.WalkDir(".", func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return err
		}
		groups[filepath.Dir(path)] = append(groups[filepath.Dir(path)], f)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for dir, files := range groups {
		info := &types.Info{Types: map[ast.Expr]types.TypeAndValue{}, Defs: map[*ast.Ident]types.Object{}, Uses: map[*ast.Ident]types.Object{}}
		// Mutually exclusive race/non-race files define the same bookkeeping
		// constant. Checking every source file still fills type information for
		// guarded constructions in either build variant.
		config := types.Config{Importer: importer.ForCompiler(fset, "source", nil), Error: func(err error) {
			if !strings.Contains(err.Error(), "raceEnabled redeclared") && !strings.Contains(err.Error(), "other declaration of raceEnabled") {
				t.Error(err)
			}
		}}
		_, _ = config.Check("github.com/ajitpratap0/GoSQLX/pkg/sql/parser/"+dir, fset, files, info)
		for _, file := range files {
			for _, decl := range file.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok {
					ast.Inspect(decl, func(n ast.Node) bool {
						fail := false
						switch n := n.(type) {
						case *ast.CompositeLit:
							fail = renderHintGuarded(info.TypeOf(n))
						case *ast.ValueSpec:
							fail = n.Type != nil && len(n.Values) == 0 && renderHintGuarded(info.TypeOf(n.Type))
						case *ast.CallExpr:
							id, ok := n.Fun.(*ast.Ident)
							if ok && id.Name == "new" && len(n.Args) == 1 {
								fail = renderHintGuarded(info.TypeOf(n.Args[0]))
							}
						}
						if fail {
							t.Errorf("%s: package-scope guarded construction bypasses recording", fset.Position(n.Pos()))
						}
						return true
					})
					continue
				}
				if fn.Body == nil {
					continue
				}
				recording := false
				allowed := map[*ast.CompositeLit]bool{}
				ast.Inspect(fn.Body, func(n ast.Node) bool {
					call, ok := n.(*ast.CallExpr)
					if !ok {
						return true
					}
					sel, ok := call.Fun.(*ast.SelectorExpr)
					if !ok {
						return true
					}
					if renderHintRecordingCall(info, fset, sel) {
						recording = true
					}
					if len(call.Args) == 1 {
						arg := call.Args[0]
						if unary, ok := arg.(*ast.UnaryExpr); ok && unary.Op == token.AND {
							arg = unary.X
						}
						if lit, ok := arg.(*ast.CompositeLit); ok && renderHintRecordingCall(info, fset, sel) && sel.Sel.Name == "hint"+renderHintTypeName(info.TypeOf(lit)) {
							allowed[lit] = true
						}
					}
					return true
				})
				helper := strings.HasPrefix(fn.Name.Name, "hint") && strings.HasSuffix(fset.Position(fn.Pos()).Filename, "render_hints.go")
				ast.Inspect(fn.Body, func(n ast.Node) bool {
					report := func(pos token.Pos, message string) { t.Errorf("%s: %s", fset.Position(pos), message) }
					switch n := n.(type) {
					case *ast.CompositeLit:
						if renderHintGuarded(info.TypeOf(n)) && !allowed[n] && !helper {
							report(n.Pos(), "guarded literal must use recording helper")
						}
					case *ast.CallExpr:
						if id, ok := n.Fun.(*ast.Ident); ok && id.Name == "new" && len(n.Args) == 1 && renderHintGuarded(info.TypeOf(n.Args[0])) && !helper {
							report(n.Pos(), "new of guarded type bypasses recording helper")
						}
					case *ast.ValueSpec:
						if n.Type != nil && len(n.Values) == 0 && renderHintGuarded(info.TypeOf(n.Type)) && !helper {
							report(n.Pos(), "zero-value guarded variable bypasses recording helper")
						}
					case *ast.AssignStmt:
						if recording {
							break
						}
						for _, lhs := range n.Lhs {
							sel, ok := lhs.(*ast.SelectorExpr)
							if !ok {
								continue
							}
							typ, field := renderHintTypeName(info.TypeOf(sel.X)), sel.Sel.Name
							relevant := (typ == "BinaryExpression" || typ == "UnaryExpression") && (field == "Operator" || field == "Lambda" || field == "PipesOr" || field == "CustomOp")
							relevant = relevant || (typ == "CastExpression" || typ == "ColumnDef") && field == "Type"
							relevant = relevant || typ == "AlterTableOperation" && (field == "DataType" || field == "ColumnDef" || field == "ColumnDefs")
							relevant = relevant || typ == "CreateMaterializedViewStatement" && field == "ColumnDefs"
							if relevant {
								report(lhs.Pos(), "rewrite field assignment requires a recording helper in its function")
							}
						}
					}
					return true
				})
			}
		}
	}
}

func renderHintTypeName(typ types.Type) string {
	if ptr, ok := typ.(*types.Pointer); ok {
		typ = ptr.Elem()
	}
	named, ok := typ.(*types.Named)
	if !ok || named.Obj().Pkg() == nil || named.Obj().Pkg().Path() != "github.com/ajitpratap0/GoSQLX/pkg/sql/ast" {
		return ""
	}
	return named.Obj().Name()
}
func renderHintGuarded(typ types.Type) bool {
	switch renderHintTypeName(typ) {
	case "BinaryExpression", "UnaryExpression", "UnicodeEscapeExpression", "ObjectLiteral", "CastExpression", "ColumnDef":
		return true
	}
	return false
}

func TestRenderHintStatementAndParserReuse(t *testing.T) {
	p := GetParser()
	defer func() { PutParser(p) }()
	parse := func(sql string) (*sqlast.AST, uint64, uint32) {
		t.Helper()
		tk, err := tokenizer.New()
		if err != nil {
			t.Fatal(err)
		}
		tokens, err := tk.Tokenize([]byte(sql))
		if err != nil {
			t.Fatal(err)
		}
		tree, err := p.ParseFromModelTokens(tokens)
		if err != nil {
			t.Fatal(err)
		}
		generation := renderhint.ParserGeneration(p)
		mask, valid := renderhint.ParserMask(p, len(tree.Statements), generation)
		if !valid {
			t.Fatalf("%s: invalid mask", sql)
		}
		return tree, mask, generation
	}
	clean, mask, oldGeneration := parse("SELECT a; SELECT b")
	if mask != 0 {
		t.Fatalf("clean mask = %x", mask)
	}
	sqlast.ReleaseAST(clean)
	PutParser(p)
	p = GetParser()
	for _, sql := range []string{"SELECT a ^ b", "SELECT CAST(a AS \"MyType\")", "ALTER TABLE t ALTER COLUMN a TYPE " + "\"MyType\"" /* split: ast harvest compares SQL() with the dialect visitor; quoted types retarget by design */} {
		tree, mask, _ := parse(sql)
		if mask&1 == 0 {
			t.Fatalf("%s: missing rewrite bit: %x", sql, mask)
		}
		if _, valid := renderhint.ParserMask(p, len(tree.Statements)+1, renderhint.ParserGeneration(p)); valid {
			t.Fatal("statement-count mismatch accepted")
		}
		sqlast.ReleaseAST(tree)
	}
	clean, mask, _ = parse("SELECT a")
	defer sqlast.ReleaseAST(clean)
	if mask != 0 {
		t.Fatalf("dirty mask survived a clean parse: %x", mask)
	}
	if _, valid := renderhint.ParserMask(p, len(clean.Statements), oldGeneration); valid {
		t.Fatal("stale generation accepted")
	}
}

func TestRenderHintStructSizes(t *testing.T) {
	if unsafe.Sizeof(uintptr(0)) != 8 {
		t.Skip("64-bit layout guard")
	}
	if got := unsafe.Sizeof(sqlast.AST{}); got != 160 {
		t.Fatalf("AST grew: %d bytes, want unchanged 160", got)
	}
	// A larger parser must be justified by ParseFresh/ParseE2E allocation gates.
	t.Logf("AST = %d bytes; Parser = %d bytes (baseline 256)", unsafe.Sizeof(sqlast.AST{}), unsafe.Sizeof(Parser{}))
	if got := unsafe.Sizeof(Parser{}); got != 264 {
		t.Fatalf("Parser layout changed: %d bytes, want 264 (allocation gates must justify baseline 256 growth)", got)
	}
}

// Identify the real parser helpers, including the column parser that returns a
// fully recorded ColumnDef. A same-spelled method on another type cannot opt out.
func renderHintRecordingCall(info *types.Info, fset *token.FileSet, sel *ast.SelectorExpr) bool {
	fn, ok := info.Uses[sel.Sel].(*types.Func)
	if !ok {
		return false
	}
	sig, ok := fn.Type().(*types.Signature)
	if !ok || sig.Recv() == nil {
		return false
	}
	recv := sig.Recv().Type()
	if ptr, ok := recv.(*types.Pointer); ok {
		recv = ptr.Elem()
	}
	named, ok := recv.(*types.Named)
	if !ok || named.Obj().Name() != "Parser" || named.Obj().Pkg() != fn.Pkg() {
		return false
	}
	if fn.Name() == "parseColumnDef" {
		return true
	}
	if filepath.Base(fset.Position(fn.Pos()).Filename) != "render_hints.go" {
		return false
	}
	switch fn.Name() {
	case "noteRenderOperator", "noteRenderDataType", "hintBinaryExpression", "hintUnaryExpression", "hintUnicodeEscapeExpression", "hintObjectLiteral", "hintCastExpression", "hintColumnDef":
		return true
	}
	return false
}
