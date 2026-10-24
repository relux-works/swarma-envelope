// Package apicheck checks the repository's public API name inventories in tests.
package apicheck

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// Surface lists exported declarations, fields and methods
// from package sources. It does not infer semantic compatibility or approval.
func Surface(dir string) (string, error) {
	paths, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil {
		return "", err
	}
	var lines []string
	typeName := func(e ast.Expr) string {
		if p, ok := e.(*ast.StarExpr); ok {
			e = p.X
		}
		if n, ok := e.(*ast.Ident); ok {
			return n.Name
		}
		return ""
	}
	for _, p := range paths {
		if strings.HasSuffix(p, "_test.go") {
			continue
		}
		f, e := parser.ParseFile(token.NewFileSet(), p, nil, 0)
		if e != nil {
			return "", e
		}
		for _, d := range f.Decls {
			switch x := d.(type) {
			case *ast.FuncDecl:
				if !ast.IsExported(x.Name.Name) {
					continue
				}
				if x.Recv == nil {
					lines = append(lines, "func "+x.Name.Name)
				} else {
					n := typeName(x.Recv.List[0].Type)
					if ast.IsExported(n) {
						lines = append(lines, "method "+n+"."+x.Name.Name)
					}
				}
			case *ast.GenDecl:
				for _, sp := range x.Specs {
					switch s := sp.(type) {
					case *ast.TypeSpec:
						if !ast.IsExported(s.Name.Name) {
							continue
						}
						lines = append(lines, "type "+s.Name.Name)
						if st, ok := s.Type.(*ast.StructType); ok {
							for _, field := range st.Fields.List {
								for _, name := range field.Names {
									if ast.IsExported(name.Name) {
										lines = append(lines, "field "+s.Name.Name+"."+name.Name)
									}
								}
							}
						}
					case *ast.ValueSpec:
						for _, n := range s.Names {
							if ast.IsExported(n.Name) {
								lines = append(lines, x.Tok.String()+" "+n.Name)
							}
						}
					}
				}
			}
		}
	}
	sort.Strings(lines)
	return strings.Join(lines, "\n") + "\n", nil
}

// Check compares all exported names (including fields/methods) with api.txt.
func Check(t *testing.T) {
	t.Helper()
	got, e := Surface(".")
	if e != nil {
		t.Fatal(e)
	}
	want, e := os.ReadFile("api.txt")
	if e != nil {
		t.Fatal(e)
	}
	if got != string(want) {
		t.Fatalf("public API inventory differs; review before updating api.txt\n%s", got)
	}
}
