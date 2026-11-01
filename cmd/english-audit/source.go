package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"unicode"
)

// auditSource is a lint rule complementing the runtime interface checks. Comments
// and test fixtures are outside the product text contract. One finite exception
// accepts old role identifiers for persisted records without displaying them.
func auditSource(root string) error {
	for _, dir := range []string{"internal", "cmd"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			relative, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			if filepath.ToSlash(relative) == "internal/config/role_aliases.go" || filepath.ToSlash(relative) == "internal/legacytext/aliases.go" {
				return nil
			}
			files := token.NewFileSet()
			f, err := parser.ParseFile(files, path, nil, 0)
			if err != nil {
				return err
			}
			var finding error
			ast.Inspect(f, func(n ast.Node) bool {
				if finding != nil {
					return false
				}
				literal, ok := n.(*ast.BasicLit)
				if !ok || literal.Kind != token.STRING {
					return true
				}
				value, err := strconv.Unquote(literal.Value)
				if err != nil {
					finding = err
					return false
				}
				for _, r := range value {
					if unicode.Is(unicode.Han, r) {
						finding = fmt.Errorf("%s:%d: untranslated runtime string (comments and tests excluded)", relative, files.Position(literal.Pos()).Line)
						return false
					}
				}
				return true
			})
			return finding
		})
		if err != nil {
			return err
		}
	}
	return nil
}
