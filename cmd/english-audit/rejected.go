package main

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// A finite regression lint for confirmed translation artifacts. This is not a
// semantic-quality score; operational prose still requires human review.
func auditRejectedPhrases(root string) error {
	data, err := os.ReadFile(filepath.Join(root, "maintenance", "rejected-runtime-phrases.json"))
	if err != nil {
		return err
	}
	var rejected []string
	if err = json.Unmarshal(data, &rejected); err != nil {
		return err
	}
	for _, dir := range []string{"internal", "web/static/js", "web/templates", "tools", "agents", "roles", "skills"} {
		err = filepath.WalkDir(filepath.Join(root, dir), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || strings.HasSuffix(path, "_test.go") || strings.HasSuffix(path, ".test.cjs") {
				return nil
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			for _, phrase := range rejected {
				if phrase != "" && strings.Contains(string(data), phrase) {
					return fmt.Errorf("%s contains a rejected runtime translation artifact", path)
				}
			}
			return nil
		})
		if err != nil {
			return err
		}
	}
	return nil
}
