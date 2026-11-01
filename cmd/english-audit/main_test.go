package main

import (
	"path/filepath"
	"testing"
)

// Invoke the actual config/agent/skill loaders and generated prompt interfaces.
// This is a public-output contract, not a grep over implementation source.
func TestBundledEnglishRuntime(t *testing.T) {
	root := filepath.Join("..", "..")
	if err := audit(root); err != nil {
		t.Fatal(err)
	}
	if err := auditFrontend(root); err != nil {
		t.Fatal(err)
	}
}
