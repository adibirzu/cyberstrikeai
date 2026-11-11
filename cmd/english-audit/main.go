// english-audit validates the product's emitted bundled catalogs and prompts.
// It does not translate user data or connect to tools, models or remote targets.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode"

	"cyberstrike-ai/internal/agent"
	"cyberstrike-ai/internal/agents"
	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/multiagent"
	"cyberstrike-ai/internal/skillpackage"
)

func english(label string, value interface{}) error {
	b, err := json.Marshal(value)
	if err != nil {
		return err
	}
	for _, r := range string(b) {
		if unicode.Is(unicode.Han, r) {
			return fmt.Errorf("%s emits untranslated bundled text", label)
		}
	}
	return nil
}

func audit(root string) error {
	tools, err := config.LoadToolsFromDir(filepath.Join(root, "tools"))
	if err != nil {
		return err
	}
	for _, t := range tools {
		// Command bodies and flags are executable contracts. Descriptions are the
		// model/UI interface; executable literals are checked separately by scripts/check-tool-contracts.py
		// using parsed Python strings (excluding comments), plus pinned contracts.
		if err := english("tool "+t.Name, []string{t.ShortDescription, t.Description}); err != nil {
			return err
		}
		for _, p := range t.Parameters {
			if err := english("tool parameter "+t.Name+"."+p.Name, p.Description); err != nil {
				return err
			}
		}
	}
	roles, err := config.LoadRolesFromDir(filepath.Join(root, "roles"))
	if err != nil {
		return err
	}
	for name, role := range roles {
		if err := english("role "+name, role); err != nil {
			return err
		}
	}
	files, err := agents.LoadMarkdownAgentFiles(filepath.Join(root, "agents"))
	if err != nil {
		return err
	}
	for _, f := range files {
		if err := english("agent", f); err != nil {
			return err
		}
	}
	names, err := skillpackage.ListSkillDirNames(filepath.Join(root, "skills"))
	if err != nil {
		return err
	}
	for _, name := range names {
		view, err := skillpackage.LoadSkill(filepath.Join(root, "skills"), name, skillpackage.LoadOptions{})
		if err != nil {
			return fmt.Errorf("skill %s: %w", name, err)
		}
		if err := english("skill "+name, view); err != nil {
			return err
		}
	}
	for label, prompt := range map[string]string{"single": agent.DefaultSingleAgentSystemPrompt(), "planner": multiagent.DefaultPlanExecuteOrchestratorInstruction(), "supervisor": multiagent.DefaultSupervisorOrchestratorInstruction()} {
		if strings.TrimSpace(prompt) == "" {
			return fmt.Errorf("%s prompt is empty", label)
		}
		if err := english(label+" emitted prompt", prompt); err != nil {
			return err
		}
	}
	fmt.Printf("English bundled runtime audit passed: %d tools, %d roles, %d agent files, %d skills, 3 generated system prompts\n", len(tools), len(roles), len(files), len(names))
	return nil
}

func main() {
	root := "."
	if len(os.Args) > 1 {
		root = os.Args[1]
	}
	if err := audit(root); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := auditRejectedPhrases(root); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := auditSource(root); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := auditFrontend(root); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
