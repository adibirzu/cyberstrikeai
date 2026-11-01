package config

import (
	"strings"
	"testing"
)

func TestDefaultHitlAuditAgentPromptIncludesPrioritizedRules(t *testing.T) {
	prompt := DefaultHitlAuditAgentPrompt()
	for _, want := range []string{
		"If reject and approve rules both match, reject",
		"Change/reset user or administrator passwords",
		"Create, modify or delete users, roles or permissions",
		"Stop, disable or restart business services",
		"Matched rule: ...",
	} {
		if !strings.Contains(prompt, want) {
			t.Fatalf("default approval prompt missing %q", want)
		}
	}
}

func TestDefaultHitlAuditAgentPromptReviewEditKeepsEditedArguments(t *testing.T) {
	prompt := DefaultHitlAuditAgentPromptReviewEdit()
	if !strings.Contains(prompt, `"editedArguments":{...}`) {
		t.Fatal("review-edit prompt must preserve editedArguments output")
	}
	if !strings.Contains(prompt, "Matched rule: ...") {
		t.Fatal("review-edit prompt must require a matched rule")
	}
}

func TestJevOperatorPolicySkipsDefaultPrompt(t *testing.T) {
	if got := (HitlConfig{}).JevOperatorPolicy("approval"); got != "" {
		t.Fatalf("empty config should not send default prompt to Jev, got %q", got)
	}
	if got := (HitlConfig{AuditAgentPrompt: DefaultHitlAuditAgentPrompt()}).JevOperatorPolicy("approval"); got != "" {
		t.Fatalf("default prompt should not be sent to Jev, got %q", got)
	}
	if got := (HitlConfig{AuditAgentPrompt: "拦截所有命令执行"}).JevOperatorPolicy("approval"); got != "拦截所有命令执行" {
		t.Fatalf("custom prompt=%q", got)
	}
}
