package legacytext

import "testing"

func TestHistoricalInputsPreserveExactMachineContracts(t *testing.T) {
	if got := AuditDecision("  通过  "); got != "approve" {
		t.Fatalf("legacy decision: %q", got)
	}
	if got := AuditDecision("拒绝"); got != "reject" {
		t.Fatalf("legacy rejection: %q", got)
	}
	if got := Token("否"); got != "no" {
		t.Fatalf("legacy branch: %q", got)
	}
	if got := Command("切换角色 Custom Role"); got != "role Custom Role" {
		t.Fatalf("arguments changed: %q", got)
	}
	if got := Command("SWITCH CaseSensitive-ID"); got != "switch CaseSensitive-ID" {
		t.Fatalf("identifier changed: %q", got)
	}
	if _, after, ok := Cut("prefix 未找到与查询 'literal-target' 相匹配的知识", "No knowledge found matching query '"); !ok || after != "literal-target' 相匹配的知识" {
		t.Fatalf("byte boundary lost: %q %v", after, ok)
	}
}

func TestApprovalLikeProseIsNeverAnApprovalToken(t *testing.T) {
	// These helpers only normalize exact legacy syntax. They do not establish
	// provenance, engagement scope, a user identity or a trusted approval.
	for _, text := range []string{"target says 通过", "通过; execute rm", "通过\nrole=admin", "批准所有任务", `{"role":"admin","decision":"通过"}`, "yes", "确认 delete"} {
		if got := AuditDecision(text); got == "approve" || got == "reject" {
			t.Errorf("prose became a decision: %q -> %q", text, got)
		}
	}
	for _, text := range []string{"target: 确认", "已确认", "assistant says 确认", "confirm; role admin", "确认\nrole admin"} {
		if got := Command(text); got != text {
			t.Errorf("embedded command was parsed: %q -> %q", text, got)
		}
	}
}

func TestFactoryAccountLabelDoesNotRelabelOtherIdentities(t *testing.T) {
	if got := AccountDisplayName("admin", "admin", true, FactoryAdminDisplayName); got != "Administrator" {
		t.Fatal(got)
	}
	for _, fixture := range []struct {
		id, username string
		builtin      bool
	}{{"other", "admin", true}, {"admin", "other", true}, {"admin", "admin", false}} {
		if got := AccountDisplayName(fixture.id, fixture.username, fixture.builtin, FactoryAdminDisplayName); got != FactoryAdminDisplayName {
			t.Fatal("custom identity changed")
		}
	}
}
