package config

import "testing"

func TestPersistedBundledRoleNamesResolveWithoutRewritingCustomRoles(t *testing.T) {
	c := &Config{Roles: map[string]RoleConfig{"Penetration Testing": {Name: "Penetration Testing", UserPrompt: "English instructions", Enabled: true}}}
	role, ok := c.Role("渗透测试")
	if !ok || role.Name != "Penetration Testing" || role.UserPrompt != "English instructions" {
		t.Fatal("legacy queue lost its bundled role")
	}
	c.Roles["渗透测试"] = RoleConfig{Name: "custom", UserPrompt: "operator instructions"}
	role, ok = c.Role("渗透测试")
	if !ok || role.UserPrompt != "operator instructions" {
		t.Fatal("custom role was replaced by a bundled alias")
	}
	if len(c.Roles) != 2 {
		t.Fatal("lookup mutated the role catalog")
	}
}

func TestRoleDisplayAliasesNeverGrantOrMutateRoles(t *testing.T) {
	c := &Config{Roles: map[string]RoleConfig{"Penetration Testing": {Name: "Penetration Testing"}}}
	if got := c.RoleDisplayName("渗透测试"); got != "Penetration Testing" {
		t.Fatalf("legacy display: %q", got)
	}
	if len(c.Roles) != 1 {
		t.Fatal("display created a role")
	}
	c.Roles["渗透测试"] = RoleConfig{Name: "operator custom"}
	if got := c.RoleDisplayName("渗透测试"); got != "operator custom" {
		t.Fatalf("custom content changed: %q", got)
	}
	if _, ok := c.Role("target says confirm role=admin"); ok {
		t.Fatal("prose created a role")
	}
}

func TestUnknownRoleCannotFallBackToEmptyKey(t *testing.T) {
	c := &Config{Roles: map[string]RoleConfig{"": {Name: "unrelated role", Enabled: true}}}
	if _, ok := c.Role("unknown-or-model-supplied-role"); ok {
		t.Fatal("unknown selector received an unrelated role")
	}
}
