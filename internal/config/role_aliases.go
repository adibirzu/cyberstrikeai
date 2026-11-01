package config

// BuiltinRoleAliases keeps persisted queues/conversations and bookmarks usable
// after bundled role labels become English. These are accepted input identifiers,
// never display labels. Custom roles take precedence over these legacy aliases.
var BuiltinRoleAliases = map[string]string{
	"默认":      "Default",
	"二进制分析":   "Binary Analysis",
	"数字取证":    "Digital Forensics",
	"云安全审计":   "Cloud Security Audit",
	"综合漏洞扫描":  "Comprehensive Vulnerability Scan",
	"渗透测试":    "Penetration Testing",
	"信息收集":    "Information Gathering",
	"容器安全":    "Container Security",
	"后渗透测试":   "Post-exploitation Testing",
	"Web框架测试": "Web Framework Testing",
	"Web应用扫描": "Web Application Scan",
	"API安全测试": "API Security Testing",
}

// Role resolves a current name or a legacy bundled identifier without mutating
// the operator's role catalog or persisted records.
func (c *Config) Role(name string) (RoleConfig, bool) {
	if c == nil {
		return RoleConfig{}, false
	}
	if role, ok := c.Roles[name]; ok {
		return role, true
	}
	current, known := BuiltinRoleAliases[name]
	if !known {
		return RoleConfig{}, false
	}
	role, ok := c.Roles[current]
	return role, ok
}

func IsDefaultRole(name string) bool { return name == "" || name == "Default" || name == "默认" }

// RoleDisplayName renders a historical bundled selector without changing it in
// storage. An exact custom role still takes precedence through Role.
func (c *Config) RoleDisplayName(name string) string {
	if role, ok := c.Role(name); ok && role.Name != "" {
		return role.Name
	}
	if current, ok := BuiltinRoleAliases[name]; ok {
		return current
	}
	if name == "" {
		return "Default"
	}
	return name
}
