// Package legacytext recognizes persisted vendor-era input without translating
// or rewriting user data. It never supplies product display text.
package legacytext

import "strings"

func Contains(s, current string) bool {
	if strings.Contains(strings.ToLower(s), strings.ToLower(current)) {
		return true
	}
	for _, old := range historical(current) {
		if strings.Contains(s, old) {
			return true
		}
	}
	return false
}
func HasPrefix(s, current string) bool {
	if strings.HasPrefix(s, current) {
		return true
	}
	for _, old := range historical(current) {
		if strings.HasPrefix(s, old) {
			return true
		}
	}
	return false
}
func Cut(s, current string) (string, string, bool) {
	if before, after, ok := strings.Cut(s, current); ok {
		return before, after, true
	}
	for _, old := range historical(current) {
		if before, after, ok := strings.Cut(s, old); ok {
			return before, after, true
		}
	}
	return s, "", false
}
func Token(s string) string {
	if current, ok := tokens[strings.TrimSpace(s)]; ok {
		return current
	}
	return s
}

func historical(current string) []string {
	if values, ok := aliases[current]; ok {
		return values
	}
	for key, values := range aliases {
		if strings.EqualFold(key, current) {
			return values
		}
	}
	return nil
}

func Equal(s, current string) bool {
	if s == current {
		return true
	}
	for _, old := range historical(current) {
		if s == old {
			return true
		}
	}
	return false
}
func AuditDecision(s string) string {
	if current, ok := auditDecisionTokens[strings.TrimSpace(s)]; ok {
		return current
	}
	return s
}
func Command(s string) string {
	best := ""
	replacement := ""
	for old, current := range commandAliases {
		if (s == old || strings.HasPrefix(s, old+" ")) && len(old) > len(best) {
			best = old
			replacement = current
		}
	}
	if best != "" {
		return replacement + s[len(best):]
	}
	lower := strings.ToLower(s)
	for _, current := range commandAliases {
		if (lower == current || strings.HasPrefix(lower, current+" ")) && len(current) > len(best) {
			best = current
			replacement = current
		}
	}
	if best != "" {
		return replacement + s[len(best):]
	}
	return s
}

// AccountDisplayName only renders an exact historical factory label. It never
// changes the account record, native identity, permissions or binding.
func AccountDisplayName(id, username string, builtin bool, display string) string {
	if builtin && id == "admin" && username == "admin" && display == FactoryAdminDisplayName {
		return "Administrator"
	}
	return display
}
