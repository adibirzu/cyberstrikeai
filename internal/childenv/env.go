// Package childenv defines the environment boundary between the server and
// operator-enabled tools. Environment filtering is not a filesystem sandbox.
package childenv

import (
	"os"
	"sort"
	"strings"
)

// AllowlistVariable names additional server variables an operator deliberately
// makes available to child tools. It contains comma-separated exact names.
const AllowlistVariable = "CYBERSTRIKE_CHILD_ENV_ALLOWLIST"

// Build preserves the execution environment without implicitly sharing server
// credentials. Explicit per-MCP credentials override inherited values. Operators
// can allow additional exact names through AllowlistVariable; there is no wildcard.
func Build(explicit map[string]string) []string {
	return BuildForTool(explicit, nil)
}

// BuildForTool adds only the exact inherited names selected in this tool's
// operator-owned recipe. Routing/CA settings preserve engagement network policy;
// proxy URLs may contain credentials and are intentionally visible to children.
func BuildForTool(explicit map[string]string, inherit []string) []string {
	allowed := map[string]bool{}
	for _, key := range []string{"PATH", "HOME", "USER", "LOGNAME", "TMPDIR", "TMP", "TEMP", "SystemRoot", "SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "TERM", "COLUMNS", "LINES", "SSL_CERT_FILE", "SSL_CERT_DIR", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "all_proxy", "no_proxy", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE"} {
		allowed[key] = true
	}
	for _, key := range strings.Split(os.Getenv(AllowlistVariable), ",") {
		key = strings.TrimSpace(key)
		if validName(key) && key != AllowlistVariable {
			allowed[key] = true
		}
	}
	for _, key := range inherit {
		if validName(key) && key != AllowlistVariable {
			allowed[key] = true
		}
	}
	values := map[string]string{}
	for _, entry := range os.Environ() {
		key, value, ok := strings.Cut(entry, "=")
		if ok && allowed[key] {
			values[key] = value
		}
	}
	// The maintained product uses English diagnostics even on a Chinese host.
	values["LANG"] = "C"
	values["LC_ALL"] = "C"
	values["LANGUAGE"] = "en_US:en"
	for key, value := range explicit {
		if validName(key) {
			values[key] = value
		}
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := make([]string, 0, len(keys))
	for _, key := range keys {
		result = append(result, key+"="+values[key])
	}
	return result
}

func validName(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		if !(r == '_' || r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || i > 0 && r >= '0' && r <= '9') {
			return false
		}
	}
	return true
}
