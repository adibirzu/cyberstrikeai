package security

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"cyberstrike-ai/internal/childenv"
	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/mcp"
	"go.uber.org/zap"
)

func TestDisabledToolsCannotLaunchChild(t *testing.T) {
	if os.Getenv("CSAI_DISABLED_TOOL_HELPER") == "1" {
		if err := os.WriteFile(os.Getenv("CSAI_DISABLED_TOOL_MARKER"), []byte("executed"), 0o600); err != nil {
			os.Exit(2)
		}
		os.Exit(0)
	}
	recipe, err := config.LoadToolFromFile(filepath.Join("..", "..", "tools", "dnslog.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if recipe.Enabled {
		t.Fatal("insecure external callback recipe must be opt-in")
	}
	marker := filepath.Join(t.TempDir(), "child-ran")
	t.Setenv("CSAI_DISABLED_TOOL_HELPER", "1")
	t.Setenv("CSAI_DISABLED_TOOL_MARKER", marker)
	t.Setenv(childenv.AllowlistVariable, "CSAI_DISABLED_TOOL_HELPER,CSAI_DISABLED_TOOL_MARKER")
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	// Replace the network recipe with a harmless executable fixture before calling
	// the actual executor. Even a gate regression cannot contact the OAST service.
	recipe.Command = binary
	recipe.Args = []string{"-test.run=^TestDisabledToolsCannotLaunchChild$"}
	recipe.Parameters = nil
	logger := zap.NewNop()
	server := mcp.NewServer(logger)
	executor := NewExecutor(&config.SecurityConfig{Tools: []config.ToolConfig{*recipe, {Name: "exec", Enabled: false}}}, server, logger)
	if _, err := executor.ExecuteTool(context.Background(), "dnslog", nil); err == nil {
		t.Fatal("disabled callback tool accepted")
	}
	if _, err := executor.ExecuteTool(context.Background(), "exec", map[string]interface{}{"command": "echo must-not-run"}); err == nil || !strings.Contains(err.Error(), "disabled") {
		t.Fatalf("disabled exec accepted: %v", err)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("disabled tool launched a child")
	}
	recipe.Enabled = true
	executor = NewExecutor(&config.SecurityConfig{Tools: []config.ToolConfig{*recipe}}, server, logger)
	result, err := executor.ExecuteTool(context.Background(), "dnslog", nil)
	if err != nil || result == nil || result.IsError {
		t.Fatalf("explicitly enabled capability broken: %v %#v", err, result)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatal("positive-control child did not execute")
	}
}

func TestDNSlogRecipeKeepsIndependentPrivateSessions(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is not installed")
	}
	recipe, err := config.LoadToolFromFile(filepath.Join("..", "..", "tools", "dnslog.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(t.TempDir(), "sessions")
	fake := `import sys, types, os, json
fake=types.ModuleType("requests")
class Cookies(dict):
    def get_dict(self): return dict(self)
class Response:
    def __init__(self,text): self.text=text
    def raise_for_status(self): pass
class Session:
    def __init__(self): self.cookies=Cookies()
    def get(self,url,params=None,timeout=None):
        assert url.startswith("https://oast.fixture/")
        if url.endswith("getdomain.php"):
            domain=os.environ["CSAI_FAKE_DOMAIN"]
            self.cookies["PHPSESSID"]="cookie-"+domain
            return Response(domain)
        domain=params["t"]
        assert self.cookies.get("PHPSESSID")=="cookie-"+domain
        return Response(json.dumps([[domain,"fixture-record"]]))
fake.Session=Session
fake.RequestException=type("RequestException",(Exception,),{})
sys.modules["requests"]=fake
`
	run := func(domain string, args ...string) (string, error) {
		cmd := exec.Command(python, append([]string{"-c", fake + "\n" + recipe.Args[1]}, args...)...)
		cmd.Env = childenv.Build(map[string]string{"DNSLOG_SESSION_DIR": root, "DNSLOG_BASE_URL": "https://oast.fixture", "CSAI_FAKE_DOMAIN": domain})
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	for _, domain := range []string{"one.fixture", "two.fixture"} {
		if out, err := run(domain, "get_domain"); err != nil {
			t.Fatalf("get domain: %v %s", err, out)
		}
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("session files=%d, want 2", len(entries))
	}
	for _, domain := range []string{"one.fixture", "two.fixture"} {
		out, err := run(domain, "get_records", domain, "0")
		if err != nil || !strings.Contains(out, "fixture-record") {
			t.Fatalf("separate session lost: %v %s", err, out)
		}
	}
	if out, err := run("missing.fixture", "get_records", "missing.fixture"); err == nil || !strings.Contains(out, "No local session") {
		t.Fatalf("missing session not rejected: %v %s", err, out)
	}
}
