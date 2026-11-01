package childenv

import (
	"encoding/json"
	"os"
	"os/exec"
	"testing"
)

func TestChildEnvironmentBoundary(t *testing.T) {
	if os.Getenv("CSAI_TEST_CHILD_ENV") == "1" {
		values := map[string]string{}
		for _, k := range []string{"OPENAI_API_KEY", "ANTHROPIC_API_KEY", "DATABASE_URL", "LITELLM_API_KEY", "CLAUDE_CODE_OAUTH_TOKEN", "CYBERSTRIKE_ACCESS_USER_MAP", "CSAI_TOOL_CREDENTIAL", "CSAI_ALLOWED", "PATH", "HOME", "LC_ALL"} {
			values[k] = os.Getenv(k)
		}
		_ = json.NewEncoder(os.Stdout).Encode(values)
		os.Exit(0)
	}
	for _, key := range []string{"OPENAI_API_KEY", "ANTHROPIC_API_KEY", "DATABASE_URL", "LITELLM_API_KEY", "CLAUDE_CODE_OAUTH_TOKEN", "CYBERSTRIKE_ACCESS_USER_MAP"} {
		t.Setenv(key, "server-only-test-value")
	}
	t.Setenv("CSAI_ALLOWED", "intentional-tool-value")
	t.Setenv(AllowlistVariable, " CSAI_ALLOWED , INVALID*, =BAD ")
	bin, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, "-test.run=^TestChildEnvironmentBoundary$")
	cmd.Env = Build(map[string]string{"CSAI_TEST_CHILD_ENV": "1", "CSAI_TOOL_CREDENTIAL": "explicit-tool-value"})
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]string
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"OPENAI_API_KEY", "ANTHROPIC_API_KEY", "DATABASE_URL", "LITELLM_API_KEY", "CLAUDE_CODE_OAUTH_TOKEN", "CYBERSTRIKE_ACCESS_USER_MAP"} {
		if got[key] != "" {
			t.Errorf("server secret %s reached child", key)
		}
	}
	if got["CSAI_TOOL_CREDENTIAL"] != "explicit-tool-value" || got["CSAI_ALLOWED"] != "intentional-tool-value" || got["PATH"] == "" || got["HOME"] == "" || got["LC_ALL"] != "C" {
		t.Fatal("child lost required execution, locale or explicit credential environment")
	}
}
