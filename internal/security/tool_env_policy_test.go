package security

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"cyberstrike-ai/internal/childenv"
	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/mcp"
	"go.uber.org/zap"
)

func TestRecipeEnvironmentAndNucleiPolicyAtChildBoundary(t *testing.T) {
	if os.Getenv("CSAI_RECIPE_FIXTURE") == "1" {
		_ = json.NewEncoder(os.Stdout).Encode(map[string]interface{}{"args": os.Args, "SHODAN_API_KEY": os.Getenv("SHODAN_API_KEY"), "OPENAI_API_KEY": os.Getenv("OPENAI_API_KEY"), "EXPLICIT": os.Getenv("EXPLICIT"), "HTTPS_PROXY": os.Getenv("HTTPS_PROXY"), "REQUESTS_CA_BUNDLE": os.Getenv("REQUESTS_CA_BUNDLE")})
		os.Exit(0)
	}
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(childenv.AllowlistVariable, "")
	t.Setenv("OPENAI_API_KEY", "synthetic-server-secret")
	t.Setenv("SHODAN_API_KEY", "synthetic-tool-key")
	t.Setenv("HTTPS_PROXY", "https://user:synthetic-proxy-credential@proxy.fixture")
	t.Setenv("REQUESTS_CA_BUNDLE", "/fixture/ca.pem")
	tool := config.ToolConfig{Name: "fixture", Command: binary, Enabled: true, Args: []string{"-test.run=^TestRecipeEnvironmentAndNucleiPolicyAtChildBoundary$", "--"}, Env: map[string]string{"CSAI_RECIPE_FIXTURE": "1", "EXPLICIT": "synthetic-explicit"}, InheritEnv: []string{"SHODAN_API_KEY"}}
	run := func(recipe config.ToolConfig, args map[string]interface{}) string {
		t.Helper()
		executor := NewExecutor(&config.SecurityConfig{Tools: []config.ToolConfig{recipe}}, mcp.NewServer(zap.NewNop()), zap.NewNop())
		result, err := executor.ExecuteTool(context.Background(), recipe.Name, args)
		if err != nil {
			t.Fatal(err)
		}
		if result.IsError {
			t.Fatal(mcp.ToolResultPlainText(result))
		}
		return mcp.ToolResultPlainText(result)
	}
	var got map[string]interface{}
	if err := json.Unmarshal([]byte(run(tool, nil)), &got); err != nil {
		t.Fatal(err)
	}
	if got["OPENAI_API_KEY"] != "" || got["SHODAN_API_KEY"] != "synthetic-tool-key" || got["EXPLICIT"] != "synthetic-explicit" || got["HTTPS_PROXY"] != "https://user:synthetic-proxy-credential@proxy.fixture" || got["REQUESTS_CA_BUNDLE"] != "/fixture/ca.pem" {
		t.Fatal("per-tool credentials, server-secret filtering or routing failed")
	}
	tool.InheritEnv = nil
	var other map[string]interface{}
	_ = json.Unmarshal([]byte(run(tool, nil)), &other)
	if other["SHODAN_API_KEY"] != "" {
		t.Fatal("credential shared with unrelated child")
	}
	encoded, _ := json.Marshal(tool)
	if strings.Contains(string(encoded), "synthetic-explicit") {
		t.Fatal("config JSON exposes explicit environment values")
	}
	recipe, err := config.LoadToolFromFile(filepath.Join("..", "..", "tools", "nuclei.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	recipe.Command = binary
	recipe.Args = append(tool.Args, recipe.Args...)
	recipe.Env = tool.Env
	output := run(*recipe, map[string]interface{}{"target": "https://target.fixture"})
	if !strings.Contains(output, "-no-interactsh") {
		t.Fatal("default child invocation permits public OAST")
	}
	for _, override := range []string{"-no-interactsh=false", "-ni=false", "-iserver https://public.fixture", "-interactsh-server=https://public.fixture"} {
		executor := NewExecutor(&config.SecurityConfig{Tools: []config.ToolConfig{*recipe}}, mcp.NewServer(zap.NewNop()), zap.NewNop())
		if _, err := executor.ExecuteTool(context.Background(), "nuclei", map[string]interface{}{"target": "https://target.fixture", "additional_args": override}); err == nil {
			t.Fatalf("model OAST override accepted: %s", override)
		}
	}
}
