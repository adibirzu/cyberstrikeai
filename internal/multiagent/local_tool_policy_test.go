package multiagent

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"cyberstrike-ai/internal/agent"
	"cyberstrike-ai/internal/authctx"
	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/mcp"
	"cyberstrike-ai/internal/toolguard"
	"github.com/cloudwego/eino/compose"
	"github.com/cloudwego/eino/schema"
	"go.uber.org/zap"
)

func TestNativeLocalStacksEnforceDisabledExecGuardAndTrustedHITL(t *testing.T) {
	server := mcp.NewServer(zap.NewNop())
	guard, err := toolguard.NewManager(toolguard.Config{Enabled: true, Rules: []toolguard.Rule{{ID: "synthetic", Name: "Fixture restriction", Enabled: true, Pattern: "blocked-fixture", Message: "Fixture blocked"}}})
	if err != nil {
		t.Fatal(err)
	}
	server.SetToolGuard(guard)
	ag := agent.NewAgent(&config.OpenAIConfig{}, &config.AgentConfig{}, server, nil, zap.NewNop(), 1)
	ctx := authctx.WithPrincipal(context.Background(), authctx.NewPrincipal("fixture", "fixture", "own", map[string]bool{"agent:local-execute": true}))
	for _, mode := range []string{"invoke", "stream"} {
		t.Run(mode, func(t *testing.T) {
			for _, tc := range []struct {
				name, args          string
				disabled, edit, run bool
			}{
				{"execute", `{"command":"harmless"}`, true, false, false},
				{"execute", `{"command":"blocked-fixture"}`, false, false, false},
				{"read_file", `{"path":"blocked-fixture"}`, false, false, false},
				{"write_file", `{"path":"blocked-fixture"}`, false, false, false},
				{"execute", `{"command":"harmless"}`, false, true, false},
				{"execute", `{"command":"harmless"}`, false, false, true},
			} {
				cfg := &config.Config{}
				cfg.Security.Tools = []config.ToolConfig{{Name: "exec", Enabled: !tc.disabled}}
				marker := filepath.Join(t.TempDir(), "executed")
				callCtx := ctx
				approvals := 0
				callCtx = WithHITLToolInterceptor(callCtx, func(_ context.Context, _ string, args string) (string, error) {
					approvals++
					if tc.edit {
						return `{"command":"blocked-fixture"}`, nil
					}
					return args, nil
				})
				input := &compose.ToolInput{Name: tc.name, Arguments: tc.args}
				var result string
				if mode == "invoke" {
					var next compose.InvokableToolEndpoint = func(context.Context, *compose.ToolInput) (*compose.ToolOutput, error) {
						return &compose.ToolOutput{Result: "executed"}, os.WriteFile(marker, []byte("fixture"), 0600)
					}
					stack := nativeToolCallMiddlewares(cfg, ag)
					for i := len(stack) - 1; i >= 0; i-- {
						if stack[i].Invokable != nil {
							next = stack[i].Invokable(next)
						}
					}
					out, err := next(callCtx, input)
					if err != nil {
						t.Fatal(err)
					}
					result = out.Result
				} else {
					var next compose.StreamableToolEndpoint = func(context.Context, *compose.ToolInput) (*compose.StreamToolOutput, error) {
						return &compose.StreamToolOutput{Result: schema.StreamReaderFromArray([]string{"executed"})}, os.WriteFile(marker, []byte("fixture"), 0600)
					}
					stack := nativeToolCallMiddlewares(cfg, ag)
					for i := len(stack) - 1; i >= 0; i-- {
						if stack[i].Streamable != nil {
							next = stack[i].Streamable(next)
						}
					}
					out, err := next(callCtx, input)
					if err != nil {
						t.Fatal(err)
					}
					defer out.Result.Close()
					for {
						part, err := out.Result.Recv()
						if err == io.EOF {
							break
						}
						if err != nil {
							t.Fatal(err)
						}
						result += part
					}
				}
				_, err := os.Stat(marker)
				ran := err == nil
				if ran != tc.run {
					t.Fatalf("%s disabled=%v edited=%v: ran=%v result=%s", tc.name, tc.disabled, tc.edit, ran, result)
				}
				if approvals != 1 {
					t.Fatalf("existing HITL interceptor called %d times", approvals)
				}
				if !tc.run && !strings.Contains(result, "disabled") && !strings.Contains(result, "blocked") {
					t.Fatalf("missing policy refusal: %s", result)
				}
			}
		})
	}
}
