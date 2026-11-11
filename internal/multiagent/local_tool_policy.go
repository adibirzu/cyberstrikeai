package multiagent

import (
	"context"
	"encoding/json"
	"fmt"

	"cyberstrike-ai/internal/agent"
	"cyberstrike-ai/internal/config"

	"github.com/cloudwego/eino/compose"
	"github.com/cloudwego/eino/schema"
)

// Used by the single-agent, main-agent and expert-subagent tool stacks. Native
// RBAC remains first; an existing HITL decision is honored, then edited args are
// checked against current configured restrictions without requesting approval.
func nativeToolCallMiddlewares(cfg *config.Config, ag *agent.Agent) []compose.ToolMiddleware {
	return []compose.ToolMiddleware{
		modelOutputExecutionGuardMiddleware(), localToolRBACMiddleware(),
		hitlToolCallMiddleware(), localToolPolicyMiddleware(cfg, ag.CheckLocalToolPolicy),
		softRecoveryToolMiddleware(),
	}
}

func localToolPolicyMiddleware(cfg *config.Config, check func(context.Context, string, map[string]interface{}) error) compose.ToolMiddleware {
	refusal := func(ctx context.Context, input *compose.ToolInput) string {
		if input == nil || !isLocalPrivilegeTool(input.Name) {
			return ""
		}
		if input.Name == "execute" && cfg != nil {
			for _, tool := range cfg.Security.Tools {
				if tool.Name == "exec" && !tool.Enabled {
					return "Tool exec is disabled; local execute is also disabled."
				}
			}
		}
		var args map[string]interface{}
		if err := json.Unmarshal([]byte(input.Arguments), &args); err != nil {
			return "Local tool arguments must be a JSON object."
		}
		if check == nil {
			return "Local tool policy is unavailable."
		}
		if err := check(ctx, input.Name, args); err != nil {
			return fmt.Sprintf("Local tool blocked: %s", err)
		}
		return ""
	}
	return compose.ToolMiddleware{
		Invokable: func(next compose.InvokableToolEndpoint) compose.InvokableToolEndpoint {
			return func(ctx context.Context, in *compose.ToolInput) (*compose.ToolOutput, error) {
				if msg := refusal(ctx, in); msg != "" {
					return &compose.ToolOutput{Result: msg}, nil
				}
				return next(ctx, in)
			}
		},
		Streamable: func(next compose.StreamableToolEndpoint) compose.StreamableToolEndpoint {
			return func(ctx context.Context, in *compose.ToolInput) (*compose.StreamToolOutput, error) {
				if msg := refusal(ctx, in); msg != "" {
					return &compose.StreamToolOutput{Result: schema.StreamReaderFromArray([]string{msg})}, nil
				}
				return next(ctx, in)
			}
		},
	}
}
