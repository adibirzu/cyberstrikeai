package handler

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"unicode"

	"cyberstrike-ai/internal/mcp"
	"go.uber.org/zap"
)

func requireEnglishOutput(t *testing.T, label string, value interface{}) {
	t.Helper()
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range string(body) {
		if unicode.Is(unicode.Han, r) {
			t.Fatalf("%s contains untranslated product text", label)
		}
	}
}

func TestBatchMCPRuntimeMetadataAndValidationAreEnglish(t *testing.T) {
	server := mcp.NewServer(zap.NewNop())
	h := &AgentHandler{batchTaskManager: NewBatchTaskManager(zap.NewNop())}
	RegisterBatchTaskMCPTools(server, h, zap.NewNop())
	tools := server.GetAllTools()
	if len(tools) != 13 {
		t.Fatalf("registered %d batch tools; expected the full set of 13", len(tools))
	}
	for _, tool := range tools {
		requireEnglishOutput(t, tool.Name+" metadata", tool)
		// No target, model or scheduler is invoked: these public tool calls fail at
		// argument/principal validation before any operation can execute.
		result, _, err := server.CallTool(context.Background(), tool.Name, nil)
		if err != nil {
			t.Fatalf("%s: %v", tool.Name, err)
		}
		if result == nil || !result.IsError {
			t.Fatalf("%s accepted missing required input", tool.Name)
		}
		requireEnglishOutput(t, tool.Name+" validation", result)
		if !strings.HasPrefix(tool.Name, "batch_task_") {
			t.Fatalf("tool identifier changed: %s", tool.Name)
		}
	}
}
