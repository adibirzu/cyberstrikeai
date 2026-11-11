package handler

import (
	"net/http"

	"cyberstrike-ai/internal/database"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// OpenAPIHandler OpenAPI处理器
type OpenAPIHandler struct {
	db               *database.DB
	logger           *zap.Logger
	conversationHdlr *ConversationHandler
	agentHdlr        *AgentHandler
}

// NewOpenAPIHandler 创建新的OpenAPI处理器
func NewOpenAPIHandler(db *database.DB, logger *zap.Logger, conversationHdlr *ConversationHandler, agentHdlr *AgentHandler) *OpenAPIHandler {
	return &OpenAPIHandler{
		db:               db,
		logger:           logger,
		conversationHdlr: conversationHdlr,
		agentHdlr:        agentHdlr,
	}
}

// GetOpenAPISpec 获取OpenAPI规范
func (h *OpenAPIHandler) GetOpenAPISpec(c *gin.Context) {
	host := c.Request.Host
	scheme := "http"
	if c.Request.TLS != nil {
		scheme = "https"
	}

	finalizationRequestSchema := map[string]interface{}{
		"type":        "object",
		"description": "Final response to delivery strategy. The backend does not extrapolate execution intent from the content of the natural language; the enforcement portal should make a visible statement whether or not it requires proof of a completed tool.",
		"properties": map[string]interface{}{
			"requireExecutionEvidence": map[string]interface{}{
				"type":        "boolean",
				"description": "for true when, missing completed The tool execution record triggers no continuation of injection or eventual disruption; Normal chat can be omitted or set as false.",
			},
		},
	}

	spec := map[string]interface{}{
		"openapi": "3.0.0",
		"info": map[string]interface{}{
			"title":       "CyberStrikeAI API",
			"description": "AI-driven automated security testing platform API documents",
			"version":     "1.0.0",
			"contact": map[string]interface{}{
				"name": "CyberStrikeAI",
			},
		},
		"servers": []map[string]interface{}{
			{
				"url":         scheme + "://" + host,
				"description": "Current Server",
			},
		},
		"components": map[string]interface{}{
			"securitySchemes": map[string]interface{}{
				"bearerAuth": map[string]interface{}{
					"type":         "http",
					"scheme":       "bearer",
					"bearerFormat": "JWT",
					"description":  "Use Bearer Token for authentication. Token is obtained through the /api/auth/login interface.",
				},
			},
			"schemas": map[string]interface{}{
				"CreateConversationRequest": map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"title": map[string]interface{}{
							"type":        "string",
							"description": "Dialogue title",
							"example":     "Web Application Safety Test",
						},
						"projectId": map[string]interface{}{
							"type":        "string",
							"description": "Binded Item ID (optional, shared factboard)",
						},
					},
				},
				"SetConversationProjectRequest": map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"projectId": map[string]interface{}{
							"type":        "string",
							"description": "Item ID; Empty string means untie",
						},
					},
					"required": []string{"projectId"},
				},
				"AgentChatResponse": map[string]interface{}{
					"type":        "object",
					"description": "Agent Non-flow response.response Just deliver text; Is there a need for a successful final response? finalized/finalizable/status Reference.",
					"properties": map[string]interface{}{
						"response": map[string]interface{}{
							"type":        "string",
							"description": "Text delivered to users.finalized=false It's time to stop./Not completed, Not a successful conclusion..",
						},
						"conversationId": map[string]interface{}{
							"type":        "string",
							"description": "Dialogue ID",
						},
						"assistantMessageId": map[string]interface{}{
							"type":        "string",
							"description": "Assistant Message ID (partial interface returns)",
						},
						"mcpExecutionIds": map[string]interface{}{
							"type":        "array",
							"description": "Involving this round MCP Tool execution ID",
							"items":       map[string]interface{}{"type": "string"},
						},
						"agentMode": map[string]interface{}{
							"type":        "string",
							"description": "agent Mode, for example eino_single, eino_deep, workflow",
						},
						"finalized": map[string]interface{}{
							"type":        "boolean",
							"description": "Is the final response checked? Only true can be considered a successful final response.",
						},
						"finalizable": map[string]interface{}{
							"type":        "boolean",
							"description": "Can the candidate output be elevated to the final response?",
						},
						"status": map[string]interface{}{
							"type":        "string",
							"description": "Finalization status",
							"enum":        []string{"completed", "in_progress", "blocked", "failed", "cancelled", "awaiting_hitl"},
						},
						"completionReason": map[string]interface{}{
							"type":        "string",
							"description": "Reasons for eventualization or disruption, e.g., verified, pending_tool_executions, missing_execution_evidence",
						},
						"evidenceVerified": map[string]interface{}{
							"type":        "boolean",
							"description": "Whether or not the evidence meets the requirement of finalization",
						},
						"evidenceRefs": map[string]interface{}{
							"type":        "array",
							"description": "Evidence cited, for example mcp_execution:<id>",
							"items":       map[string]interface{}{"type": "string"},
						},
						"pendingExecutionIds": map[string]interface{}{
							"type":        "array",
							"description": "Still queued/running tool executing ID",
							"items":       map[string]interface{}{"type": "string"},
						},
						"missingChecks": map[string]interface{}{
							"type":        "array",
							"description": "List of reasons for failure to pass finalisation",
							"items":       map[string]interface{}{"type": "string"},
						},
					},
					"required": []string{"response", "conversationId", "finalized", "finalizable", "status", "evidenceVerified"},
				},
				"Conversation": map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"id": map[string]interface{}{
							"type":        "string",
							"description": "Conversation ID",
							"example":     "550e8400-e29b-41d4-a716-446655440000",
						},
						"title": map[string]interface{}{
							"type":        "string",
							"description": "Dialogue title",
							"example":     "Web Application Safety Test",
						},
						"createdAt": map[string]interface{}{
							"type":        "string",
							"format":      "date-time",
							"description": "Created",
						},
						"updatedAt": map[string]interface{}{
							"type":        "string",
							"format":      "date-time",
							"description": "Updated at",
						},
						"projectId": map[string]interface{}{
							"type":        "string",
							"description": "Bind Item ID (optional)",
						},
					},
				},
				"ConversationDetail": map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"id": map[string]interface{}{
							"type":        "string",
							"description": "Conversation ID",
						},
						"title": map[string]interface{}{
							"type":        "string",
							"description": "Dialogue title",
						},
						"status": map[string]interface{}{
							"type":        "string",
							"description": "Dialogue Status: active (Ongoing) , completed (Completed) , failed (Failed) ",
							"enum":        []string{"active", "completed", "failed"},
						},
						"createdAt": map[string]interface{}{
							"type":        "string",
							"format":      "date-time",
							"description": "Created",
						},
						"updatedAt": map[string]interface{}{
							"type":        "string",
							"format":      "date-time",
							"description": "Updated at",
						},
						"messages": map[string]interface{}{
							"type":        "array",
							"description": "Message List",
							"items": map[string]interface{}{
								"$ref": "#/components/schemas/Message",
							},
						},
						"messageCount": map[string]interface{}{
							"type":        "integer",
							"description": "Number of messages",
						},
					},
				},
				"Message": map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"id": map[string]interface{}{
							"type":        "string",
							"description": "Message ID",
						},
						"conversationId": map[string]interface{}{
							"type":        "string",
							"description": "Conversation ID",
						},
						"role": map[string]interface{}{
							"type":        "string",
							"description": "Message Role: user (user) , assistant (Assistant) ",
							"enum":        []string{"user", "assistant"},
						},
						"content": map[string]interface{}{
							"type":        "string",
							"description": "Message Contents",
						},
						"createdAt": map[string]interface{}{
							"type":        "string",
							"format":      "date-time",
							"description": "Created",
						},
					},
				},
				"ConversationResults": map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"conversationId": map[string]interface{}{
							"type":        "string",
							"description": "Conversation ID",
						},
						"messages": map[string]interface{}{
							"type":        "array",
							"description": "Message List",
							"items": map[string]interface{}{
								"$ref": "#/components/schemas/Message",
							},
						},
						"vulnerabilities": map[string]interface{}{
							"type":        "array",
							"description": "List of detected holes",
							"items": map[string]interface{}{
								"$ref": "#/components/schemas/Vulnerability",
							},
						},
						"executionResults": map[string]interface{}{
							"type":        "array",
							"description": "Execution results",
							"items": map[string]interface{}{
								"$ref": "#/components/schemas/ExecutionResult",
							},
						},
					},
				},
				"Vulnerability": map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"id": map[string]interface{}{
							"type":        "string",
							"description": "Vulnerability ID",
						},
						"title": map[string]interface{}{
							"type":        "string",
							"description": "Hole Title",
						},
						"description": map[string]interface{}{
							"type":        "string",
							"description": "Hole Description",
						},
						"severity": map[string]interface{}{
							"type":        "string",
							"description": "Severity",
							"enum":        []string{"critical", "high", "medium", "low", "info"},
						},
						"status": map[string]interface{}{
							"type":        "string",
							"description": "Status",
							"enum":        []string{"open", "confirmed", "fixed", "false_positive", "ignored"},
						},
						"target": map[string]interface{}{
							"type":        "string",
							"description": "Targets affected",
						},
					},
				},
				"AssetImportItem": map[string]interface{}{
					"type":        "object",
					"description": "assets to be imported;host,ip,domain at least one non-empty",
					"properties": map[string]interface{}{
						"project_id":         map[string]interface{}{"type": "string", "description": "Items of which ID; Callers must have access"},
						"host":               map[string]interface{}{"type": "string", "maxLength": 500, "example": "https://app.example.com:443"},
						"ip":                 map[string]interface{}{"type": "string", "example": "192.0.2.10"},
						"port":               map[string]interface{}{"type": "integer", "minimum": 0, "maximum": 65535, "example": 443},
						"domain":             map[string]interface{}{"type": "string", "example": "app.example.com"},
						"protocol":           map[string]interface{}{"type": "string", "example": "https"},
						"title":              map[string]interface{}{"type": "string", "maxLength": 500},
						"server":             map[string]interface{}{"type": "string", "maxLength": 255, "example": "nginx"},
						"country":            map[string]interface{}{"type": "string"},
						"province":           map[string]interface{}{"type": "string"},
						"city":               map[string]interface{}{"type": "string"},
						"responsible_person": map[string]interface{}{"type": "string", "maxLength": 255, "description": "Head of Assets"},
						"department":         map[string]interface{}{"type": "string", "maxLength": 255, "description": "Department"},
						"business_system":    map[string]interface{}{"type": "string", "maxLength": 255, "description": "Operating systems under which"},
						"environment":        map[string]interface{}{"type": "string", "enum": []string{"production", "staging", "testing", "development", "other"}},
						"criticality":        map[string]interface{}{"type": "string", "enum": []string{"critical", "high", "medium", "low"}},
						"source":             map[string]interface{}{"type": "string"},
						"source_query":       map[string]interface{}{"type": "string"},
						"status":             map[string]interface{}{"type": "string", "enum": []string{"active", "inactive"}, "default": "active"},
						"tags": map[string]interface{}{
							"type":     "array",
							"maxItems": 30,
							"items":    map[string]interface{}{"type": "string", "maxLength": 64},
						},
					},
				},
				"AssetImportRequest": map[string]interface{}{
					"type":     "object",
					"required": []string{"assets"},
					"properties": map[string]interface{}{
						"assets": map[string]interface{}{
							"type":     "array",
							"minItems": 1,
							"maxItems": 100000,
							"items":    map[string]interface{}{"$ref": "#/components/schemas/AssetImportItem"},
						},
						"source":       map[string]interface{}{"type": "string", "description": "Default source used when not filling in the asset"},
						"source_query": map[string]interface{}{"type": "string", "description": "Default source query or import file name"},
					},
				},
				"AssetImportResult": map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"created": map[string]interface{}{"type": "integer", "description": "Number of new", "example": 120},
						"updated": map[string]interface{}{"type": "integer", "description": "To merge the amount", "example": 8},
						"skipped": map[string]interface{}{"type": "integer", "description": "Skip Number", "example": 2},
					},
				},
				"ExecutionResult": map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"id": map[string]interface{}{
							"type":        "string",
							"description": "Execute ID",
						},
						"toolName": map[string]interface{}{
							"type":        "string",
							"description": "Tool name",
						},
						"status": map[string]interface{}{
							"type":        "string",
							"description": "Execute Status",
							"enum":        []string{"queued", "running", "completed", "failed", "cancelled", "hard_timeout", "orphaned"},
						},
						"result": map[string]interface{}{
							"type":        "string",
							"description": "Execution result",
						},
						"createdAt": map[string]interface{}{
							"type":        "string",
							"format":      "date-time",
							"description": "Created",
						},
					},
				},
				"Error": map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"error": map[string]interface{}{
							"type":        "string",
							"description": "Error info",
						},
					},
				},
				"LoginRequest": map[string]interface{}{
					"type":     "object",
					"required": []string{"password"},
					"properties": map[string]interface{}{
						"password": map[string]interface{}{
							"type":        "string",
							"description": "Login Password",
						},
					},
				},
				"LoginResponse": map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"token": map[string]interface{}{
							"type":        "string",
							"description": "Authenticate Token",
						},
						"expires_at": map[string]interface{}{
							"type":        "string",
							"format":      "date-time",
							"description": "Token Expiry",
						},
						"session_duration_hr": map[string]interface{}{
							"type":        "integer",
							"description": "Duration of sessions (hours)",
						},
					},
				},
				"ChangePasswordRequest": map[string]interface{}{
					"type":     "object",
					"required": []string{"oldPassword", "newPassword"},
					"properties": map[string]interface{}{
						"oldPassword": map[string]interface{}{
							"type":        "string",
							"description": "Current password",
						},
						"newPassword": map[string]interface{}{
							"type":        "string",
							"description": "New password (at least 8 places)",
						},
					},
				},
				"UpdateConversationRequest": map[string]interface{}{
					"type":     "object",
					"required": []string{"title"},
					"properties": map[string]interface{}{
						"title": map[string]interface{}{
							"type":        "string",
							"description": "Dialogue title",
						},
					},
				},
				"BatchTaskRequest": map[string]interface{}{
					"type":     "object",
					"required": []string{"tasks"},
					"properties": map[string]interface{}{
						"title": map[string]interface{}{
							"type":        "string",
							"description": "Task Title (optional)",
						},
						"tasks": map[string]interface{}{
							"type":        "array",
							"description": "Task list, one task per line",
							"items": map[string]interface{}{
								"type": "string",
							},
						},
						"role": map[string]interface{}{
							"type":        "string",
							"description": "Role Name (optional)",
						},
						"agentMode": map[string]interface{}{
							"type":        "string",
							"description": "Proxy Mode: eino_single (Eino ADK Single Agent, Default) | deep | plan_execute | supervisor",
							"enum":        []string{"eino_single", "deep", "plan_execute", "supervisor"},
						},
						"scheduleMode": map[string]interface{}{
							"type":        "string",
							"description": "Schedule mode (manual | cron)",
							"enum":        []string{"manual", "cron"},
						},
						"cronExpr": map[string]interface{}{
							"type":        "string",
							"description": "Cron Expression (scheduleMode=cron)",
						},
						"executeNow": map[string]interface{}{
							"type":        "boolean",
							"description": "Whether to execute immediately after creation (default false)",
						},
					},
				},
				"BatchQueue": map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"id": map[string]interface{}{
							"type":        "string",
							"description": "Queue ID",
						},
						"title": map[string]interface{}{
							"type":        "string",
							"description": "Queue Title",
						},
						"status": map[string]interface{}{
							"type":        "string",
							"description": "Queue Status",
							"enum":        []string{"pending", "running", "paused", "completed", "failed"},
						},
						"tasks": map[string]interface{}{
							"type":        "array",
							"description": "Task list",
							"items": map[string]interface{}{
								"type": "object",
							},
						},
						"createdAt": map[string]interface{}{
							"type":        "string",
							"format":      "date-time",
							"description": "Created",
						},
					},
				},
				"CancelAgentLoopRequest": map[string]interface{}{
					"type":     "object",
					"required": []string{"conversationId"},
					"properties": map[string]interface{}{
						"conversationId": map[string]interface{}{
							"type":        "string",
							"description": "Conversation ID",
						},
						"reason": map[string]interface{}{
							"type":        "string",
							"description": "optional.and MCP Monitor Page\"Termination and description\"Unanimously: Text returned to the model from the current tool when not being available (includes USER INTERRUPT NOTE Blocks) ",
						},
						"continueAfter": map[string]interface{}{
							"type":        "boolean",
							"description": "Only terminate the current MCP tool call for true (no cancellation of the whole round); already available tools must be implemented, otherwise 400",
						},
					},
				},
				"AgentTask": map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"conversationId": map[string]interface{}{
							"type":        "string",
							"description": "Conversation ID",
						},
						"status": map[string]interface{}{
							"type":        "string",
							"description": "Task Status",
							"enum":        []string{"running", "completed", "failed", "cancelled", "timeout"},
						},
						"startedAt": map[string]interface{}{
							"type":        "string",
							"format":      "date-time",
							"description": "Started at",
						},
					},
				},
				"CreateVulnerabilityRequest": map[string]interface{}{
					"type":     "object",
					"required": []string{"conversation_id", "title", "description", "severity", "type", "target", "reproduction_steps", "evidence", "impact", "recommendation"},
					"properties": map[string]interface{}{
						"conversation_id": map[string]interface{}{
							"type":        "string",
							"description": "Conversation ID",
						},
						"title": map[string]interface{}{
							"type":        "string",
							"description": "Hole Title",
						},
						"description": map[string]interface{}{
							"type":        "string",
							"description": "Hole Description",
						},
						"severity": map[string]interface{}{
							"type":        "string",
							"description": "Severity",
							"enum":        []string{"critical", "high", "medium", "low", "info"},
						},
						"status": map[string]interface{}{
							"type":        "string",
							"description": "Status",
							"enum":        []string{"open", "closed", "fixed"},
						},
						"type": map[string]interface{}{
							"type":        "string",
							"description": "Vulnerability type",
						},
						"target": map[string]interface{}{
							"type":        "string",
							"description": "Targets affected",
						},
						"preconditions":      map[string]interface{}{"type": "string", "description": "Preconditions"},
						"reproduction_steps": map[string]interface{}{"type": "string", "description": "Reproduction steps"},
						"evidence":           map[string]interface{}{"type": "string", "description": "Evidence/POC, including response to request, command output, intercept description, log, etc."},
						"impact": map[string]interface{}{
							"type":        "string",
							"description": "Impact",
						},
						"recommendation": map[string]interface{}{
							"type":        "string",
							"description": "Remediation",
						},
						"retest_notes": map[string]interface{}{"type": "string", "description": "Retest method"},
						"retest_log":   map[string]interface{}{"type": "string", "description": "Repeating records (read-only, added by the repeat process)"},
					},
				},
				"UpdateVulnerabilityRequest": map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"title": map[string]interface{}{
							"type":        "string",
							"description": "Hole Title",
						},
						"description": map[string]interface{}{
							"type":        "string",
							"description": "Hole Description",
						},
						"severity": map[string]interface{}{
							"type":        "string",
							"description": "Severity",
							"enum":        []string{"critical", "high", "medium", "low", "info"},
						},
						"status": map[string]interface{}{
							"type":        "string",
							"description": "Status",
							"enum":        []string{"open", "confirmed", "fixed", "false_positive", "ignored"},
						},
						"type": map[string]interface{}{
							"type":        "string",
							"description": "Vulnerability type",
						},
						"target": map[string]interface{}{
							"type":        "string",
							"description": "Targets affected",
						},
						"preconditions":      map[string]interface{}{"type": "string", "description": "Preconditions"},
						"reproduction_steps": map[string]interface{}{"type": "string", "description": "Reproduction steps"},
						"evidence":           map[string]interface{}{"type": "string", "description": "Evidence/POC, including response to request, command output, intercept description, log, etc."},
						"impact": map[string]interface{}{
							"type":        "string",
							"description": "Impact",
						},
						"recommendation": map[string]interface{}{
							"type":        "string",
							"description": "Remediation",
						},
						"retest_notes": map[string]interface{}{"type": "string", "description": "Retest method"},
					},
				},
				"ListVulnerabilitiesResponse": map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"vulnerabilities": map[string]interface{}{
							"type":        "array",
							"description": "Hole List",
							"items": map[string]interface{}{
								"$ref": "#/components/schemas/Vulnerability",
							},
						},
						"total": map[string]interface{}{
							"type":        "integer",
							"description": "Total",
						},
						"page": map[string]interface{}{
							"type":        "integer",
							"description": "This page",
						},
						"page_size": map[string]interface{}{
							"type":        "integer",
							"description": "Number per page",
						},
						"total_pages": map[string]interface{}{
							"type":        "integer",
							"description": "Total number of pages",
						},
					},
				},
				"VulnerabilityStats": map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"total": map[string]interface{}{
							"type":        "integer",
							"description": "Total",
						},
						"by_severity": map[string]interface{}{
							"type":        "object",
							"description": "By severity",
						},
						"by_status": map[string]interface{}{
							"type":        "object",
							"description": "By Status",
						},
					},
				},
				"RoleConfig": map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"name": map[string]interface{}{
							"type":        "string",
							"description": "Role Name",
						},
						"description": map[string]interface{}{
							"type":        "string",
							"description": "Role description",
						},
						"enabled": map[string]interface{}{
							"type":        "boolean",
							"description": "Enable",
						},
						"systemPrompt": map[string]interface{}{
							"type":        "string",
							"description": "System Hints",
						},
						"userPrompt": map[string]interface{}{
							"type":        "string",
							"description": "User prompt",
						},
						"tools": map[string]interface{}{
							"type":        "array",
							"description": "Tool List",
							"items": map[string]interface{}{
								"type": "string",
							},
						},
					},
				},
				"Skill": map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"name": map[string]interface{}{
							"type":        "string",
							"description": "Skill name",
						},
						"description": map[string]interface{}{
							"type":        "string",
							"description": "Skill Description",
						},
						"path": map[string]interface{}{
							"type":        "string",
							"description": "Skill Path",
						},
					},
				},
				"CreateSkillRequest": map[string]interface{}{
					"type":     "object",
					"required": []string{"name", "description"},
					"properties": map[string]interface{}{
						"name": map[string]interface{}{
							"type":        "string",
							"description": "Skill name",
						},
						"description": map[string]interface{}{
							"type":        "string",
							"description": "Skill Description",
						},
					},
				},
				"UpdateSkillRequest": map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"description": map[string]interface{}{
							"type":        "string",
							"description": "Skill Description",
						},
					},
				},
				"ToolExecution": map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"id": map[string]interface{}{
							"type":        "string",
							"description": "Execute ID",
						},
						"toolName": map[string]interface{}{
							"type":        "string",
							"description": "Tool name",
						},
						"status": map[string]interface{}{
							"type":        "string",
							"description": "Execute Status",
							"enum":        []string{"queued", "running", "completed", "failed", "cancelled", "hard_timeout", "orphaned"},
						},
						"createdAt": map[string]interface{}{
							"type":        "string",
							"format":      "date-time",
							"description": "Created",
						},
					},
				},
				"MonitorResponse": map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"executions": map[string]interface{}{
							"type":        "array",
							"description": "Execution Record List (Light field, does not contain arguments/result) ",
							"items": map[string]interface{}{
								"$ref": "#/components/schemas/ToolExecution",
							},
						},
						"summary": map[string]interface{}{
							"type":        "object",
							"description": "Tool Call Summary",
						},
						"topTools": map[string]interface{}{
							"type":        "array",
							"description": "Call Top N tool",
							"items": map[string]interface{}{
								"type": "object",
							},
						},
						"timestamp": map[string]interface{}{
							"type":        "string",
							"format":      "date-time",
							"description": "Timetamp",
						},
						"total": map[string]interface{}{
							"type":        "integer",
							"description": "Total implementation records",
						},
						"page": map[string]interface{}{
							"type":        "integer",
							"description": "This page",
						},
						"pageSize": map[string]interface{}{
							"type":        "integer",
							"description": "Number per page",
						},
						"totalPages": map[string]interface{}{
							"type":        "integer",
							"description": "Total number of pages",
						},
						"retentionDays": map[string]interface{}{
							"type":        "integer",
							"description": "Number of days to execute record retention",
						},
					},
				},
				"ConfigResponse": map[string]interface{}{
					"type":        "object",
					"description": "Configure Information (includes openai, vision, multi_agent etc.) ",
					"properties": map[string]interface{}{
						"agent": map[string]interface{}{
							"$ref": "#/components/schemas/AgentConfig",
						},
						"vision": map[string]interface{}{
							"$ref": "#/components/schemas/VisionConfig",
						},
					},
				},
				"UpdateConfigRequest": map[string]interface{}{
					"type":        "object",
					"description": "Update Configuration Request",
					"properties": map[string]interface{}{
						"agent": map[string]interface{}{
							"$ref": "#/components/schemas/AgentConfig",
						},
						"vision": map[string]interface{}{
							"$ref": "#/components/schemas/VisionConfig",
						},
					},
				},
				"AgentConfig": map[string]interface{}{
					"type":        "object",
					"description": "Agent Runs and External MCP Card Death Protection Configuration",
					"properties": map[string]interface{}{
						"max_iterations":                         map[string]interface{}{"type": "integer", "description": "Max iterations"},
						"tool_timeout_minutes":                   map[string]interface{}{"type": "integer", "description": "A single tool executes hard timeout (minutes)"},
						"tool_wait_timeout_seconds":              map[string]interface{}{"type": "integer", "description": "Tool single-wheel waiting seconds; Back then execution_id, worker Continue backstage execution."},
						"external_mcp_max_concurrent_per_server": map[string]interface{}{"type": "integer", "description": "Single external MCP server with maximum; 0 = default 2; negative = unlimited"},
						"external_mcp_max_concurrent_total":      map[string]interface{}{"type": "integer", "description": "External MCP global cap; 0 = default 16; negative = unlimited"},
						"external_mcp_circuit_failure_threshold": map[string]interface{}{"type": "integer", "description": "Continuous failure melting threshold; 0 = default 3; negative number = closed melting"},
						"external_mcp_circuit_cooldown_seconds":  map[string]interface{}{"type": "integer", "description": "Melting out cooling seconds; 0 = default 60"},
						"shell_no_output_timeout_seconds":        map[string]interface{}{"type": "integer", "description": "execute/exec Number of consecutive no-out termination seconds"},
						"workspace_root_dir":                     map[string]interface{}{"type": "string", "description": "Session working directory root path"},
						"system_prompt_path":                     map[string]interface{}{"type": "string", "description": "A single-agent system hint file path"},
					},
				},
				"VisionConfig": map[string]interface{}{
					"type":        "object",
					"description": "Visual analysis (analyze_image MCP tool);enabled and model non-empty registration tool",
					"properties": map[string]interface{}{
						"enabled":                     map[string]interface{}{"type": "boolean", "description": "Enable analyze_image"},
						"model":                       map[string]interface{}{"type": "string", "description": "Visual model name (required)", "example": "qwen-vl-max"},
						"api_key":                     map[string]interface{}{"type": "string", "description": "API Key; empty reuse openai.api_key"},
						"base_url":                    map[string]interface{}{"type": "string", "description": "Base URL;empty reuse openai.base_url"},
						"provider":                    map[string]interface{}{"type": "string", "description": "Provider; empty reuser openai.provider"},
						"timeout_seconds":             map[string]interface{}{"type": "integer", "description": "VL Call timeout (sec)"},
						"max_image_bytes":             map[string]interface{}{"type": "integer", "description": "Original file size limit (bytes)"},
						"max_dimension":               map[string]interface{}{"type": "integer", "description": "Max long-edge pixels"},
						"jpeg_quality":                map[string]interface{}{"type": "integer", "description": "JPEG Quality 60-100"},
						"max_payload_bytes":           map[string]interface{}{"type": "integer", "description": "Max API payload (bytes)"},
						"skip_preprocess_below_bytes": map[string]interface{}{"type": "integer", "description": "Shorter byte and straight-forward when dimension compliance; 0 = always compressed"},
						"detail":                      map[string]interface{}{"type": "string", "enum": []string{"low", "high", "auto"}, "description": "OpenAI compatible image detail"},
					},
				},
				"AnalyzeImageToolCall": map[string]interface{}{
					"type":        "object",
					"description": "Internal MCP Tools analyze_image: Analyse server local pictures, returns plain text (Authentication code/UI/Wrong pay.) ",
					"properties": map[string]interface{}{
						"path": map[string]interface{}{
							"type":        "string",
							"description": "An absolute path to the picture or a path to the process work directory",
						},
						"question": map[string]interface{}{
							"type":        "string",
							"description": "Optional: Focus issues; Proof Code proposal \"Exert only\"",
						},
					},
					"required": []string{"path"},
				},
				"ExternalMCPConfig": map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"enabled": map[string]interface{}{
							"type":        "boolean",
							"description": "Enable",
						},
						"command": map[string]interface{}{
							"type":        "string",
							"description": "Command",
						},
						"args": map[string]interface{}{
							"type":        "array",
							"description": "Parameter List",
							"items": map[string]interface{}{
								"type": "string",
							},
						},
					},
				},
				"ExternalMCPResponse": map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"config": map[string]interface{}{
							"$ref": "#/components/schemas/ExternalMCPConfig",
						},
						"status": map[string]interface{}{
							"type":        "string",
							"description": "Status",
							"enum":        []string{"connected", "disconnected", "error", "disabled"},
						},
						"toolCount": map[string]interface{}{
							"type":        "integer",
							"description": "Tool count",
						},
						"error": map[string]interface{}{
							"type":        "string",
							"description": "Error info",
						},
					},
				},
				"AddOrUpdateExternalMCPRequest": map[string]interface{}{
					"type":     "object",
					"required": []string{"config"},
					"properties": map[string]interface{}{
						"config": map[string]interface{}{
							"$ref": "#/components/schemas/ExternalMCPConfig",
						},
					},
				},
				"AttackChain": map[string]interface{}{
					"type":        "object",
					"description": "Attack chain data",
				},
				"MCPMessage": map[string]interface{}{
					"type":        "object",
					"description": "MCP Message (Systems for JSON-RPC 2.0)",
					"required":    []string{"jsonrpc"},
					"properties": map[string]interface{}{
						"id": map[string]interface{}{
							"description": "Message ID, Could be a string, Number or null.For requests, Must provide; For notification, You can omit it.",
							"oneOf": []map[string]interface{}{
								{"type": "string"},
								{"type": "number"},
								{"type": "null"},
							},
							"example": "550e8400-e29b-41d4-a716-446655440000",
						},
						"method": map[string]interface{}{
							"type":        "string",
							"description": "Method name. Support method:\n- `initialize`: Initialize MCP connection\n- `tools/list`: List all available tools\n- `tools/call`: Call Tool\n- `prompts/list`: List all hint templates\n- `prompts/get`: Gettips template\n- `resources/list`: List all resources\n- `resources/read`: Read resource content\n- `sampling/request`: Sample request",
							"enum": []string{
								"initialize",
								"tools/list",
								"tools/call",
								"prompts/list",
								"prompts/get",
								"resources/list",
								"resources/read",
								"sampling/request",
							},
							"example": "tools/list",
						},
						"params": map[string]interface{}{
							"description": "Methodological parameters (JSON objects) with different structures depending on the method",
							"type":        "object",
						},
						"jsonrpc": map[string]interface{}{
							"type":        "string",
							"description": "JSON-RPC version, fixed to \"2.0\"",
							"enum":        []string{"2.0"},
							"example":     "2.0",
						},
					},
				},
				"MCPInitializeParams": map[string]interface{}{
					"type":     "object",
					"required": []string{"protocolVersion", "capabilities", "clientInfo"},
					"properties": map[string]interface{}{
						"protocolVersion": map[string]interface{}{
							"type":        "string",
							"description": "Protocol Version",
							"example":     "2024-11-05",
						},
						"capabilities": map[string]interface{}{
							"type":        "object",
							"description": "Client capacity",
						},
						"clientInfo": map[string]interface{}{
							"type":     "object",
							"required": []string{"name", "version"},
							"properties": map[string]interface{}{
								"name": map[string]interface{}{
									"type":        "string",
									"description": "Client Name",
									"example":     "MyClient",
								},
								"version": map[string]interface{}{
									"type":        "string",
									"description": "Client Version",
									"example":     "1.0.0",
								},
							},
						},
					},
				},
				"MCPCallToolParams": map[string]interface{}{
					"type":     "object",
					"required": []string{"name", "arguments"},
					"properties": map[string]interface{}{
						"name": map[string]interface{}{
							"type":        "string",
							"description": "Tool name",
							"example":     "nmap",
						},
						"arguments": map[string]interface{}{
							"type":        "object",
							"description": "Tool Parameters (key pairs), depending on the tool definition",
							"example": map[string]interface{}{
								"target": "192.168.1.1",
								"ports":  "80,443",
							},
						},
					},
				},
				"MCPResponse": map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"id": map[string]interface{}{
							"description": "Message ID (same as id in request)",
							"oneOf": []map[string]interface{}{
								{"type": "string"},
								{"type": "number"},
								{"type": "null"},
							},
						},
						"result": map[string]interface{}{
							"description": "Methodological implementation results (JSON objects), structure dependent on the method of call",
							"type":        "object",
						},
						"error": map[string]interface{}{
							"type":        "object",
							"description": "Error message (if enforcement fails)",
							"properties": map[string]interface{}{
								"code": map[string]interface{}{
									"type":        "integer",
									"description": "Error Code",
									"example":     -32600,
								},
								"message": map[string]interface{}{
									"type":        "string",
									"description": "Error message",
									"example":     "Invalid Request",
								},
								"data": map[string]interface{}{
									"description": "Error Details (optional)",
								},
							},
						},
						"jsonrpc": map[string]interface{}{
							"type":        "string",
							"description": "JSON-RPC version",
							"example":     "2.0",
						},
					},
				},
			},
		},
		"security": []map[string]interface{}{
			{
				"bearerAuth": []string{},
			},
		},
		"paths": map[string]interface{}{
			"/api/auth/login": map[string]interface{}{
				"post": map[string]interface{}{
					"tags":        []string{"Auth"},
					"summary":     "User login",
					"description": "Use password login to obtain authentication of Token",
					"operationId": "login",
					"security":    []map[string]interface{}{},
					"requestBody": map[string]interface{}{
						"required": true,
						"content": map[string]interface{}{
							"application/json": map[string]interface{}{
								"schema": map[string]interface{}{
									"$ref": "#/components/schemas/LoginRequest",
								},
							},
						},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Login successful",
							"content": map[string]interface{}{
								"application/json": map[string]interface{}{
									"schema": map[string]interface{}{
										"$ref": "#/components/schemas/LoginResponse",
									},
								},
							},
						},
						"401": map[string]interface{}{
							"description": "Invalid password",
						},
					},
				},
			},
			"/api/auth/logout": map[string]interface{}{
				"post": map[string]interface{}{
					"tags":        []string{"Auth"},
					"summary":     "User logout",
					"description": "Logout the current session to disable Token",
					"operationId": "logout",
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Logout successful",
							"content": map[string]interface{}{
								"application/json": map[string]interface{}{
									"schema": map[string]interface{}{
										"type": "object",
										"properties": map[string]interface{}{
											"message": map[string]interface{}{
												"type":    "string",
												"example": "Signed out",
											},
										},
									},
								},
							},
						},
						"401": map[string]interface{}{
							"description": "Unauthorized",
						},
					},
				},
			},
			"/api/auth/change-password": map[string]interface{}{
				"post": map[string]interface{}{
					"tags":        []string{"Auth"},
					"summary":     "Change password",
					"description": "Modify login password, all sessions will expire after change",
					"operationId": "changePassword",
					"requestBody": map[string]interface{}{
						"required": true,
						"content": map[string]interface{}{
							"application/json": map[string]interface{}{
								"schema": map[string]interface{}{
									"$ref": "#/components/schemas/ChangePasswordRequest",
								},
							},
						},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Password changed successfully",
							"content": map[string]interface{}{
								"application/json": map[string]interface{}{
									"schema": map[string]interface{}{
										"type": "object",
										"properties": map[string]interface{}{
											"message": map[string]interface{}{
												"type":    "string",
												"example": "Password updated, re-entry with new password",
											},
										},
									},
								},
							},
						},
						"400": map[string]interface{}{
							"description": "Bad request",
						},
						"401": map[string]interface{}{
							"description": "Unauthorized",
						},
					},
				},
			},
			"/api/auth/validate": map[string]interface{}{
				"get": map[string]interface{}{
					"tags":        []string{"Auth"},
					"summary":     "Validate Token",
					"description": "Verify the validity of the current Token",
					"operationId": "validateToken",
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Token valid",
							"content": map[string]interface{}{
								"application/json": map[string]interface{}{
									"schema": map[string]interface{}{
										"type": "object",
										"properties": map[string]interface{}{
											"token": map[string]interface{}{
												"type":        "string",
												"description": "Token",
											},
											"expires_at": map[string]interface{}{
												"type":        "string",
												"format":      "date-time",
												"description": "Expiry Time",
											},
										},
									},
								},
							},
						},
						"401": map[string]interface{}{
							"description": "Token invalid or expired",
						},
					},
				},
			},
			"/api/conversations": map[string]interface{}{
				"post": map[string]interface{}{
					"tags":        []string{"Conversation Management"},
					"summary":     "Conversation created",
					"description": "Create a new security test dialogue.\n** Important note**:\n• Dialogues created** to be immediately stored in the database**\n- ✅ Front-end page meeting**Auto Refresh**Show New Dialog\n- ** Dialogue with the front-end**\n** Two ways to create dialogue**:\n**Modalities 1 (Recommendations) : ** Direct Use `/api/eino-agent` Send Message, **Not provided** `conversationId` Parameters, System automatically creates new conversations and sends messages.It's the easiest way., One step to create and send.\n**Modalities 2: ** Create an empty dialogue with this peer first, Then use the returned one. `conversationId` Call `/api/eino-agent` Send Message.Applies to the need to create dialogue first, Send the message later..\n** Example:**\n```json\n{\n  \"title\": \"Web Application of security tests\"\n}\n```",
					"operationId": "createConversation",
					"requestBody": map[string]interface{}{
						"required": true,
						"content": map[string]interface{}{
							"application/json": map[string]interface{}{
								"schema": map[string]interface{}{
									"$ref": "#/components/schemas/CreateConversationRequest",
								},
							},
						},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Conversation created",
							"content": map[string]interface{}{
								"application/json": map[string]interface{}{
									"schema": map[string]interface{}{
										"$ref": "#/components/schemas/Conversation",
									},
								},
							},
						},
						"400": map[string]interface{}{
							"description": "Bad request",
						},
						"401": map[string]interface{}{
							"description": "Unauthorized, valid Token required",
						},
						"500": map[string]interface{}{
							"description": "Internal server error",
						},
					},
				},
				"get": map[string]interface{}{
					"tags":        []string{"Conversation Management"},
					"summary":     "List conversations",
					"description": "Get a dialogue list, support page breaks and search",
					"operationId": "listConversations",
					"parameters": []map[string]interface{}{
						{
							"name":        "limit",
							"in":          "query",
							"required":    false,
							"description": "Number of returns limited",
							"schema": map[string]interface{}{
								"type":    "integer",
								"default": 50,
								"minimum": 1,
								"maximum": 100,
							},
						},
						{
							"name":        "offset",
							"in":          "query",
							"required":    false,
							"description": "Offset",
							"schema": map[string]interface{}{
								"type":    "integer",
								"default": 0,
								"minimum": 0,
							},
						},
						{
							"name":        "search",
							"in":          "query",
							"required":    false,
							"description": "Search keywords",
							"schema": map[string]interface{}{
								"type": "string",
							},
						},
						{
							"name":        "project_id",
							"in":          "query",
							"required":    false,
							"description": "Filter by Project; Pass __none__ Dialogue indicating only unbound items",
							"schema": map[string]interface{}{
								"type": "string",
							},
						},
						{
							"name":        "sort_by",
							"in":          "query",
							"required":    false,
							"description": "Sorted fields: updated_at (default) or created_at",
							"schema": map[string]interface{}{
								"type": "string",
								"enum": []string{"updated_at", "created_at"},
							},
						},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Success",
							"content": map[string]interface{}{
								"application/json": map[string]interface{}{
									"schema": map[string]interface{}{
										"type": "array",
										"items": map[string]interface{}{
											"$ref": "#/components/schemas/Conversation",
										},
									},
								},
							},
						},
						"401": map[string]interface{}{
							"description": "Unauthorized, valid Token required",
						},
					},
				},
			},
			"/api/conversations/{id}": map[string]interface{}{
				"get": map[string]interface{}{
					"tags":        []string{"Conversation Management"},
					"summary":     "Get conversation detail",
					"description": "Access to detailed information on the designated dialogue, including dialogue information and newslists",
					"operationId": "getConversation",
					"parameters": []map[string]interface{}{
						{
							"name":        "id",
							"in":          "path",
							"required":    true,
							"description": "Conversation ID",
							"schema": map[string]interface{}{
								"type": "string",
							},
						},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Success",
							"content": map[string]interface{}{
								"application/json": map[string]interface{}{
									"schema": map[string]interface{}{
										"$ref": "#/components/schemas/ConversationDetail",
									},
								},
							},
						},
						"404": map[string]interface{}{
							"description": "Conversation not found",
						},
						"401": map[string]interface{}{
							"description": "Unauthorized, valid Token required",
						},
					},
				},
				"put": map[string]interface{}{
					"tags":        []string{"Conversation Management"},
					"summary":     "Update conversation",
					"description": "Update dialogue title",
					"operationId": "updateConversation",
					"parameters": []map[string]interface{}{
						{
							"name":        "id",
							"in":          "path",
							"required":    true,
							"description": "Conversation ID",
							"schema": map[string]interface{}{
								"type": "string",
							},
						},
					},
					"requestBody": map[string]interface{}{
						"required": true,
						"content": map[string]interface{}{
							"application/json": map[string]interface{}{
								"schema": map[string]interface{}{
									"$ref": "#/components/schemas/UpdateConversationRequest",
								},
							},
						},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Updated successfully",
							"content": map[string]interface{}{
								"application/json": map[string]interface{}{
									"schema": map[string]interface{}{
										"$ref": "#/components/schemas/Conversation",
									},
								},
							},
						},
						"400": map[string]interface{}{
							"description": "Bad request",
						},
						"404": map[string]interface{}{
							"description": "Conversation not found",
						},
						"401": map[string]interface{}{
							"description": "Unauthorized, valid Token required",
						},
					},
				},
				"delete": map[string]interface{}{
					"tags":        []string{"Conversation Management"},
					"summary":     "Conversation deleted",
					"description": "Delete the designated dialogue and its session data (message, attack chain, etc.).** The gap record will be kept** and only the link to the session will be removed.** This operation cannot be resumed**.",
					"operationId": "deleteConversation",
					"parameters": []map[string]interface{}{
						{
							"name":        "id",
							"in":          "path",
							"required":    true,
							"description": "Conversation ID",
							"schema": map[string]interface{}{
								"type": "string",
							},
						},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Deleted successfully",
							"content": map[string]interface{}{
								"application/json": map[string]interface{}{
									"schema": map[string]interface{}{
										"type": "object",
										"properties": map[string]interface{}{
											"message": map[string]interface{}{
												"type":        "string",
												"description": "Success Message",
												"example":     "Deleted successfully",
											},
										},
									},
								},
							},
						},
						"404": map[string]interface{}{
							"description": "Conversation not found",
						},
						"401": map[string]interface{}{
							"description": "Unauthorized, valid Token required",
						},
						"500": map[string]interface{}{
							"description": "Internal server error",
						},
					},
				},
			},
			"/api/conversations/{id}/project": map[string]interface{}{
				"put": map[string]interface{}{
					"tags":        []string{"Conversation Management"},
					"summary":     "Sets the item for the dialogue",
					"description": "Bind or delink dialogue to projects for sharing the fact sheet",
					"operationId": "setConversationProject",
					"parameters": []map[string]interface{}{
						{
							"name": "id", "in": "path", "required": true,
							"description": "Conversation ID",
							"schema":      map[string]interface{}{"type": "string"},
						},
					},
					"requestBody": map[string]interface{}{
						"required": true,
						"content": map[string]interface{}{
							"application/json": map[string]interface{}{
								"schema": map[string]interface{}{
									"$ref": "#/components/schemas/SetConversationProjectRequest",
								},
							},
						},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{"description": "Set successfully"},
						"400": map[string]interface{}{"description": "Project does not exist or parameter error"},
						"404": map[string]interface{}{"description": "Conversation not found"},
						"401": map[string]interface{}{"description": "Unauthorized"},
					},
				},
			},
			"/api/conversations/{id}/results": map[string]interface{}{
				"get": map[string]interface{}{
					"tags":        []string{"Conversation Management"},
					"summary":     "Get conversation result",
					"description": "Access to the results of the implementation of the designated dialogue, including information, gaps and implementation results",
					"operationId": "getConversationResults",
					"parameters": []map[string]interface{}{
						{
							"name":        "id",
							"in":          "path",
							"required":    true,
							"description": "Conversation ID",
							"schema": map[string]interface{}{
								"type": "string",
							},
						},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Success",
							"content": map[string]interface{}{
								"application/json": map[string]interface{}{
									"schema": map[string]interface{}{
										"$ref": "#/components/schemas/ConversationResults",
									},
								},
							},
						},
						"404": map[string]interface{}{
							"description": "Conversation or result not found",
						},
						"401": map[string]interface{}{
							"description": "Unauthorized, valid Token required",
						},
					},
				},
			},
			"/api/eino-agent": map[string]interface{}{
				"post": map[string]interface{}{
					"tags":        []string{"Conversation Interaction"},
					"summary":     "Send messages and get AI responses (Eino ADK Single Agent, non-flowing)",
					"description": "Send a message to the AI and return a non-streaming reply through the Eino single-agent MCP tool chain. Independent of multi_agent.enabled; compatible eino_skills/eino_middleware settings still apply. Supports webshellConnectionId, roles and attachments.",
					"operationId": "sendMessageEinoSingleAgent",
					"requestBody": map[string]interface{}{
						"required": true,
						"content": map[string]interface{}{
							"application/json": map[string]interface{}{
								"schema": map[string]interface{}{
									"type": "object",
									"properties": map[string]interface{}{
										"message":              map[string]interface{}{"type": "string"},
										"conversationId":       map[string]interface{}{"type": "string"},
										"role":                 map[string]interface{}{"type": "string"},
										"webshellConnectionId": map[string]interface{}{"type": "string"},
										"finalization":         finalizationRequestSchema,
									},
									"required": []string{"message"},
								},
							},
						},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Success.Only finalized=true Expression of successful final response; finalized=false when response Not completed/Interruption description.",
							"content": map[string]interface{}{
								"application/json": map[string]interface{}{
									"schema": map[string]interface{}{"$ref": "#/components/schemas/AgentChatResponse"},
								},
							},
						},
						"400": map[string]interface{}{"description": "Invalid parameters"},
						"401": map[string]interface{}{"description": "Unauthorized"},
						"500": map[string]interface{}{"description": "Execution failed"},
					},
				},
			},
			"/api/eino-agent/stream": map[string]interface{}{
				"post": map[string]interface{}{
					"tags":        []string{"Conversation Interaction"},
					"summary":     "Send messages and get AI responses (Eino ADK Single Agent, SSE)",
					"description": "Send a message and receive SSE events through the Eino single-agent ADK, independently of multi_agent.enabled. Events include tool_call/response_delta/thinking. response_start/response_delta are provisional; only type=response with data.finalized=true denotes a successful final reply. Missing completed execution evidence may trigger finalization_auto_continue, which resumes from the existing trace without injected instructions. With data.finalized=false, message explains the incomplete or blocked result.",
					"operationId": "sendMessageEinoSingleAgentStream",
					"requestBody": map[string]interface{}{
						"required": true,
						"content": map[string]interface{}{
							"application/json": map[string]interface{}{
								"schema": map[string]interface{}{
									"type": "object",
									"properties": map[string]interface{}{
										"message":              map[string]interface{}{"type": "string"},
										"conversationId":       map[string]interface{}{"type": "string"},
										"role":                 map[string]interface{}{"type": "string"},
										"webshellConnectionId": map[string]interface{}{"type": "string"},
										"finalization":         finalizationRequestSchema,
									},
									"required": []string{"message"},
								},
							},
						},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "text/event-stream（SSE）",
							"content": map[string]interface{}{
								"text/event-stream": map[string]interface{}{
									"schema": map[string]interface{}{
										"type":        "string",
										"description": "SSE Stream.Final response Events data Organisation finalized, finalizable, status, completionReason, evidenceVerified, evidenceRefs, pendingExecutionIds, missingChecks; Process event may contain finalization_auto_continue.",
									},
								},
							},
						},
						"401": map[string]interface{}{"description": "Unauthorized"},
					},
				},
			},
			"/api/multi-agent": map[string]interface{}{
				"post": map[string]interface{}{
					"tags":        []string{"Conversation Interaction"},
					"summary":     "Send messages and get AI responses (Eino multi-agent, non-flowing)",
					"description": "and `POST /api/eino-agent` Same request, But by **CloudWeGo Eino** Multiple proxy execution.Organisation `orchestration` (`deep` | `plan_execute` | `supervisor`) Assign, Default as `deep`.**Preconditions**: `multi_agent.enabled: true`; Back when not enabled 404 JSON.Support `webshellConnectionId`.",
					"operationId": "sendMessageMultiAgent",
					"requestBody": map[string]interface{}{
						"required": true,
						"content": map[string]interface{}{
							"application/json": map[string]interface{}{
								"schema": map[string]interface{}{
									"type": "object",
									"properties": map[string]interface{}{
										"message": map[string]interface{}{
											"type":        "string",
											"description": "Message to send (required)",
										},
										"conversationId": map[string]interface{}{
											"type":        "string",
											"description": "Dialogue ID (optional, new if not available)",
										},
										"role": map[string]interface{}{
											"type":        "string",
											"description": "Role Name (optional)",
										},
										"webshellConnectionId": map[string]interface{}{
											"type":        "string",
											"description": "WebShell Connect ID (optional, consistent with Eino single/multi-agent flow behaviour)",
										},
										"finalization": finalizationRequestSchema,
										"orchestration": map[string]interface{}{
											"type":        "string",
											"description": "Eino Prearranged: deep | plan_execute | supervisor; Default deep",
											"enum":        []string{"deep", "plan_execute", "supervisor"},
										},
									},
									"required": []string{"message"},
								},
							},
						},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Success.Only finalized=true Expression of successful final response; finalized=false when response Not completed/Interruption description.",
							"content": map[string]interface{}{
								"application/json": map[string]interface{}{
									"schema": map[string]interface{}{"$ref": "#/components/schemas/AgentChatResponse"},
								},
							},
						},
						"400": map[string]interface{}{"description": "Invalid parameters"},
						"401": map[string]interface{}{"description": "Unauthorized"},
						"404": map[string]interface{}{"description": "Multiple proxy not enabled or dialogue does not exist"},
						"500": map[string]interface{}{"description": "Execution failed"},
					},
				},
			},
			"/api/multi-agent/stream": map[string]interface{}{
				"post": map[string]interface{}{
					"tags":        []string{"Conversation Interaction"},
					"summary":     "Send messages and get AI responses (Eino Multiple Agent, SSE)",
					"description": "and `POST /api/eino-agent/stream` Similar; By Eino Multiple proxy execution.`orchestration` Assign deep / plan_execute / supervisor, Default deep.`response_start` / `response_delta` Only candidates./Process Output; Only `type: response` and `data.finalized=true` That means we're on our way..Missing completed Possible first delivery of evidence `finalization_auto_continue`, Indicates that the service is based on existing trace No re-entry..**Preconditions**: `multi_agent.enabled: true`; When not enabled SSE The first entry in the article reads `type: error` Pick up. `done`.Support `webshellConnectionId`.",
					"operationId": "sendMessageMultiAgentStream",
					"requestBody": map[string]interface{}{
						"required": true,
						"content": map[string]interface{}{
							"application/json": map[string]interface{}{
								"schema": map[string]interface{}{
									"type": "object",
									"properties": map[string]interface{}{
										"message":              map[string]interface{}{"type": "string"},
										"conversationId":       map[string]interface{}{"type": "string"},
										"role":                 map[string]interface{}{"type": "string"},
										"webshellConnectionId": map[string]interface{}{"type": "string"},
										"finalization":         finalizationRequestSchema,
										"orchestration": map[string]interface{}{
											"type":        "string",
											"description": "deep | plan_execute | supervisor; Default deep",
											"enum":        []string{"deep", "plan_execute", "supervisor"},
										},
									},
									"required": []string{"message"},
								},
							},
						},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "text/event-stream（SSE）",
							"content": map[string]interface{}{
								"text/event-stream": map[string]interface{}{
									"schema": map[string]interface{}{
										"type":        "string",
										"description": "SSE Stream.Final response Events data Organisation finalized, finalizable, status, completionReason, evidenceVerified, evidenceRefs, pendingExecutionIds, missingChecks; Process event may contain finalization_auto_continue.",
									},
								},
							},
						},
						"401": map[string]interface{}{"description": "Unauthorized"},
					},
				},
			},
			"/api/agent-loop/cancel": map[string]interface{}{
				"post": map[string]interface{}{
					"tags":        []string{"Conversation Interaction"},
					"summary":     "Cancel Task",
					"description": "Cancel an active Agent Loop",
					"operationId": "cancelAgentLoop",
					"requestBody": map[string]interface{}{
						"required": true,
						"content": map[string]interface{}{
							"application/json": map[string]interface{}{
								"schema": map[string]interface{}{
									"$ref": "#/components/schemas/CancelAgentLoopRequest",
								},
							},
						},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Cancel request submitted",
							"content": map[string]interface{}{
								"application/json": map[string]interface{}{
									"schema": map[string]interface{}{
										"type": "object",
										"properties": map[string]interface{}{
											"status": map[string]interface{}{
												"type":    "string",
												"example": "cancelling",
											},
											"conversationId": map[string]interface{}{
												"type":        "string",
												"description": "Conversation ID",
											},
											"message": map[string]interface{}{
												"type":    "string",
												"example": "A request for cancellation has been submitted and the task will cease after the completion of the current steps.",
											},
										},
									},
								},
							},
						},
						"404": map[string]interface{}{
							"description": "No running task found",
						},
						"401": map[string]interface{}{
							"description": "Unauthorized",
						},
					},
				},
			},
			"/api/agent-loop/tasks": map[string]interface{}{
				"get": map[string]interface{}{
					"tags":        []string{"Conversation Interaction"},
					"summary":     "List running tasks",
					"description": "Fetch all running Agent Loop jobs",
					"operationId": "listAgentTasks",
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Success",
							"content": map[string]interface{}{
								"application/json": map[string]interface{}{
									"schema": map[string]interface{}{
										"type": "object",
										"properties": map[string]interface{}{
											"tasks": map[string]interface{}{
												"type":        "array",
												"description": "Task list",
												"items": map[string]interface{}{
													"$ref": "#/components/schemas/AgentTask",
												},
											},
										},
									},
								},
							},
						},
						"401": map[string]interface{}{
							"description": "Unauthorized",
						},
					},
				},
			},
			"/api/agent-loop/tasks/completed": map[string]interface{}{
				"get": map[string]interface{}{
					"tags":        []string{"Conversation Interaction"},
					"summary":     "List completed tasks",
					"description": "Fetch recently completed Agent Loop mission history",
					"operationId": "listCompletedTasks",
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Success",
							"content": map[string]interface{}{
								"application/json": map[string]interface{}{
									"schema": map[string]interface{}{
										"type": "object",
										"properties": map[string]interface{}{
											"tasks": map[string]interface{}{
												"type":        "array",
												"description": "Completed tasks",
												"items": map[string]interface{}{
													"$ref": "#/components/schemas/AgentTask",
												},
											},
										},
									},
								},
							},
						},
						"401": map[string]interface{}{
							"description": "Unauthorized",
						},
					},
				},
			},
			"/api/batch-tasks": map[string]interface{}{
				"post": map[string]interface{}{
					"tags":        []string{"Batch Task"},
					"summary":     "Batch task queue created",
					"description": "Create a batch queue containing multiple tasks",
					"operationId": "createBatchQueue",
					"requestBody": map[string]interface{}{
						"required": true,
						"content": map[string]interface{}{
							"application/json": map[string]interface{}{
								"schema": map[string]interface{}{
									"$ref": "#/components/schemas/BatchTaskRequest",
								},
							},
						},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Created successfully",
							"content": map[string]interface{}{
								"application/json": map[string]interface{}{
									"schema": map[string]interface{}{
										"type": "object",
										"properties": map[string]interface{}{
											"queueId": map[string]interface{}{
												"type":        "string",
												"description": "Queue ID",
											},
											"queue": map[string]interface{}{
												"$ref": "#/components/schemas/BatchQueue",
											},
											"started": map[string]interface{}{
												"type":        "boolean",
												"description": "Implementation initiated immediately",
											},
										},
									},
								},
							},
						},
						"400": map[string]interface{}{
							"description": "Bad request",
						},
						"401": map[string]interface{}{
							"description": "Unauthorized",
						},
					},
				},
				"get": map[string]interface{}{
					"tags":        []string{"Batch Task"},
					"summary":     "List batch task queues",
					"description": "Fetch all batch queues",
					"operationId": "listBatchQueues",
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Success",
							"content": map[string]interface{}{
								"application/json": map[string]interface{}{
									"schema": map[string]interface{}{
										"type": "object",
										"properties": map[string]interface{}{
											"queues": map[string]interface{}{
												"type":        "array",
												"description": "Queue List",
												"items": map[string]interface{}{
													"$ref": "#/components/schemas/BatchQueue",
												},
											},
										},
									},
								},
							},
						},
						"401": map[string]interface{}{
							"description": "Unauthorized",
						},
					},
				},
			},
			"/api/batch-tasks/{queueId}": map[string]interface{}{
				"get": map[string]interface{}{
					"tags":        []string{"Batch Task"},
					"summary":     "Get batch task queue",
					"description": "Fetch details of the specified batch queue",
					"operationId": "getBatchQueue",
					"parameters": []map[string]interface{}{
						{
							"name":        "queueId",
							"in":          "path",
							"required":    true,
							"description": "Queue ID",
							"schema": map[string]interface{}{
								"type": "string",
							},
						},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Success",
							"content": map[string]interface{}{
								"application/json": map[string]interface{}{
									"schema": map[string]interface{}{
										"$ref": "#/components/schemas/BatchQueue",
									},
								},
							},
						},
						"404": map[string]interface{}{
							"description": "Queue not found",
						},
						"401": map[string]interface{}{
							"description": "Unauthorized",
						},
					},
				},
				"delete": map[string]interface{}{
					"tags":        []string{"Batch Task"},
					"summary":     "Batch task queue deleted",
					"description": "Delete the specified batch queue",
					"operationId": "deleteBatchQueue",
					"parameters": []map[string]interface{}{
						{
							"name":        "queueId",
							"in":          "path",
							"required":    true,
							"description": "Queue ID",
							"schema": map[string]interface{}{
								"type": "string",
							},
						},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Deleted successfully",
						},
						"404": map[string]interface{}{
							"description": "Queue not found",
						},
						"401": map[string]interface{}{
							"description": "Unauthorized",
						},
					},
				},
			},
			"/api/batch-tasks/{queueId}/start": map[string]interface{}{
				"post": map[string]interface{}{
					"tags":        []string{"Batch Task"},
					"summary":     "Batch task queue started",
					"description": "Start a batch of tasks in the queue",
					"operationId": "startBatchQueue",
					"parameters": []map[string]interface{}{
						{
							"name":        "queueId",
							"in":          "path",
							"required":    true,
							"description": "Queue ID",
							"schema": map[string]interface{}{
								"type": "string",
							},
						},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Started successfully",
						},
						"404": map[string]interface{}{
							"description": "Queue not found",
						},
						"401": map[string]interface{}{
							"description": "Unauthorized",
						},
					},
				},
			},
			"/api/batch-tasks/{queueId}/pause": map[string]interface{}{
				"post": map[string]interface{}{
					"tags":        []string{"Batch Task"},
					"summary":     "Batch task queue paused",
					"description": "Pause the ongoing batch queue",
					"operationId": "pauseBatchQueue",
					"parameters": []map[string]interface{}{
						{
							"name":        "queueId",
							"in":          "path",
							"required":    true,
							"description": "Queue ID",
							"schema": map[string]interface{}{
								"type": "string",
							},
						},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Paused successfully",
						},
						"404": map[string]interface{}{
							"description": "Queue not found",
						},
						"401": map[string]interface{}{
							"description": "Unauthorized",
						},
					},
				},
			},
			"/api/batch-tasks/{queueId}/tasks": map[string]interface{}{
				"post": map[string]interface{}{
					"tags":        []string{"Batch Task"},
					"summary":     "Add task to queue",
					"description": "Adds a new task to the batch task queue. The task will be added to the end of the queue and executed in the queue order. Each task will create an independent dialogue to support full status tracking.\n** Task format**:\nThe job content is a string describing the security test tasks to be performed. For example:\n- \"Scanning SQLs from http://example.com to insert a loophole.\"\n- 192.168.1.1 Port scan.\n- \"Specify an XSS loophole at https://target.com.\"\n** Use of examples**:\n```json\n{\n  \"task\": \"Scanning SQL leaks at http://example.com\"\n}\n```",
					"operationId": "addBatchTask",
					"parameters": []map[string]interface{}{
						{
							"name":        "queueId",
							"in":          "path",
							"required":    true,
							"description": "Queue ID",
							"schema": map[string]interface{}{
								"type": "string",
							},
						},
					},
					"requestBody": map[string]interface{}{
						"required": true,
						"content": map[string]interface{}{
							"application/json": map[string]interface{}{
								"schema": map[string]interface{}{
									"type":     "object",
									"required": []string{"task"},
									"properties": map[string]interface{}{
										"task": map[string]interface{}{
											"type":        "string",
											"description": "Mission content, describing the security test tasks to be performed (required)",
											"example":     "Scan SQL for leaks at http://example.com",
										},
									},
								},
								"examples": map[string]interface{}{
									"sqlInjection": map[string]interface{}{
										"summary":     "SQL injection scan",
										"description": "SQL-scan target site plugged in.",
										"value": map[string]interface{}{
											"task": "Scan SQL for leaks at http://example.com",
										},
									},
									"portScan": map[string]interface{}{
										"summary":     "Port scan",
										"description": "Port scan of target IP",
										"value": map[string]interface{}{
											"task": "192.168.1.1 Port scanning",
										},
									},
								},
							},
						},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Added successfully",
							"content": map[string]interface{}{
								"application/json": map[string]interface{}{
									"schema": map[string]interface{}{
										"type": "object",
										"properties": map[string]interface{}{
											"taskId": map[string]interface{}{
												"type":        "string",
												"description": "New Task ID",
											},
											"message": map[string]interface{}{
												"type":        "string",
												"description": "Success Message",
												"example":     "Task added to queue",
											},
										},
									},
								},
							},
						},
						"400": map[string]interface{}{
							"description": "Bad request (e.g. task is empty)",
						},
						"404": map[string]interface{}{
							"description": "Queue not found",
						},
						"401": map[string]interface{}{
							"description": "Unauthorized",
						},
					},
				},
			},
			"/api/batch-tasks/{queueId}/tasks/{taskId}": map[string]interface{}{
				"put": map[string]interface{}{
					"tags":        []string{"Batch Task"},
					"summary":     "Update batch task",
					"description": "Update specified tasks in the batch queue",
					"operationId": "updateBatchTask",
					"parameters": []map[string]interface{}{
						{
							"name":        "queueId",
							"in":          "path",
							"required":    true,
							"description": "Queue ID",
							"schema": map[string]interface{}{
								"type": "string",
							},
						},
						{
							"name":        "taskId",
							"in":          "path",
							"required":    true,
							"description": "Task ID",
							"schema": map[string]interface{}{
								"type": "string",
							},
						},
					},
					"requestBody": map[string]interface{}{
						"required": true,
						"content": map[string]interface{}{
							"application/json": map[string]interface{}{
								"schema": map[string]interface{}{
									"type": "object",
									"properties": map[string]interface{}{
										"task": map[string]interface{}{
											"type":        "string",
											"description": "Task content",
										},
									},
								},
							},
						},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Updated successfully",
						},
						"404": map[string]interface{}{
							"description": "Task not found",
						},
						"401": map[string]interface{}{
							"description": "Unauthorized",
						},
					},
				},
				"delete": map[string]interface{}{
					"tags":        []string{"Batch Task"},
					"summary":     "Delete batch task",
					"description": "Remove specified task from the batch queue",
					"operationId": "deleteBatchTask",
					"parameters": []map[string]interface{}{
						{
							"name":        "queueId",
							"in":          "path",
							"required":    true,
							"description": "Queue ID",
							"schema": map[string]interface{}{
								"type": "string",
							},
						},
						{
							"name":        "taskId",
							"in":          "path",
							"required":    true,
							"description": "Task ID",
							"schema": map[string]interface{}{
								"type": "string",
							},
						},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Deleted successfully",
						},
						"404": map[string]interface{}{
							"description": "Task not found",
						},
						"401": map[string]interface{}{
							"description": "Unauthorized",
						},
					},
				},
			},
			"/api/assets/import": map[string]interface{}{
				"post": map[string]interface{}{
					"tags":        []string{"Asset Management"},
					"summary":     "Import assets in bulk",
					"description": "Add or Press\"target + Port + Agreements\"To reset the assets..Received JSON, Not directly received XLSX/CSV Documentation; Most single times 100000 Article, requires asset:write permissions.",
					"operationId": "importAssets",
					"requestBody": map[string]interface{}{
						"required": true,
						"content": map[string]interface{}{
							"application/json": map[string]interface{}{
								"schema": map[string]interface{}{"$ref": "#/components/schemas/AssetImportRequest"},
							},
						},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Import completed",
							"content": map[string]interface{}{
								"application/json": map[string]interface{}{
									"schema": map[string]interface{}{"$ref": "#/components/schemas/AssetImportResult"},
								},
							},
						},
						"400": map[string]interface{}{"description": "Asset count or field validation failed"},
						"401": map[string]interface{}{"description": "Unauthorized"},
						"403": map[string]interface{}{"description": "Missing asset:write permission or access to the specified project"},
						"500": map[string]interface{}{"description": "Import transaction failed"},
					},
				},
			},
			"/api/projects": map[string]interface{}{
				"get": map[string]interface{}{
					"tags":        []string{"Project Management"},
					"summary":     "List projects",
					"operationId": "listProjects",
					"parameters": []map[string]interface{}{
						{"name": "status", "in": "query", "schema": map[string]interface{}{"type": "string", "enum": []string{"active", "archived"}}},
						{"name": "limit", "in": "query", "schema": map[string]interface{}{"type": "integer", "default": 200}},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{"description": "Project list"},
						"401": map[string]interface{}{"description": "Unauthorized"},
					},
				},
				"post": map[string]interface{}{
					"tags":        []string{"Project Management"},
					"summary":     "Create project",
					"operationId": "createProject",
					"requestBody": map[string]interface{}{
						"required": true,
						"content": map[string]interface{}{
							"application/json": map[string]interface{}{
								"schema": map[string]interface{}{
									"type": "object",
									"properties": map[string]interface{}{
										"name":        map[string]interface{}{"type": "string"},
										"description": map[string]interface{}{"type": "string"},
										"scope_json":  map[string]interface{}{"type": "string"},
									},
									"required": []string{"name"},
								},
							},
						},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{"description": "Created successfully"},
						"401": map[string]interface{}{"description": "Unauthorized"},
					},
				},
			},
			"/api/projects/{id}": map[string]interface{}{
				"get": map[string]interface{}{
					"tags": []string{"Project Management"}, "summary": "Get project", "operationId": "getProject",
					"parameters": []map[string]interface{}{
						{"name": "id", "in": "path", "required": true, "schema": map[string]interface{}{"type": "string"}},
					},
					"responses": map[string]interface{}{"200": map[string]interface{}{"description": "Project detail"}},
				},
				"put": map[string]interface{}{
					"tags": []string{"Project Management"}, "summary": "Update project", "operationId": "updateProject",
					"parameters": []map[string]interface{}{
						{"name": "id", "in": "path", "required": true, "schema": map[string]interface{}{"type": "string"}},
					},
					"responses": map[string]interface{}{"200": map[string]interface{}{"description": "Updated successfully"}},
				},
				"delete": map[string]interface{}{
					"tags": []string{"Project Management"}, "summary": "Delete project", "operationId": "deleteProject",
					"parameters": []map[string]interface{}{
						{"name": "id", "in": "path", "required": true, "schema": map[string]interface{}{"type": "string"}},
					},
					"responses": map[string]interface{}{"200": map[string]interface{}{"description": "Deleted successfully"}},
				},
			},
			"/api/projects/{id}/facts": map[string]interface{}{
				"get": map[string]interface{}{
					"tags": []string{"Project Management"}, "summary": "List or get fact by key", "operationId": "listProjectFacts",
					"parameters": []map[string]interface{}{
						{"name": "id", "in": "path", "required": true, "schema": map[string]interface{}{"type": "string"}},
						{"name": "fact_key", "in": "query", "schema": map[string]interface{}{"type": "string"}},
						{"name": "include_links", "in": "query", "schema": map[string]interface{}{"type": "boolean"}},
						{"name": "include_link_counts", "in": "query", "schema": map[string]interface{}{"type": "boolean"}},
					},
					"responses": map[string]interface{}{"200": map[string]interface{}{"description": "Fact list or single fact (may include link_counts / outgoing_links)"}},
				},
				"post": map[string]interface{}{
					"tags": []string{"Project Management"}, "summary": "Create/update fact", "operationId": "upsertProjectFactREST",
					"parameters": []map[string]interface{}{
						{"name": "id", "in": "path", "required": true, "schema": map[string]interface{}{"type": "string"}},
					},
					"requestBody": map[string]interface{}{
						"required": true,
						"content": map[string]interface{}{
							"application/json": map[string]interface{}{
								"schema": map[string]interface{}{
									"type": "object",
									"properties": map[string]interface{}{
										"fact_key": map[string]interface{}{"type": "string"},
										"summary":  map[string]interface{}{"type": "string"},
										"links": map[string]interface{}{
											"type": "array",
											"items": map[string]interface{}{
												"type": "object",
												"properties": map[string]interface{}{
													"to":   map[string]interface{}{"type": "string"},
													"type": map[string]interface{}{"type": "string"},
												},
											},
										},
										"links_text": map[string]interface{}{"type": "string", "description": "type: fact_key per line"},
									},
								},
							},
						},
					},
					"responses": map[string]interface{}{"200": map[string]interface{}{"description": "Success"}},
				},
			},
			"/api/projects/{id}/fact-graph": map[string]interface{}{
				"get": map[string]interface{}{
					"tags": []string{"Project Management"}, "summary": "Get project fact attack path graph", "operationId": "getProjectFactGraph",
					"parameters": []map[string]interface{}{
						{"name": "id", "in": "path", "required": true, "schema": map[string]interface{}{"type": "string"}},
						{"name": "view", "in": "query", "schema": map[string]interface{}{"type": "string", "enum": []string{"path", "full"}, "default": "path"}},
						{"name": "exclude_deprecated", "in": "query", "schema": map[string]interface{}{"type": "boolean", "default": true}},
					},
					"responses": map[string]interface{}{"200": map[string]interface{}{"description": "nodes + edges"}},
				},
			},
			"/api/projects/{id}/fact-edges": map[string]interface{}{
				"get": map[string]interface{}{
					"tags": []string{"Project Management"}, "summary": "List all project fact edges", "operationId": "listProjectFactEdges",
					"parameters": []map[string]interface{}{
						{"name": "id", "in": "path", "required": true, "schema": map[string]interface{}{"type": "string"}},
					},
					"responses": map[string]interface{}{"200": map[string]interface{}{"description": "Edge list"}},
				},
				"post": map[string]interface{}{
					"tags": []string{"Project Management"}, "summary": "Add fact edge", "operationId": "createProjectFactEdge",
					"parameters": []map[string]interface{}{
						{"name": "id", "in": "path", "required": true, "schema": map[string]interface{}{"type": "string"}},
					},
					"requestBody": map[string]interface{}{
						"required": true,
						"content": map[string]interface{}{
							"application/json": map[string]interface{}{
								"schema": map[string]interface{}{
									"type":     "object",
									"required": []string{"source_fact_key", "target_fact_key", "edge_type"},
									"properties": map[string]interface{}{
										"source_fact_key": map[string]interface{}{"type": "string"},
										"target_fact_key": map[string]interface{}{"type": "string"},
										"edge_type":       map[string]interface{}{"type": "string"},
										"confidence":      map[string]interface{}{"type": "string"},
									},
								},
							},
						},
					},
					"responses": map[string]interface{}{"200": map[string]interface{}{"description": "Edge created"}},
				},
			},
			"/api/projects/{id}/fact-edges/{edgeId}": map[string]interface{}{
				"delete": map[string]interface{}{
					"tags": []string{"Project Management"}, "summary": "Delete fact edge", "operationId": "deleteProjectFactEdge",
					"parameters": []map[string]interface{}{
						{"name": "id", "in": "path", "required": true, "schema": map[string]interface{}{"type": "string"}},
						{"name": "edgeId", "in": "path", "required": true, "schema": map[string]interface{}{"type": "string"}},
					},
					"responses": map[string]interface{}{"200": map[string]interface{}{"description": "Deleted successfully"}},
				},
			},
			"/api/projects/{id}/promote-attack-chain/{conversationId}": map[string]interface{}{
				"post": map[string]interface{}{
					"tags": []string{"Project Management"}, "summary": "Promote conversation attack chain to project fact graph", "operationId": "promoteAttackChainToProject",
					"parameters": []map[string]interface{}{
						{"name": "id", "in": "path", "required": true, "schema": map[string]interface{}{"type": "string"}},
						{"name": "conversationId", "in": "path", "required": true, "schema": map[string]interface{}{"type": "string"}},
					},
					"responses": map[string]interface{}{"200": map[string]interface{}{"description": "Promotion result (facts/edges/graph)"}},
				},
			},
			"/api/vulnerabilities": map[string]interface{}{
				"get": map[string]interface{}{
					"tags":        []string{"Vulnerability Management"},
					"summary":     "List vulnerabilities",
					"description": "Get a list of leaks, support page breaks and filters",
					"operationId": "listVulnerabilities",
					"parameters": []map[string]interface{}{
						{
							"name":        "limit",
							"in":          "query",
							"required":    false,
							"description": "Number per page",
							"schema": map[string]interface{}{
								"type":    "integer",
								"default": 20,
								"minimum": 1,
								"maximum": 100,
							},
						},
						{
							"name":        "offset",
							"in":          "query",
							"required":    false,
							"description": "Offset",
							"schema": map[string]interface{}{
								"type":    "integer",
								"default": 0,
								"minimum": 0,
							},
						},
						{
							"name":        "page",
							"in":          "query",
							"required":    false,
							"description": "Page number (and offset for one)",
							"schema": map[string]interface{}{
								"type":    "integer",
								"minimum": 1,
							},
						},
						{
							"name":        "id",
							"in":          "query",
							"required":    false,
							"description": "Vulnerability ID",
							"schema": map[string]interface{}{
								"type": "string",
							},
						},
						{
							"name":        "conversation_id",
							"in":          "query",
							"required":    false,
							"description": "Conversation ID",
							"schema": map[string]interface{}{
								"type": "string",
							},
						},
						{
							"name":        "project_id",
							"in":          "query",
							"required":    false,
							"description": "Item ID",
							"schema": map[string]interface{}{
								"type": "string",
							},
						},
						{
							"name":        "severity",
							"in":          "query",
							"required":    false,
							"description": "Severity",
							"schema": map[string]interface{}{
								"type": "string",
								"enum": []string{"critical", "high", "medium", "low", "info"},
							},
						},
						{
							"name":        "status",
							"in":          "query",
							"required":    false,
							"description": "Status",
							"schema": map[string]interface{}{
								"type": "string",
								"enum": []string{"open", "closed", "fixed"},
							},
						},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Success",
							"content": map[string]interface{}{
								"application/json": map[string]interface{}{
									"schema": map[string]interface{}{
										"$ref": "#/components/schemas/ListVulnerabilitiesResponse",
									},
								},
							},
						},
						"401": map[string]interface{}{
							"description": "Unauthorized",
						},
					},
				},
				"post": map[string]interface{}{
					"tags":        []string{"Vulnerability Management"},
					"summary":     "Create vulnerability",
					"description": "Create a new bug record",
					"operationId": "createVulnerability",
					"requestBody": map[string]interface{}{
						"required": true,
						"content": map[string]interface{}{
							"application/json": map[string]interface{}{
								"schema": map[string]interface{}{
									"$ref": "#/components/schemas/CreateVulnerabilityRequest",
								},
							},
						},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Created successfully",
							"content": map[string]interface{}{
								"application/json": map[string]interface{}{
									"schema": map[string]interface{}{
										"$ref": "#/components/schemas/Vulnerability",
									},
								},
							},
						},
						"400": map[string]interface{}{
							"description": "Bad request",
						},
						"401": map[string]interface{}{
							"description": "Unauthorized",
						},
					},
				},
			},
			"/api/vulnerabilities/stats": map[string]interface{}{
				"get": map[string]interface{}{
					"tags":        []string{"Vulnerability Management"},
					"summary":     "Get vulnerability statistics",
					"description": "Access to gap statistics",
					"operationId": "getVulnerabilityStats",
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Success",
							"content": map[string]interface{}{
								"application/json": map[string]interface{}{
									"schema": map[string]interface{}{
										"$ref": "#/components/schemas/VulnerabilityStats",
									},
								},
							},
						},
						"401": map[string]interface{}{
							"description": "Unauthorized",
						},
					},
				},
			},
			"/api/vulnerabilities/{id}": map[string]interface{}{
				"get": map[string]interface{}{
					"tags":        []string{"Vulnerability Management"},
					"summary":     "Get vulnerability",
					"description": "Get details about the specified bug",
					"operationId": "getVulnerability",
					"parameters": []map[string]interface{}{
						{
							"name":        "id",
							"in":          "path",
							"required":    true,
							"description": "Vulnerability ID",
							"schema": map[string]interface{}{
								"type": "string",
							},
						},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Success",
							"content": map[string]interface{}{
								"application/json": map[string]interface{}{
									"schema": map[string]interface{}{
										"$ref": "#/components/schemas/Vulnerability",
									},
								},
							},
						},
						"404": map[string]interface{}{
							"description": "There is no loophole.",
						},
						"401": map[string]interface{}{
							"description": "Unauthorized",
						},
					},
				},
				"put": map[string]interface{}{
					"tags":        []string{"Vulnerability Management"},
					"summary":     "Update vulnerability",
					"description": "Update Hole Info",
					"operationId": "updateVulnerability",
					"parameters": []map[string]interface{}{
						{
							"name":        "id",
							"in":          "path",
							"required":    true,
							"description": "Vulnerability ID",
							"schema": map[string]interface{}{
								"type": "string",
							},
						},
					},
					"requestBody": map[string]interface{}{
						"required": true,
						"content": map[string]interface{}{
							"application/json": map[string]interface{}{
								"schema": map[string]interface{}{
									"$ref": "#/components/schemas/UpdateVulnerabilityRequest",
								},
							},
						},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Updated successfully",
							"content": map[string]interface{}{
								"application/json": map[string]interface{}{
									"schema": map[string]interface{}{
										"$ref": "#/components/schemas/Vulnerability",
									},
								},
							},
						},
						"400": map[string]interface{}{
							"description": "Bad request",
						},
						"404": map[string]interface{}{
							"description": "There is no loophole.",
						},
						"401": map[string]interface{}{
							"description": "Unauthorized",
						},
					},
				},
				"delete": map[string]interface{}{
					"tags":        []string{"Vulnerability Management"},
					"summary":     "Delete vulnerabilities",
					"description": "Remove the specified loophole",
					"operationId": "deleteVulnerability",
					"parameters": []map[string]interface{}{
						{
							"name":        "id",
							"in":          "path",
							"required":    true,
							"description": "Vulnerability ID",
							"schema": map[string]interface{}{
								"type": "string",
							},
						},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Deleted successfully",
						},
						"404": map[string]interface{}{
							"description": "There is no loophole.",
						},
						"401": map[string]interface{}{
							"description": "Unauthorized",
						},
					},
				},
			},
			"/api/roles": map[string]interface{}{
				"get": map[string]interface{}{
					"tags":        []string{"Role Management"},
					"summary":     "List roles",
					"description": "Get all security test roles.",
					"operationId": "getRoles",
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Success",
							"content": map[string]interface{}{
								"application/json": map[string]interface{}{
									"schema": map[string]interface{}{
										"type": "object",
										"properties": map[string]interface{}{
											"roles": map[string]interface{}{
												"type":        "array",
												"description": "Role List",
												"items": map[string]interface{}{
													"$ref": "#/components/schemas/RoleConfig",
												},
											},
										},
									},
								},
							},
						},
						"401": map[string]interface{}{
							"description": "Unauthorized",
						},
					},
				},
				"post": map[string]interface{}{
					"tags":        []string{"Role Management"},
					"summary":     "Role created",
					"description": "Create a new security test role",
					"operationId": "createRole",
					"requestBody": map[string]interface{}{
						"required": true,
						"content": map[string]interface{}{
							"application/json": map[string]interface{}{
								"schema": map[string]interface{}{
									"$ref": "#/components/schemas/RoleConfig",
								},
							},
						},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Created successfully",
						},
						"400": map[string]interface{}{
							"description": "Bad request",
						},
						"401": map[string]interface{}{
							"description": "Unauthorized",
						},
					},
				},
			},
			"/api/roles/{name}": map[string]interface{}{
				"get": map[string]interface{}{
					"tags":        []string{"Role Management"},
					"summary":     "Get role",
					"description": "Get details about the given role",
					"operationId": "getRole",
					"parameters": []map[string]interface{}{
						{
							"name":        "name",
							"in":          "path",
							"required":    true,
							"description": "Role Name",
							"schema": map[string]interface{}{
								"type": "string",
							},
						},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Success",
							"content": map[string]interface{}{
								"application/json": map[string]interface{}{
									"schema": map[string]interface{}{
										"type": "object",
										"properties": map[string]interface{}{
											"role": map[string]interface{}{
												"$ref": "#/components/schemas/RoleConfig",
											},
										},
									},
								},
							},
						},
						"404": map[string]interface{}{
							"description": "Role not found",
						},
						"401": map[string]interface{}{
							"description": "Unauthorized",
						},
					},
				},
				"put": map[string]interface{}{
					"tags":        []string{"Role Management"},
					"summary":     "Role updated",
					"description": "Update configuration of assigned roles",
					"operationId": "updateRole",
					"parameters": []map[string]interface{}{
						{
							"name":        "name",
							"in":          "path",
							"required":    true,
							"description": "Role Name",
							"schema": map[string]interface{}{
								"type": "string",
							},
						},
					},
					"requestBody": map[string]interface{}{
						"required": true,
						"content": map[string]interface{}{
							"application/json": map[string]interface{}{
								"schema": map[string]interface{}{
									"$ref": "#/components/schemas/RoleConfig",
								},
							},
						},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Updated successfully",
						},
						"400": map[string]interface{}{
							"description": "Bad request",
						},
						"404": map[string]interface{}{
							"description": "Role not found",
						},
						"401": map[string]interface{}{
							"description": "Unauthorized",
						},
					},
				},
				"delete": map[string]interface{}{
					"tags":        []string{"Role Management"},
					"summary":     "Role deleted",
					"description": "Remove the specified role",
					"operationId": "deleteRole",
					"parameters": []map[string]interface{}{
						{
							"name":        "name",
							"in":          "path",
							"required":    true,
							"description": "Role Name",
							"schema": map[string]interface{}{
								"type": "string",
							},
						},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Deleted successfully",
						},
						"404": map[string]interface{}{
							"description": "Role not found",
						},
						"401": map[string]interface{}{
							"description": "Unauthorized",
						},
					},
				},
			},
			"/api/skills": map[string]interface{}{
				"get": map[string]interface{}{
					"tags":        []string{"Skills Management"},
					"summary":     "List Skills",
					"description": "Get all Skills lists, support page breaks and search",
					"operationId": "getSkills",
					"parameters": []map[string]interface{}{
						{
							"name":        "limit",
							"in":          "query",
							"required":    false,
							"description": "Number per page",
							"schema": map[string]interface{}{
								"type":    "integer",
								"default": 20,
							},
						},
						{
							"name":        "offset",
							"in":          "query",
							"required":    false,
							"description": "Offset",
							"schema": map[string]interface{}{
								"type":    "integer",
								"default": 0,
							},
						},
						{
							"name":        "search",
							"in":          "query",
							"required":    false,
							"description": "Search keywords",
							"schema": map[string]interface{}{
								"type": "string",
							},
						},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Success",
							"content": map[string]interface{}{
								"application/json": map[string]interface{}{
									"schema": map[string]interface{}{
										"type": "object",
										"properties": map[string]interface{}{
											"skills": map[string]interface{}{
												"type":        "array",
												"description": "Skills List",
												"items": map[string]interface{}{
													"$ref": "#/components/schemas/Skill",
												},
											},
											"total": map[string]interface{}{
												"type":        "integer",
												"description": "Total",
											},
										},
									},
								},
							},
						},
						"401": map[string]interface{}{
							"description": "Unauthorized",
						},
					},
				},
				"post": map[string]interface{}{
					"tags":        []string{"Skills Management"},
					"summary":     "Create Skill",
					"description": "Create a new Skill",
					"operationId": "createSkill",
					"requestBody": map[string]interface{}{
						"required": true,
						"content": map[string]interface{}{
							"application/json": map[string]interface{}{
								"schema": map[string]interface{}{
									"$ref": "#/components/schemas/CreateSkillRequest",
								},
							},
						},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Created successfully",
						},
						"400": map[string]interface{}{
							"description": "Bad request",
						},
						"401": map[string]interface{}{
							"description": "Unauthorized",
						},
					},
				},
			},
			"/api/skills/stats": map[string]interface{}{
				"get": map[string]interface{}{
					"tags":        []string{"Skills Management"},
					"summary":     "Get Skill statistics",
					"description": "Access Skill to statistical information",
					"operationId": "getSkillStats",
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Success",
							"content": map[string]interface{}{
								"application/json": map[string]interface{}{
									"schema": map[string]interface{}{
										"type":        "object",
										"description": "Statistical information",
									},
								},
							},
						},
						"401": map[string]interface{}{
							"description": "Unauthorized",
						},
					},
				},
				"delete": map[string]interface{}{
					"tags":        []string{"Skills Management"},
					"summary":     "Clear Skill statistics",
					"description": "Clear all Skill call statistics",
					"operationId": "clearSkillStats",
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Cleared.",
						},
						"401": map[string]interface{}{
							"description": "Unauthorized",
						},
					},
				},
			},
			"/api/skills/{name}": map[string]interface{}{
				"get": map[string]interface{}{
					"tags":        []string{"Skills Management"},
					"summary":     "Get Skill",
					"description": "Get specified Skill details",
					"operationId": "getSkill",
					"parameters": []map[string]interface{}{
						{
							"name":        "name",
							"in":          "path",
							"required":    true,
							"description": "Skill name",
							"schema": map[string]interface{}{
								"type": "string",
							},
						},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Success",
							"content": map[string]interface{}{
								"application/json": map[string]interface{}{
									"schema": map[string]interface{}{
										"$ref": "#/components/schemas/Skill",
									},
								},
							},
						},
						"404": map[string]interface{}{
							"description": "Skill doesn't exist.",
						},
						"401": map[string]interface{}{
							"description": "Unauthorized",
						},
					},
				},
				"put": map[string]interface{}{
					"tags":        []string{"Skills Management"},
					"summary":     "Update Skill",
					"description": "Update information about assigned Skill",
					"operationId": "updateSkill",
					"parameters": []map[string]interface{}{
						{
							"name":        "name",
							"in":          "path",
							"required":    true,
							"description": "Skill name",
							"schema": map[string]interface{}{
								"type": "string",
							},
						},
					},
					"requestBody": map[string]interface{}{
						"required": true,
						"content": map[string]interface{}{
							"application/json": map[string]interface{}{
								"schema": map[string]interface{}{
									"$ref": "#/components/schemas/UpdateSkillRequest",
								},
							},
						},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Updated successfully",
						},
						"400": map[string]interface{}{
							"description": "Bad request",
						},
						"404": map[string]interface{}{
							"description": "Skill doesn't exist.",
						},
						"401": map[string]interface{}{
							"description": "Unauthorized",
						},
					},
				},
				"delete": map[string]interface{}{
					"tags":        []string{"Skills Management"},
					"summary":     "Delete Skill",
					"description": "Delete Assigned Skill",
					"operationId": "deleteSkill",
					"parameters": []map[string]interface{}{
						{
							"name":        "name",
							"in":          "path",
							"required":    true,
							"description": "Skill name",
							"schema": map[string]interface{}{
								"type": "string",
							},
						},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Deleted successfully",
						},
						"404": map[string]interface{}{
							"description": "Skill doesn't exist.",
						},
						"401": map[string]interface{}{
							"description": "Unauthorized",
						},
					},
				},
			},
			"/api/skills/{name}/bound-roles": map[string]interface{}{
				"get": map[string]interface{}{
					"tags":        []string{"Skills Management"},
					"summary":     "Get bound roles",
					"description": "Fetch all roles to use the specified Skill",
					"operationId": "getSkillBoundRoles",
					"parameters": []map[string]interface{}{
						{
							"name":        "name",
							"in":          "path",
							"required":    true,
							"description": "Skill name",
							"schema": map[string]interface{}{
								"type": "string",
							},
						},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Success",
							"content": map[string]interface{}{
								"application/json": map[string]interface{}{
									"schema": map[string]interface{}{
										"type": "object",
										"properties": map[string]interface{}{
											"roles": map[string]interface{}{
												"type":        "array",
												"description": "Role List",
												"items": map[string]interface{}{
													"type": "string",
												},
											},
										},
									},
								},
							},
						},
						"404": map[string]interface{}{
							"description": "Skill doesn't exist.",
						},
						"401": map[string]interface{}{
							"description": "Unauthorized",
						},
					},
				},
			},
			"/api/skills/{name}/stats": map[string]interface{}{
				"delete": map[string]interface{}{
					"tags":        []string{"Skills Management"},
					"summary":     "Clear Skill statistics",
					"description": "Empty the call statistics for Skill",
					"operationId": "clearSkillStatsByName",
					"parameters": []map[string]interface{}{
						{
							"name":        "name",
							"in":          "path",
							"required":    true,
							"description": "Skill name",
							"schema": map[string]interface{}{
								"type": "string",
							},
						},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Cleared.",
						},
						"404": map[string]interface{}{
							"description": "Skill doesn't exist.",
						},
						"401": map[string]interface{}{
							"description": "Unauthorized",
						},
					},
				},
			},
			"/api/monitor": map[string]interface{}{
				"get": map[string]interface{}{
					"tags":        []string{"Monitoring"},
					"summary":     "Get monitoring info",
					"description": "Access tools to execute surveillance information, support page breaks and filters",
					"operationId": "monitor",
					"parameters": []map[string]interface{}{
						{
							"name":        "page",
							"in":          "query",
							"required":    false,
							"description": "Page",
							"schema": map[string]interface{}{
								"type":    "integer",
								"default": 1,
								"minimum": 1,
							},
						},
						{
							"name":        "page_size",
							"in":          "query",
							"required":    false,
							"description": "Number per page",
							"schema": map[string]interface{}{
								"type":    "integer",
								"default": 20,
								"minimum": 1,
								"maximum": 100,
							},
						},
						{
							"name":        "status",
							"in":          "query",
							"required":    false,
							"description": "Status filter",
							"schema": map[string]interface{}{
								"type": "string",
								"enum": []string{"queued", "running", "completed", "failed", "cancelled", "hard_timeout", "orphaned"},
							},
						},
						{
							"name":        "tool",
							"in":          "query",
							"required":    false,
							"description": "Toolname filter (support matching)",
							"schema": map[string]interface{}{
								"type": "string",
							},
						},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Success",
							"content": map[string]interface{}{
								"application/json": map[string]interface{}{
									"schema": map[string]interface{}{
										"$ref": "#/components/schemas/MonitorResponse",
									},
								},
							},
						},
						"401": map[string]interface{}{
							"description": "Unauthorized",
						},
					},
				},
			},
			"/api/monitor/execution/{id}": map[string]interface{}{
				"get": map[string]interface{}{
					"tags":        []string{"Monitoring"},
					"summary":     "Get execution records",
					"description": "Get detailed information on the specified execution record",
					"operationId": "getExecution",
					"parameters": []map[string]interface{}{
						{
							"name":        "id",
							"in":          "path",
							"required":    true,
							"description": "Execute ID",
							"schema": map[string]interface{}{
								"type": "string",
							},
						},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Success",
							"content": map[string]interface{}{
								"application/json": map[string]interface{}{
									"schema": map[string]interface{}{
										"$ref": "#/components/schemas/ToolExecution",
									},
								},
							},
						},
						"404": map[string]interface{}{
							"description": "No execution record exists",
						},
						"401": map[string]interface{}{
							"description": "Unauthorized",
						},
					},
				},
				"delete": map[string]interface{}{
					"tags":        []string{"Monitoring"},
					"summary":     "Delete execution",
					"description": "Delete the specified execution record",
					"operationId": "deleteExecution",
					"parameters": []map[string]interface{}{
						{
							"name":        "id",
							"in":          "path",
							"required":    true,
							"description": "Execute ID",
							"schema": map[string]interface{}{
								"type": "string",
							},
						},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Deleted successfully",
						},
						"404": map[string]interface{}{
							"description": "No execution record exists",
						},
						"401": map[string]interface{}{
							"description": "Unauthorized",
						},
					},
				},
			},
			"/api/monitor/execution/{id}/cancel": map[string]interface{}{
				"post": map[string]interface{}{
					"tags":        []string{"Monitoring"},
					"summary":     "Cancel ongoing tool execution",
					"description": "Under implementation within the current process MCP Tool Call Send context Cancel the signal.; Upper dialogue/A multistep mission can continue..Return if execution is completed or not operational within process 404.",
					"operationId": "cancelExecution",
					"parameters": []map[string]interface{}{
						{
							"name":        "id",
							"in":          "path",
							"required":    true,
							"description": "Execute ID",
							"schema": map[string]interface{}{
								"type": "string",
							},
						},
					},
					"requestBody": map[string]interface{}{
						"required": false,
						"content": map[string]interface{}{
							"application/json": map[string]interface{}{
								"schema": map[string]interface{}{
									"type": "object",
									"properties": map[string]interface{}{
										"note": map[string]interface{}{
											"type":        "string",
											"description": "Optional. Non-empty hours and tools have returned output merge to large model with a \" user termination statement\" header block to distinguish from the original command line",
										},
									},
								},
							},
						},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Termination signal sent",
						},
						"400": map[string]interface{}{
							"description": "Request is not legal, JSON.",
						},
						"404": map[string]interface{}{
							"description": "No ongoing tool was found for implementation",
						},
						"401": map[string]interface{}{
							"description": "Unauthorized",
						},
					},
				},
			},
			"/api/monitor/executions": map[string]interface{}{
				"delete": map[string]interface{}{
					"tags":        []string{"Monitoring"},
					"summary":     "Batch delete execution records",
					"description": "Batch delete execution records",
					"operationId": "deleteExecutions",
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Deleted successfully",
						},
						"401": map[string]interface{}{
							"description": "Unauthorized",
						},
					},
				},
			},
			"/api/monitor/stats": map[string]interface{}{
				"get": map[string]interface{}{
					"tags":        []string{"Monitoring"},
					"summary":     "Get statistics",
					"description": "Access to tools to implement statistical information",
					"operationId": "getStats",
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Success",
							"content": map[string]interface{}{
								"application/json": map[string]interface{}{
									"schema": map[string]interface{}{
										"type":        "object",
										"description": "Statistical information",
									},
								},
							},
						},
						"401": map[string]interface{}{
							"description": "Unauthorized",
						},
					},
				},
			},
			"/api/system/update/source": map[string]interface{}{
				"post": map[string]interface{}{
					"tags":        []string{"System update"},
					"summary":     "Configure update source (from which repository this installation is updated)",
					"description": "Write Update Source config.yaml of update Paragraph: Single repo Fields (Warehouse Address) , Update default branch following the repository.Leave space. (Or write empty strings) = Back to the official warehouse. https://github.com/AIPentest/CyberStrikeAI.git.White List As https/http/ssh/git/file:// The absolute path to this machine. (git of ext:: The transmission will execute the command., They all refuse.) .",
					"operationId": "saveUpdateSource",
					"requestBody": map[string]interface{}{
						"content": map[string]interface{}{
							"application/json": map[string]interface{}{
								"schema": map[string]interface{}{
									"type": "object",
									"properties": map[string]interface{}{
										"repo": map[string]interface{}{"type": "string", "description": "Update source repository address; empty = official repository"},
									},
								},
							},
						},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{"description": "Saved (returns configuration value and official default address)"},
						"400": map[string]interface{}{"description": "The warehouse address is not valid."},
						"401": map[string]interface{}{"description": "Unauthorized"},
					},
				},
			},
			"/api/system/update/adopt": map[string]interface{}{
				"post": map[string]interface{}{
					"tags":        []string{"System update"},
					"summary":     "Take off git Directory access update source",
					"description": "Unpressure/Pack the directory access configured as a new source (Unconfigured = Official warehouse) : Not confirm Preview without side effects (In the temporary warehouse. fetch, Lists the content of the carriers that the document will be replaced by the target version) ; confirm=true Timewise execution (202 + job_id, Use /api/system/update/job Round) : git init, Add origin, Locally update the content of the default branch of the source, Save the transporter content and release it back., Replaced files left to .update-backup/<Timetamp>/overwritten/.Already. git Back on the working tree 409 (Update instead of access) .",
					"operationId": "adoptUpdateSource",
					"requestBody": map[string]interface{}{
						"content": map[string]interface{}{
							"application/json": map[string]interface{}{
								"schema": map[string]interface{}{
									"type": "object",
									"properties": map[string]interface{}{
										"confirm": map[string]interface{}{"type": "boolean", "description": "false/Default=Preview only; true=Confirmation of implementation"},
										"restart": map[string]interface{}{"type": "boolean", "description": "Exiting process after successful access to external guardian pulls up, default false"},
									},
								},
							},
						},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{"description": "Preview results (plan: list of documents to be replaced/reserved and total)"},
						"202": map[string]interface{}{"description": "Access accepted, return job_id"},
						"400": map[string]interface{}{"description": "Update source address is not valid, or request restart without restarting hooks"},
						"409": map[string]interface{}{"description": "The directory already is. git Work Tree; There may be a mission in progress."},
						"401": map[string]interface{}{"description": "Unauthorized"},
					},
				},
			},
			"/api/config": map[string]interface{}{
				"get": map[string]interface{}{
					"tags":        []string{"Configuration Management"},
					"summary":     "Get configuration",
					"description": "Get System Configuration Information",
					"operationId": "getConfig",
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Success",
							"content": map[string]interface{}{
								"application/json": map[string]interface{}{
									"schema": map[string]interface{}{
										"$ref": "#/components/schemas/ConfigResponse",
									},
								},
							},
						},
						"401": map[string]interface{}{
							"description": "Unauthorized",
						},
					},
				},
				"put": map[string]interface{}{
					"tags":        []string{"Configuration Management"},
					"summary":     "Update configuration",
					"description": "Update System Configuration",
					"operationId": "updateConfig",
					"requestBody": map[string]interface{}{
						"required": true,
						"content": map[string]interface{}{
							"application/json": map[string]interface{}{
								"schema": map[string]interface{}{
									"$ref": "#/components/schemas/UpdateConfigRequest",
								},
							},
						},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Updated successfully",
						},
						"400": map[string]interface{}{
							"description": "Bad request",
						},
						"401": map[string]interface{}{
							"description": "Unauthorized",
						},
					},
				},
			},
			"/api/storage/meta": map[string]interface{}{
				"get": map[string]interface{}{
					"tags":        []string{"Storage cleanup"},
					"summary":     "Fetch Storage Cleanup Policy",
					"description": "Returns the active status and retention of automatic cleanup switches, spacing, broad window and all clean categories",
					"operationId": "getStorageMeta",
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Success",
						},
						"401": map[string]interface{}{
							"description": "Unauthorized",
						},
						"403": map[string]interface{}{
							"description": "missing storage:read permissions",
						},
					},
				},
			},
			"/api/storage/status": map[string]interface{}{
				"get": map[string]interface{}{
					"tags":        []string{"Storage cleanup"},
					"summary":     "Access to running space occupancy",
					"description": "Return file system capacity (including inode) to the occupancy, recoverable amount for each category; result by short TTL cache",
					"operationId": "getStorageStatus",
					"parameters": []interface{}{
						map[string]interface{}{
							"name":        "refresh",
							"in":          "query",
							"description": "Force re-routing directory while running over a true directory, bypassing cache",
							"required":    false,
							"schema":      map[string]interface{}{"type": "boolean"},
						},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Success",
						},
						"401": map[string]interface{}{
							"description": "Unauthorized",
						},
						"403": map[string]interface{}{
							"description": "missing storage:read permissions",
						},
					},
				},
			},
			"/api/storage/cleanup": map[string]interface{}{
				"post": map[string]interface{}{
					"tags":        []string{"Storage cleanup"},
					"summary":     "Preview or execute running space clean-up",
					"description": "Default dry_run=true only does not delete; true deletion must be accompanied by dry_run=false and confirm=true. Only handles enabled categories, only a round is allowed at the same time",
					"operationId": "runStorageCleanup",
					"requestBody": map[string]interface{}{
						"required": false,
						"content": map[string]interface{}{
							"application/json": map[string]interface{}{
								"schema": map[string]interface{}{
									"type": "object",
									"properties": map[string]interface{}{
										"dry_run": map[string]interface{}{
											"type":        "boolean",
											"description": "Press when omitted true Processing",
										},
										"confirm": map[string]interface{}{
											"type":        "boolean",
											"description": "dry_run=false It has to be. true",
										},
										"categories": map[string]interface{}{
											"type":        "array",
											"description": "qualifying categories; omitting to indicate all active categories",
											"items":       map[string]interface{}{"type": "string"},
										},
									},
								},
							},
						},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Implementation completed (or preview completed)",
						},
						"400": map[string]interface{}{
							"description": "Missing confirm, or type keys not registered",
						},
						"401": map[string]interface{}{
							"description": "Unauthorized",
						},
						"403": map[string]interface{}{
							"description": "missing storage:write permissions",
						},
						"409": map[string]interface{}{
							"description": "A clean-up round is in progress.",
						},
					},
				},
			},
			"/api/config/tools": map[string]interface{}{
				"get": map[string]interface{}{
					"tags":        []string{"Configuration Management"},
					"summary":     "Get tool configuration",
					"description": "Get configuration information for all tools",
					"operationId": "getTools",
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Success",
							"content": map[string]interface{}{
								"application/json": map[string]interface{}{
									"schema": map[string]interface{}{
										"type":        "array",
										"description": "Tool Configuration List",
									},
								},
							},
						},
						"401": map[string]interface{}{
							"description": "Unauthorized",
						},
					},
				},
			},
			"/api/config/apply": map[string]interface{}{
				"post": map[string]interface{}{
					"tags":        []string{"Configuration Management"},
					"summary":     "Apply config",
					"description": "Apply Configuration Changes",
					"operationId": "applyConfig",
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Application Success",
						},
						"401": map[string]interface{}{
							"description": "Unauthorized",
						},
					},
				},
			},
			"/api/external-mcp": map[string]interface{}{
				"get": map[string]interface{}{
					"tags":        []string{"External MCP Management"},
					"summary":     "List external MCP",
					"description": "Get all external MCP configurations and status",
					"operationId": "getExternalMCPs",
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Success",
							"content": map[string]interface{}{
								"application/json": map[string]interface{}{
									"schema": map[string]interface{}{
										"type": "object",
										"properties": map[string]interface{}{
											"servers": map[string]interface{}{
												"type":        "object",
												"description": "MCP Server Configuration",
												"additionalProperties": map[string]interface{}{
													"$ref": "#/components/schemas/ExternalMCPResponse",
												},
											},
											"stats": map[string]interface{}{
												"type":        "object",
												"description": "Statistical information",
											},
										},
									},
								},
							},
						},
						"401": map[string]interface{}{
							"description": "Unauthorized",
						},
					},
				},
			},
			"/api/external-mcp/stats": map[string]interface{}{
				"get": map[string]interface{}{
					"tags":        []string{"External MCP Management"},
					"summary":     "Get external MCP statistics",
					"description": "Access to external MCP statistical information",
					"operationId": "getExternalMCPStats",
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Success",
							"content": map[string]interface{}{
								"application/json": map[string]interface{}{
									"schema": map[string]interface{}{
										"type":        "object",
										"description": "Statistical information",
									},
								},
							},
						},
						"401": map[string]interface{}{
							"description": "Unauthorized",
						},
					},
				},
			},
			"/api/external-mcp/{name}": map[string]interface{}{
				"get": map[string]interface{}{
					"tags":        []string{"External MCP Management"},
					"summary":     "Get external MCP",
					"description": "Get specified external MCP configuration and status",
					"operationId": "getExternalMCP",
					"parameters": []map[string]interface{}{
						{
							"name":        "name",
							"in":          "path",
							"required":    true,
							"description": "MCP name",
							"schema": map[string]interface{}{
								"type": "string",
							},
						},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Success",
							"content": map[string]interface{}{
								"application/json": map[string]interface{}{
									"schema": map[string]interface{}{
										"$ref": "#/components/schemas/ExternalMCPResponse",
									},
								},
							},
						},
						"404": map[string]interface{}{
							"description": "MCP does not exist",
						},
						"401": map[string]interface{}{
							"description": "Unauthorized",
						},
					},
				},
				"put": map[string]interface{}{
					"tags":        []string{"External MCP Management"},
					"summary":     "Add or update external MCP",
					"description": "Adds a new external MCP configuration or updates the current configuration.\n**Transfer mode**:\nTwo modes of transmission are supported:\n**1. stdio (standard input output)**:\n```json\n{\n  \"config\": {\n    \"enabled\": true,\n    \"command\": \"node\",\n    \"args\": [\"/path/to/mcp-server.js\"],\n    \"env\": {}\n  }\n}\n```\n**2. sse (Server-Sent Events) **: \n```json\n{\n  \"config\": {\n    \"enabled\": true,\n    \"transport\": \"sse\",\n    \"url\": \"http://127.0.0.1:8082/sse\",\n    \"timeout\": 30\n  }\n}\n```\n** Description of configuration parameters**:\n- `enabled`: Enable (boolean, Required) \n- `command`: Command (stdio Mode Needed, for example: \"node\", \"python\") \n- `args`: Command Arguments (stdio Mode Needed) \n- `env`: Environmental variables (object, optional) \n- `transport`: Transfer (\"stdio\" or \"sse\", sse Mode Needed) \n- `url`: SSE Peer URL (sse Mode Needed) \n- `timeout`: Timeout (seconds, optional, Default 30) \n- `description`: description (optional) ",
					"operationId": "addOrUpdateExternalMCP",
					"parameters": []map[string]interface{}{
						{
							"name":        "name",
							"in":          "path",
							"required":    true,
							"description": "MCP name (sole identifier)",
							"schema": map[string]interface{}{
								"type": "string",
							},
						},
					},
					"requestBody": map[string]interface{}{
						"required": true,
						"content": map[string]interface{}{
							"application/json": map[string]interface{}{
								"schema": map[string]interface{}{
									"$ref": "#/components/schemas/AddOrUpdateExternalMCPRequest",
								},
								"examples": map[string]interface{}{
									"stdio": map[string]interface{}{
										"summary":     "stdio mode config",
										"description": "Connect external MCP servers with standard input output",
										"value": map[string]interface{}{
											"config": map[string]interface{}{
												"enabled":     true,
												"command":     "node",
												"args":        []string{"/path/to/mcp-server.js"},
												"env":         map[string]interface{}{},
												"timeout":     30,
												"description": "Node.js MCP server",
											},
										},
									},
									"sse": map[string]interface{}{
										"summary":     "SSE mode config",
										"description": "Connect external MCP servers using Server-Sent Events",
										"value": map[string]interface{}{
											"config": map[string]interface{}{
												"enabled":     true,
												"transport":   "sse",
												"url":         "http://127.0.0.1:8082/sse",
												"timeout":     30,
												"description": "SSE MCP server",
											},
										},
									},
								},
							},
						},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Operation successfully",
							"content": map[string]interface{}{
								"application/json": map[string]interface{}{
									"schema": map[string]interface{}{
										"type": "object",
										"properties": map[string]interface{}{
											"message": map[string]interface{}{
												"type":    "string",
												"example": "External MCP configuration saved",
											},
										},
									},
								},
							},
						},
						"400": map[string]interface{}{
							"description": "Bad request (e.g. invalid config or missing required fields)",
							"content": map[string]interface{}{
								"application/json": map[string]interface{}{
									"schema": map[string]interface{}{
										"$ref": "#/components/schemas/Error",
									},
									"example": map[string]interface{}{
										"error": "The stdio mode needs to provide command and args parameters",
									},
								},
							},
						},
						"401": map[string]interface{}{
							"description": "Unauthorized",
						},
					},
				},
				"delete": map[string]interface{}{
					"tags":        []string{"External MCP Management"},
					"summary":     "Delete external MCP",
					"description": "Remove specified external MCP configuration",
					"operationId": "deleteExternalMCP",
					"parameters": []map[string]interface{}{
						{
							"name":        "name",
							"in":          "path",
							"required":    true,
							"description": "MCP name",
							"schema": map[string]interface{}{
								"type": "string",
							},
						},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Deleted successfully",
						},
						"404": map[string]interface{}{
							"description": "MCP does not exist",
						},
						"401": map[string]interface{}{
							"description": "Unauthorized",
						},
					},
				},
			},
			"/api/external-mcp/{name}/start": map[string]interface{}{
				"post": map[string]interface{}{
					"tags":        []string{"External MCP Management"},
					"summary":     "Start external MCP",
					"description": "Start specified external MCP server",
					"operationId": "startExternalMCP",
					"parameters": []map[string]interface{}{
						{
							"name":        "name",
							"in":          "path",
							"required":    true,
							"description": "MCP name",
							"schema": map[string]interface{}{
								"type": "string",
							},
						},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Started successfully",
						},
						"404": map[string]interface{}{
							"description": "MCP does not exist",
						},
						"401": map[string]interface{}{
							"description": "Unauthorized",
						},
					},
				},
			},
			"/api/external-mcp/{name}/stop": map[string]interface{}{
				"post": map[string]interface{}{
					"tags":        []string{"External MCP Management"},
					"summary":     "Stop external MCP",
					"description": "Disable specified external MCP server",
					"operationId": "stopExternalMCP",
					"parameters": []map[string]interface{}{
						{
							"name":        "name",
							"in":          "path",
							"required":    true,
							"description": "MCP name",
							"schema": map[string]interface{}{
								"type": "string",
							},
						},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Stop Success",
						},
						"404": map[string]interface{}{
							"description": "MCP does not exist",
						},
						"401": map[string]interface{}{
							"description": "Unauthorized",
						},
					},
				},
			},
			"/api/attack-chain/{conversationId}": map[string]interface{}{
				"get": map[string]interface{}{
					"tags":        []string{"Attack Chains"},
					"summary":     "Get attack chain",
					"description": "Access to specified dialogue attack chain visualization data",
					"operationId": "getAttackChain",
					"parameters": []map[string]interface{}{
						{
							"name":        "conversationId",
							"in":          "path",
							"required":    true,
							"description": "Conversation ID",
							"schema": map[string]interface{}{
								"type": "string",
							},
						},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Success",
							"content": map[string]interface{}{
								"application/json": map[string]interface{}{
									"schema": map[string]interface{}{
										"$ref": "#/components/schemas/AttackChain",
									},
								},
							},
						},
						"404": map[string]interface{}{
							"description": "Conversation not found",
						},
						"401": map[string]interface{}{
							"description": "Unauthorized",
						},
					},
				},
			},
			"/api/attack-chain/{conversationId}/regenerate": map[string]interface{}{
				"post": map[string]interface{}{
					"tags":        []string{"Attack Chains"},
					"summary":     "Regenerate attack chains",
					"description": "Regeneration of data for the specified dialogue attack chain visualization",
					"operationId": "regenerateAttackChain",
					"parameters": []map[string]interface{}{
						{
							"name":        "conversationId",
							"in":          "path",
							"required":    true,
							"description": "Conversation ID",
							"schema": map[string]interface{}{
								"type": "string",
							},
						},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Regeneration succeeded",
							"content": map[string]interface{}{
								"application/json": map[string]interface{}{
									"schema": map[string]interface{}{
										"$ref": "#/components/schemas/AttackChain",
									},
								},
							},
						},
						"404": map[string]interface{}{
							"description": "Conversation not found",
						},
						"401": map[string]interface{}{
							"description": "Unauthorized",
						},
					},
				},
			},
			"/api/conversations/{id}/pinned": map[string]interface{}{
				"put": map[string]interface{}{
					"tags":        []string{"Conversation Management"},
					"summary":     "Pin conversation",
					"description": "Sets or cancels the top state of the dialogue",
					"operationId": "updateConversationPinned",
					"parameters": []map[string]interface{}{
						{
							"name":        "id",
							"in":          "path",
							"required":    true,
							"description": "Conversation ID",
							"schema": map[string]interface{}{
								"type": "string",
							},
						},
					},
					"requestBody": map[string]interface{}{
						"required": true,
						"content": map[string]interface{}{
							"application/json": map[string]interface{}{
								"schema": map[string]interface{}{
									"type":     "object",
									"required": []string{"pinned"},
									"properties": map[string]interface{}{
										"pinned": map[string]interface{}{
											"type":        "boolean",
											"description": "Top or not",
										},
									},
								},
							},
						},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Updated successfully",
						},
						"404": map[string]interface{}{
							"description": "Conversation not found",
						},
						"401": map[string]interface{}{
							"description": "Unauthorized",
						},
					},
				},
			},
			"/api/knowledge/categories": map[string]interface{}{
				"get": map[string]interface{}{
					"tags":        []string{"Knowledge Base"},
					"summary":     "Get categories",
					"description": "All classifications to access the knowledge base",
					"operationId": "getKnowledgeCategories",
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Success",
							"content": map[string]interface{}{
								"application/json": map[string]interface{}{
									"schema": map[string]interface{}{
										"type": "object",
										"properties": map[string]interface{}{
											"categories": map[string]interface{}{
												"type":        "array",
												"description": "Category List",
												"items": map[string]interface{}{
													"type": "string",
												},
											},
											"enabled": map[string]interface{}{
												"type":        "boolean",
												"description": "Whether the knowledge base is enabled",
											},
										},
									},
								},
							},
						},
						"401": map[string]interface{}{
							"description": "Unauthorized",
						},
					},
				},
			},
			"/api/knowledge/items": map[string]interface{}{
				"get": map[string]interface{}{
					"tags":        []string{"Knowledge Base"},
					"summary":     "List knowledge items",
					"description": "Access to all knowledge items in the knowledge base",
					"operationId": "getKnowledgeItems",
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Success",
							"content": map[string]interface{}{
								"application/json": map[string]interface{}{
									"schema": map[string]interface{}{
										"type": "object",
										"properties": map[string]interface{}{
											"items": map[string]interface{}{
												"type":        "array",
												"description": "List of knowledge items",
											},
											"enabled": map[string]interface{}{
												"type":        "boolean",
												"description": "Whether the knowledge base is enabled",
											},
										},
									},
								},
							},
						},
						"401": map[string]interface{}{
							"description": "Unauthorized",
						},
					},
				},
				"post": map[string]interface{}{
					"tags":        []string{"Knowledge Base"},
					"summary":     "Create knowledge item",
					"description": "Create a new knowledge entry",
					"operationId": "createKnowledgeItem",
					"requestBody": map[string]interface{}{
						"required": true,
						"content": map[string]interface{}{
							"application/json": map[string]interface{}{
								"schema": map[string]interface{}{
									"type":        "object",
									"description": "Knowledge Item Data",
								},
							},
						},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Created successfully",
						},
						"400": map[string]interface{}{
							"description": "Bad request",
						},
						"401": map[string]interface{}{
							"description": "Unauthorized",
						},
					},
				},
			},
			"/api/knowledge/items/{id}": map[string]interface{}{
				"get": map[string]interface{}{
					"tags":        []string{"Knowledge Base"},
					"summary":     "Get knowledge item",
					"description": "Get detailed information on the specified knowledge entry",
					"operationId": "getKnowledgeItem",
					"parameters": []map[string]interface{}{
						{
							"name":        "id",
							"in":          "path",
							"required":    true,
							"description": "Knowledge ID",
							"schema": map[string]interface{}{
								"type": "string",
							},
						},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Success",
						},
						"404": map[string]interface{}{
							"description": "Knowledge does not exist",
						},
						"401": map[string]interface{}{
							"description": "Unauthorized",
						},
					},
				},
				"put": map[string]interface{}{
					"tags":        []string{"Knowledge Base"},
					"summary":     "Update knowledge item",
					"description": "Update the specified knowledge entry",
					"operationId": "updateKnowledgeItem",
					"parameters": []map[string]interface{}{
						{
							"name":        "id",
							"in":          "path",
							"required":    true,
							"description": "Knowledge ID",
							"schema": map[string]interface{}{
								"type": "string",
							},
						},
					},
					"requestBody": map[string]interface{}{
						"required": true,
						"content": map[string]interface{}{
							"application/json": map[string]interface{}{
								"schema": map[string]interface{}{
									"type":        "object",
									"description": "Knowledge Item Data",
								},
							},
						},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Updated successfully",
						},
						"404": map[string]interface{}{
							"description": "Knowledge does not exist",
						},
						"401": map[string]interface{}{
							"description": "Unauthorized",
						},
					},
				},
				"delete": map[string]interface{}{
					"tags":        []string{"Knowledge Base"},
					"summary":     "Knowledge item deleted",
					"description": "Delete the specified knowledge entry",
					"operationId": "deleteKnowledgeItem",
					"parameters": []map[string]interface{}{
						{
							"name":        "id",
							"in":          "path",
							"required":    true,
							"description": "Knowledge ID",
							"schema": map[string]interface{}{
								"type": "string",
							},
						},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Deleted successfully",
						},
						"404": map[string]interface{}{
							"description": "Knowledge does not exist",
						},
						"401": map[string]interface{}{
							"description": "Unauthorized",
						},
					},
				},
			},
			"/api/knowledge/index-status": map[string]interface{}{
				"get": map[string]interface{}{
					"tags":        []string{"Knowledge Base"},
					"summary":     "Get index status",
					"description": "Build status of access to knowledge base index",
					"operationId": "getIndexStatus",
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Success",
							"content": map[string]interface{}{
								"application/json": map[string]interface{}{
									"schema": map[string]interface{}{
										"type": "object",
										"properties": map[string]interface{}{
											"enabled": map[string]interface{}{
												"type":        "boolean",
												"description": "Whether the knowledge base is enabled",
											},
											"total_items": map[string]interface{}{
												"type":        "integer",
												"description": "Total number of knowledge items",
											},
											"indexed_items": map[string]interface{}{
												"type":        "integer",
												"description": "Number of indexed knowledge items",
											},
											"progress_percent": map[string]interface{}{
												"type":        "number",
												"description": "Index progress per cent",
											},
											"is_complete": map[string]interface{}{
												"type":        "boolean",
												"description": "Index completed",
											},
										},
									},
								},
							},
						},
						"401": map[string]interface{}{
							"description": "Unauthorized",
						},
					},
				},
			},
			"/api/knowledge/index": map[string]interface{}{
				"post": map[string]interface{}{
					"tags":        []string{"Knowledge Base"},
					"summary":     "Build index",
					"description": "Build knowledge base vector index.Default to process knowledge items without vectors only; mode=full Full-time reconstruction.",
					"operationId": "startKnowledgeIndex",
					"parameters": []map[string]interface{}{
						{
							"name":        "mode",
							"in":          "query",
							"required":    false,
							"description": "Index Mode: missing (Default, Complete Missing Vector) or full (Full reconstruction) ",
							"schema": map[string]interface{}{
								"type":    "string",
								"enum":    []string{"missing", "full"},
								"default": "missing",
							},
						},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Index Job Started",
						},
						"400": map[string]interface{}{
							"description": "Invalid mode Parameters",
						},
						"401": map[string]interface{}{
							"description": "Unauthorized",
						},
						"409": map[string]interface{}{
							"description": "The indexing task is ongoing",
						},
					},
				},
			},
			"/api/knowledge/scan": map[string]interface{}{
				"post": map[string]interface{}{
					"tags":        []string{"Knowledge Base"},
					"summary":     "Scan knowledge base",
					"description": "Scan the knowledge base directory and import new knowledge files",
					"operationId": "scanKnowledgeBase",
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Scan job started.",
						},
						"401": map[string]interface{}{
							"description": "Unauthorized",
						},
					},
				},
			},
			"/api/knowledge/search": map[string]interface{}{
				"post": map[string]interface{}{
					"tags":        []string{"Knowledge Base"},
					"summary":     "Search knowledge base",
					"description": "Searches for relevant content in the knowledge base. Based on vector search, returns the most relevant result by semantic similarity (cosine) of the query to the knowledge clip.\n** Search description**:\n- Semantic Similarity Search: Embedded Vector + Cosine Similarity, Configure Similarity Thresholds with TopK\n- Filterable by risk type, metadata, etc. (e.g. SQL injection, XSS, file upload, etc.)\n- Suggested first call `/api/knowledge/categories` Get a list of available risk types\n** Use of examples**:\n```json\n{\n  \"query\": \"SQL The way to detect the holes.\",\n  \"riskType\": \"SQL Injection\",\n  \"topK\": 5,\n  \"threshold\": 0.7\n}\n```",
					"operationId": "searchKnowledge",
					"requestBody": map[string]interface{}{
						"required": true,
						"content": map[string]interface{}{
							"application/json": map[string]interface{}{
								"schema": map[string]interface{}{
									"type":     "object",
									"required": []string{"query"},
									"properties": map[string]interface{}{
										"query": map[string]interface{}{
											"type":        "string",
											"description": "Search for query content to describe the subject of security knowledge you want to understand (required)",
											"example":     "SQL's method of detecting holes.",
										},
										"riskType": map[string]interface{}{
											"type":        "string",
											"description": "optional: Specify risk type (for example: SQL Injection, XSS, File upload etc.) .Suggested first call `/api/knowledge/categories` Get a list of available risk types, Then use the right type of risk for precise search., This will reduce the search time significantly..Search for all types if not specified.",
											"example":     "SQL Injection",
										},
										"topK": map[string]interface{}{
											"type":        "integer",
											"description": "Optional: Return number of Top-K results, default 5",
											"default":     5,
											"minimum":     1,
											"maximum":     50,
											"example":     5,
										},
										"threshold": map[string]interface{}{
											"type":        "number",
											"format":      "float",
											"description": "Optional: Similarity threshold (between 0-1), default 0.7. Only a result of a similarity greater than or equal to this value returns",
											"default":     0.7,
											"minimum":     0,
											"maximum":     1,
											"example":     0.7,
										},
									},
								},
								"examples": map[string]interface{}{
									"basic": map[string]interface{}{
										"summary":     "Basic search",
										"description": "Simplest search, only query content",
										"value": map[string]interface{}{
											"query": "SQL's method of detecting holes.",
										},
									},
									"withRiskType": map[string]interface{}{
										"summary":     "Search by risk type",
										"description": "Specify the type of risk to be accurately searched",
										"value": map[string]interface{}{
											"query":     "SQL's method of detecting holes.",
											"riskType":  "SQL Injection",
											"topK":      5,
											"threshold": 0.7,
										},
									},
								},
							},
						},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Search successful",
							"content": map[string]interface{}{
								"application/json": map[string]interface{}{
									"schema": map[string]interface{}{
										"type": "object",
										"properties": map[string]interface{}{
											"results": map[string]interface{}{
												"type":        "array",
												"description": "Search result list, Each result contains: item (Knowledge Item Information) , chunks (A matching knowledge clip) , score (Similarity Scores) ",
												"items": map[string]interface{}{
													"type": "object",
													"properties": map[string]interface{}{
														"item": map[string]interface{}{
															"type":        "object",
															"description": "Knowledge Item Information",
														},
														"chunks": map[string]interface{}{
															"type":        "array",
															"description": "A list of matching knowledge clips",
														},
														"score": map[string]interface{}{
															"type":        "number",
															"description": "Similarity fractions (between 0 and 1)",
														},
													},
												},
											},
											"enabled": map[string]interface{}{
												"type":        "boolean",
												"description": "Whether the knowledge base is enabled",
											},
										},
									},
									"example": map[string]interface{}{
										"results": []map[string]interface{}{
											{
												"item": map[string]interface{}{
													"id":       "item-1",
													"title":    "SQL Injection Hole Detection",
													"category": "SQL Injection",
												},
												"chunks": []map[string]interface{}{
													{
														"text": "The way SQL injects holes is...",
													},
												},
												"score": 0.85,
											},
										},
										"enabled": true,
									},
								},
							},
						},
						"400": map[string]interface{}{
							"description": "Bad request (e.g. query is empty)",
							"content": map[string]interface{}{
								"application/json": map[string]interface{}{
									"schema": map[string]interface{}{
										"$ref": "#/components/schemas/Error",
									},
									"example": map[string]interface{}{
										"error": "Query cannot be empty",
									},
								},
							},
						},
						"401": map[string]interface{}{
							"description": "Unauthorized",
						},
						"500": map[string]interface{}{
							"description": "Internal server error (e.g. knowledge base not enabled or retrieval failed)",
						},
					},
				},
			},
			"/api/knowledge/retrieval-logs": map[string]interface{}{
				"get": map[string]interface{}{
					"tags":        []string{"Knowledge Base"},
					"summary":     "Get retrieval logs",
					"description": "Access knowledge base search log",
					"operationId": "getRetrievalLogs",
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Success",
							"content": map[string]interface{}{
								"application/json": map[string]interface{}{
									"schema": map[string]interface{}{
										"type": "object",
										"properties": map[string]interface{}{
											"logs": map[string]interface{}{
												"type":        "array",
												"description": "Retrieval log list",
											},
											"enabled": map[string]interface{}{
												"type":        "boolean",
												"description": "Whether the knowledge base is enabled",
											},
										},
									},
								},
							},
						},
						"401": map[string]interface{}{
							"description": "Unauthorized",
						},
					},
				},
			},
			"/api/knowledge/retrieval-logs/{id}": map[string]interface{}{
				"delete": map[string]interface{}{
					"tags":        []string{"Knowledge Base"},
					"summary":     "Delete retrieval log",
					"description": "Remove the specified search log",
					"operationId": "deleteRetrievalLog",
					"parameters": []map[string]interface{}{
						{
							"name":        "id",
							"in":          "path",
							"required":    true,
							"description": "Log ID",
							"schema": map[string]interface{}{
								"type": "string",
							},
						},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Deleted successfully",
						},
						"404": map[string]interface{}{
							"description": "Log does not exist",
						},
						"401": map[string]interface{}{
							"description": "Unauthorized",
						},
					},
				},
			},
			// ==================== 对话交互 - 缺失端点 ====================
			"/api/conversations/{id}/delete-turn": map[string]interface{}{
				"post": map[string]interface{}{
					"tags":        []string{"Conversation Interaction"},
					"summary":     "Conversation turn deleted",
					"description": "Delete the dialogue cycle where the message is specified (From Round user Message to the next round user Everything before the message.) , And empty. last_react status.",
					"operationId": "deleteConversationTurn",
					"parameters": []map[string]interface{}{
						{
							"name":        "id",
							"in":          "path",
							"required":    true,
							"description": "Conversation ID",
							"schema":      map[string]interface{}{"type": "string"},
						},
					},
					"requestBody": map[string]interface{}{
						"required": true,
						"content": map[string]interface{}{
							"application/json": map[string]interface{}{
								"schema": map[string]interface{}{
									"type":     "object",
									"required": []string{"messageId"},
									"properties": map[string]interface{}{
										"messageId": map[string]interface{}{
											"type":        "string",
											"description": "anchor message ID, identify the wheel to delete",
										},
									},
								},
							},
						},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Deleted successfully",
							"content": map[string]interface{}{
								"application/json": map[string]interface{}{
									"schema": map[string]interface{}{
										"type": "object",
										"properties": map[string]interface{}{
											"deletedMessageIds": map[string]interface{}{
												"type":        "array",
												"items":       map[string]interface{}{"type": "string"},
												"description": "Message deleted ID List",
											},
											"message": map[string]interface{}{
												"type":    "string",
												"example": "ok",
											},
										},
									},
								},
							},
						},
						"400": map[string]interface{}{"description": "Bad request or delete failed"},
						"401": map[string]interface{}{"description": "Unauthorized"},
						"404": map[string]interface{}{"description": "Conversation not found"},
					},
				},
			},
			"/api/messages/{id}/process-details": map[string]interface{}{
				"get": map[string]interface{}{
					"tags":        []string{"Conversation Interaction"},
					"summary":     "Get message process details",
					"description": "Load details of the execution of the specified message as required, Including tool calls, Thinking, things like that..Default Return 50 Article; When exporting or old integration requires full circulation full=1.",
					"operationId": "getMessageProcessDetails",
					"parameters": []map[string]interface{}{
						{
							"name":        "id",
							"in":          "path",
							"required":    true,
							"description": "Message ID",
							"schema":      map[string]interface{}{"type": "string"},
						},
						{
							"name":        "summary",
							"in":          "query",
							"required":    false,
							"description": "Only return details of the process (total / iterationCount / maxIteration) ",
							"schema":      map[string]interface{}{"type": "boolean"},
						},
						{
							"name":        "limit",
							"in":          "query",
							"required":    false,
							"description": "Page break size, default 50, maximum 500",
							"schema":      map[string]interface{}{"type": "integer", "default": 50, "maximum": 500},
						},
						{
							"name":        "offset",
							"in":          "query",
							"required":    false,
							"description": "Page Break Volume, Default 0",
							"schema":      map[string]interface{}{"type": "integer", "default": 0},
						},
						{
							"name":        "full",
							"in":          "query",
							"required":    false,
							"description": "Active returns full mass process details; export/compatibility of old integration is only recommended",
							"schema":      map[string]interface{}{"type": "boolean"},
						},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Success",
							"content": map[string]interface{}{
								"application/json": map[string]interface{}{
									"schema": map[string]interface{}{
										"type": "object",
										"properties": map[string]interface{}{
											"processDetails": map[string]interface{}{
												"type": "array",
												"items": map[string]interface{}{
													"type": "object",
													"properties": map[string]interface{}{
														"id":             map[string]interface{}{"type": "string", "description": "Detailed Record ID"},
														"messageId":      map[string]interface{}{"type": "string", "description": "Parent message ID"},
														"conversationId": map[string]interface{}{"type": "string", "description": "Conversation ID"},
														"eventType":      map[string]interface{}{"type": "string", "description": "Event type (e.g. tool_call, thinking)"},
														"message":        map[string]interface{}{"type": "string", "description": "Event Message"},
														"data":           map[string]interface{}{"description": "Event Additional Data (JSON Object)"},
														"createdAt":      map[string]interface{}{"type": "string", "format": "date-time", "description": "Created"},
													},
												},
											},
											"total":   map[string]interface{}{"type": "integer", "description": "Total process details"},
											"offset":  map[string]interface{}{"type": "integer", "description": "Current Page Offset"},
											"limit":   map[string]interface{}{"type": "integer", "description": "Current Page Break Size"},
											"hasMore": map[string]interface{}{"type": "boolean", "description": "Is there any more process details?"},
											"summary": map[string]interface{}{
												"type":        "object",
												"description": "summary=1 Summary returned on",
											},
										},
									},
								},
							},
						},
						"400": map[string]interface{}{"description": "Invalid parameters"},
						"401": map[string]interface{}{"description": "Unauthorized"},
					},
				},
			},

			// ==================== 批量任务 - 缺失端点 ====================
			"/api/batch-tasks/{queueId}/rerun": map[string]interface{}{
				"post": map[string]interface{}{
					"tags":        []string{"Batch Task"},
					"summary":     "Batch task queue rerun",
					"description": "Reset the batch queue of completed or cancelled tasks and restart all tasks.",
					"operationId": "rerunBatchQueue",
					"parameters": []map[string]interface{}{
						{
							"name":        "queueId",
							"in":          "path",
							"required":    true,
							"description": "Queue ID",
							"schema":      map[string]interface{}{"type": "string"},
						},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Rerun successful.",
							"content": map[string]interface{}{
								"application/json": map[string]interface{}{
									"schema": map[string]interface{}{
										"type": "object",
										"properties": map[string]interface{}{
											"message": map[string]interface{}{"type": "string", "example": "Batch task restarted"},
											"queueId": map[string]interface{}{"type": "string", "description": "Queue ID"},
										},
									},
								},
							},
						},
						"400": map[string]interface{}{"description": "Only completed or cancelled queues can be rerun"},
						"401": map[string]interface{}{"description": "Unauthorized"},
						"404": map[string]interface{}{"description": "Queue not found"},
					},
				},
			},
			"/api/batch-tasks/{queueId}/metadata": map[string]interface{}{
				"put": map[string]interface{}{
					"tags":        []string{"Batch Task"},
					"summary":     "Update queue metadata",
					"description": "Modifys the title, role and proxy mode of the batch task queue.",
					"operationId": "updateBatchQueueMetadata",
					"parameters": []map[string]interface{}{
						{
							"name":        "queueId",
							"in":          "path",
							"required":    true,
							"description": "Queue ID",
							"schema":      map[string]interface{}{"type": "string"},
						},
					},
					"requestBody": map[string]interface{}{
						"required": true,
						"content": map[string]interface{}{
							"application/json": map[string]interface{}{
								"schema": map[string]interface{}{
									"type": "object",
									"properties": map[string]interface{}{
										"title":     map[string]interface{}{"type": "string", "description": "Queue Title"},
										"role":      map[string]interface{}{"type": "string", "description": "Name of the role used"},
										"agentMode": map[string]interface{}{"type": "string", "description": "Agent mode", "enum": []string{"eino_single", "deep", "plan_execute", "supervisor"}},
									},
								},
							},
						},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Updated successfully",
							"content": map[string]interface{}{
								"application/json": map[string]interface{}{
									"schema": map[string]interface{}{
										"type": "object",
										"properties": map[string]interface{}{
											"queue": map[string]interface{}{"$ref": "#/components/schemas/BatchQueue"},
										},
									},
								},
							},
						},
						"400": map[string]interface{}{"description": "Invalid parameters"},
						"401": map[string]interface{}{"description": "Unauthorized"},
					},
				},
			},
			"/api/batch-tasks/{queueId}/schedule": map[string]interface{}{
				"put": map[string]interface{}{
					"tags":        []string{"Batch Task"},
					"summary":     "Update queue schedule",
					"description": "Modifys the schedule mode and Cron expression for the batch task queue. The queue cannot be modified.",
					"operationId": "updateBatchQueueSchedule",
					"parameters": []map[string]interface{}{
						{
							"name":        "queueId",
							"in":          "path",
							"required":    true,
							"description": "Queue ID",
							"schema":      map[string]interface{}{"type": "string"},
						},
					},
					"requestBody": map[string]interface{}{
						"required": true,
						"content": map[string]interface{}{
							"application/json": map[string]interface{}{
								"schema": map[string]interface{}{
									"type": "object",
									"properties": map[string]interface{}{
										"scheduleMode": map[string]interface{}{"type": "string", "description": "Schedule Mode", "enum": []string{"manual", "cron"}},
										"cronExpr":     map[string]interface{}{"type": "string", "description": "Cron Expression (scheduleMode is required if cron)", "example": "0 2 * * *"},
									},
								},
							},
						},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Updated successfully",
							"content": map[string]interface{}{
								"application/json": map[string]interface{}{
									"schema": map[string]interface{}{
										"type": "object",
										"properties": map[string]interface{}{
											"queue": map[string]interface{}{"$ref": "#/components/schemas/BatchQueue"},
										},
									},
								},
							},
						},
						"400": map[string]interface{}{"description": "Bad request or queue is running"},
						"401": map[string]interface{}{"description": "Unauthorized"},
						"404": map[string]interface{}{"description": "Queue not found"},
					},
				},
			},
			"/api/batch-tasks/{queueId}/schedule-enabled": map[string]interface{}{
				"put": map[string]interface{}{
					"tags":        []string{"Batch Task"},
					"summary":     "Toggle cron auto-schedule",
					"description": "The Cron AutoStaffing function of the batch task queue is activated or closed, and manual execution is not affected.",
					"operationId": "setBatchQueueScheduleEnabled",
					"parameters": []map[string]interface{}{
						{
							"name":        "queueId",
							"in":          "path",
							"required":    true,
							"description": "Queue ID",
							"schema":      map[string]interface{}{"type": "string"},
						},
					},
					"requestBody": map[string]interface{}{
						"required": true,
						"content": map[string]interface{}{
							"application/json": map[string]interface{}{
								"schema": map[string]interface{}{
									"type":     "object",
									"required": []string{"scheduleEnabled"},
									"properties": map[string]interface{}{
										"scheduleEnabled": map[string]interface{}{"type": "boolean", "description": "Whether or not to enable automatic scheduling"},
									},
								},
							},
						},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Set successfully",
							"content": map[string]interface{}{
								"application/json": map[string]interface{}{
									"schema": map[string]interface{}{
										"type": "object",
										"properties": map[string]interface{}{
											"queue": map[string]interface{}{"$ref": "#/components/schemas/BatchQueue"},
										},
									},
								},
							},
						},
						"401": map[string]interface{}{"description": "Unauthorized"},
						"404": map[string]interface{}{"description": "Queue not found"},
					},
				},
			},
			// ==================== FOFA信息收集 ====================
			"/api/fofa/search": map[string]interface{}{
				"post": map[string]interface{}{
					"tags":        []string{"FOFA Recon"},
					"summary":     "FOFA search",
					"description": "Run FOFA search search and return asset information through the end agent.",
					"operationId": "fofaSearch",
					"requestBody": map[string]interface{}{
						"required": true,
						"content": map[string]interface{}{
							"application/json": map[string]interface{}{
								"schema": map[string]interface{}{
									"type":     "object",
									"required": []string{"query"},
									"properties": map[string]interface{}{
										"query":  map[string]interface{}{"type": "string", "description": "FOFA query syntax", "example": "domain=\"example.com\""},
										"size":   map[string]interface{}{"type": "integer", "description": "Number of returns (Default 100, maximum 10000) ", "default": 100},
										"page":   map[string]interface{}{"type": "integer", "description": "Page Number (default 1)", "default": 1},
										"fields": map[string]interface{}{"type": "string", "description": "Return field, commas separated", "example": "host,ip,port,title"},
										"full":   map[string]interface{}{"type": "boolean", "description": "Whether to query all data", "default": false},
									},
								},
							},
						},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Search successful",
							"content": map[string]interface{}{
								"application/json": map[string]interface{}{
									"schema": map[string]interface{}{
										"type": "object",
										"properties": map[string]interface{}{
											"query":         map[string]interface{}{"type": "string", "description": "Query actually executed"},
											"size":          map[string]interface{}{"type": "integer"},
											"page":          map[string]interface{}{"type": "integer"},
											"total":         map[string]interface{}{"type": "integer", "description": "Total Matches"},
											"fields":        map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "string"}},
											"results_count": map[string]interface{}{"type": "integer"},
											"results":       map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "object"}, "description": "Search result list"},
										},
									},
								},
							},
						},
						"400": map[string]interface{}{"description": "Invalid parameters"},
						"401": map[string]interface{}{"description": "Unauthorized"},
					},
				},
			},
			"/api/fofa/parse": map[string]interface{}{
				"post": map[string]interface{}{
					"tags":        []string{"FOFA Recon"},
					"summary":     "Parse natural language to FOFA syntax",
					"description": "Use AI to interpret a natural language description to FOFA query syntax, which requires manual confirmation before the query is executed.",
					"operationId": "fofaParse",
					"requestBody": map[string]interface{}{
						"required": true,
						"content": map[string]interface{}{
							"application/json": map[string]interface{}{
								"schema": map[string]interface{}{
									"type":     "object",
									"required": []string{"text"},
									"properties": map[string]interface{}{
										"text": map[string]interface{}{"type": "string", "description": "Natural Language Description", "example": "Find a website using WordPress"},
									},
								},
							},
						},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Parse successful",
							"content": map[string]interface{}{
								"application/json": map[string]interface{}{
									"schema": map[string]interface{}{
										"type": "object",
										"properties": map[string]interface{}{
											"query":       map[string]interface{}{"type": "string", "description": "Generated FOFA query syntax"},
											"explanation": map[string]interface{}{"type": "string", "description": "Syntax Interpretation"},
											"warnings":    map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "string"}, "description": "Potential risks or ambiguities"},
										},
									},
								},
							},
						},
						"400": map[string]interface{}{"description": "Invalid parameters"},
						"401": map[string]interface{}{"description": "Unauthorized"},
					},
				},
			},

			// ==================== 配置管理 - 缺失端点 ====================
			"/api/config/test-vision": map[string]interface{}{
				"post": map[string]interface{}{
					"tags":        []string{"Configuration Management"},
					"summary":     "Test visual model connections",
					"description": "Test Vision Model API Available.vision.api_key/base_url Time to pass openai Section Back.",
					"operationId": "testVision",
					"requestBody": map[string]interface{}{
						"required": true,
						"content": map[string]interface{}{
							"application/json": map[string]interface{}{
								"schema": map[string]interface{}{
									"type":     "object",
									"required": []string{"vision"},
									"properties": map[string]interface{}{
										"vision": map[string]interface{}{"$ref": "#/components/schemas/VisionConfig"},
										"openai": map[string]interface{}{
											"type":        "object",
											"description": "main LLM configuration (vision Fields left blank for API Key/Base URL Back) ",
										},
									},
								},
							},
						},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Test result",
							"content": map[string]interface{}{
								"application/json": map[string]interface{}{
									"schema": map[string]interface{}{
										"type": "object",
										"properties": map[string]interface{}{
											"success":    map[string]interface{}{"type": "boolean"},
											"error":      map[string]interface{}{"type": "string"},
											"model":      map[string]interface{}{"type": "string"},
											"latency_ms": map[string]interface{}{"type": "number"},
										},
									},
								},
							},
						},
						"400": map[string]interface{}{"description": "Invalid parameters"},
						"401": map[string]interface{}{"description": "Unauthorized"},
					},
				},
			},
			"/api/config/test-openai": map[string]interface{}{
				"post": map[string]interface{}{
					"tags":        []string{"Configuration Management"},
					"summary":     "Test OpenAI API connection",
					"description": "Tests whether the specified OpenAI/Claude API configuration is available and sends a minimum request to verify connectivity.",
					"operationId": "testOpenAI",
					"requestBody": map[string]interface{}{
						"required": true,
						"content": map[string]interface{}{
							"application/json": map[string]interface{}{
								"schema": map[string]interface{}{
									"type":     "object",
									"required": []string{"api_key", "model"},
									"properties": map[string]interface{}{
										"provider": map[string]interface{}{"type": "string", "description": "LLM provider (openai/claude)", "example": "openai"},
										"base_url": map[string]interface{}{"type": "string", "description": "API base address (optional, default automatic selection according to provider)"},
										"api_key":  map[string]interface{}{"type": "string", "description": "API Key"},
										"model":    map[string]interface{}{"type": "string", "description": "Model name", "example": "gpt-4"},
									},
								},
							},
						},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Test result",
							"content": map[string]interface{}{
								"application/json": map[string]interface{}{
									"schema": map[string]interface{}{
										"type": "object",
										"properties": map[string]interface{}{
											"success":    map[string]interface{}{"type": "boolean", "description": "Whether or not the connection was successful"},
											"error":      map[string]interface{}{"type": "string", "description": "Reason for failure (success=false when) "},
											"model":      map[string]interface{}{"type": "string", "description": "Models used in practice (success=true)"},
											"latency_ms": map[string]interface{}{"type": "number", "description": "Delay in milliseconds (success=true)"},
										},
									},
								},
							},
						},
						"400": map[string]interface{}{"description": "Invalid parameters"},
						"401": map[string]interface{}{"description": "Unauthorized"},
					},
				},
			},
			"/api/config/test-typesafe": map[string]interface{}{
				"post": map[string]interface{}{
					"tags":        []string{"Configuration Management"},
					"summary":     "Test TypeSafe Jev connection",
					"description": "Sends a minimum Noul request to verify whether TypeSafe System One API Key is available.",
					"operationId": "testTypeSafe",
					"requestBody": map[string]interface{}{
						"required": true,
						"content": map[string]interface{}{
							"application/json": map[string]interface{}{
								"schema": map[string]interface{}{
									"type":     "object",
									"required": []string{"api_key"},
									"properties": map[string]interface{}{
										"base_url": map[string]interface{}{"type": "string", "description": "optional, Default https://api.typesafe.ai"},
										"api_key":  map[string]interface{}{"type": "string", "description": "TypeSafe API Key"},
										"model":    map[string]interface{}{"type": "string", "description": "optional, default jev-latest", "example": "jev-latest"},
									},
								},
							},
						},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Test result",
							"content": map[string]interface{}{
								"application/json": map[string]interface{}{
									"schema": map[string]interface{}{
										"type": "object",
										"properties": map[string]interface{}{
											"success":    map[string]interface{}{"type": "boolean"},
											"error":      map[string]interface{}{"type": "string"},
											"model":      map[string]interface{}{"type": "string"},
											"latency_ms": map[string]interface{}{"type": "number"},
										},
									},
								},
							},
						},
						"400": map[string]interface{}{"description": "Invalid parameters"},
						"401": map[string]interface{}{"description": "Unauthorized"},
					},
				},
			},
			"/api/config/list-models": map[string]interface{}{
				"post": map[string]interface{}{
					"tags":        []string{"Configuration Management"},
					"summary":     "Get Model List",
					"description": "The proxy calls OpenAI compatible GET / Models and returns the list of available models id. Claude does not support it.",
					"operationId": "listModels",
					"requestBody": map[string]interface{}{
						"required": true,
						"content": map[string]interface{}{
							"application/json": map[string]interface{}{
								"schema": map[string]interface{}{
									"type":     "object",
									"required": []string{"api_key"},
									"properties": map[string]interface{}{
										"provider": map[string]interface{}{"type": "string", "description": "LLM provider (openai/claude)", "example": "openai"},
										"base_url": map[string]interface{}{"type": "string", "description": "API base address (optional)"},
										"api_key":  map[string]interface{}{"type": "string", "description": "API Key"},
									},
								},
							},
						},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Get results",
							"content": map[string]interface{}{
								"application/json": map[string]interface{}{
									"schema": map[string]interface{}{
										"type": "object",
										"properties": map[string]interface{}{
											"success":   map[string]interface{}{"type": "boolean"},
											"supported": map[string]interface{}{"type": "boolean"},
											"error":     map[string]interface{}{"type": "string"},
											"models":    map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "string"}},
											"count":     map[string]interface{}{"type": "integer"},
										},
									},
								},
							},
						},
						"400": map[string]interface{}{"description": "Invalid parameters"},
						"401": map[string]interface{}{"description": "Unauthorized"},
					},
				},
			},

			// ==================== 终端 ====================
			"/api/terminal/run": map[string]interface{}{
				"post": map[string]interface{}{
					"tags":        []string{"Terminal"},
					"summary":     "Execute terminal commands",
					"description": "Execute Shell commands on the server and return the results.",
					"operationId": "terminalRun",
					"requestBody": map[string]interface{}{
						"required": true,
						"content": map[string]interface{}{
							"application/json": map[string]interface{}{
								"schema": map[string]interface{}{
									"type":     "object",
									"required": []string{"command"},
									"properties": map[string]interface{}{
										"command": map[string]interface{}{"type": "string", "description": "Command to execute"},
										"shell":   map[string]interface{}{"type": "string", "description": "Shell type (default sh/cmd)"},
										"cwd":     map[string]interface{}{"type": "string", "description": "Work Directory (optional)"},
									},
								},
							},
						},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Execution completed",
							"content": map[string]interface{}{
								"application/json": map[string]interface{}{
									"schema": map[string]interface{}{
										"type": "object",
										"properties": map[string]interface{}{
											"stdout":    map[string]interface{}{"type": "string", "description": "Standard Output"},
											"stderr":    map[string]interface{}{"type": "string", "description": "Standard error"},
											"exit_code": map[string]interface{}{"type": "integer", "description": "Exit Code"},
											"error":     map[string]interface{}{"type": "string", "description": "Execution error (optional)"},
										},
									},
								},
							},
						},
						"401": map[string]interface{}{"description": "Unauthorized"},
					},
				},
			},
			"/api/terminal/run/stream": map[string]interface{}{
				"post": map[string]interface{}{
					"tags":        []string{"Terminal"},
					"summary":     "Run terminal command (stream)",
					"description": "Here. SSE Fluid execution Shell Command, Return output in real time.Organisation JSON: {\"t\": \"out\"|\"err\"|\"exit\", \"d\": \"Data\", \"c\": Exit Code}",
					"operationId": "terminalRunStream",
					"requestBody": map[string]interface{}{
						"required": true,
						"content": map[string]interface{}{
							"application/json": map[string]interface{}{
								"schema": map[string]interface{}{
									"type":     "object",
									"required": []string{"command"},
									"properties": map[string]interface{}{
										"command": map[string]interface{}{"type": "string", "description": "Command to execute"},
										"shell":   map[string]interface{}{"type": "string", "description": "Shell type (default sh/cmd)"},
										"cwd":     map[string]interface{}{"type": "string", "description": "Work Directory (optional)"},
									},
								},
							},
						},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "SSE event stream",
							"content": map[string]interface{}{
								"text/event-stream": map[string]interface{}{
									"schema": map[string]interface{}{
										"type":        "string",
										"description": "Server-Sent Events Stream, Every event is JSON: {\"t\":\"out|err|exit\",\"d\":\"data\",\"c\":exitCode}",
									},
								},
							},
						},
						"401": map[string]interface{}{"description": "Unauthorized"},
					},
				},
			},
			"/api/terminal/ws": map[string]interface{}{
				"get": map[string]interface{}{
					"tags":        []string{"Terminal"},
					"summary":     "WebSocket terminal",
					"description": "through WebSocket Create interactive terminal connections, Support PTY.Client Send text/Binary data entered as command, It can also be sent JSON: {\"type\":\"resize\",\"cols\":80,\"rows\":24} Resize Terminal.Service returns binary PTY Output.",
					"operationId": "terminalWS",
					"responses": map[string]interface{}{
						"101": map[string]interface{}{"description": "WebSocket connection established"},
						"401": map[string]interface{}{"description": "Unauthorized"},
					},
				},
			},

			// ==================== WebShell管理 ====================
			"/api/webshell/connections": map[string]interface{}{
				"get": map[string]interface{}{
					"tags":        []string{"WebShell Management"},
					"summary":     "List WebShell connections",
					"description": "Fetches the list of all saved WebShell connections.",
					"operationId": "listWebshellConnections",
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Success",
							"content": map[string]interface{}{
								"application/json": map[string]interface{}{
									"schema": map[string]interface{}{
										"type": "array",
										"items": map[string]interface{}{
											"type": "object",
											"properties": map[string]interface{}{
												"id":         map[string]interface{}{"type": "string", "description": "Connect ID"},
												"url":        map[string]interface{}{"type": "string", "description": "WebShell URL"},
												"password":   map[string]interface{}{"type": "string", "description": "Connect Password"},
												"type":       map[string]interface{}{"type": "string", "description": "Shell Type", "enum": []string{"php", "asp", "aspx", "jsp", "custom"}},
												"method":     map[string]interface{}{"type": "string", "description": "Method of request", "enum": []string{"get", "post"}},
												"cmd_param":  map[string]interface{}{"type": "string", "description": "Command parameter name"},
												"remark":     map[string]interface{}{"type": "string", "description": "Notes"},
												"created_at": map[string]interface{}{"type": "string", "format": "date-time"},
											},
										},
									},
								},
							},
						},
						"401": map[string]interface{}{"description": "Unauthorized"},
					},
				},
				"post": map[string]interface{}{
					"tags":        []string{"WebShell Management"},
					"summary":     "Create WebShell connection",
					"description": "Saves a new WebShell connection configuration.",
					"operationId": "createWebshellConnection",
					"requestBody": map[string]interface{}{
						"required": true,
						"content": map[string]interface{}{
							"application/json": map[string]interface{}{
								"schema": map[string]interface{}{
									"type":     "object",
									"required": []string{"url"},
									"properties": map[string]interface{}{
										"url":       map[string]interface{}{"type": "string", "description": "WebShell URL"},
										"password":  map[string]interface{}{"type": "string", "description": "Connect Password"},
										"type":      map[string]interface{}{"type": "string", "description": "Shell Type", "enum": []string{"php", "asp", "aspx", "jsp", "custom"}},
										"method":    map[string]interface{}{"type": "string", "description": "Method of request", "enum": []string{"get", "post"}},
										"cmd_param": map[string]interface{}{"type": "string", "description": "Command parameter name"},
										"remark":    map[string]interface{}{"type": "string", "description": "Notes"},
									},
								},
							},
						},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{"description": "Created successfully"},
						"400": map[string]interface{}{"description": "Invalid parameters"},
						"401": map[string]interface{}{"description": "Unauthorized"},
					},
				},
			},
			"/api/webshell/connections/{id}": map[string]interface{}{
				"put": map[string]interface{}{
					"tags":        []string{"WebShell Management"},
					"summary":     "Update WebShell connection",
					"description": "Updates the existing WebShell connection configuration.",
					"operationId": "updateWebshellConnection",
					"parameters": []map[string]interface{}{
						{"name": "id", "in": "path", "required": true, "description": "Connect ID", "schema": map[string]interface{}{"type": "string"}},
					},
					"requestBody": map[string]interface{}{
						"required": true,
						"content": map[string]interface{}{
							"application/json": map[string]interface{}{
								"schema": map[string]interface{}{
									"type": "object",
									"properties": map[string]interface{}{
										"url":       map[string]interface{}{"type": "string"},
										"password":  map[string]interface{}{"type": "string"},
										"type":      map[string]interface{}{"type": "string", "enum": []string{"php", "asp", "aspx", "jsp", "custom"}},
										"method":    map[string]interface{}{"type": "string", "enum": []string{"get", "post"}},
										"cmd_param": map[string]interface{}{"type": "string"},
										"remark":    map[string]interface{}{"type": "string"},
									},
								},
							},
						},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{"description": "Updated successfully"},
						"401": map[string]interface{}{"description": "Unauthorized"},
						"404": map[string]interface{}{"description": "Connection not found"},
					},
				},
				"delete": map[string]interface{}{
					"tags":        []string{"WebShell Management"},
					"summary":     "Delete WebShell connection",
					"description": "Deletes the specified WebShell connection configuration.",
					"operationId": "deleteWebshellConnection",
					"parameters": []map[string]interface{}{
						{"name": "id", "in": "path", "required": true, "description": "Connect ID", "schema": map[string]interface{}{"type": "string"}},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{"description": "Deleted successfully"},
						"401": map[string]interface{}{"description": "Unauthorized"},
						"404": map[string]interface{}{"description": "Connection not found"},
					},
				},
			},
			"/api/webshell/connections/{id}/state": map[string]interface{}{
				"get": map[string]interface{}{
					"tags":        []string{"WebShell Management"},
					"summary":     "Get connection state",
					"description": "Gets the saved status data for WebShell connection.",
					"operationId": "getWebshellConnectionState",
					"parameters": []map[string]interface{}{
						{"name": "id", "in": "path", "required": true, "description": "Connect ID", "schema": map[string]interface{}{"type": "string"}},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Success",
							"content": map[string]interface{}{
								"application/json": map[string]interface{}{
									"schema": map[string]interface{}{
										"type": "object",
										"properties": map[string]interface{}{
											"state": map[string]interface{}{"type": "object", "description": "Status Data (Advisory JSON)"},
										},
									},
								},
							},
						},
						"401": map[string]interface{}{"description": "Unauthorized"},
					},
				},
				"put": map[string]interface{}{
					"tags":        []string{"WebShell Management"},
					"summary":     "Save connection state",
					"description": "Saves the status data of WebShell connection.",
					"operationId": "saveWebshellConnectionState",
					"parameters": []map[string]interface{}{
						{"name": "id", "in": "path", "required": true, "description": "Connect ID", "schema": map[string]interface{}{"type": "string"}},
					},
					"requestBody": map[string]interface{}{
						"required": true,
						"content": map[string]interface{}{
							"application/json": map[string]interface{}{
								"schema": map[string]interface{}{
									"type": "object",
									"properties": map[string]interface{}{
										"state": map[string]interface{}{"type": "object", "description": "Status Data (Advisory JSON)"},
									},
								},
							},
						},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{"description": "Saved successfully"},
						"401": map[string]interface{}{"description": "Unauthorized"},
					},
				},
			},
			"/api/webshell/connections/{id}/ai-history": map[string]interface{}{
				"get": map[string]interface{}{
					"tags":        []string{"WebShell Management"},
					"summary":     "Get AI chat history",
					"description": "Get Assigned WebShell Connected AI Auxiliary dialogue history message.",
					"operationId": "getWebshellAIHistory",
					"parameters": []map[string]interface{}{
						{"name": "id", "in": "path", "required": true, "description": "Connect ID", "schema": map[string]interface{}{"type": "string"}},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Success",
							"content": map[string]interface{}{
								"application/json": map[string]interface{}{
									"schema": map[string]interface{}{
										"type": "object",
										"properties": map[string]interface{}{
											"conversationId": map[string]interface{}{"type": "string"},
											"messages": map[string]interface{}{
												"type": "array",
												"items": map[string]interface{}{
													"type": "object",
													"properties": map[string]interface{}{
														"id":        map[string]interface{}{"type": "string"},
														"role":      map[string]interface{}{"type": "string"},
														"content":   map[string]interface{}{"type": "string"},
														"createdAt": map[string]interface{}{"type": "string", "format": "date-time"},
													},
												},
											},
										},
									},
								},
							},
						},
						"401": map[string]interface{}{"description": "Unauthorized"},
					},
				},
			},
			"/api/webshell/connections/{id}/ai-conversations": map[string]interface{}{
				"get": map[string]interface{}{
					"tags":        []string{"WebShell Management"},
					"summary":     "List AI conversations",
					"description": "Fetches a list of all AI-assisted conversations that are specified for WebShell.",
					"operationId": "listWebshellAIConversations",
					"parameters": []map[string]interface{}{
						{"name": "id", "in": "path", "required": true, "description": "Connect ID", "schema": map[string]interface{}{"type": "string"}},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Success",
							"content": map[string]interface{}{
								"application/json": map[string]interface{}{
									"schema": map[string]interface{}{
										"type": "array",
										"items": map[string]interface{}{
											"type": "object",
											"properties": map[string]interface{}{
												"id":        map[string]interface{}{"type": "string"},
												"title":     map[string]interface{}{"type": "string"},
												"createdAt": map[string]interface{}{"type": "string", "format": "date-time"},
											},
										},
									},
								},
							},
						},
						"401": map[string]interface{}{"description": "Unauthorized"},
					},
				},
			},
			"/api/webshell/exec": map[string]interface{}{
				"post": map[string]interface{}{
					"tags":        []string{"WebShell Management"},
					"summary":     "Execute WebShell command",
					"description": "Executes a remote command by a specified WebShell connection.",
					"operationId": "webshellExec",
					"requestBody": map[string]interface{}{
						"required": true,
						"content": map[string]interface{}{
							"application/json": map[string]interface{}{
								"schema": map[string]interface{}{
									"type":     "object",
									"required": []string{"url", "command"},
									"properties": map[string]interface{}{
										"url":       map[string]interface{}{"type": "string", "description": "WebShell URL"},
										"password":  map[string]interface{}{"type": "string"},
										"type":      map[string]interface{}{"type": "string", "enum": []string{"php", "asp", "aspx", "jsp", "custom"}},
										"method":    map[string]interface{}{"type": "string", "enum": []string{"get", "post"}},
										"cmd_param": map[string]interface{}{"type": "string"},
										"command":   map[string]interface{}{"type": "string", "description": "Command to execute"},
									},
								},
							},
						},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Execution result",
							"content": map[string]interface{}{
								"application/json": map[string]interface{}{
									"schema": map[string]interface{}{
										"type": "object",
										"properties": map[string]interface{}{
											"ok":        map[string]interface{}{"type": "boolean"},
											"output":    map[string]interface{}{"type": "string", "description": "Command Output"},
											"error":     map[string]interface{}{"type": "string", "description": "Error info"},
											"http_code": map[string]interface{}{"type": "integer", "description": "HTTP Response Code"},
										},
									},
								},
							},
						},
						"401": map[string]interface{}{"description": "Unauthorized"},
					},
				},
			},
			"/api/webshell/file": map[string]interface{}{
				"post": map[string]interface{}{
					"tags":        []string{"WebShell Management"},
					"summary":     "WebShell file operation",
					"description": "Remote file operations (column directories, reading and writing files, creation of directories, renaming, deletion, uploading, etc.) through WebShell.",
					"operationId": "webshellFileOp",
					"requestBody": map[string]interface{}{
						"required": true,
						"content": map[string]interface{}{
							"application/json": map[string]interface{}{
								"schema": map[string]interface{}{
									"type":     "object",
									"required": []string{"url", "action", "path"},
									"properties": map[string]interface{}{
										"url":         map[string]interface{}{"type": "string", "description": "WebShell URL"},
										"password":    map[string]interface{}{"type": "string"},
										"type":        map[string]interface{}{"type": "string", "enum": []string{"php", "asp", "aspx", "jsp", "custom"}},
										"method":      map[string]interface{}{"type": "string", "enum": []string{"get", "post"}},
										"cmd_param":   map[string]interface{}{"type": "string"},
										"action":      map[string]interface{}{"type": "string", "description": "Operation Type", "enum": []string{"list", "read", "delete", "write", "mkdir", "rename", "upload", "upload_chunk"}},
										"path":        map[string]interface{}{"type": "string", "description": "Destination file/ directory path"},
										"target_path": map[string]interface{}{"type": "string", "description": "Destination Path (use when rename)"},
										"content":     map[string]interface{}{"type": "string", "description": "Document content (used in write/upload)"},
										"chunk_index": map[string]interface{}{"type": "integer", "description": "Block Index (used whenupload_chunk)"},
									},
								},
							},
						},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Operation result",
							"content": map[string]interface{}{
								"application/json": map[string]interface{}{
									"schema": map[string]interface{}{
										"type": "object",
										"properties": map[string]interface{}{
											"ok":     map[string]interface{}{"type": "boolean"},
											"output": map[string]interface{}{"type": "string"},
											"error":  map[string]interface{}{"type": "string"},
										},
									},
								},
							},
						},
						"401": map[string]interface{}{"description": "Unauthorized"},
					},
				},
			},

			// ==================== 对话附件 ====================
			"/api/chat-uploads": map[string]interface{}{
				"get": map[string]interface{}{
					"tags":        []string{"Chat uploads"},
					"summary":     "List uploads",
					"description": "Get a list of the dialogue files, including manually upload attachments, tool outputs and session products, which can be filtered by session, project, source, filename and page break.",
					"operationId": "listChatUploads",
					"parameters": []map[string]interface{}{
						{"name": "conversation", "in": "query", "required": false, "description": "Filter by Dialogue ID", "schema": map[string]interface{}{"type": "string"}},
						{"name": "project", "in": "query", "required": false, "description": "Filter by Item ID", "schema": map[string]interface{}{"type": "string"}},
						{"name": "source", "in": "query", "required": false, "description": "Filter by Source: upload/reduction/workspace/conversation_artifact/all", "schema": map[string]interface{}{"type": "string", "enum": []string{"all", "upload", "reduction", "workspace", "conversation_artifact"}}},
						{"name": "search", "in": "query", "required": false, "description": "Search by filename or subpath", "schema": map[string]interface{}{"type": "string"}},
						{"name": "page", "in": "query", "required": false, "description": "Page number, start with 1.", "schema": map[string]interface{}{"type": "integer", "default": 1}},
						{"name": "pageSize", "in": "query", "required": false, "description": "Number per page, Pass all Return All", "schema": map[string]interface{}{"oneOf": []map[string]interface{}{{"type": "integer"}, {"type": "string", "enum": []string{"all"}}}}},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Success",
							"content": map[string]interface{}{
								"application/json": map[string]interface{}{
									"schema": map[string]interface{}{
										"type": "object",
										"properties": map[string]interface{}{
											"files": map[string]interface{}{
												"type": "array",
												"items": map[string]interface{}{
													"type": "object",
													"properties": map[string]interface{}{
														"relativePath":      map[string]interface{}{"type": "string"},
														"absolutePath":      map[string]interface{}{"type": "string"},
														"name":              map[string]interface{}{"type": "string"},
														"size":              map[string]interface{}{"type": "integer"},
														"modifiedUnix":      map[string]interface{}{"type": "integer"},
														"date":              map[string]interface{}{"type": "string"},
														"conversationId":    map[string]interface{}{"type": "string"},
														"conversationTitle": map[string]interface{}{"type": "string"},
														"projectId":         map[string]interface{}{"type": "string"},
														"projectName":       map[string]interface{}{"type": "string"},
														"subPath":           map[string]interface{}{"type": "string"},
														"source":            map[string]interface{}{"type": "string", "description": "upload/reduction/workspace/conversation_artifact"},
													},
												},
											},
											"folders": map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "string"}},
											"total":   map[string]interface{}{"type": "integer"},
											"page":    map[string]interface{}{"type": "integer"},
											"pageSize": map[string]interface{}{
												"type": "integer",
											},
										},
									},
								},
							},
						},
						"401": map[string]interface{}{"description": "Unauthorized"},
					},
				},
				"post": map[string]interface{}{
					"tags":        []string{"Chat uploads"},
					"summary":     "Upload file",
					"description": "Uploads the document to the dialogue attachment directory (multipart/form-data).",
					"operationId": "uploadChatFile",
					"requestBody": map[string]interface{}{
						"required": true,
						"content": map[string]interface{}{
							"multipart/form-data": map[string]interface{}{
								"schema": map[string]interface{}{
									"type":     "object",
									"required": []string{"file"},
									"properties": map[string]interface{}{
										"file":           map[string]interface{}{"type": "string", "format": "binary", "description": "Uploading files"},
										"conversationId": map[string]interface{}{"type": "string", "description": "Linked Dialogue ID (optional)"},
										"relativeDir":    map[string]interface{}{"type": "string", "description": "Target directory relative path (optional)"},
									},
								},
							},
						},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Uploaded",
							"content": map[string]interface{}{
								"application/json": map[string]interface{}{
									"schema": map[string]interface{}{
										"type": "object",
										"properties": map[string]interface{}{
											"ok":           map[string]interface{}{"type": "boolean"},
											"relativePath": map[string]interface{}{"type": "string"},
											"absolutePath": map[string]interface{}{"type": "string"},
											"name":         map[string]interface{}{"type": "string"},
										},
									},
								},
							},
						},
						"401": map[string]interface{}{"description": "Unauthorized"},
					},
				},
				"delete": map[string]interface{}{
					"tags":        []string{"Chat uploads"},
					"summary":     "Delete upload",
					"description": "Delete the designated dialogue attachment document.",
					"operationId": "deleteChatUpload",
					"requestBody": map[string]interface{}{
						"required": true,
						"content": map[string]interface{}{
							"application/json": map[string]interface{}{
								"schema": map[string]interface{}{
									"type":     "object",
									"required": []string{"path"},
									"properties": map[string]interface{}{
										"path": map[string]interface{}{"type": "string", "description": "File relative path"},
									},
								},
							},
						},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{"description": "Deleted successfully"},
						"401": map[string]interface{}{"description": "Unauthorized"},
					},
				},
			},
			"/api/chat-uploads/export": map[string]interface{}{
				"get": map[string]interface{}{
					"tags":        []string{"Chat uploads"},
					"summary":     "Export uploads",
					"description": "Export dialog files to current filter conditions ZIP, Organisation manifest.json.",
					"operationId": "exportChatUploads",
					"parameters": []map[string]interface{}{
						{"name": "conversation", "in": "query", "required": false, "description": "Filter by Dialogue ID", "schema": map[string]interface{}{"type": "string"}},
						{"name": "project", "in": "query", "required": false, "description": "Filter by Item ID", "schema": map[string]interface{}{"type": "string"}},
						{"name": "source", "in": "query", "required": false, "description": "Filter by Source: upload/reduction/workspace/conversation_artifact/all", "schema": map[string]interface{}{"type": "string", "enum": []string{"all", "upload", "reduction", "workspace", "conversation_artifact"}}},
						{"name": "search", "in": "query", "required": false, "description": "Search by filename or subpath", "schema": map[string]interface{}{"type": "string"}},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "ZIP file download",
							"content": map[string]interface{}{
								"application/zip": map[string]interface{}{
									"schema": map[string]interface{}{"type": "string", "format": "binary"},
								},
							},
						},
						"401": map[string]interface{}{"description": "Unauthorized"},
					},
				},
			},
			"/api/chat-uploads/download": map[string]interface{}{
				"get": map[string]interface{}{
					"tags":        []string{"Chat uploads"},
					"summary":     "Download upload",
					"description": "Downloads a specified dialogue attachment document.",
					"operationId": "downloadChatUpload",
					"parameters": []map[string]interface{}{
						{"name": "path", "in": "query", "required": true, "description": "File relative path", "schema": map[string]interface{}{"type": "string"}},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "File download",
							"content": map[string]interface{}{
								"application/octet-stream": map[string]interface{}{
									"schema": map[string]interface{}{"type": "string", "format": "binary"},
								},
							},
						},
						"401": map[string]interface{}{"description": "Unauthorized"},
						"404": map[string]interface{}{"description": "File not found"},
					},
				},
			},
			"/api/chat-uploads/path": map[string]interface{}{
				"get": map[string]interface{}{
					"tags":        []string{"Chat uploads"},
					"summary":     "Parsing Attachment Path",
					"description": "Resolves the relative or internal virtual path of file management as the absolute path of the server for copying the file/director path.",
					"operationId": "resolveChatUploadPath",
					"parameters": []map[string]interface{}{
						{"name": "path", "in": "query", "required": true, "description": "Relative or virtual path (for example __workspace__/projects/<id>/csv) ", "schema": map[string]interface{}{"type": "string"}},
						{"name": "kind", "in": "query", "required": false, "description": "Path type: file/directory, default file", "schema": map[string]interface{}{"type": "string", "enum": []string{"file", "directory"}}},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Parse successful",
							"content": map[string]interface{}{
								"application/json": map[string]interface{}{
									"schema": map[string]interface{}{
										"type": "object",
										"properties": map[string]interface{}{
											"absolutePath": map[string]interface{}{"type": "string"},
											"isDir":        map[string]interface{}{"type": "boolean"},
										},
									},
								},
							},
						},
						"401": map[string]interface{}{"description": "Unauthorized"},
						"403": map[string]interface{}{"description": "No access."},
						"404": map[string]interface{}{"description": "Path does not exist"},
					},
				},
			},
			"/api/chat-uploads/content": map[string]interface{}{
				"get": map[string]interface{}{
					"tags":        []string{"Chat uploads"},
					"summary":     "Get file text content",
					"description": "Reads and returns the contents of a text file.",
					"operationId": "getChatUploadContent",
					"parameters": []map[string]interface{}{
						{"name": "path", "in": "query", "required": true, "description": "File relative path", "schema": map[string]interface{}{"type": "string"}},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Success",
							"content": map[string]interface{}{
								"application/json": map[string]interface{}{
									"schema": map[string]interface{}{
										"type": "object",
										"properties": map[string]interface{}{
											"content": map[string]interface{}{"type": "string", "description": "Document text"},
										},
									},
								},
							},
						},
						"401": map[string]interface{}{"description": "Unauthorized"},
						"404": map[string]interface{}{"description": "File not found"},
					},
				},
				"put": map[string]interface{}{
					"tags":        []string{"Chat uploads"},
					"summary":     "Write file text content",
					"description": "Writes or overwrites the contents of a text file.",
					"operationId": "putChatUploadContent",
					"requestBody": map[string]interface{}{
						"required": true,
						"content": map[string]interface{}{
							"application/json": map[string]interface{}{
								"schema": map[string]interface{}{
									"type":     "object",
									"required": []string{"path", "content"},
									"properties": map[string]interface{}{
										"path":    map[string]interface{}{"type": "string", "description": "File relative path"},
										"content": map[string]interface{}{"type": "string", "description": "Document text"},
									},
								},
							},
						},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{"description": "Written successfully"},
						"401": map[string]interface{}{"description": "Unauthorized"},
					},
				},
			},
			"/api/chat-uploads/mkdir": map[string]interface{}{
				"post": map[string]interface{}{
					"tags":        []string{"Chat uploads"},
					"summary":     "Create upload directory",
					"description": "Creates a subdirectorial under the dialogue annex directory.",
					"operationId": "mkdirChatUpload",
					"requestBody": map[string]interface{}{
						"required": true,
						"content": map[string]interface{}{
							"application/json": map[string]interface{}{
								"schema": map[string]interface{}{
									"type":     "object",
									"required": []string{"name"},
									"properties": map[string]interface{}{
										"parent": map[string]interface{}{"type": "string", "description": "Parent directory relative path"},
										"name":   map[string]interface{}{"type": "string", "description": "Directory Name"},
									},
								},
							},
						},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Created successfully",
							"content": map[string]interface{}{
								"application/json": map[string]interface{}{
									"schema": map[string]interface{}{
										"type": "object",
										"properties": map[string]interface{}{
											"ok":           map[string]interface{}{"type": "boolean"},
											"relativePath": map[string]interface{}{"type": "string"},
										},
									},
								},
							},
						},
						"401": map[string]interface{}{"description": "Unauthorized"},
					},
				},
			},
			"/api/chat-uploads/rename": map[string]interface{}{
				"put": map[string]interface{}{
					"tags":        []string{"Chat uploads"},
					"summary":     "Rename upload",
					"description": "Renames the dialogue attachment file or directory.",
					"operationId": "renameChatUpload",
					"requestBody": map[string]interface{}{
						"required": true,
						"content": map[string]interface{}{
							"application/json": map[string]interface{}{
								"schema": map[string]interface{}{
									"type":     "object",
									"required": []string{"path", "newName"},
									"properties": map[string]interface{}{
										"path":    map[string]interface{}{"type": "string", "description": "Current file relative path"},
										"newName": map[string]interface{}{"type": "string", "description": "New name"},
									},
								},
							},
						},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Renamed successfully",
							"content": map[string]interface{}{
								"application/json": map[string]interface{}{
									"schema": map[string]interface{}{
										"type": "object",
										"properties": map[string]interface{}{
											"ok":           map[string]interface{}{"type": "boolean"},
											"relativePath": map[string]interface{}{"type": "string"},
										},
									},
								},
							},
						},
						"401": map[string]interface{}{"description": "Unauthorized"},
					},
				},
			},

			// ==================== 机器人集成 ====================
			"/api/robot/wecom": map[string]interface{}{
				"get": map[string]interface{}{
					"tags":        []string{"Robot Integration"},
					"summary":     "WeCom callback verification",
					"description": "The URL of the enterprise's micro-credit server validates the callback (for configuration of the message receiving address).",
					"operationId": "wecomCallbackVerify",
					"security":    []map[string]interface{}{},
					"parameters": []map[string]interface{}{
						{"name": "msg_signature", "in": "query", "required": true, "schema": map[string]interface{}{"type": "string"}},
						{"name": "timestamp", "in": "query", "required": true, "schema": map[string]interface{}{"type": "string"}},
						{"name": "nonce", "in": "query", "required": true, "schema": map[string]interface{}{"type": "string"}},
						{"name": "echostr", "in": "query", "required": true, "schema": map[string]interface{}{"type": "string"}},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{"description": "Verification successful, decrypted echostr returned"},
					},
				},
				"post": map[string]interface{}{
					"tags":        []string{"Robot Integration"},
					"summary":     "WeCom message callback",
					"description": "Receives a tweet from the enterprise.",
					"operationId": "wecomCallbackMessage",
					"security":    []map[string]interface{}{},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{"description": "Processed successfully"},
					},
				},
			},
			"/api/robot/dingtalk": map[string]interface{}{
				"post": map[string]interface{}{
					"tags":        []string{"Robot Integration"},
					"summary":     "DingTalk message callback",
					"description": "You can receive the news from the nails. You need no authentication, call from the nail server.",
					"operationId": "dingtalkCallback",
					"security":    []map[string]interface{}{},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{"description": "Processed successfully"},
					},
				},
			},
			"/api/robot/lark": map[string]interface{}{
				"post": map[string]interface{}{
					"tags":        []string{"Robot Integration"},
					"summary":     "Lark message callback",
					"description": "Receives the news from the flyer book.",
					"operationId": "larkCallback",
					"security":    []map[string]interface{}{},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{"description": "Processed successfully"},
					},
				},
			},
			"/api/robot/test": map[string]interface{}{
				"post": map[string]interface{}{
					"tags":        []string{"Robot Integration"},
					"summary":     "Test robot message processing",
					"description": "Simulates a robotic message process for debugging and validation.",
					"operationId": "testRobot",
					"requestBody": map[string]interface{}{
						"required": true,
						"content": map[string]interface{}{
							"application/json": map[string]interface{}{
								"schema": map[string]interface{}{
									"type":     "object",
									"required": []string{"platform", "text"},
									"properties": map[string]interface{}{
										"platform": map[string]interface{}{"type": "string", "description": "Platform Type", "enum": []string{"dingtalk", "lark", "wecom"}},
										"user_id":  map[string]interface{}{"type": "string", "description": "Simulate User ID", "example": "test"},
										"text":     map[string]interface{}{"type": "string", "description": "Message Text", "example": "Help"},
									},
								},
							},
						},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{"description": "Processed successfully"},
						"401": map[string]interface{}{"description": "Unauthorized"},
					},
				},
			},

			// ==================== 多代理Markdown ====================
			"/api/multi-agent/markdown-agents": map[string]interface{}{
				"get": map[string]interface{}{
					"tags":        []string{"Markdown Agents"},
					"summary":     "List Markdown agents",
					"description": "Get All Multiple Agents Markdown Define File List.",
					"operationId": "listMarkdownAgents",
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Success",
							"content": map[string]interface{}{
								"application/json": map[string]interface{}{
									"schema": map[string]interface{}{
										"type": "object",
										"properties": map[string]interface{}{
											"agents": map[string]interface{}{
												"type": "array",
												"items": map[string]interface{}{
													"type": "object",
													"properties": map[string]interface{}{
														"filename":        map[string]interface{}{"type": "string", "description": "Name"},
														"id":              map[string]interface{}{"type": "string", "description": "Proxy ID"},
														"name":            map[string]interface{}{"type": "string", "description": "Proxy Name"},
														"description":     map[string]interface{}{"type": "string", "description": "Proxy Description"},
														"is_orchestrator": map[string]interface{}{"type": "boolean", "description": "Whether or not to be a organiser"},
														"kind":            map[string]interface{}{"type": "string", "description": "Organization Type"},
													},
												},
											},
											"dir": map[string]interface{}{"type": "string", "description": "Proxy-Definition Directory Path"},
										},
									},
								},
							},
						},
						"401": map[string]interface{}{"description": "Unauthorized"},
					},
				},
				"post": map[string]interface{}{
					"tags":        []string{"Markdown Agents"},
					"summary":     "Create Markdown agent",
					"description": "Creates a new multi-agent Markdown definition file.",
					"operationId": "createMarkdownAgent",
					"requestBody": map[string]interface{}{
						"required": true,
						"content": map[string]interface{}{
							"application/json": map[string]interface{}{
								"schema": map[string]interface{}{
									"type":     "object",
									"required": []string{"name"},
									"properties": map[string]interface{}{
										"filename":       map[string]interface{}{"type": "string", "description": "Filename (optional, automatic)"},
										"id":             map[string]interface{}{"type": "string", "description": "Proxy ID"},
										"name":           map[string]interface{}{"type": "string", "description": "Proxy Name"},
										"description":    map[string]interface{}{"type": "string", "description": "Proxy Description"},
										"tools":          map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "string"}, "description": "List of available tools"},
										"instruction":    map[string]interface{}{"type": "string", "description": "Proxy Command"},
										"bind_role":      map[string]interface{}{"type": "string", "description": "Bind the role."},
										"max_iterations": map[string]interface{}{"type": "integer", "description": "Max iterations"},
										"kind":           map[string]interface{}{"type": "string", "description": "Organization Type"},
										"raw":            map[string]interface{}{"type": "string", "description": "Original Markdown Content"},
									},
								},
							},
						},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Created successfully",
							"content": map[string]interface{}{
								"application/json": map[string]interface{}{
									"schema": map[string]interface{}{
										"type": "object",
										"properties": map[string]interface{}{
											"filename": map[string]interface{}{"type": "string"},
											"message":  map[string]interface{}{"type": "string", "example": "Created"},
										},
									},
								},
							},
						},
						"400": map[string]interface{}{"description": "Invalid parameters"},
						"401": map[string]interface{}{"description": "Unauthorized"},
					},
				},
			},
			"/api/multi-agent/markdown-agents/{filename}": map[string]interface{}{
				"get": map[string]interface{}{
					"tags":        []string{"Markdown Agents"},
					"summary":     "Get Markdown agent detail",
					"description": "Get Assigned Markdown Details of the proxy definition document.",
					"operationId": "getMarkdownAgent",
					"parameters": []map[string]interface{}{
						{"name": "filename", "in": "path", "required": true, "description": "Name", "schema": map[string]interface{}{"type": "string"}},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Success",
							"content": map[string]interface{}{
								"application/json": map[string]interface{}{
									"schema": map[string]interface{}{
										"type": "object",
										"properties": map[string]interface{}{
											"filename":        map[string]interface{}{"type": "string"},
											"raw":             map[string]interface{}{"type": "string", "description": "Original Markdown Content"},
											"id":              map[string]interface{}{"type": "string"},
											"name":            map[string]interface{}{"type": "string"},
											"description":     map[string]interface{}{"type": "string"},
											"tools":           map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "string"}},
											"instruction":     map[string]interface{}{"type": "string"},
											"bind_role":       map[string]interface{}{"type": "string"},
											"max_iterations":  map[string]interface{}{"type": "integer"},
											"kind":            map[string]interface{}{"type": "string"},
											"is_orchestrator": map[string]interface{}{"type": "boolean"},
										},
									},
								},
							},
						},
						"401": map[string]interface{}{"description": "Unauthorized"},
						"404": map[string]interface{}{"description": "Agent not found"},
					},
				},
				"put": map[string]interface{}{
					"tags":        []string{"Markdown Agents"},
					"summary":     "Update Markdown agent",
					"description": "Updates the designated Markdown proxy definition.",
					"operationId": "updateMarkdownAgent",
					"parameters": []map[string]interface{}{
						{"name": "filename", "in": "path", "required": true, "description": "Name", "schema": map[string]interface{}{"type": "string"}},
					},
					"requestBody": map[string]interface{}{
						"required": true,
						"content": map[string]interface{}{
							"application/json": map[string]interface{}{
								"schema": map[string]interface{}{
									"type": "object",
									"properties": map[string]interface{}{
										"name":           map[string]interface{}{"type": "string"},
										"description":    map[string]interface{}{"type": "string"},
										"tools":          map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "string"}},
										"instruction":    map[string]interface{}{"type": "string"},
										"bind_role":      map[string]interface{}{"type": "string"},
										"max_iterations": map[string]interface{}{"type": "integer"},
										"kind":           map[string]interface{}{"type": "string"},
										"raw":            map[string]interface{}{"type": "string"},
									},
								},
							},
						},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Updated successfully",
							"content": map[string]interface{}{
								"application/json": map[string]interface{}{
									"schema": map[string]interface{}{
										"type": "object",
										"properties": map[string]interface{}{
											"message": map[string]interface{}{"type": "string", "example": "Saved"},
										},
									},
								},
							},
						},
						"401": map[string]interface{}{"description": "Unauthorized"},
						"404": map[string]interface{}{"description": "Agent not found"},
					},
				},
				"delete": map[string]interface{}{
					"tags":        []string{"Markdown Agents"},
					"summary":     "Delete Markdown agent",
					"description": "Deletes the designated Markdown proxy definition file.",
					"operationId": "deleteMarkdownAgent",
					"parameters": []map[string]interface{}{
						{"name": "filename", "in": "path", "required": true, "description": "Name", "schema": map[string]interface{}{"type": "string"}},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Deleted successfully",
							"content": map[string]interface{}{
								"application/json": map[string]interface{}{
									"schema": map[string]interface{}{
										"type": "object",
										"properties": map[string]interface{}{
											"message": map[string]interface{}{"type": "string", "example": "Deleted"},
										},
									},
								},
							},
						},
						"401": map[string]interface{}{"description": "Unauthorized"},
						"404": map[string]interface{}{"description": "Agent not found"},
					},
				},
			},

			// ==================== Skills管理 - 缺失端点 ====================
			"/api/skills/{name}/files": map[string]interface{}{
				"get": map[string]interface{}{
					"tags":        []string{"Skills Management"},
					"summary":     "List skill package files",
					"description": "Gets a list of all files under the specified skill kit directory.",
					"operationId": "listSkillPackageFiles",
					"parameters": []map[string]interface{}{
						{"name": "name", "in": "path", "required": true, "description": "Name of skills/ID", "schema": map[string]interface{}{"type": "string"}},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Success",
							"content": map[string]interface{}{
								"application/json": map[string]interface{}{
									"schema": map[string]interface{}{
										"type": "object",
										"properties": map[string]interface{}{
											"files": map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "string"}, "description": "File Path List"},
										},
									},
								},
							},
						},
						"401": map[string]interface{}{"description": "Unauthorized"},
						"404": map[string]interface{}{"description": "Skills don't exist."},
					},
				},
			},
			"/api/skills/{name}/file": map[string]interface{}{
				"get": map[string]interface{}{
					"tags":        []string{"Skills Management"},
					"summary":     "Get skill package file content",
					"description": "Reads the contents of the document specified in the skill package.",
					"operationId": "getSkillPackageFile",
					"parameters": []map[string]interface{}{
						{"name": "name", "in": "path", "required": true, "description": "Name of skills/ID", "schema": map[string]interface{}{"type": "string"}},
						{"name": "path", "in": "query", "required": true, "description": "File relative path", "schema": map[string]interface{}{"type": "string"}},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Success",
							"content": map[string]interface{}{
								"application/json": map[string]interface{}{
									"schema": map[string]interface{}{
										"type": "object",
										"properties": map[string]interface{}{
											"path":    map[string]interface{}{"type": "string", "description": "File Path"},
											"content": map[string]interface{}{"type": "string", "description": "Document contents"},
										},
									},
								},
							},
						},
						"401": map[string]interface{}{"description": "Unauthorized"},
						"404": map[string]interface{}{"description": "File not found"},
					},
				},
				"put": map[string]interface{}{
					"tags":        []string{"Skills Management"},
					"summary":     "Write skill package file",
					"description": "Writes or updates the contents of the documents in the skill pack.",
					"operationId": "putSkillPackageFile",
					"parameters": []map[string]interface{}{
						{"name": "name", "in": "path", "required": true, "description": "Name of skills/ID", "schema": map[string]interface{}{"type": "string"}},
					},
					"requestBody": map[string]interface{}{
						"required": true,
						"content": map[string]interface{}{
							"application/json": map[string]interface{}{
								"schema": map[string]interface{}{
									"type":     "object",
									"required": []string{"path"},
									"properties": map[string]interface{}{
										"path":    map[string]interface{}{"type": "string", "description": "File relative path"},
										"content": map[string]interface{}{"type": "string", "description": "Document contents"},
									},
								},
							},
						},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Saved successfully",
							"content": map[string]interface{}{
								"application/json": map[string]interface{}{
									"schema": map[string]interface{}{
										"type": "object",
										"properties": map[string]interface{}{
											"message": map[string]interface{}{"type": "string", "example": "saved"},
											"path":    map[string]interface{}{"type": "string"},
										},
									},
								},
							},
						},
						"401": map[string]interface{}{"description": "Unauthorized"},
					},
				},
			},

			// ==================== 监控 - 缺失端点 ====================
			"/api/monitor/executions/names": map[string]interface{}{
				"post": map[string]interface{}{
					"tags":        []string{"Monitoring"},
					"summary":     "Batch get tool names",
					"description": "Retrieving the corresponding tool name according to the implementation ID list batch and eliminating the front-end N+1 request.",
					"operationId": "batchGetToolNames",
					"requestBody": map[string]interface{}{
						"required": true,
						"content": map[string]interface{}{
							"application/json": map[string]interface{}{
								"schema": map[string]interface{}{
									"type":     "object",
									"required": []string{"ids"},
									"properties": map[string]interface{}{
										"ids": map[string]interface{}{
											"type":        "array",
											"items":       map[string]interface{}{"type": "string"},
											"description": "Execute Record ID List",
										},
									},
								},
							},
						},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Successfully returned map of ID to tool name",
							"content": map[string]interface{}{
								"application/json": map[string]interface{}{
									"schema": map[string]interface{}{
										"type":                 "object",
										"additionalProperties": map[string]interface{}{"type": "string"},
										"description":          "Key for ID, value as tool name",
										"example":              map[string]interface{}{"exec-001": "nmap", "exec-002": "sqlmap"},
									},
								},
							},
						},
						"400": map[string]interface{}{"description": "Invalid parameters"},
						"401": map[string]interface{}{"description": "Unauthorized"},
					},
				},
			},

			// ==================== 知识库 - 缺失端点 ====================
			"/api/knowledge/stats": map[string]interface{}{
				"get": map[string]interface{}{
					"tags":        []string{"Knowledge Base"},
					"summary":     "Get knowledge base stats",
					"description": "Overall statistical information on the knowledge base, including the number of classifications and entries.",
					"operationId": "getKnowledgeStats",
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Success",
							"content": map[string]interface{}{
								"application/json": map[string]interface{}{
									"schema": map[string]interface{}{
										"type": "object",
										"properties": map[string]interface{}{
											"enabled":          map[string]interface{}{"type": "boolean", "description": "Whether the knowledge base is enabled"},
											"total_categories": map[string]interface{}{"type": "integer", "description": "Total number of categories"},
											"total_items":      map[string]interface{}{"type": "integer", "description": "Total number of entries"},
										},
									},
								},
							},
						},
						"401": map[string]interface{}{"description": "Unauthorized"},
					},
				},
			},

			"/api/mcp": map[string]interface{}{
				"post": map[string]interface{}{
					"tags":        []string{"MCP"},
					"summary":     "MCP endpoint",
					"description": "MCP (Model Context Protocol) endpoint for processing requests for MCP agreements.\n** Terms of reference**:\nThis endpoint follows JSON-RPC 2.0 and supports the following methods:\n**1. initialize** - Initialize MCP connection\n```json\n{\n  \"jsonrpc\": \"2.0\",\n  \"id\": \"init-1\",\n  \"method\": \"initialize\",\n  \"params\": {\n    \"protocolVersion\": \"2024-11-05\",\n    \"capabilities\": {},\n    \"clientInfo\": {\n      \"name\": \"MyClient\",\n      \"version\": \"1.0.0\"\n    }\n  }\n}\n```\n**2. tools/list** - List all available tools\n```json\n{\n  \"jsonrpc\": \"2.0\",\n  \"id\": \"list-1\",\n  \"method\": \"tools/list\",\n  \"params\": {}\n}\n```\n**3. tools/call** - Call tool\n```json\n{\n  \"jsonrpc\": \"2.0\",\n  \"id\": \"call-1\",\n  \"method\": \"tools/call\",\n  \"params\": {\n    \"name\": \"nmap\",\n    \"arguments\": {\n      \"target\": \"192.168.1.1\",\n      \"ports\": \"80,443\"\n    }\n  }\n}\n```\n**4. prompts/list** - List all hint templates\n```json\n{\n  \"jsonrpc\": \"2.0\",\n  \"id\": \"prompts-list-1\",\n  \"method\": \"prompts/list\",\n  \"params\": {}\n}\n```\n**5. prompts/get** - Gettips template\n```json\n{\n  \"jsonrpc\": \"2.0\",\n  \"id\": \"prompt-get-1\",\n  \"method\": \"prompts/get\",\n  \"params\": {\n    \"name\": \"prompt-name\",\n    \"arguments\": {}\n  }\n}\n```\n**6. resources/list** - List all resources\n```json\n{\n  \"jsonrpc\": \"2.0\",\n  \"id\": \"resources-list-1\",\n  \"method\": \"resources/list\",\n  \"params\": {}\n}\n```\n**7. resources/read** - Read resource content\n```json\n{\n  \"jsonrpc\": \"2.0\",\n  \"id\": \"resource-read-1\",\n  \"method\": \"resources/read\",\n  \"params\": {\n    \"uri\": \"resource://example\"\n  }\n}\n```\n**Application of the wrong code**:\n- `-32700`: Parse error - JSON Parsing Error\n- `-32600`: Invalid Request - Invalid request\n- `-32601`: Method not found - Method does not exist\n- `-32602`: Invalid params - Invalid Parameter\n- `-32603`: Internal error - Internal error",
					"operationId": "mcpEndpoint",
					"requestBody": map[string]interface{}{
						"required": true,
						"content": map[string]interface{}{
							"application/json": map[string]interface{}{
								"schema": map[string]interface{}{
									"$ref": "#/components/schemas/MCPMessage",
								},
								"examples": map[string]interface{}{
									"listTools": map[string]interface{}{
										"summary":     "List all tools",
										"description": "A list of all available MCP tools in the system",
										"value": map[string]interface{}{
											"jsonrpc": "2.0",
											"id":      "list-tools-1",
											"method":  "tools/list",
											"params":  map[string]interface{}{},
										},
									},
									"callTool": map[string]interface{}{
										"summary":     "Invoke tool",
										"description": "Call specified MCP tool",
										"value": map[string]interface{}{
											"jsonrpc": "2.0",
											"id":      "call-tool-1",
											"method":  "tools/call",
											"params": map[string]interface{}{
												"name": "nmap",
												"arguments": map[string]interface{}{
													"target": "192.168.1.1",
													"ports":  "80,443",
												},
											},
										},
									},
									"initialize": map[string]interface{}{
										"summary":     "Initialize connection",
										"description": "Initialize MCP connections and acquire server capabilities",
										"value": map[string]interface{}{
											"jsonrpc": "2.0",
											"id":      "init-1",
											"method":  "initialize",
											"params": map[string]interface{}{
												"protocolVersion": "2024-11-05",
												"capabilities":    map[string]interface{}{},
												"clientInfo": map[string]interface{}{
													"name":    "MyClient",
													"version": "1.0.0",
												},
											},
										},
									},
								},
							},
						},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "MCP Response (JSON-RPC 2.0 format)",
							"content": map[string]interface{}{
								"application/json": map[string]interface{}{
									"schema": map[string]interface{}{
										"$ref": "#/components/schemas/MCPResponse",
									},
									"examples": map[string]interface{}{
										"success": map[string]interface{}{
											"summary":     "Success response",
											"description": "Example of a successful response called by a tool",
											"value": map[string]interface{}{
												"jsonrpc": "2.0",
												"id":      "call-tool-1",
												"result": map[string]interface{}{
													"content": []map[string]interface{}{
														{
															"type": "text",
															"text": "Tool Execution Results...",
														},
													},
													"isError": false,
												},
											},
										},
										"error": map[string]interface{}{
											"summary":     "Error response",
											"description": "Example of response to failed tool call",
											"value": map[string]interface{}{
												"jsonrpc": "2.0",
												"id":      "call-tool-1",
												"error": map[string]interface{}{
													"code":    -32601,
													"message": "Tool not found",
													"data":    "The tool 'unknown-tool 'does not exist",
												},
											},
										},
									},
								},
							},
						},
						"400": map[string]interface{}{
							"description": "Request format error (JSON resolution failed)",
							"content": map[string]interface{}{
								"application/json": map[string]interface{}{
									"schema": map[string]interface{}{
										"$ref": "#/components/schemas/MCPResponse",
									},
									"example": map[string]interface{}{
										"id": nil,
										"error": map[string]interface{}{
											"code":    -32700,
											"message": "Parse error",
											"data":    "unexpected end of JSON input",
										},
										"jsonrpc": "2.0",
									},
								},
							},
						},
						"401": map[string]interface{}{
							"description": "Unauthorized, valid Token required",
						},
						"405": map[string]interface{}{
							"description": "Method not allowed (POST only)",
						},
					},
				},
			},
			"/api/system/update": map[string]interface{}{
				"get": map[string]interface{}{
					"tags":        []string{"System update"},
					"summary":     "View the source version of this installation",
					"description": "Read installation directory own git Work Tree (Branch, Far, Current Submission, Local Changes, Is there any? Go Tool Chain, Can we roll back?) , Do not launch any network requests",
					"operationId": "getUpdateStatus",
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Installation status and latest update task",
						},
						"401": map[string]interface{}{
							"description": "Unauthorized",
						},
					},
				},
			},
			"/api/system/update/check": map[string]interface{}{
				"post": map[string]interface{}{
					"tags":        []string{"System update"},
					"summary":     "Check for new submissions of updates to this installation",
					"description": "Update source repository for configuration (Unconfigured = Official warehouse https://github.com/AIPentest/CyberStrikeAI.git) Default branch execution fetch, Report is behind schedule./Lead submissions and list of new submissions.Check failed to return 200 And... checkError, Oh, no.\"I can't.\"Speaking.\"It's the latest.\"",
					"operationId": "checkUpdate",
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Check result (including checkError for unsuccessful check)",
						},
						"401": map[string]interface{}{
							"description": "Unauthorized",
						},
					},
				},
			},
			"/api/system/update/apply": map[string]interface{}{
				"post": map[string]interface{}{
					"tags":        []string{"System update"},
					"summary":     "Update source code and recompile",
					"description": "Update to Update Source Repository Default, Recompile binary and convert atoms (Old binary retention .prev To roll back.) .Refusal to execute and name when the source file or branch has been forkted; roles/skills/tools/agents/bundles/knowledge_base/data/config.yaml Wait until the carrier content is merged, Merge and Return, List of retained documents keptContent.Request for immediate return job_id, Progress GET /api/system/update/job Round; Tasks returned while running 409",
					"operationId": "applyUpdate",
					"requestBody": map[string]interface{}{
						"content": map[string]interface{}{
							"application/json": map[string]interface{}{
								"schema": map[string]interface{}{
									"type": "object",
									"properties": map[string]interface{}{
										"restart": map[string]interface{}{
											"type":        "boolean",
											"description": "Follow-up successfully and gracefully close and exit the process; only pulled up when externally guarded, default false",
										},
									},
								},
							},
						},
					},
					"responses": map[string]interface{}{
						"202": map[string]interface{}{
							"description": "Job accepted, return job_id",
						},
						"400": map[string]interface{}{
							"description": "Request body is not legal or requests to restart but this launch is not equipped to restart hooks",
						},
						"409": map[string]interface{}{
							"description": "One update already in progress",
						},
						"401": map[string]interface{}{
							"description": "Unauthorized",
						},
					},
				},
			},
			"/api/system/update/job": map[string]interface{}{
				"get": map[string]interface{}{
					"tags":        []string{"System update"},
					"summary":     "View update progress",
					"description": "Returns the status of a running or last updated task, Line-by-line progress steps, Result result And failed. failure; It's never updated. job for null",
					"operationId": "getUpdateJob",
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Task Status",
						},
						"401": map[string]interface{}{
							"description": "Unauthorized",
						},
					},
				},
			},
			"/api/system/update/rollback": map[string]interface{}{
				"post": map[string]interface{}{
					"tags":        []string{"System update"},
					"summary":     "Roll back before this update",
					"description": "Retrieve old submissions from the last update record and replace the old binary with the previous one. Since that update, HEAD has changed or returned 409 rejections when the current source code is changed, instead of discarding the job after the update",
					"operationId": "rollbackUpdate",
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Rolling Back",
						},
						"409": map[string]interface{}{
							"description": "No rolling records, updates in progress, or HEAD has been moved",
						},
						"401": map[string]interface{}{
							"description": "Unauthorized",
						},
					},
				},
			},
		},
	}

	addAgentRunSpec(spec)
	enrichSpecWithI18nKeys(spec)
	c.JSON(http.StatusOK, spec)
}

// GetConversationResults 获取对话结果（OpenAPI端点）
// 注意：创建对话和获取对话详情直接使用标准的 /api/conversations 端点
// 这个端点只是为了提供结果聚合功能
func (h *OpenAPIHandler) GetConversationResults(c *gin.Context) {
	conversationID := c.Param("id")

	// 验证对话是否存在
	conv, err := h.db.GetConversation(conversationID)
	if err != nil {
		h.logger.Error("Failed to access dialogue", zap.Error(err))
		c.JSON(http.StatusNotFound, gin.H{"error": "Conversation not found"})
		return
	}

	// 获取消息列表
	messages, err := h.db.GetMessages(conversationID)
	if err != nil {
		h.logger.Error("Failed to fetch message", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// 获取漏洞列表
	vulnList, err := h.db.ListVulnerabilities(1000, 0, database.VulnerabilityListFilter{ConversationID: conversationID})
	if err != nil {
		h.logger.Warn("Failed to list vulnerabilities", zap.Error(err))
		vulnList = []*database.Vulnerability{}
	}
	vulnerabilities := make([]database.Vulnerability, len(vulnList))
	for i, v := range vulnList {
		vulnerabilities[i] = *v
	}

	// 获取执行结果（历史大结果由 Eino reduction 落盘，此处不再聚合文件存储）
	executionResults := []map[string]interface{}{}

	response := map[string]interface{}{
		"conversationId":   conv.ID,
		"messages":         messages,
		"vulnerabilities":  vulnerabilities,
		"executionResults": executionResults,
	}

	c.JSON(http.StatusOK, response)
}
