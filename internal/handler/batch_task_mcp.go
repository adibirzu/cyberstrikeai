package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"cyberstrike-ai/internal/authctx"
	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/mcp"
	"cyberstrike-ai/internal/mcp/builtin"

	"go.uber.org/zap"
)

// RegisterBatchTaskMCPTools 注册批量任务队列相关 MCP 工具（需传入已初始化 DB 的 AgentHandler）
func RegisterBatchTaskMCPTools(mcpServer *mcp.Server, h *AgentHandler, logger *zap.Logger) {
	if mcpServer == nil || h == nil || logger == nil {
		return
	}

	reg := func(tool mcp.Tool, fn func(ctx context.Context, args map[string]interface{}) (*mcp.ToolResult, error)) {
		mcpServer.RegisterTool(tool, fn)
	}

	// --- list ---
	reg(mcp.Tool{
		Name:             builtin.ToolBatchTaskList,
		Description:      "List batch task queues as compact summaries: queue metadata, subtask id/status/truncated message and status counts. Use batch_task_get(queue_id) for complete subtasks including result, error, conversationId and timestamps.\n\nUse this Task Management tool only when the user explicitly requests the corresponding batch task or queue operation. Do not invoke it without that request.",
		ShortDescription: "List batch task queues",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"status": map[string]interface{}{
					"type":        "string",
					"description": "Status filter: all (default), pending, running, paused, completed, cancelled",
					"enum":        []string{"all", "pending", "running", "paused", "completed", "cancelled"},
				},
				"keyword": map[string]interface{}{
					"type":        "string",
					"description": "Search by queue ID or title",
				},
				"page": map[string]interface{}{
					"type":        "integer",
					"description": "Page number, starting at 1; default 1",
				},
				"page_size": map[string]interface{}{
					"type":        "integer",
					"description": "Items per page; default 20, maximum 100",
				},
			},
		},
	}, func(ctx context.Context, args map[string]interface{}) (*mcp.ToolResult, error) {
		status := mcpArgString(args, "status")
		if status == "" {
			status = "all"
		}
		keyword := mcpArgString(args, "keyword")
		page := int(mcpArgFloat(args, "page"))
		if page <= 0 {
			page = 1
		}
		pageSize := int(mcpArgFloat(args, "page_size"))
		if pageSize <= 0 {
			pageSize = 20
		}
		if pageSize > 100 {
			pageSize = 100
		}
		offset := (page - 1) * pageSize
		if offset > 100000 {
			offset = 100000
		}
		queues := []*BatchTaskQueue{}
		total := 0
		var err error
		if principal, ok := authctx.PrincipalFromContext(ctx); ok {
			queues, total, err = h.batchTaskManager.ListQueuesForAccess(pageSize, offset, status, keyword, principal.UserID, principal.ScopeFor("tasks:read"))
		} else {
			return batchMCPTextResult("Missing authenticated principal", true), nil
		}
		if err != nil {
			return batchMCPTextResult(fmt.Sprintf("Failed to list queues: %v", err), true), nil
		}
		totalPages := (total + pageSize - 1) / pageSize
		if totalPages == 0 {
			totalPages = 1
		}
		slim := make([]batchTaskQueueMCPListItem, 0, len(queues))
		for _, q := range queues {
			if q == nil {
				continue
			}
			slim = append(slim, toBatchTaskQueueMCPListItem(q))
		}
		payload := map[string]interface{}{
			"queues":      slim,
			"total":       total,
			"page":        page,
			"page_size":   pageSize,
			"total_pages": totalPages,
		}
		logger.Info("MCP batch_task_list", zap.String("status", status), zap.Int("total", total))
		return batchMCPJSONResult(payload)
	})

	// --- get ---
	reg(mcp.Tool{
		Name:             builtin.ToolBatchTaskGet,
		Description:      "Get one batch task queue by queue_id, including subtasks, Cron settings, schedule toggle and recent errors.\n\nUse this Task Management tool only when the user explicitly requests the corresponding batch task or queue operation. Do not invoke it without that request.",
		ShortDescription: "Get batch task queue details",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"queue_id": map[string]interface{}{
					"type":        "string",
					"description": "Queue ID",
				},
			},
			"required": []string{"queue_id"},
		},
	}, func(ctx context.Context, args map[string]interface{}) (*mcp.ToolResult, error) {
		qid := mcpArgString(args, "queue_id")
		if qid == "" {
			return batchMCPTextResult("queue_id must not be empty", true), nil
		}
		queue, ok := h.batchTaskManager.GetBatchQueue(qid)
		if !ok {
			return batchMCPTextResult("Queue not found: "+qid, true), nil
		}
		return batchMCPJSONResult(queue)
	})

	// --- create ---
	reg(mcp.Tool{
		Name:             builtin.ToolBatchTaskCreate,
		Description:      "Use this Task Management tool only when the user explicitly asks to create batch tasks, a task queue or scheduled tasks. Complete ordinary requests in the current conversation; do not create a queue on your own.\n\nPurpose: register independent user instructions in one application task queue so the user can monitor progress, pause/resume and schedule reruns. This is a queue and scheduling entry point, not a subagent conversation for exploring the current problem.\n\nWhen to use: explicitly requested batch execution, recurring Cron execution of the same instructions, or coordination with the Task Management page. Analysis or coding that needs immediate follow-up or the current conversation context belongs in this conversation; do not create a queue merely to delegate.\n\nParameters: provide either tasks (an array of strings) or tasks_text (one instruction per line). Each item is an independent instruction to execute in queue order. agent_mode: eino_single (Eino ADK single agent, default), or deep / plan_execute / supervisor (requires multi-agent support). This does not split the main conversation into subagents. schedule_mode: manual (default) or cron; cron requires a five-field cron_expr such as \"0 */6 * * *\".\n\nExecution: creation defaults to pending and does not execute. Set execute_now=true to start immediately, or call batch_task_start later. Automatic Cron rounds require schedule_enabled=true, controlled with batch_task_schedule_enabled.",
		ShortDescription: "Task Management: create a batch task queue (optional immediate or Cron execution)",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"title": map[string]interface{}{
					"type":        "string",
					"description": "Optional queue title for identification in Task Management",
				},
				"role": map[string]interface{}{
					"type":        "string",
					"description": "Queue role name; empty uses the default",
				},
				"tasks": map[string]interface{}{
					"type":        "array",
					"description": "Independent subtask instructions; provide either tasks or tasks_text",
					"items":       map[string]interface{}{"type": "string"},
				},
				"tasks_text": map[string]interface{}{
					"type":        "string",
					"description": "Multiline instructions, one subtask per line; alternative to tasks",
				},
				"agent_mode": map[string]interface{}{
					"type":        "string",
					"description": "Execution mode: eino_single (Eino ADK, default), or deep/plan_execute/supervisor (Eino orchestration; requires multi-agent support)",
					"enum":        []string{"eino_single", "deep", "plan_execute", "supervisor"},
				},
				"schedule_mode": map[string]interface{}{
					"type":        "string",
					"description": "manual (run only when started) or cron (triggered by expression)",
					"enum":        []string{"manual", "cron"},
				},
				"cron_expr": map[string]interface{}{
					"type":        "string",
					"description": "Required for schedule_mode=cron. Five fields: minute hour day month weekday; e.g. \"0 */6 * * *\" or \"30 2 * * 1-5\"",
				},
				"execute_now": map[string]interface{}{
					"type":        "boolean",
					"description": "Start immediately after creation; default false (pending until batch_task_start)",
				},
				"project_id": map[string]interface{}{
					"type":        "string",
					"description": "Optional project ID for subtask conversations; defaults to config.project.default_project_id",
				},
				"concurrency": map[string]interface{}{
					"type":        "integer",
					"description": "Concurrent subtasks; default 1 (serial), maximum 8. Use 1-2 for scanning tools.",
				},
			},
		},
	}, func(ctx context.Context, args map[string]interface{}) (*mcp.ToolResult, error) {
		tasks, errMsg := batchMCPTasksFromArgs(args)
		if errMsg != "" {
			return batchMCPTextResult(errMsg, true), nil
		}
		title := mcpArgString(args, "title")
		role := mcpArgString(args, "role")
		agentMode := config.NormalizeAgentMode(mcpArgString(args, "agent_mode"))
		scheduleMode := normalizeBatchQueueScheduleMode(mcpArgString(args, "schedule_mode"))
		cronExpr := strings.TrimSpace(mcpArgString(args, "cron_expr"))
		var nextRunAt *time.Time
		if scheduleMode == "cron" {
			if cronExpr == "" {
				return batchMCPTextResult("cron_expr must not be empty in Cron mode", true), nil
			}
			sch, err := h.batchCronParser.Parse(cronExpr)
			if err != nil {
				return batchMCPTextResult("Invalid Cron expression: "+err.Error(), true), nil
			}
			n := sch.Next(time.Now())
			nextRunAt = &n
		}
		executeNow, ok := mcpArgBool(args, "execute_now")
		if !ok {
			executeNow = false
		}
		projectID := strings.TrimSpace(mcpArgString(args, "project_id"))
		if principal, ok := authctx.PrincipalFromContext(ctx); ok && projectID != "" && principal.ScopeFor("tasks:write") != database.RBACScopeAll {
			if h.db == nil || !h.db.UserCanAccessResource(principal.UserID, principal.ScopeFor("tasks:write"), "project", projectID) {
				return batchMCPTextResult("No access to the target project", true), nil
			}
		}
		concurrency := int(mcpArgFloat(args, "concurrency"))
		queue, createErr := h.batchTaskManager.CreateBatchQueue(title, role, agentMode, scheduleMode, cronExpr, projectID, nextRunAt, concurrency, tasks)
		if createErr != nil {
			return batchMCPTextResult("Failed to create queue: "+createErr.Error(), true), nil
		}
		if principal, ok := authctx.PrincipalFromContext(ctx); ok && h.db != nil {
			_ = h.db.SetResourceOwner("batch_task", queue.ID, principal.UserID)
			_ = h.db.AssignResourceToUser(principal.UserID, "batch_task", queue.ID)
		}
		started := false
		if executeNow {
			ok, err := h.startBatchQueueExecution(queue.ID, false)
			if !ok {
				return batchMCPTextResult("Queue not found: "+queue.ID, true), nil
			}
			if err != nil {
				return batchMCPTextResult("Queue created but failed to start: "+err.Error(), true), nil
			}
			started = true
			if refreshed, exists := h.batchTaskManager.GetBatchQueue(queue.ID); exists {
				queue = refreshed
			}
		}
		logger.Info("MCP batch_task_create", zap.String("queueId", queue.ID), zap.Int("taskCount", len(tasks)))
		return batchMCPJSONResult(map[string]interface{}{
			"queue_id":    queue.ID,
			"queue":       queue,
			"started":     started,
			"execute_now": executeNow,
			"reminder": func() string {
				if started {
					return "Queue created and started immediately."
				}
				return "Queue created with status pending. Call batch_task_start with this queue_id to execute. Automatic Cron scheduling requires schedule_enabled=true; use batch_task_schedule_enabled."
			}(),
		})
	})

	// --- start ---
	reg(mcp.Tool{
		Name:             builtin.ToolBatchTaskStart,
		Description:      "Start or resume a pending/paused batch task queue. Use after batch_task_create: creating a queue alone does not execute its subtasks.\n\nUse this Task Management tool only when the user explicitly requests the corresponding batch task or queue operation. Do not invoke it without that request.",
		ShortDescription: "Start/resume a batch task queue (required after creation to execute)",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"queue_id": map[string]interface{}{
					"type":        "string",
					"description": "Queue ID",
				},
			},
			"required": []string{"queue_id"},
		},
	}, func(ctx context.Context, args map[string]interface{}) (*mcp.ToolResult, error) {
		qid := mcpArgString(args, "queue_id")
		if qid == "" {
			return batchMCPTextResult("queue_id must not be empty", true), nil
		}
		ok, err := h.startBatchQueueExecution(qid, false)
		if !ok {
			return batchMCPTextResult("Queue not found: "+qid, true), nil
		}
		if err != nil {
			return batchMCPTextResult("Failed to start: "+err.Error(), true), nil
		}
		logger.Info("MCP batch_task_start", zap.String("queueId", qid))
		return batchMCPTextResult("Start requested; the queue will begin execution.", false), nil
	})

	// --- rerun (reset + start for completed/cancelled queues) ---
	reg(mcp.Tool{
		Name:             builtin.ToolBatchTaskRerun,
		Description:      "Rerun a completed or cancelled batch task queue. Resets all subtask statuses and executes another round.\n\nUse this Task Management tool only when the user explicitly requests the corresponding batch task or queue operation. Do not invoke it without that request.",
		ShortDescription: "Rerun a batch task queue",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"queue_id": map[string]interface{}{
					"type":        "string",
					"description": "Queue ID",
				},
			},
			"required": []string{"queue_id"},
		},
	}, func(ctx context.Context, args map[string]interface{}) (*mcp.ToolResult, error) {
		qid := mcpArgString(args, "queue_id")
		if qid == "" {
			return batchMCPTextResult("queue_id must not be empty", true), nil
		}
		queue, exists := h.batchTaskManager.GetBatchQueue(qid)
		if !exists {
			return batchMCPTextResult("Queue not found: "+qid, true), nil
		}
		if queue.Status != "completed" && queue.Status != "cancelled" {
			return batchMCPTextResult("Only completed or cancelled queues can be rerun; current status: "+queue.Status, true), nil
		}
		if !h.batchTaskManager.ResetQueueForRerun(qid) {
			return batchMCPTextResult("Failed to reset queue", true), nil
		}
		ok, err := h.startBatchQueueExecution(qid, false)
		if !ok {
			return batchMCPTextResult("Failed to start", true), nil
		}
		if err != nil {
			return batchMCPTextResult("Failed to start: "+err.Error(), true), nil
		}
		logger.Info("MCP batch_task_rerun", zap.String("queueId", qid))
		return batchMCPTextResult("Queue reset and restarted.", false), nil
	})

	// --- pause ---
	reg(mcp.Tool{
		Name:             builtin.ToolBatchTaskPause,
		Description:      "Pause a running batch task queue, cancelling the current subtask.\n\nUse this Task Management tool only when the user explicitly requests the corresponding batch task or queue operation. Do not invoke it without that request.",
		ShortDescription: "Pause a batch task queue",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"queue_id": map[string]interface{}{
					"type":        "string",
					"description": "Queue ID",
				},
			},
			"required": []string{"queue_id"},
		},
	}, func(ctx context.Context, args map[string]interface{}) (*mcp.ToolResult, error) {
		qid := mcpArgString(args, "queue_id")
		if qid == "" {
			return batchMCPTextResult("queue_id must not be empty", true), nil
		}
		if !h.batchTaskManager.PauseQueue(qid) {
			return batchMCPTextResult("Cannot pause: queue not found or not running", true), nil
		}
		logger.Info("MCP batch_task_pause", zap.String("queueId", qid))
		return batchMCPTextResult("Queue paused.", false), nil
	})

	// --- delete queue ---
	reg(mcp.Tool{
		Name:             builtin.ToolBatchTaskDelete,
		Description:      "Delete a batch task queue and its subtask records.\n\nUse this Task Management tool only when the user explicitly requests the corresponding batch task or queue operation. Do not invoke it without that request.",
		ShortDescription: "Delete a batch task queue",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"queue_id": map[string]interface{}{
					"type":        "string",
					"description": "Queue ID",
				},
			},
			"required": []string{"queue_id"},
		},
	}, func(ctx context.Context, args map[string]interface{}) (*mcp.ToolResult, error) {
		qid := mcpArgString(args, "queue_id")
		if qid == "" {
			return batchMCPTextResult("queue_id must not be empty", true), nil
		}
		if err := h.batchTaskManager.DeleteQueue(qid); err != nil {
			switch {
			case errors.Is(err, ErrBatchQueueNotFound):
				return batchMCPTextResult("Failed to delete: queue not found", true), nil
			case errors.Is(err, ErrBatchQueueExecutorActive):
				return batchMCPTextResult("Failed to delete: queue executor is still active; try again later", true), nil
			case errors.Is(err, ErrBatchQueueStillRunning):
				return batchMCPTextResult("Failed to delete: queue is running", true), nil
			default:
				return batchMCPTextResult("Failed to delete: "+err.Error(), true), nil
			}
		}
		logger.Info("MCP batch_task_delete", zap.String("queueId", qid))
		return batchMCPTextResult("Queue deleted.", false), nil
	})

	// --- update metadata (title/role/agentMode) ---
	reg(mcp.Tool{
		Name:             builtin.ToolBatchTaskUpdateMetadata,
		Description:      "Change the title, role and agent mode of a batch task queue. The queue must not be running.\n\nUse this Task Management tool only when the user explicitly requests the corresponding batch task or queue operation. Do not invoke it without that request.",
		ShortDescription: "Change batch queue title/role/agent mode",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"queue_id": map[string]interface{}{
					"type":        "string",
					"description": "Queue ID",
				},
				"title": map[string]interface{}{
					"type":        "string",
					"description": "New title; an empty string clears it",
				},
				"role": map[string]interface{}{
					"type":        "string",
					"description": "New role name; an empty string uses the default role",
				},
				"agent_mode": map[string]interface{}{
					"type":        "string",
					"description": "Agent mode: eino_single, deep, plan_execute, supervisor",
					"enum":        []string{"eino_single", "deep", "plan_execute", "supervisor"},
				},
				"concurrency": map[string]interface{}{
					"type":        "integer",
					"description": "Concurrent subtasks; default 1, maximum 8",
				},
			},
			"required": []string{"queue_id"},
		},
	}, func(ctx context.Context, args map[string]interface{}) (*mcp.ToolResult, error) {
		qid := mcpArgString(args, "queue_id")
		if qid == "" {
			return batchMCPTextResult("queue_id must not be empty", true), nil
		}
		title := mcpArgString(args, "title")
		role := mcpArgString(args, "role")
		agentMode := mcpArgString(args, "agent_mode")
		var concurrency *int
		if raw, ok := args["concurrency"]; ok && raw != nil {
			v := int(mcpArgFloat(args, "concurrency"))
			concurrency = &v
		}
		if err := h.batchTaskManager.UpdateQueueMetadata(qid, title, role, agentMode, concurrency); err != nil {
			return batchMCPTextResult(err.Error(), true), nil
		}
		updated, _ := h.batchTaskManager.GetBatchQueue(qid)
		logger.Info("MCP batch_task_update_metadata", zap.String("queueId", qid))
		return batchMCPJSONResult(updated)
	})

	// --- update schedule ---
	reg(mcp.Tool{
		Name:             builtin.ToolBatchTaskUpdateSchedule,
		Description:      "Change the schedule mode and Cron expression of a batch task queue that is not running. Cron mode requires a valid cron_expr; manual mode clears the Cron configuration.\n\nUse this Task Management tool only when the user explicitly requests the corresponding batch task or queue operation. Do not invoke it without that request.",
		ShortDescription: "Change batch task schedule (Cron expression)",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"queue_id": map[string]interface{}{
					"type":        "string",
					"description": "Queue ID",
				},
				"schedule_mode": map[string]interface{}{
					"type":        "string",
					"description": "manual or cron",
					"enum":        []string{"manual", "cron"},
				},
				"cron_expr": map[string]interface{}{
					"type":        "string",
					"description": "Cron expression, required for schedule_mode=cron. Five fields: minute hour day month weekday; e.g. \"0 */6 * * *\" (every six hours) or \"30 2 * * 1-5\" (weekdays at 02:30)",
				},
			},
			"required": []string{"queue_id", "schedule_mode"},
		},
	}, func(ctx context.Context, args map[string]interface{}) (*mcp.ToolResult, error) {
		qid := mcpArgString(args, "queue_id")
		if qid == "" {
			return batchMCPTextResult("queue_id must not be empty", true), nil
		}
		queue, exists := h.batchTaskManager.GetBatchQueue(qid)
		if !exists {
			return batchMCPTextResult("Queue not found: "+qid, true), nil
		}
		if queue.Status == "running" {
			return batchMCPTextResult("Cannot change schedule while queue is running", true), nil
		}
		scheduleMode := normalizeBatchQueueScheduleMode(mcpArgString(args, "schedule_mode"))
		cronExpr := strings.TrimSpace(mcpArgString(args, "cron_expr"))
		var nextRunAt *time.Time
		if scheduleMode == "cron" {
			if cronExpr == "" {
				return batchMCPTextResult("cron_expr must not be empty in Cron mode", true), nil
			}
			sch, err := h.batchCronParser.Parse(cronExpr)
			if err != nil {
				return batchMCPTextResult("Invalid Cron expression: "+err.Error(), true), nil
			}
			n := sch.Next(time.Now())
			nextRunAt = &n
		}
		h.batchTaskManager.UpdateQueueSchedule(qid, scheduleMode, cronExpr, nextRunAt)
		updated, _ := h.batchTaskManager.GetBatchQueue(qid)
		logger.Info("MCP batch_task_update_schedule", zap.String("queueId", qid), zap.String("scheduleMode", scheduleMode), zap.String("cronExpr", cronExpr))
		return batchMCPJSONResult(updated)
	})

	// --- schedule enabled ---
	reg(mcp.Tool{
		Name:             builtin.ToolBatchTaskScheduleEnabled,
		Description:      "Enable or disable automatic Cron triggers for a queue. Disabling keeps the Cron expression and permits manual starts. Only meaningful for schedule_mode=cron.\n\nUse this Task Management tool only when the user explicitly requests the corresponding batch task or queue operation. Do not invoke it without that request.",
		ShortDescription: "Toggle batch task Cron scheduling",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"queue_id": map[string]interface{}{
					"type":        "string",
					"description": "Queue ID",
				},
				"schedule_enabled": map[string]interface{}{
					"type":        "boolean",
					"description": "true allows scheduled triggers; false permits manual execution only",
				},
			},
			"required": []string{"queue_id", "schedule_enabled"},
		},
	}, func(ctx context.Context, args map[string]interface{}) (*mcp.ToolResult, error) {
		qid := mcpArgString(args, "queue_id")
		if qid == "" {
			return batchMCPTextResult("queue_id must not be empty", true), nil
		}
		en, ok := mcpArgBool(args, "schedule_enabled")
		if !ok {
			return batchMCPTextResult("schedule_enabled must be a boolean", true), nil
		}
		if _, exists := h.batchTaskManager.GetBatchQueue(qid); !exists {
			return batchMCPTextResult("Queue not found", true), nil
		}
		if !h.batchTaskManager.SetScheduleEnabled(qid, en) {
			return batchMCPTextResult("Update failed", true), nil
		}
		queue, _ := h.batchTaskManager.GetBatchQueue(qid)
		logger.Info("MCP batch_task_schedule_enabled", zap.String("queueId", qid), zap.Bool("enabled", en))
		return batchMCPJSONResult(queue)
	})

	// --- add task ---
	reg(mcp.Tool{
		Name:             builtin.ToolBatchTaskAdd,
		Description:      "Append one subtask to a pending queue.\n\nUse this Task Management tool only when the user explicitly requests the corresponding batch task or queue operation. Do not invoke it without that request.",
		ShortDescription: "Add a subtask to a batch queue",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"queue_id": map[string]interface{}{
					"type":        "string",
					"description": "Queue ID",
				},
				"message": map[string]interface{}{
					"type":        "string",
					"description": "Task instruction",
				},
			},
			"required": []string{"queue_id", "message"},
		},
	}, func(ctx context.Context, args map[string]interface{}) (*mcp.ToolResult, error) {
		qid := mcpArgString(args, "queue_id")
		msg := strings.TrimSpace(mcpArgString(args, "message"))
		if qid == "" || msg == "" {
			return batchMCPTextResult("queue_id and message must not be empty", true), nil
		}
		task, err := h.batchTaskManager.AddTaskToQueue(qid, msg)
		if err != nil {
			return batchMCPTextResult(err.Error(), true), nil
		}
		queue, _ := h.batchTaskManager.GetBatchQueue(qid)
		logger.Info("MCP batch_task_add_task", zap.String("queueId", qid), zap.String("taskId", task.ID))
		return batchMCPJSONResult(map[string]interface{}{"task": task, "queue": queue})
	})

	// --- update task ---
	reg(mcp.Tool{
		Name:             builtin.ToolBatchTaskUpdate,
		Description:      "Change the instruction of a pending subtask in a pending queue.\n\nUse this Task Management tool only when the user explicitly requests the corresponding batch task or queue operation. Do not invoke it without that request.",
		ShortDescription: "Update a batch subtask instruction",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"queue_id": map[string]interface{}{
					"type":        "string",
					"description": "Queue ID",
				},
				"task_id": map[string]interface{}{
					"type":        "string",
					"description": "Subtask ID",
				},
				"message": map[string]interface{}{
					"type":        "string",
					"description": "New task instruction",
				},
			},
			"required": []string{"queue_id", "task_id", "message"},
		},
	}, func(ctx context.Context, args map[string]interface{}) (*mcp.ToolResult, error) {
		qid := mcpArgString(args, "queue_id")
		tid := mcpArgString(args, "task_id")
		msg := strings.TrimSpace(mcpArgString(args, "message"))
		if qid == "" || tid == "" || msg == "" {
			return batchMCPTextResult("queue_id, task_id and message must not be empty", true), nil
		}
		if err := h.batchTaskManager.UpdateTaskMessage(qid, tid, msg); err != nil {
			return batchMCPTextResult(err.Error(), true), nil
		}
		queue, _ := h.batchTaskManager.GetBatchQueue(qid)
		logger.Info("MCP batch_task_update_task", zap.String("queueId", qid), zap.String("taskId", tid))
		return batchMCPJSONResult(queue)
	})

	// --- remove task ---
	reg(mcp.Tool{
		Name:             builtin.ToolBatchTaskRemove,
		Description:      "Delete a pending subtask from a pending queue.\n\nUse this Task Management tool only when the user explicitly requests the corresponding batch task or queue operation. Do not invoke it without that request.",
		ShortDescription: "Delete a batch subtask",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"queue_id": map[string]interface{}{
					"type":        "string",
					"description": "Queue ID",
				},
				"task_id": map[string]interface{}{
					"type":        "string",
					"description": "Subtask ID",
				},
			},
			"required": []string{"queue_id", "task_id"},
		},
	}, func(ctx context.Context, args map[string]interface{}) (*mcp.ToolResult, error) {
		qid := mcpArgString(args, "queue_id")
		tid := mcpArgString(args, "task_id")
		if qid == "" || tid == "" {
			return batchMCPTextResult("queue_id and task_id must not be empty", true), nil
		}
		if err := h.batchTaskManager.DeleteTask(qid, tid); err != nil {
			return batchMCPTextResult(err.Error(), true), nil
		}
		queue, _ := h.batchTaskManager.GetBatchQueue(qid)
		logger.Info("MCP batch_task_remove_task", zap.String("queueId", qid), zap.String("taskId", tid))
		return batchMCPJSONResult(queue)
	})

	logger.Debug("Batch task MCP tools registered", zap.Int("count", 12))
}

// --- batch_task_list 精简结构（避免把每条子任务的 result 等大段文本塞进列表上下文） ---

const mcpBatchListTaskMessageMaxRunes = 160

// batchTaskMCPListSummary 列表中的子任务摘要（完整字段用 batch_task_get）
type batchTaskMCPListSummary struct {
	ID      string `json:"id"`
	Status  string `json:"status"`
	Message string `json:"message,omitempty"`
}

// batchTaskQueueMCPListItem 列表中的队列摘要
type batchTaskQueueMCPListItem struct {
	ID                    string                    `json:"id"`
	Title                 string                    `json:"title,omitempty"`
	Role                  string                    `json:"role,omitempty"`
	AgentMode             string                    `json:"agentMode"`
	ScheduleMode          string                    `json:"scheduleMode"`
	CronExpr              string                    `json:"cronExpr,omitempty"`
	NextRunAt             *time.Time                `json:"nextRunAt,omitempty"`
	ScheduleEnabled       bool                      `json:"scheduleEnabled"`
	LastScheduleTriggerAt *time.Time                `json:"lastScheduleTriggerAt,omitempty"`
	Status                string                    `json:"status"`
	CreatedAt             time.Time                 `json:"createdAt"`
	StartedAt             *time.Time                `json:"startedAt,omitempty"`
	CompletedAt           *time.Time                `json:"completedAt,omitempty"`
	CurrentIndex          int                       `json:"currentIndex"`
	Concurrency           int                       `json:"concurrency"`
	TaskTotal             int                       `json:"task_total"`
	TaskCounts            map[string]int            `json:"task_counts"`
	Tasks                 []batchTaskMCPListSummary `json:"tasks"`
}

func truncateStringRunes(s string, maxRunes int) string {
	if maxRunes <= 0 {
		return ""
	}
	n := 0
	for i := range s {
		if n == maxRunes {
			out := strings.TrimSpace(s[:i])
			if out == "" {
				return "…"
			}
			return out + "…"
		}
		n++
	}
	return s
}

const mcpBatchListMaxTasksPerQueue = 200 // 列表中每个队列最多返回的子任务摘要数

func toBatchTaskQueueMCPListItem(q *BatchTaskQueue) batchTaskQueueMCPListItem {
	counts := map[string]int{
		"pending":   0,
		"running":   0,
		"completed": 0,
		"failed":    0,
		"cancelled": 0,
	}
	tasks := make([]batchTaskMCPListSummary, 0, len(q.Tasks))
	for _, t := range q.Tasks {
		if t == nil {
			continue
		}
		counts[t.Status]++
		// 列表视图限制子任务摘要数量，完整列表通过 batch_task_get 查看
		if len(tasks) < mcpBatchListMaxTasksPerQueue {
			tasks = append(tasks, batchTaskMCPListSummary{
				ID:      t.ID,
				Status:  t.Status,
				Message: truncateStringRunes(t.Message, mcpBatchListTaskMessageMaxRunes),
			})
		}
	}
	return batchTaskQueueMCPListItem{
		ID:                    q.ID,
		Title:                 q.Title,
		Role:                  q.Role,
		AgentMode:             q.AgentMode,
		ScheduleMode:          q.ScheduleMode,
		CronExpr:              q.CronExpr,
		NextRunAt:             q.NextRunAt,
		ScheduleEnabled:       q.ScheduleEnabled,
		LastScheduleTriggerAt: q.LastScheduleTriggerAt,
		Status:                q.Status,
		CreatedAt:             q.CreatedAt,
		StartedAt:             q.StartedAt,
		CompletedAt:           q.CompletedAt,
		CurrentIndex:          q.CurrentIndex,
		Concurrency:           q.Concurrency,
		TaskTotal:             len(tasks),
		TaskCounts:            counts,
		Tasks:                 tasks,
	}
}

func batchMCPTextResult(text string, isErr bool) *mcp.ToolResult {
	return &mcp.ToolResult{
		Content: []mcp.Content{{Type: "text", Text: text}},
		IsError: isErr,
	}
}

func batchMCPJSONResult(v interface{}) (*mcp.ToolResult, error) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return batchMCPTextResult(fmt.Sprintf("Failed to encode JSON: %v", err), true), nil
	}
	return &mcp.ToolResult{Content: []mcp.Content{{Type: "text", Text: string(b)}}}, nil
}

func batchMCPTasksFromArgs(args map[string]interface{}) ([]string, string) {
	if raw, ok := args["tasks"]; ok && raw != nil {
		switch t := raw.(type) {
		case []interface{}:
			out := make([]string, 0, len(t))
			for _, x := range t {
				if s, ok := x.(string); ok {
					if tr := strings.TrimSpace(s); tr != "" {
						out = append(out, tr)
					}
				}
			}
			if len(out) > 0 {
				return out, ""
			}
		}
	}
	if txt := mcpArgString(args, "tasks_text"); txt != "" {
		lines := strings.Split(txt, "\n")
		out := make([]string, 0, len(lines))
		for _, line := range lines {
			if tr := strings.TrimSpace(line); tr != "" {
				out = append(out, tr)
			}
		}
		if len(out) > 0 {
			return out, ""
		}
	}
	return nil, "Provide tasks (an array of strings) or tasks_text (multiline text, one task per line)"
}

func mcpArgString(args map[string]interface{}, key string) string {
	v, ok := args[key]
	if !ok || v == nil {
		return ""
	}
	switch t := v.(type) {
	case string:
		return strings.TrimSpace(t)
	case float64:
		return strings.TrimSpace(strconv.FormatFloat(t, 'f', -1, 64))
	case json.Number:
		return strings.TrimSpace(t.String())
	default:
		return strings.TrimSpace(fmt.Sprint(t))
	}
}

func mcpArgFloat(args map[string]interface{}, key string) float64 {
	v, ok := args[key]
	if !ok || v == nil {
		return 0
	}
	switch t := v.(type) {
	case float64:
		return t
	case int:
		return float64(t)
	case int64:
		return float64(t)
	case json.Number:
		f, _ := t.Float64()
		return f
	case string:
		f, _ := strconv.ParseFloat(strings.TrimSpace(t), 64)
		return f
	default:
		return 0
	}
}

func mcpArgBool(args map[string]interface{}, key string) (val bool, ok bool) {
	v, exists := args[key]
	if !exists {
		return false, false
	}
	switch t := v.(type) {
	case bool:
		return t, true
	case string:
		s := strings.ToLower(strings.TrimSpace(t))
		if s == "true" || s == "1" || s == "yes" {
			return true, true
		}
		if s == "false" || s == "0" || s == "no" {
			return false, true
		}
	case float64:
		return t != 0, true
	}
	return false, false
}
