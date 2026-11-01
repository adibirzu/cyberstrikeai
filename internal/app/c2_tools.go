package app

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"cyberstrike-ai/internal/agent"
	"cyberstrike-ai/internal/authctx"
	"cyberstrike-ai/internal/c2"
	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/mcp"
	"cyberstrike-ai/internal/mcp/builtin"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// registerC2Tools 注册所有 C2 MCP 工具（合并同类项，减少工具数量以节省上下文 token）。
// webListenPort 为本进程 Web/API 监听端口（配置 server.port，启动时已加载），用于 MCP 描述中提示勿与 C2 bind_port 冲突。
func registerC2Tools(mcpServer *mcp.Server, c2Manager *c2.Manager, logger *zap.Logger, webListenPort int) {
	registerC2ListenerTool(mcpServer, c2Manager, logger, webListenPort)
	registerC2SessionTool(mcpServer, c2Manager, logger)
	registerC2TaskTool(mcpServer, c2Manager, logger)
	registerC2TaskManageTool(mcpServer, c2Manager, logger)
	registerC2PayloadTool(mcpServer, c2Manager, logger, webListenPort)
	registerC2EventTool(mcpServer, c2Manager, logger)
	registerC2ProfileTool(mcpServer, c2Manager, logger)
	registerC2FileTool(mcpServer, c2Manager, logger)
	logger.Debug("C2 MCP tools registered (8 unified tools)")
}

func makeC2Result(data interface{}, err error) (*mcp.ToolResult, error) {
	if err != nil {
		return &mcp.ToolResult{
			Content: []mcp.Content{{Type: "text", Text: err.Error()}},
			IsError: true,
		}, nil
	}
	text, _ := json.Marshal(data)
	return &mcp.ToolResult{
		Content: []mcp.Content{{Type: "text", Text: string(text)}},
	}, nil
}

// ============================================================================
// c2_listener — 监听器统一工具
// ============================================================================

func registerC2ListenerTool(s *mcp.Server, m *c2.Manager, l *zap.Logger, webListenPort int) {
	s.RegisterTool(mcp.Tool{
		Name: builtin.ToolC2Listener,
		Description: fmt.Sprintf(`Manage authorized C2 listeners using action:
- list: list accessible listeners; get: read listener details (listener_id).
- create: requires name/type/bind_port. A successful create returns implant_token once for X-Implant-Token/oneliner use; list/get/start do not return it.
- update: modify name/bind_host/bind_port/remark/config/callback_host (listener_id).
- start/stop/delete: operate on the specified listener_id.
Types: tcp_reverse, http_beacon, https_beacon, websocket. tcp_reverse defaults to authenticated CSB1 encrypted beacons (AES-GCM and ImplantToken). Unencrypted legacy bash/nc shells require explicit config.allow_legacy_shell=true and are not recommended.
The bind_port must differ from this service's Web/API port %d (server.port) and be available. Otherwise binding may fail or callbacks may reach the Web service instead of C2. Native scope/RBAC/HITL gates still apply.`, webListenPort),
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"action":        map[string]interface{}{"type": "string", "description": "Operation: list/get/create/update/start/stop/delete", "enum": []string{"list", "get", "create", "update", "start", "stop", "delete"}},
				"listener_id":   map[string]interface{}{"type": "string", "description": "Listener ID (get/update/start/stop/delete required)"},
				"name":          map[string]interface{}{"type": "string", "description": "Listener name (create/update)"},
				"type":          map[string]interface{}{"type": "string", "description": "Listener type (create)", "enum": []string{"tcp_reverse", "http_beacon", "https_beacon", "websocket"}},
				"bind_host":     map[string]interface{}{"type": "string", "description": "Bind address; default 127.0.0.1. Explicit 0.0.0.0 listens on all interfaces."},
				"callback_host": map[string]interface{}{"type": "string", "description": "Optional callback hostname/IP, stored in config_json and preferred over bind_host for generated payloads. An empty update value clears it."},
				"bind_port":     map[string]interface{}{"type": "integer", "description": fmt.Sprintf("Required bind port for create; must differ from Web/API port %d (server.port)", webListenPort), "minimum": 1, "maximum": 65535},
				"project_id":    map[string]interface{}{"type": "string", "description": "Project ID. On create, omission uses the current conversation project; an unbound conversation creates an unbound listener."},
				"profile_id":    map[string]interface{}{"type": "string", "description": "Malleable Profile ID"},
				"remark":        map[string]interface{}{"type": "string", "description": "Notes"},
				"config":        map[string]interface{}{"type": "object", "description": "Advanced beacon path/TLS/operational configuration for create/update. tcp_reverse allow_legacy_shell:true explicitly permits unencrypted legacy shells (default false)."},
			},
			"required": []string{"action"},
		},
	}, func(ctx context.Context, params map[string]interface{}) (*mcp.ToolResult, error) {
		action := getString(params, "action")
		id := getString(params, "listener_id")

		switch action {
		case "list":
			listeners, err := m.DB().ListC2ListenersForAccess(c2ToolAccess(ctx), mcpEffectiveProjectFilter(ctx, m.DB()))
			if err != nil {
				return makeC2Result(nil, err)
			}
			for _, li := range listeners {
				li.EncryptionKey = ""
				li.ImplantToken = ""
			}
			return makeC2Result(map[string]interface{}{"listeners": listeners, "count": len(listeners)}, nil)

		case "get":
			listener, err := m.DB().GetC2Listener(id)
			if err != nil {
				return makeC2Result(nil, err)
			}
			if listener == nil {
				return makeC2Result(nil, fmt.Errorf("listener not found"))
			}
			listener.EncryptionKey = ""
			listener.ImplantToken = ""
			return makeC2Result(map[string]interface{}{"listener": listener}, nil)

		case "create":
			var cfg *c2.ListenerConfig
			if cfgRaw, ok := params["config"]; ok && cfgRaw != nil {
				cfgBytes, _ := json.Marshal(cfgRaw)
				cfg = &c2.ListenerConfig{}
				_ = json.Unmarshal(cfgBytes, cfg)
			}
			projectID := strings.TrimSpace(getString(params, "project_id"))
			if projectID == "" {
				projectID = mcpEffectiveProjectFilter(ctx, m.DB())
				if projectID == database.ProjectFilterUnbound {
					projectID = ""
				}
			}
			input := c2.CreateListenerInput{
				Name:         getString(params, "name"),
				Type:         getString(params, "type"),
				BindHost:     getString(params, "bind_host"),
				BindPort:     int(getFloat64(params, "bind_port")),
				ProfileID:    getString(params, "profile_id"),
				Remark:       getString(params, "remark"),
				ProjectID:    projectID,
				Config:       cfg,
				CallbackHost: getString(params, "callback_host"),
			}
			listener, err := m.CreateListener(input)
			if err != nil {
				return makeC2Result(nil, err)
			}
			if principal, ok := authctx.PrincipalFromContext(ctx); ok {
				_ = m.DB().SetResourceOwner("c2_listener", listener.ID, principal.UserID)
				_ = m.DB().AssignResourceToUser(principal.UserID, "c2_listener", listener.ID)
			}
			implantToken := listener.ImplantToken
			listener.EncryptionKey = ""
			listener.ImplantToken = ""
			return makeC2Result(map[string]interface{}{
				"listener":      listener,
				"implant_token": implantToken,
			}, nil)

		case "update":
			listener, err := m.DB().GetC2Listener(id)
			if err != nil {
				return makeC2Result(nil, err)
			}
			if listener == nil {
				return makeC2Result(nil, fmt.Errorf("listener not found"))
			}
			if m.IsListenerRunning(id) {
				newHost := getString(params, "bind_host")
				newPort := int(getFloat64(params, "bind_port"))
				if (newHost != "" && newHost != listener.BindHost) || (newPort > 0 && newPort != listener.BindPort) {
					return makeC2Result(nil, fmt.Errorf("cannot modify bind address while listener is running"))
				}
			}
			if v := getString(params, "name"); v != "" {
				listener.Name = v
			}
			if v := getString(params, "bind_host"); v != "" {
				listener.BindHost = v
			}
			if v := int(getFloat64(params, "bind_port")); v > 0 {
				listener.BindPort = v
			}
			if v := getString(params, "profile_id"); v != "" {
				listener.ProfileID = v
			}
			if v, ok := params["remark"]; ok {
				listener.Remark, _ = v.(string)
			}
			if cfgRaw, ok := params["config"]; ok && cfgRaw != nil {
				cfgBytes, _ := json.Marshal(cfgRaw)
				listener.ConfigJSON = string(cfgBytes)
			}
			if _, ok := params["callback_host"]; ok {
				pcfg := &c2.ListenerConfig{}
				raw := strings.TrimSpace(listener.ConfigJSON)
				if raw == "" {
					raw = "{}"
				}
				_ = json.Unmarshal([]byte(raw), pcfg)
				pcfg.CallbackHost = strings.TrimSpace(getString(params, "callback_host"))
				pcfg.ApplyDefaults()
				cfgBytes, err := json.Marshal(pcfg)
				if err != nil {
					return makeC2Result(nil, err)
				}
				listener.ConfigJSON = string(cfgBytes)
			}
			if err := m.DB().UpdateC2Listener(listener); err != nil {
				return makeC2Result(nil, err)
			}
			listener.EncryptionKey = ""
			listener.ImplantToken = ""
			return makeC2Result(map[string]interface{}{"listener": listener}, nil)

		case "start":
			listener, err := m.StartListener(id)
			if err != nil {
				return makeC2Result(nil, err)
			}
			listener.EncryptionKey = ""
			listener.ImplantToken = ""
			return makeC2Result(map[string]interface{}{"listener": listener}, nil)

		case "stop":
			err := m.StopListener(id)
			return makeC2Result(map[string]interface{}{"stopped": err == nil}, err)

		case "delete":
			err := m.DeleteListener(id)
			return makeC2Result(map[string]interface{}{"deleted": err == nil}, err)

		default:
			return makeC2Result(nil, fmt.Errorf("unknown action: %s", action))
		}
	})
}

// ============================================================================
// c2_session — 会话统一工具
// ============================================================================

func registerC2SessionTool(s *mcp.Server, m *c2.Manager, l *zap.Logger) {
	s.RegisterTool(mcp.Tool{
		Name: builtin.ToolC2Session,
		Description: `Manage accessible C2 sessions using action:
- list: filter by listener_id/status/os/search/suspicious.
- get: details and recent task history (session_id).
- set_sleep: heartbeat interval/jitter (session_id).
- kill: send an exit task to the implant (session_id); delivery is not proof of remote termination.
- delete: remove one session record (session_id).
- delete_batch: remove session records (session_ids array).`,
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"action":         map[string]interface{}{"type": "string", "description": "Operation: list/get/set_sleep/kill/delete/delete_batch", "enum": []string{"list", "get", "set_sleep", "kill", "delete", "delete_batch"}},
				"session_id":     map[string]interface{}{"type": "string", "description": "Session ID (get/set_sleep/kill/delete required)"},
				"session_ids":    map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "string"}, "description": "Session ID List (delete_batch)"},
				"listener_id":    map[string]interface{}{"type": "string", "description": "Filter by listening (list) "},
				"status":         map[string]interface{}{"type": "string", "description": "Filter by Status: active/sleeping/dead/killed (list) "},
				"os":             map[string]interface{}{"type": "string", "description": "Press OS filter: linux/windows/darwin (list)"},
				"search":         map[string]interface{}{"type": "string", "description": "Fuzzy search hostname/username/IP(list)"},
				"suspicious":     map[string]interface{}{"type": "boolean", "description": "Suspected misreporting only: offline and tcp_*/ unknown / PID 0 (list)"},
				"limit":          map[string]interface{}{"type": "integer", "description": "Maximum number of returns (list)"},
				"sleep_seconds":  map[string]interface{}{"type": "integer", "description": "Heart beat interval seconds (set_sleep)"},
				"jitter_percent": map[string]interface{}{"type": "integer", "description": "Dithering percentage 0-100 (set_sleep)"},
			},
			"required": []string{"action"},
		},
	}, func(ctx context.Context, params map[string]interface{}) (*mcp.ToolResult, error) {
		action := getString(params, "action")
		id := getString(params, "session_id")

		switch action {
		case "list":
			filter := database.ListC2SessionsFilter{
				ListenerID: getString(params, "listener_id"),
				ProjectID:  mcpEffectiveProjectFilter(ctx, m.DB()),
				Status:     getString(params, "status"),
				OS:         getString(params, "os"),
				Search:     getString(params, "search"),
			}
			if limit := int(getFloat64(params, "limit")); limit > 0 {
				filter.Limit = limit
			}
			if v, ok := params["suspicious"].(bool); ok && v {
				filter.Suspicious = true
			}
			sessions, err := m.DB().ListC2SessionsForAccess(filter, c2ToolAccess(ctx))
			return makeC2Result(map[string]interface{}{"sessions": sessions, "count": len(sessions)}, err)

		case "get":
			session, err := m.DB().GetC2Session(id)
			if err != nil {
				return makeC2Result(nil, err)
			}
			if session == nil {
				return makeC2Result(nil, fmt.Errorf("session not found"))
			}
			tasks, _ := m.DB().ListC2Tasks(database.ListC2TasksFilter{SessionID: id, Limit: 10})
			return makeC2Result(map[string]interface{}{"session": session, "tasks": tasks}, nil)

		case "set_sleep":
			sleep := int(getFloat64(params, "sleep_seconds"))
			jitter := int(getFloat64(params, "jitter_percent"))
			task, err := m.SetSessionSleep(id, sleep, jitter)
			out := map[string]interface{}{
				"updated":        err == nil,
				"sleep_seconds":  sleep,
				"jitter_percent": jitter,
			}
			if task != nil {
				out["task_id"] = task.ID
			}
			return makeC2Result(out, err)

		case "kill":
			task, err := m.EnqueueTask(c2.EnqueueTaskInput{
				SessionID:      id,
				TaskType:       c2.TaskTypeExit,
				Payload:        map[string]interface{}{},
				Source:         "ai",
				ConversationID: agent.ConversationIDFromContext(ctx),
				UserCtx:        ctx,
			})
			return makeC2Result(map[string]interface{}{"task": task}, err)

		case "delete":
			err := m.DB().DeleteC2Session(id)
			return makeC2Result(map[string]interface{}{"deleted": err == nil}, err)

		case "delete_batch":
			rawIDs, _ := params["session_ids"].([]interface{})
			ids := make([]string, 0, len(rawIDs))
			for _, v := range rawIDs {
				if s, ok := v.(string); ok && strings.TrimSpace(s) != "" {
					ids = append(ids, strings.TrimSpace(s))
				}
			}
			n, err := m.DB().DeleteC2SessionsByIDs(ids)
			return makeC2Result(map[string]interface{}{"deleted": n}, err)

		default:
			return makeC2Result(nil, fmt.Errorf("unknown action: %s", action))
		}
	})
}

// ============================================================================
// c2_task — 任务下发统一工具（合并所有 task 类型）
// ============================================================================

func registerC2TaskTool(s *mcp.Server, m *c2.Manager, l *zap.Logger) {
	s.RegisterTool(mcp.Tool{
		Name: builtin.ToolC2Task,
		Description: `Send an authorized task to an accessible C2 session using task_type:
- exec/shell: command required; shell preserves the working directory.
- pwd/ps/screenshot/socks_stop: no additional parameters.
- cd/ls: path required; kill_proc: pid required.
- upload: remote_path and file_id; download: remote_path.
- port_fwd: action=start/stop, local_port, remote_host and remote_port.
- socks_start: port (default 1080).
- load_assembly: base64 data or file_id, with optional args.
- persist: optional method=auto/cron/bashrc/launchagent/registry/schtasks.
Returns task_id. Retrieve results with c2_task_manage wait/get_result. Task submission is not proof of execution. Privileged/lasting actions require the actual engagement scope and native gates.`,
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"session_id":      map[string]interface{}{"type": "string", "description": "C2 session ID (s_xxx)"},
				"task_type":       map[string]interface{}{"type": "string", "description": "Task Type", "enum": []string{"exec", "shell", "pwd", "cd", "ls", "ps", "kill_proc", "upload", "download", "screenshot", "port_fwd", "socks_start", "socks_stop", "load_assembly", "persist"}},
				"command":         map[string]interface{}{"type": "string", "description": "Command (exec/shell)"},
				"path":            map[string]interface{}{"type": "string", "description": "Path (cd/ls)"},
				"pid":             map[string]interface{}{"type": "integer", "description": "Process ID (kill_proc)"},
				"remote_path":     map[string]interface{}{"type": "string", "description": "Remote Path (upload/download)"},
				"file_id":         map[string]interface{}{"type": "string", "description": "Service-end file ID (upload/load_assembly)"},
				"data":            map[string]interface{}{"type": "string", "description": "base64 data (load_assembly)"},
				"args":            map[string]interface{}{"type": "string", "description": "Command line parameters (load_assembly)"},
				"action":          map[string]interface{}{"type": "string", "description": "start/stop（port_fwd）"},
				"local_port":      map[string]interface{}{"type": "integer", "description": "Local port (port_fwd)"},
				"remote_host":     map[string]interface{}{"type": "string", "description": "Remote Host (port_fwd)"},
				"remote_port":     map[string]interface{}{"type": "integer", "description": "Remote Port (port_fwd)"},
				"port":            map[string]interface{}{"type": "integer", "description": "SOCKS5 port (socks_start), default 1080"},
				"method":          map[string]interface{}{"type": "string", "description": "Persistence method: auto/cron/bashrc/launchagent/registry/schtasks"},
				"timeout_seconds": map[string]interface{}{"type": "integer", "description": "Timeout seconds, default 60"},
			},
			"required": []string{"session_id", "task_type"},
		},
	}, func(ctx context.Context, params map[string]interface{}) (*mcp.ToolResult, error) {
		sessionID := getString(params, "session_id")
		taskTypeStr := getString(params, "task_type")
		taskType := c2.TaskType(taskTypeStr)
		timeout := getFloat64(params, "timeout_seconds")

		payload := map[string]interface{}{"timeout_seconds": timeout}

		switch taskType {
		case c2.TaskTypeExec, c2.TaskTypeShell:
			payload["command"] = getString(params, "command")
		case c2.TaskTypeCd, c2.TaskTypeLs:
			payload["path"] = getString(params, "path")
		case c2.TaskTypeKillProc:
			payload["pid"] = params["pid"]
		case c2.TaskTypeUpload:
			payload["remote_path"] = getString(params, "remote_path")
			payload["file_id"] = getString(params, "file_id")
		case c2.TaskTypeDownload:
			payload["remote_path"] = getString(params, "remote_path")
		case c2.TaskTypePortFwd:
			payload["action"] = getString(params, "action")
			payload["local_port"] = params["local_port"]
			payload["remote_host"] = getString(params, "remote_host")
			payload["remote_port"] = params["remote_port"]
		case c2.TaskTypeSocksStart:
			payload["port"] = params["port"]
		case c2.TaskTypeLoadAssembly:
			payload["data"] = getString(params, "data")
			payload["file_id"] = getString(params, "file_id")
			payload["args"] = getString(params, "args")
		case c2.TaskTypePersist:
			payload["method"] = getString(params, "method")
		case c2.TaskTypePwd, c2.TaskTypePs, c2.TaskTypeScreenshot, c2.TaskTypeSocksStop:
			// no extra params
		default:
			return makeC2Result(nil, fmt.Errorf("unsupported task_type: %s", taskTypeStr))
		}

		input := c2.EnqueueTaskInput{
			SessionID:      sessionID,
			TaskType:       taskType,
			Payload:        payload,
			Source:         "ai",
			ConversationID: agent.ConversationIDFromContext(ctx),
			UserCtx:        ctx,
		}
		task, err := m.EnqueueTask(input)
		if err != nil {
			return makeC2Result(nil, err)
		}
		return makeC2Result(map[string]interface{}{"task_id": task.ID, "status": task.Status}, nil)
	})
}

// ============================================================================
// c2_task_manage — 任务管理工具（查询/等待/取消）
// ============================================================================

func registerC2TaskManageTool(s *mcp.Server, m *c2.Manager, l *zap.Logger) {
	s.RegisterTool(mcp.Tool{
		Name: builtin.ToolC2TaskManage,
		Description: `Manage accessible C2 tasks using action:
- get_result: task details and result (task_id).
- wait: wait for completion and return its result (task_id).
- list: filter by session_id/status.
- cancel: cancel a queued task (task_id); cancellation is not proof a remote process stopped.`,
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"action":          map[string]interface{}{"type": "string", "description": "Operation: get_result/wait/list/cancel", "enum": []string{"get_result", "wait", "list", "cancel"}},
				"task_id":         map[string]interface{}{"type": "string", "description": "Tasks ID (get_result/wait/cancel requires) "},
				"session_id":      map[string]interface{}{"type": "string", "description": "Filter by Session (list)"},
				"status":          map[string]interface{}{"type": "string", "description": "Filtered by status: queued/sent/running/success/failed/cancelled (list)"},
				"limit":           map[string]interface{}{"type": "integer", "description": "Maximum number of returns (list)"},
				"timeout_seconds": map[string]interface{}{"type": "integer", "description": "Waiting for timeout seconds (wait) , Default 60"},
			},
			"required": []string{"action"},
		},
	}, func(ctx context.Context, params map[string]interface{}) (*mcp.ToolResult, error) {
		action := getString(params, "action")

		switch action {
		case "get_result":
			id := getString(params, "task_id")
			task, err := m.DB().GetC2Task(id)
			if err != nil {
				return makeC2Result(nil, err)
			}
			if task == nil {
				return makeC2Result(nil, fmt.Errorf("task not found"))
			}
			return makeC2Result(map[string]interface{}{"task": task}, nil)

		case "wait":
			id := getString(params, "task_id")
			timeout := int(getFloat64(params, "timeout_seconds"))
			if timeout <= 0 {
				timeout = 60
			}
			deadline := time.Now().Add(time.Duration(timeout) * time.Second)
			for time.Now().Before(deadline) {
				task, err := m.DB().GetC2Task(id)
				if err != nil {
					return makeC2Result(nil, err)
				}
				if task == nil {
					return makeC2Result(nil, fmt.Errorf("task not found"))
				}
				if task.Status == "success" || task.Status == "failed" || task.Status == "cancelled" {
					return makeC2Result(map[string]interface{}{"task": task}, nil)
				}
				select {
				case <-time.After(500 * time.Millisecond):
				case <-ctx.Done():
					return makeC2Result(nil, ctx.Err())
				}
			}
			return makeC2Result(nil, fmt.Errorf("timeout waiting for task completion"))

		case "list":
			filter := database.ListC2TasksFilter{
				SessionID: getString(params, "session_id"),
				ProjectID: mcpEffectiveProjectFilter(ctx, m.DB()),
				Status:    getString(params, "status"),
			}
			if limit := int(getFloat64(params, "limit")); limit > 0 {
				filter.Limit = limit
			}
			tasks, err := m.DB().ListC2TasksForAccess(filter, c2ToolAccess(ctx))
			return makeC2Result(map[string]interface{}{"tasks": tasks, "count": len(tasks)}, err)

		case "cancel":
			id := getString(params, "task_id")
			err := m.CancelTask(id)
			return makeC2Result(map[string]interface{}{"cancelled": err == nil}, err)

		default:
			return makeC2Result(nil, fmt.Errorf("unknown action: %s", action))
		}
	})
}

// ============================================================================
// c2_payload — Payload 统一工具
// ============================================================================

func registerC2PayloadTool(s *mcp.Server, m *c2.Manager, l *zap.Logger, webListenPort int) {
	s.RegisterTool(mcp.Tool{
		Name: builtin.ToolC2Payload,
		Description: fmt.Sprintf(`Generate a C2 payload for an operator-authorized listener/target. Select action:
- oneliner: generate a one-line payload compatible with the listener protocol. tcp_reverse defaults to an encrypted beacon built with action=build. Legacy bash/nc/nc_mkfifo/python/perl/powershell kinds require explicit listener config.allow_legacy_shell=true.
- For http_beacon/https_beacon/websocket, the only oneliner kind is curl_beacon (inline bash+curl). Its trailing & backgrounds the complete bash -c command. Preserve that suffix when invoking through exec/execute; removing it leaves the loop in the foreground until timeout/cancellation.
- For publicly reachable tcp_reverse listeners, use build for an encrypted beacon; do not enable legacy shells merely for compatibility.
- Omitting kind selects the first compatible kind (curl_beacon for HTTP).
- build: cross-compile a beacon binary for http_beacon/https_beacon/websocket/tcp_reverse. Encrypted tcp_reverse starts with CSB1, uses AES-GCM and verifies ImplantToken before accepting the connection.
The listener bind_port must differ from this service's Web port %d (server.port); otherwise callbacks will fail. Scope and native C2/RBAC gates still apply.`, webListenPort),
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"action":         map[string]interface{}{"type": "string", "description": "Operation: oneliner/build", "enum": []string{"oneliner", "build"}},
				"listener_id":    map[string]interface{}{"type": "string", "description": "Required listener ID. For oneliner, select a kind compatible with its listener type."},
				"kind":           map[string]interface{}{"type": "string", "description": "only action=oneliner requires.tcp_reverse: bash|nc|nc_mkfifo|python|perl|powershell; http_beacon|https_beacon|websocket: only curl_beacon"},
				"host":           map[string]interface{}{"type": "string", "description": "Optional callback host override for oneliner/build. Otherwise use listener callback_host, then bind_host (an unspecified 0.0.0.0 bind may trigger external-IP detection)."},
				"os":             map[string]interface{}{"type": "string", "description": "Target OS (build): linux/windows/darwin", "default": "linux"},
				"arch":           map[string]interface{}{"type": "string", "description": "Target architecture (build): amd64/arm64/386/arm", "default": "amd64"},
				"sleep_seconds":  map[string]interface{}{"type": "integer", "description": "Default heartbeat interval (build)"},
				"jitter_percent": map[string]interface{}{"type": "integer", "description": "Default heartbeat jitter percentage (build)"},
			},
			"required": []string{"action", "listener_id"},
		},
	}, func(ctx context.Context, params map[string]interface{}) (*mcp.ToolResult, error) {
		action := getString(params, "action")
		listenerID := getString(params, "listener_id")

		switch action {
		case "oneliner":
			listener, err := m.DB().GetC2Listener(listenerID)
			if err != nil {
				return makeC2Result(nil, err)
			}
			if listener == nil {
				return makeC2Result(nil, fmt.Errorf("listener not found"))
			}
			host := c2.ResolveBeaconDialHost(listener, getString(params, "host"), l, listenerID)
			kind := c2.OnelinerKind(getString(params, "kind"))
			if kind == "" {
				compatible := c2.OnelinerKindsForListener(listener.Type)
				if len(compatible) > 0 {
					kind = compatible[0]
				}
			}
			if !c2.IsOnelinerCompatible(listener.Type, kind) {
				compatible := c2.OnelinerKindsForListener(listener.Type)
				names := make([]string, len(compatible))
				for i, k := range compatible {
					names[i] = string(k)
				}
				return makeC2Result(nil, fmt.Errorf("%s is not supported by the listening type %s, compatible type: %v", listener.Type, kind, names))
			}
			if err := c2.ValidateOnelinerForListener(listener, kind); err != nil {
				return makeC2Result(nil, err)
			}
			input := c2.OnelinerInput{
				Kind:         kind,
				Host:         host,
				Port:         listener.BindPort,
				HTTPBaseURL:  fmt.Sprintf("http://%s:%d", host, listener.BindPort),
				ImplantToken: listener.ImplantToken,
			}
			oneliner, err := c2.GenerateOneliner(input)
			if err != nil {
				return makeC2Result(nil, err)
			}
			out := map[string]interface{}{
				"oneliner": oneliner, "kind": input.Kind, "host": host, "port": listener.BindPort,
			}
			if kind == c2.OnelinerCurl {
				out["usage_note"] = "Synchronize exec/execute: The whole paragraph must be executed as it is (at the end there must be \" & \" ). Remove the rest of the message while the tool will never end and the tool will remain stuck."
			}
			return makeC2Result(out, nil)

		case "build":
			builder := c2.NewPayloadBuilder(m, l, "", "")
			input := c2.PayloadBuilderInput{
				ListenerID:    listenerID,
				OS:            getString(params, "os"),
				Arch:          getString(params, "arch"),
				SleepSeconds:  int(getFloat64(params, "sleep_seconds")),
				JitterPercent: int(getFloat64(params, "jitter_percent")),
				Host:          strings.TrimSpace(getString(params, "host")),
			}
			result, err := builder.BuildBeacon(input)
			if err != nil {
				return makeC2Result(nil, err)
			}
			if principal, ok := authctx.PrincipalFromContext(ctx); ok {
				_ = m.DB().RecordC2PayloadArtifact(filepath.Base(result.OutputPath), result.PayloadID, result.ListenerID, principal.UserID)
			}
			return makeC2Result(map[string]interface{}{
				"payload_id": result.PayloadID, "download_path": result.DownloadPath,
				"os": result.OS, "arch": result.Arch, "size_bytes": result.SizeBytes,
			}, nil)

		default:
			return makeC2Result(nil, fmt.Errorf("unknown action: %s", action))
		}
	})
}

// ============================================================================
// c2_event — 事件查询工具
// ============================================================================

func registerC2EventTool(s *mcp.Server, m *c2.Manager, l *zap.Logger) {
	s.RegisterTool(mcp.Tool{
		Name:        builtin.ToolC2Event,
		Description: "Get C2 events (online/ offline/task/ error) to support filtering by level/category/session/task/time",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"level":      map[string]interface{}{"type": "string", "description": "Level filter:info/warn/critical"},
				"category":   map[string]interface{}{"type": "string", "description": "Category filter: listener/session/task/payload/opsec"},
				"session_id": map[string]interface{}{"type": "string", "description": "Filter by Session"},
				"task_id":    map[string]interface{}{"type": "string", "description": "Filter by Task"},
				"since":      map[string]interface{}{"type": "string", "description": "Start Time (RFC3339 Format, for example 2025-01-01T00:00:00Z) "},
				"limit":      map[string]interface{}{"type": "integer", "default": 50, "description": "Return count"},
			},
		},
	}, func(ctx context.Context, params map[string]interface{}) (*mcp.ToolResult, error) {
		filter := database.ListC2EventsFilter{
			Level:     getString(params, "level"),
			Category:  getString(params, "category"),
			ProjectID: mcpEffectiveProjectFilter(ctx, m.DB()),
			SessionID: getString(params, "session_id"),
			TaskID:    getString(params, "task_id"),
			Limit:     int(getFloat64(params, "limit")),
		}
		if filter.Limit <= 0 {
			filter.Limit = 50
		}
		if since := getString(params, "since"); since != "" {
			if t, err := time.Parse(time.RFC3339, since); err == nil {
				filter.Since = &t
			}
		}
		events, err := m.DB().ListC2EventsForAccess(filter, c2ToolAccess(ctx))
		return makeC2Result(map[string]interface{}{"events": events, "count": len(events)}, err)
	})
}

func c2ToolAccess(ctx context.Context) database.RBACListAccess {
	principal, ok := authctx.PrincipalFromContext(ctx)
	if !ok {
		return database.RBACListAccess{Scope: database.RBACScopeAssigned}
	}
	return database.RBACListAccess{UserID: principal.UserID, Scope: principal.ScopeFor("c2:read")}
}

// ============================================================================
// c2_profile — Malleable Profile 管理工具（新增）
// ============================================================================

func registerC2ProfileTool(s *mcp.Server, m *c2.Manager, l *zap.Logger) {
	s.RegisterTool(mcp.Tool{
		Name: builtin.ToolC2Profile,
		Description: `Manage C2 communication profiles using action:
- list: all accessible profiles; get: profile details (profile_id).
- create: name required; optional user_agent/uris/request_headers/response_headers/body_template/jitter_min_ms/jitter_max_ms.
- update/delete: profile_id required.
Profiles affect beacon communication formatting; they do not supply authorization or isolate an untrusted implant.`,
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"action":           map[string]interface{}{"type": "string", "description": "Operation: list/get/create/update/delete", "enum": []string{"list", "get", "create", "update", "delete"}},
				"profile_id":       map[string]interface{}{"type": "string", "description": "Profile ID (get/update/delete required)"},
				"name":             map[string]interface{}{"type": "string", "description": "Profile name"},
				"user_agent":       map[string]interface{}{"type": "string", "description": "User-Agent string"},
				"uris":             map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "string"}, "description": "Beacon request URI list"},
				"request_headers":  map[string]interface{}{"type": "object", "description": "Custom Header"},
				"response_headers": map[string]interface{}{"type": "object", "description": "Custom Response Header"},
				"body_template":    map[string]interface{}{"type": "string", "description": "Response template"},
				"jitter_min_ms":    map[string]interface{}{"type": "integer", "description": "Minimum jitter (ms)"},
				"jitter_max_ms":    map[string]interface{}{"type": "integer", "description": "Maximum jitter (ms)"},
			},
			"required": []string{"action"},
		},
	}, func(ctx context.Context, params map[string]interface{}) (*mcp.ToolResult, error) {
		action := getString(params, "action")
		id := getString(params, "profile_id")

		switch action {
		case "list":
			profiles, err := m.DB().ListC2Profiles()
			return makeC2Result(map[string]interface{}{"profiles": profiles, "count": len(profiles)}, err)

		case "get":
			profile, err := m.DB().GetC2Profile(id)
			if err != nil {
				return makeC2Result(nil, err)
			}
			if profile == nil {
				return makeC2Result(nil, fmt.Errorf("profile not found"))
			}
			return makeC2Result(map[string]interface{}{"profile": profile}, nil)

		case "create":
			profile := &database.C2Profile{
				ID:           "p_" + strings.ReplaceAll(uuid.New().String(), "-", "")[:14],
				Name:         getString(params, "name"),
				UserAgent:    getString(params, "user_agent"),
				BodyTemplate: getString(params, "body_template"),
				JitterMinMS:  int(getFloat64(params, "jitter_min_ms")),
				JitterMaxMS:  int(getFloat64(params, "jitter_max_ms")),
				CreatedAt:    time.Now(),
			}
			if uris, ok := params["uris"]; ok {
				if arr, ok := uris.([]interface{}); ok {
					for _, u := range arr {
						if s, ok := u.(string); ok {
							profile.URIs = append(profile.URIs, s)
						}
					}
				}
			}
			if rh, ok := params["request_headers"]; ok {
				if m, ok := rh.(map[string]interface{}); ok {
					profile.RequestHeaders = make(map[string]string)
					for k, v := range m {
						profile.RequestHeaders[k], _ = v.(string)
					}
				}
			}
			if rh, ok := params["response_headers"]; ok {
				if m, ok := rh.(map[string]interface{}); ok {
					profile.ResponseHeaders = make(map[string]string)
					for k, v := range m {
						profile.ResponseHeaders[k], _ = v.(string)
					}
				}
			}
			if err := m.DB().CreateC2Profile(profile); err != nil {
				return makeC2Result(nil, err)
			}
			return makeC2Result(map[string]interface{}{"profile": profile}, nil)

		case "update":
			profile, err := m.DB().GetC2Profile(id)
			if err != nil {
				return makeC2Result(nil, err)
			}
			if profile == nil {
				return makeC2Result(nil, fmt.Errorf("profile not found"))
			}
			if v := getString(params, "name"); v != "" {
				profile.Name = v
			}
			if v := getString(params, "user_agent"); v != "" {
				profile.UserAgent = v
			}
			if v := getString(params, "body_template"); v != "" {
				profile.BodyTemplate = v
			}
			if v := int(getFloat64(params, "jitter_min_ms")); v > 0 {
				profile.JitterMinMS = v
			}
			if v := int(getFloat64(params, "jitter_max_ms")); v > 0 {
				profile.JitterMaxMS = v
			}
			if uris, ok := params["uris"]; ok {
				if arr, ok := uris.([]interface{}); ok {
					profile.URIs = nil
					for _, u := range arr {
						if s, ok := u.(string); ok {
							profile.URIs = append(profile.URIs, s)
						}
					}
				}
			}
			if rh, ok := params["request_headers"]; ok {
				if mp, ok := rh.(map[string]interface{}); ok {
					profile.RequestHeaders = make(map[string]string)
					for k, v := range mp {
						profile.RequestHeaders[k], _ = v.(string)
					}
				}
			}
			if rh, ok := params["response_headers"]; ok {
				if mp, ok := rh.(map[string]interface{}); ok {
					profile.ResponseHeaders = make(map[string]string)
					for k, v := range mp {
						profile.ResponseHeaders[k], _ = v.(string)
					}
				}
			}
			if err := m.DB().UpdateC2Profile(profile); err != nil {
				return makeC2Result(nil, err)
			}
			return makeC2Result(map[string]interface{}{"profile": profile}, nil)

		case "delete":
			err := m.DB().DeleteC2Profile(id)
			return makeC2Result(map[string]interface{}{"deleted": err == nil}, err)

		default:
			return makeC2Result(nil, fmt.Errorf("unknown action: %s", action))
		}
	})
}

// ============================================================================
// c2_file — 文件管理工具（新增）
// ============================================================================

func registerC2FileTool(s *mcp.Server, m *c2.Manager, l *zap.Logger) {
	s.RegisterTool(mcp.Tool{
		Name: builtin.ToolC2File,
		Description: `C2 File Management. Selecting operations by action parameters:
-list: File transfer records for listing sessions (session_id required)
-get_result: Get the mission outcome document path (interception, etc., needs task_id)`,
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"action":     map[string]interface{}{"type": "string", "description": "Operation: list/get_result", "enum": []string{"list", "get_result"}},
				"session_id": map[string]interface{}{"type": "string", "description": "Session ID (list required)"},
				"task_id":    map[string]interface{}{"type": "string", "description": "Task ID (get_result required)"},
			},
			"required": []string{"action"},
		},
	}, func(ctx context.Context, params map[string]interface{}) (*mcp.ToolResult, error) {
		action := getString(params, "action")

		switch action {
		case "list":
			sessionID := getString(params, "session_id")
			if sessionID == "" {
				return makeC2Result(nil, fmt.Errorf("session_id required"))
			}
			files, err := m.DB().ListC2FilesBySession(sessionID)
			return makeC2Result(map[string]interface{}{"files": files, "count": len(files)}, err)

		case "get_result":
			taskID := getString(params, "task_id")
			task, err := m.DB().GetC2Task(taskID)
			if err != nil {
				return makeC2Result(nil, err)
			}
			if task == nil {
				return makeC2Result(nil, fmt.Errorf("task not found"))
			}
			if task.ResultBlobPath == "" {
				return makeC2Result(map[string]interface{}{"has_file": false, "task_id": taskID}, nil)
			}
			return makeC2Result(map[string]interface{}{
				"has_file":  true,
				"task_id":   taskID,
				"file_path": task.ResultBlobPath,
			}, nil)

		default:
			return makeC2Result(nil, fmt.Errorf("unknown action: %s", action))
		}
	})
}

// ============================================================================
// 工具函数
// ============================================================================

func getString(params map[string]interface{}, key string) string {
	if v, ok := params[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func getFloat64(params map[string]interface{}, key string) float64 {
	if v, ok := params[key]; ok {
		switch n := v.(type) {
		case float64:
			return n
		case int:
			return float64(n)
		case string:
			if f, err := strconv.ParseFloat(n, 64); err == nil {
				return f
			}
		}
	}
	return 0
}
