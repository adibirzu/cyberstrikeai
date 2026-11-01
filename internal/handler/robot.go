package handler

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"cyberstrike-ai/internal/legacytext"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"cyberstrike-ai/internal/audit"
	"cyberstrike-ai/internal/authctx"
	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/security"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

const (
	robotCmdHelp          = "help"
	robotCmdList          = "list"
	robotCmdListAlt       = "list"
	robotCmdSwitch        = "switch"
	robotCmdContinue      = "continue"
	robotCmdNew           = "new"
	robotCmdClear         = "clear"
	robotCmdStatus        = "status"
	robotCmdStop          = "stop"
	robotCmdRoles         = "roles"
	robotCmdRolesList     = "roles"
	robotCmdSwitchRole    = "role"
	robotCmdModes         = "mode"
	robotCmdModesList     = "modes"
	robotCmdSwitchMode    = "mode"
	robotCmdDelete        = "delete"
	robotCmdVersion       = "version"
	robotCmdProjects      = "projects"
	robotCmdProjectsList  = "projects"
	robotCmdBindProject   = "bind project"
	robotCmdNewProject    = "new project"
	robotCmdUnbindProject = "unbind project"
	robotCmdBindUser      = "bind"
	robotCmdUnbindUser    = "unbind"
	robotCmdIdentity      = "whoami"
	robotCmdTask          = "task"
	robotCmdRename        = "rename"
	robotCmdPermissions   = "permissions"
	robotCmdDoctor        = "doctor"
	robotCmdConfirm       = "confirm"
	robotCmdCancel        = "cancel"
	robotCmdVulnAlerts    = "vuln alerts"
	robotBindingCodeTTL   = 5 * time.Minute
)

type robotPendingConfirmation struct {
	Action    string
	Target    string
	ExpiresAt time.Time
}

// RobotHandler 企业微信/钉钉/飞书等机器人回调处理
type RobotHandler struct {
	config               *config.Config
	db                   *database.DB
	agentHandler         *AgentHandler
	logger               *zap.Logger
	mu                   sync.RWMutex
	sessions             map[string]string             // key: "platform_userID", value: conversationID
	sessionRoles         map[string]string             // key: "platform_userID", value: roleName（默认"默认"）
	sessionModes         map[string]string             // key: "platform_userID", value: agent mode
	cancelMu             sync.Mutex                    // 保护 runningCancels
	runningCancels       map[string]context.CancelFunc // key: "platform_userID", 用于停止命令中断任务
	wecomReplay          map[string]time.Time
	pendingConfirmations map[string]robotPendingConfirmation
	alertWake            chan struct{}
	audit                *audit.Service
}

// NewRobotHandler 创建机器人处理器
func NewRobotHandler(cfg *config.Config, db *database.DB, agentHandler *AgentHandler, logger *zap.Logger) *RobotHandler {
	return &RobotHandler{
		config:               cfg,
		db:                   db,
		agentHandler:         agentHandler,
		logger:               logger,
		sessions:             make(map[string]string),
		sessionRoles:         make(map[string]string),
		sessionModes:         make(map[string]string),
		runningCancels:       make(map[string]context.CancelFunc),
		wecomReplay:          make(map[string]time.Time),
		pendingConfirmations: make(map[string]robotPendingConfirmation),
		alertWake:            make(chan struct{}, 1),
	}
}

func (h *RobotHandler) SetAudit(s *audit.Service) {
	h.audit = s
}

func (h *RobotHandler) acceptFreshWecomRequest(timestamp, nonce, signature string) bool {
	unixSeconds, err := strconv.ParseInt(strings.TrimSpace(timestamp), 10, 64)
	if err != nil {
		return false
	}
	now := time.Now()
	requestTime := time.Unix(unixSeconds, 0)
	if requestTime.Before(now.Add(-5*time.Minute)) || requestTime.After(now.Add(5*time.Minute)) {
		return false
	}
	key := strings.TrimSpace(timestamp) + "\x00" + strings.TrimSpace(nonce) + "\x00" + strings.TrimSpace(signature)
	if strings.TrimSpace(nonce) == "" || strings.TrimSpace(signature) == "" {
		return false
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	for replayKey, seenAt := range h.wecomReplay {
		if now.Sub(seenAt) > 10*time.Minute {
			delete(h.wecomReplay, replayKey)
		}
	}
	if _, exists := h.wecomReplay[key]; exists {
		return false
	}
	h.wecomReplay[key] = now
	return true
}

// sessionKey 生成会话 key
func (h *RobotHandler) sessionKey(platform, userID string) string {
	return platform + "_" + userID
}

func normalizeRobotBindingCode(code string) string {
	return strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(code), "-", ""))
}

func hashRobotBindingCode(code string) string {
	sum := sha256.Sum256([]byte(normalizeRobotBindingCode(code)))
	return fmt.Sprintf("%x", sum[:])
}

func (h *RobotHandler) resolveRobotAccess(platform, userID string) (*database.RBACAccess, error) {
	if h.db == nil {
		return nil, fmt.Errorf("Robot authentication service is unavailable.")
	}
	authorization := h.config.Robots.AuthorizationFor(platform)
	var access *database.RBACAccess
	var err error
	switch authorization.EffectiveMode() {
	case config.RobotAuthModeUserBinding:
		access, err = h.db.ResolveRobotRBACAccess(platform, userID)
	case config.RobotAuthModeServiceAccount:
		if !authorization.ExternalUserAllowed(userID) {
			return nil, fmt.Errorf("Robot sender is not on the service-account allowlist.")
		}
		access, err = h.db.ResolveRBACAccess(strings.TrimSpace(authorization.ServiceUserID))
	default:
		return nil, fmt.Errorf("Robot authentication mode is invalid.")
	}
	if err != nil {
		return nil, err
	}
	if !access.User.Enabled {
		return nil, fmt.Errorf("The bound platform account has been disabled")
	}
	return access, nil
}

func robotPrincipal(access *database.RBACAccess) authctx.Principal {
	if access == nil {
		return authctx.Principal{}
	}
	return authctx.NewPrincipalWithScopes(access.User.ID, access.User.Username, access.Scope, access.Permissions, access.PermissionScopes)
}

func (h *RobotHandler) robotAccessDeniedMessage(platform string) string {
	if h.config.Robots.AuthorizationFor(platform).EffectiveMode() == config.RobotAuthModeServiceAccount {
		return "This sender is not on the robot service-account allowlist, or the service account is unavailable."
	}
	return "This platform account is not bound to a CyberStrikeAI user. Create a binding code in the web console and send: bind XXXX-XXXX"
}

func (h *RobotHandler) loadSessionBinding(sk string) (convID, role, agentMode string) {
	if h.db == nil || strings.TrimSpace(sk) == "" {
		return "", "", ""
	}
	binding, err := h.db.GetRobotSessionBinding(sk)
	if err != nil {
		h.logger.Warn("Failed to read robotic session binding", zap.String("session_key", sk), zap.Error(err))
		return "", "", ""
	}
	if binding == nil {
		return "", "", ""
	}
	return binding.ConversationID, binding.RoleName, binding.AgentMode
}

func (h *RobotHandler) persistSessionBinding(sk, convID, role, agentMode string) {
	if h.db == nil || strings.TrimSpace(sk) == "" || strings.TrimSpace(convID) == "" {
		return
	}
	if err := h.db.UpsertRobotSessionBinding(sk, convID, role, agentMode); err != nil {
		h.logger.Warn("Writing to robotic session binding failed", zap.String("session_key", sk), zap.Error(err))
	}
}

func (h *RobotHandler) deleteSessionBinding(sk string) {
	if h.db == nil || strings.TrimSpace(sk) == "" {
		return
	}
	if err := h.db.DeleteRobotSessionBinding(sk); err != nil {
		h.logger.Warn("Failed to remove robotic session binding", zap.String("session_key", sk), zap.Error(err))
	}
}

// getOrCreateConversation 获取或创建当前会话，title 用于新对话的标题（取用户首条消息前50字）
func (h *RobotHandler) getOrCreateConversation(platform, userID, title string, access *database.RBACAccess) (convID string, isNew bool) {
	sk := h.sessionKey(platform, userID)
	h.mu.RLock()
	convID = h.sessions[sk]
	h.mu.RUnlock()
	ownerID := access.User.ID
	readScope := robotPrincipal(access).ScopeFor("chat:read")
	if convID != "" && access.Permissions["chat:read"] && h.db.UserCanAccessResource(ownerID, readScope, "conversation", convID) {
		return convID, false
	}
	if persistedConvID, persistedRole, persistedMode := h.loadSessionBinding(sk); strings.TrimSpace(persistedConvID) != "" {
		if !access.Permissions["chat:read"] || !h.db.UserCanAccessResource(ownerID, readScope, "conversation", persistedConvID) {
			h.deleteSessionBinding(sk)
		} else {
			// 会话绑定持久化：服务重启后也可恢复当前对话和角色。
			h.mu.Lock()
			h.sessions[sk] = persistedConvID
			if strings.TrimSpace(persistedRole) != "" {
				h.sessionRoles[sk] = persistedRole
			}
			if strings.TrimSpace(persistedMode) != "" {
				h.sessionModes[sk] = config.NormalizeAgentMode(persistedMode)
			}
			h.mu.Unlock()
			return persistedConvID, false
		}
	}
	t := strings.TrimSpace(title)
	if t == "" {
		t = "New Dialogue " + time.Now().Format("01-02 15:04")
	} else {
		t = safeTruncateString(t, 50)
	}
	meta := database.ConversationCreateMeta{Source: "robot:" + platform}
	if !access.Permissions["chat:write"] {
		return "", false
	}
	meta.ProjectID = effectiveProjectID(h.config, "")
	if meta.ProjectID != "" && (!access.Permissions["project:read"] || !h.db.UserCanAccessResource(ownerID, robotPrincipal(access).ScopeFor("project:read"), "project", meta.ProjectID)) {
		meta.ProjectID = ""
	}
	conv, err := h.db.CreateConversation(t, meta)
	if err != nil {
		h.logger.Warn("Failed to create robot session", zap.Error(err))
		return "", false
	}
	convID = conv.ID
	_ = h.db.SetResourceOwner("conversation", convID, ownerID)
	h.mu.Lock()
	role := h.sessionRoles[sk]
	agentMode := h.sessionModes[sk]
	h.sessions[sk] = convID
	h.mu.Unlock()
	if agentMode == "" {
		agentMode = config.NormalizeRobotAgentMode(h.config.MultiAgent)
	}
	h.persistSessionBinding(sk, convID, role, agentMode)
	return convID, true
}

// setConversation 切换当前会话
func (h *RobotHandler) setConversation(platform, userID, convID string) {
	sk := h.sessionKey(platform, userID)
	h.mu.Lock()
	role := h.sessionRoles[sk]
	agentMode := h.sessionModes[sk]
	h.sessions[sk] = convID
	h.mu.Unlock()
	h.persistSessionBinding(sk, convID, role, agentMode)
}

// getRole 获取当前用户使用的角色，未设置时返回"默认"
func (h *RobotHandler) getRole(platform, userID string) string {
	sk := h.sessionKey(platform, userID)
	h.mu.RLock()
	role := h.sessionRoles[sk]
	h.mu.RUnlock()
	if strings.TrimSpace(role) != "" {
		return h.config.RoleDisplayName(role)
	}
	if _, persistedRole, _ := h.loadSessionBinding(sk); strings.TrimSpace(persistedRole) != "" {
		h.mu.Lock()
		h.sessionRoles[sk] = persistedRole
		h.mu.Unlock()
		return h.config.RoleDisplayName(persistedRole)
	}
	return "Default"
}

// setRole 设置当前用户使用的角色
func (h *RobotHandler) setRole(platform, userID, roleName string) {
	sk := h.sessionKey(platform, userID)
	h.mu.Lock()
	h.sessionRoles[sk] = roleName
	convID := h.sessions[sk]
	agentMode := h.sessionModes[sk]
	h.mu.Unlock()
	h.persistSessionBinding(sk, convID, roleName, agentMode)
}

func (h *RobotHandler) getAgentMode(platform, userID string) string {
	sk := h.sessionKey(platform, userID)
	h.mu.RLock()
	mode := h.sessionModes[sk]
	h.mu.RUnlock()
	if mode != "" {
		return config.NormalizeAgentMode(mode)
	}
	if _, _, persistedMode := h.loadSessionBinding(sk); persistedMode != "" {
		mode = config.NormalizeAgentMode(persistedMode)
		h.mu.Lock()
		h.sessionModes[sk] = mode
		h.mu.Unlock()
		return mode
	}
	return config.NormalizeRobotAgentMode(h.config.MultiAgent)
}

func (h *RobotHandler) setAgentMode(platform, userID, mode string) {
	sk := h.sessionKey(platform, userID)
	mode = config.NormalizeAgentMode(mode)
	h.mu.Lock()
	h.sessionModes[sk] = mode
	convID := h.sessions[sk]
	role := h.sessionRoles[sk]
	h.mu.Unlock()
	h.persistSessionBinding(sk, convID, role, mode)
}

// clearConversation 清空当前会话（切换到新对话）
func (h *RobotHandler) clearConversation(platform, userID string, access *database.RBACAccess) (newConvID string) {
	title := "New Dialogue " + time.Now().Format("01-02 15:04")
	meta := database.ConversationCreateMeta{Source: "robot:" + platform + ":new"}
	meta.ProjectID = effectiveProjectID(h.config, "")
	ownerID := access.User.ID
	if meta.ProjectID != "" && (!access.Permissions["project:read"] || !h.db.UserCanAccessResource(ownerID, robotPrincipal(access).ScopeFor("project:read"), "project", meta.ProjectID)) {
		meta.ProjectID = ""
	}
	conv, err := h.db.CreateConversation(title, meta)
	if err != nil {
		h.logger.Warn("Failed to create new dialogue", zap.Error(err))
		return ""
	}
	_ = h.db.SetResourceOwner("conversation", conv.ID, ownerID)
	h.setConversation(platform, userID, conv.ID)
	return conv.ID
}

// HandleMessage 处理用户输入，返回回复文本（供各平台 webhook 调用）
func (h *RobotHandler) HandleMessage(platform, userID, text string) (reply string) {
	platform = strings.TrimSpace(platform)
	userID = strings.TrimSpace(userID)
	text = strings.TrimSpace(text)
	if platform == "" {
		platform = "unknown"
	}
	if userID == "" {
		h.logger.Warn("The robot message is missing user identification and refused to be processed", zap.String("platform", platform))
		return "Could not identify sender, check the robot event subscription permissions (returning available user IDs)."
	}
	if text == "" {
		return "Please enter the content or send Help/help to view the command."
	}

	// 先尝试作为命令处理（支持中英文）
	if cmdReply, ok := h.handleRobotCommand(platform, userID, text); ok {
		return cmdReply
	}
	access, err := h.resolveRobotAccess(platform, userID)
	if err != nil {
		return h.robotAccessDeniedMessage(platform)
	}
	if !access.Permissions["agent:execute"] || !access.Permissions["chat:read"] || !access.Permissions["chat:write"] {
		return "Insufficient Permissions: Robotic dialogue needs agent:execute, chat:read and chat:write permissions."
	}
	if h.audit != nil && h.config.Robots.AuthorizationFor(platform).EffectiveMode() == config.RobotAuthModeServiceAccount {
		hint := sha256.Sum256([]byte(userID))
		h.audit.RecordSystem(audit.Entry{
			Category: "robot", Action: "service_account_execute", Result: "success", Actor: access.User.Username,
			ResourceType: "robot_sender", ResourceID: platform + ":" + fmt.Sprintf("%x", hint[:4]),
			Message: "White List Platform sender executes Agent using a robot service account",
		})
	}

	// 普通消息：走 Agent
	convID, _ := h.getOrCreateConversation(platform, userID, text, access)
	if convID == "" {
		return "Cannot create or retrieve the conversation; try again later."
	}
	// 若对话标题为「新对话 xx:xx」格式（由「新对话」命令创建），将标题更新为首条消息内容，与 Web 端体验一致
	if conv, err := h.db.GetConversation(convID); err == nil && legacytext.HasPrefix(conv.Title, "New Dialogue ") {
		newTitle := safeTruncateString(text, 50)
		if newTitle != "" {
			_ = h.db.UpdateConversationTitle(convID, newTitle)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), h.robotMessageTimeout())
	sk := h.sessionKey(platform, userID)
	h.cancelMu.Lock()
	h.runningCancels[sk] = cancel
	h.cancelMu.Unlock()
	defer func() {
		cancel()
		h.cancelMu.Lock()
		delete(h.runningCancels, sk)
		h.cancelMu.Unlock()
	}()
	role := h.getRole(platform, userID)
	agentMode := h.getAgentMode(platform, userID)
	resp, newConvID, err := h.agentHandler.ProcessMessageForRobot(ctx, platform, robotPrincipal(access), convID, text, role, agentMode)
	if err != nil {
		h.logger.Warn("Robot Agent execution failed.", zap.String("platform", platform), zap.String("userID", userID), zap.Error(err))
		if errors.Is(err, context.Canceled) {
			return "The task has been cancelled."
		}
		if errors.Is(err, context.DeadlineExceeded) {
			return "Please try again or streamline the scope of this request at a later stage, as the task is timed out."
		}
		return "Processing failed: " + err.Error()
	}
	if newConvID != convID {
		h.setConversation(platform, userID, newConvID)
	}
	return resp
}

func (h *RobotHandler) robotMessageTimeout() time.Duration {
	// 机器人整次消息处理超时（与单次工具超时 agent.tool_timeout_minutes 解耦）。
	return 10 * time.Hour
}

func (h *RobotHandler) cmdHelp(platform, userID string) string {
	access, _ := h.resolveRobotAccess(platform, userID)
	can := func(permission string) bool {
		return access != nil && access.Permissions[permission]
	}
	var b strings.Builder
	b.WriteString("CyberStrikeAI\n\n")
	b.WriteString("General\n")
	b.WriteString("· Help / help — Show this help\n")
	b.WriteString("· Version / version — Show Current Version Number\n")
	b.WriteString("· Tie <Tie the code.> / bind <code> — Bind Webend RBAC user\n")
	b.WriteString("Untie / unbind - Request to untie account (to be confirmed)\n")
	b.WriteString("• Identity / whoami — displays the Platform's sender, the Accumulation Mode and the current actual RBAC identity\n")
	if can("chat:read") || can("chat:write") || can("chat:delete") {
		b.WriteString("\n[Dialogue Conversation]\n")
		if can("chat:read") {
			b.WriteString("· List / list — List all dialogue titles and ID\n• Switch to <ID> / switch <ID> — designates the dialogue to continue\n• Status / status — Summarize the current selection\n· Tasks / task — View Current Task Status\n")
		}
		if can("chat:write") {
			b.WriteString("· New Dialogue / new; Clear / clear — Start New Dialogue\n· Rename <Name> / rename <name> — Modify the current dialogue title\n")
		}
		if can("chat:delete") {
			b.WriteString("· delete <ID> / delete <ID> — Delete Assigned Dialogue (Confirmed) \n")
		}
	}
	if can("roles:read") {
		b.WriteString("\n[Role]\n· Role / roles — List all available roles\n· Role <First Name> / role <name> — Toggle Current Role\n")
	}
	if can("agent:execute") {
		b.WriteString("\nMode\n· Mode / modes — List dialogue mode and current selection\n· Mode <Name> / mode <name> — Switch dialogue mode\n· Stop / stop — Abort current task\n")
	}
	if can("vulnerability:read") {
		b.WriteString("\nVulnerability alerts\n• Hole alarm - View subscription status\n· Hole alarm enabled / vuln alerts on — Open Reminder\n· Hole alarm Only serious|High risk above|Above the mid-risk / vuln alerts critical|high|medium — Set Minimum Level\n· Hole alarm close / vuln alerts off _ _ close alarm\n")
	}
	b.WriteString("\n[Diagnostics Diagnostics]\n")
	b.WriteString("• Permissions/ permissions — View current business privileges\n")
	if can("config:read") {
		b.WriteString("• Diagnosis/doctor — checking the critical configuration of robots\n")
	}
	b.WriteString("· Confirmed. / confirm; Cancel / cancel — Addressing high-risk operational confirmation\n")
	if h.projectsEnabled() && (can("project:read") || can("project:write")) {
		b.WriteString("\n[Item Project]\n")
		if can("project:read") {
			b.WriteString("· Item / projects — List all items\n")
		}
		if can("project:write") {
			b.WriteString("New item < Name > / new project <name> _ Create and bind the current dialogue\n· Bind items <ID Or name> / bind project <ID|name> — Bind existing items\n· Dismissed / unbind project — Untie the project\n")
		}
	}
	b.WriteString("\n──────────────\n")
	b.WriteString("In addition to the above command, direct input will be sent to AI for infiltration testing/security analysis.")
	return b.String()
}

func (h *RobotHandler) projectsEnabled() bool {
	return h.config != nil && h.config.Project.Enabled
}

func (h *RobotHandler) resolveProjectByIDOrName(access *database.RBACAccess, idOrName string) (*database.Project, string) {
	idOrName = strings.TrimSpace(idOrName)
	if idOrName == "" {
		return nil, "Please specify items ID Or name, for example: Bind items xxx-xxx"
	}
	ownerID := access.User.ID
	scope := robotPrincipal(access).ScopeFor("project:read")
	if p, err := h.db.GetProject(idOrName); err == nil {
		if h.db.UserCanAccessResource(ownerID, scope, "project", p.ID) {
			return p, ""
		}
		return nil, "Projects do not exist or do not have access."
	}
	list, err := h.db.ListProjectsForAccess("", "", 200, 0, ownerID, scope)
	if err != nil {
		return nil, "Failed to query projects: " + err.Error()
	}
	var matches []*database.Project
	for _, p := range list {
		if p.Name == idOrName {
			matches = append(matches, p)
		}
	}
	switch len(matches) {
	case 0:
		return nil, fmt.Sprintf("Can not delete folder: %s: No such folder", idOrName)
	case 1:
		return matches[0], ""
	default:
		var b strings.Builder
		b.WriteString(fmt.Sprintf("Name\"%s\"Match multiple items, Please use ID Tie: \n", idOrName))
		for _, p := range matches {
			b.WriteString(fmt.Sprintf("· %s\n  ID: %s\n", p.Name, p.ID))
		}
		return nil, strings.TrimSuffix(b.String(), "\n")
	}
}

func (h *RobotHandler) formatProjectLabel(projectID string) string {
	if strings.TrimSpace(projectID) == "" {
		return "Not bound"
	}
	if p, err := h.db.GetProject(projectID); err == nil {
		return fmt.Sprintf("「%s」 (%s)", p.Name, p.ID)
	}
	return projectID
}

func (h *RobotHandler) cmdProjects(platform, userID string) string {
	if !h.projectsEnabled() {
		return "The project function is not enabled (config.project.enabled)."
	}
	access, err := h.resolveRobotAccess(platform, userID)
	if err != nil {
		return "The current platform account has not been bound."
	}
	list, err := h.db.ListProjectsForAccess("", "", 50, 0, access.User.ID, robotPrincipal(access).ScopeFor("project:read"))
	if err != nil {
		return "Failed to list projects: " + err.Error()
	}
	if len(list) == 0 {
		return "No item is available. Send a new item < Name > to create and bind it to the current dialogue."
	}
	var b strings.Builder
	b.WriteString("[List of items]\n")
	for i, p := range list {
		if i >= 20 {
			b.WriteString("... that only the first 20 articles are shown\n")
			break
		}
		status := p.Status
		if status == "" {
			status = "active"
		}
		b.WriteString(fmt.Sprintf("· %s [%s]\n  ID: %s\n", p.Name, status, p.ID))
	}
	return strings.TrimSuffix(b.String(), "\n")
}

func (h *RobotHandler) cmdBindProject(platform, userID, idOrName string) string {
	if !h.projectsEnabled() {
		return "The project function is not enabled (config.project.enabled)."
	}
	access, err := h.resolveRobotAccess(platform, userID)
	if err != nil {
		return "The current platform account has not been bound."
	}
	p, errMsg := h.resolveProjectByIDOrName(access, idOrName)
	if p == nil {
		return errMsg
	}
	convID, _ := h.getOrCreateConversation(platform, userID, "", access)
	if convID == "" {
		return "Cannot retrieve the current conversation; try again later."
	}
	if err := h.db.SetConversationProjectID(convID, p.ID); err != nil {
		return "_Other Organiser " + err.Error()
	}
	return fmt.Sprintf("Current dialogue bound to item: %s\nID: %s", p.Name, p.ID)
}

func (h *RobotHandler) cmdNewProject(platform, userID, name string) string {
	if !h.projectsEnabled() {
		return "The project function is not enabled (config.project.enabled)."
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return "Please specify the name of the project, e.g., new project."
	}
	access, accessErr := h.resolveRobotAccess(platform, userID)
	if accessErr != nil {
		return "The current platform account has not been bound."
	}
	p := &database.Project{Name: name, Status: "active"}
	created, err := h.db.CreateProject(p)
	if err != nil {
		return "Failed to create item: " + err.Error()
	}
	_ = h.db.SetResourceOwner("project", created.ID, access.User.ID)
	convID, _ := h.getOrCreateConversation(platform, userID, name, access)
	if convID == "" {
		return fmt.Sprintf("Project created: %s\nID: %s\n(Closed current dialogue, please send \"%s of bound item\" manually)", created.Name, created.ID, created.ID)
	}
	if err := h.db.SetConversationProjectID(convID, created.ID); err != nil {
		return fmt.Sprintf("Project created: %s\nID: %s\nFailed to bind: %s", created.Name, created.ID, err.Error())
	}
	return fmt.Sprintf("Project created and bound to the current conversation: %s\nID: %s", created.Name, created.ID)
}

func (h *RobotHandler) cmdUnbindProject(platform, userID string) string {
	if !h.projectsEnabled() {
		return "The project function is not enabled (config.project.enabled)."
	}
	sk := h.sessionKey(platform, userID)
	h.mu.RLock()
	convID := h.sessions[sk]
	h.mu.RUnlock()
	if convID == "" {
		if persistedConvID, _, _ := h.loadSessionBinding(sk); persistedConvID != "" {
			convID = persistedConvID
		}
	}
	access, err := h.resolveRobotAccess(platform, userID)
	if err != nil {
		return "The current platform account has not been bound."
	}
	if !h.db.UserCanAccessResource(access.User.ID, robotPrincipal(access).ScopeFor("chat:write"), "conversation", convID) {
		return "The current dialogue does not exist or does not have the right to visit."
	}
	if convID == "" {
		return "There is no ongoing dialogue and there is no need to untie it."
	}
	projectID, err := h.db.GetConversationProjectID(convID)
	if err != nil {
		return "Failed to access dialogue project: " + err.Error()
	}
	if strings.TrimSpace(projectID) == "" {
		return "There are no items tied to the current dialogue."
	}
	if err := h.db.SetConversationProjectID(convID, ""); err != nil {
		return "Untie failed: " + err.Error()
	}
	return "The item of the current dialogue has been untied."
}

func (h *RobotHandler) cmdList(platform, userID string) string {
	access, err := h.resolveRobotAccess(platform, userID)
	if err != nil {
		return "The current platform account has not been bound."
	}
	convs, err := h.db.ListConversationsForAccess(50, 0, "", "", "", access.User.ID, robotPrincipal(access).ScopeFor("chat:read"))
	if err != nil {
		return "Failed to list conversations: " + err.Error()
	}
	if len(convs) == 0 {
		return "There is no dialogue. Sending any content will automatically create a new dialogue."
	}
	var b strings.Builder
	b.WriteString("[Dialogue List]\n")
	for i, c := range convs {
		if i >= 20 {
			b.WriteString("... that only the first 20 articles are shown\n")
			break
		}
		b.WriteString(fmt.Sprintf("· %s\n  ID: %s\n", c.Title, c.ID))
	}
	return strings.TrimSuffix(b.String(), "\n")
}

func (h *RobotHandler) cmdSwitch(platform, userID, convID string) string {
	if convID == "" {
		return "Please specify a dialogue. ID, for example: Switch xxx-xxx-xxx"
	}
	access, accessErr := h.resolveRobotAccess(platform, userID)
	if accessErr != nil {
		return "The current platform account has not been bound."
	}
	conv, err := h.db.GetConversation(convID)
	if err != nil || !h.db.UserCanAccessResource(access.User.ID, robotPrincipal(access).ScopeFor("chat:read"), "conversation", convID) {
		return "Conversation does not exist or access is denied."
	}
	h.setConversation(platform, userID, conv.ID)
	return fmt.Sprintf("Switched to Dialogue: \"%s\"\nID: %s", conv.Title, conv.ID)
}

func (h *RobotHandler) cmdNew(platform, userID string) string {
	access, err := h.resolveRobotAccess(platform, userID)
	if err != nil {
		return "The current platform account has not been bound."
	}
	newID := h.clearConversation(platform, userID, access)
	if newID == "" {
		return "Failed to create a new dialogue, please try again."
	}
	return "A new dialogue has been opened and can be sent directly to content."
}

func (h *RobotHandler) cmdClear(platform, userID string) string {
	return h.cmdNew(platform, userID)
}

func (h *RobotHandler) cmdStop(platform, userID string) string {
	sk := h.sessionKey(platform, userID)
	h.cancelMu.Lock()
	cancel, ok := h.runningCancels[sk]
	if ok {
		delete(h.runningCancels, sk)
		cancel()
	}
	h.cancelMu.Unlock()
	if !ok {
		return "There are no ongoing tasks."
	}
	return "Current task stopped."
}

func (h *RobotHandler) cmdStatus(platform, userID string) string {
	convID := h.currentConversationID(platform, userID)
	if convID == "" {
		return fmt.Sprintf("[Current status]\nCurrent dialogue: none\nCurrent character: %s\nCurrent mode: %s\nCurrent item: None\n\nSending any content will create a new dialogue.", h.getRole(platform, userID), robotAgentModeLabel(h.getAgentMode(platform, userID)))
	}
	access, err := h.resolveRobotAccess(platform, userID)
	if err != nil {
		return "The current platform account has not been bound."
	}
	if !h.db.UserCanAccessResource(access.User.ID, robotPrincipal(access).ScopeFor("chat:read"), "conversation", convID) {
		return "The current dialogue does not exist or does not have the right to visit."
	}
	conv, err := h.db.GetConversation(convID)
	if err != nil {
		return "Current Dialogue ID: " + convID + "(getting title failed)"
	}
	role := h.getRole(platform, userID)
	reply := fmt.Sprintf("[Current status]\nCurrent dialogue: %s\nDialogue ID: %s\nCurrent mode: %s\nCurrent character: %s", conv.Title, conv.ID, robotAgentModeLabel(h.getAgentMode(platform, userID)), role)
	if h.projectsEnabled() {
		projectID, _ := h.db.GetConversationProjectID(conv.ID)
		reply += "\nCurrent projects: " + h.formatProjectLabel(projectID)
	} else {
		reply += "\nCurrent item: Not enabled"
	}
	return reply
}

func (h *RobotHandler) currentConversationID(platform, userID string) string {
	sk := h.sessionKey(platform, userID)
	h.mu.RLock()
	convID := h.sessions[sk]
	h.mu.RUnlock()
	if convID != "" {
		return convID
	}
	persistedConvID, persistedRole, persistedMode := h.loadSessionBinding(sk)
	if persistedConvID == "" {
		return ""
	}
	h.mu.Lock()
	h.sessions[sk] = persistedConvID
	h.sessionRoles[sk] = persistedRole
	h.sessionModes[sk] = config.NormalizeAgentMode(persistedMode)
	h.mu.Unlock()
	return persistedConvID
}

func (h *RobotHandler) cmdTask(platform, userID string) string {
	convID := h.currentConversationID(platform, userID)
	if convID == "" {
		return "Mission Status\nThere is currently no dialogue and no ongoing task."
	}
	if h.agentHandler == nil || h.agentHandler.tasks == nil {
		return "Mission status service is not available."
	}
	task := h.agentHandler.tasks.GetTaskSnapshot(convID)
	if task == nil {
		return "Mission Status\nStatus: Free\nThere are no ongoing tasks."
	}
	elapsed := time.Since(task.StartedAt).Round(time.Second)
	return fmt.Sprintf("Mission Status\nStatus: %s\nRun: %s\nDialogue ID: %s\nMode: %s\nAvailable Operations: Stop / stop", task.Status, elapsed, convID, robotAgentModeLabel(h.getAgentMode(platform, userID)))
}

func (h *RobotHandler) cmdRename(platform, userID, title string) string {
	title = strings.TrimSpace(title)
	if title == "" {
		return "Please specify a new title, such as: Rename Extranet Asset Check"
	}
	title = safeTruncateString(title, 100)
	convID := h.currentConversationID(platform, userID)
	if convID == "" {
		return "There is currently no dialogue and no renaming."
	}
	access, err := h.resolveRobotAccess(platform, userID)
	if err != nil || !h.db.UserCanAccessResource(access.User.ID, robotPrincipal(access).ScopeFor("chat:write"), "conversation", convID) {
		return "The current dialogue does not exist or does not have the power to modify it."
	}
	if err := h.db.UpdateConversationTitle(convID, title); err != nil {
		return "Rename failed: " + err.Error()
	}
	h.recordRobotCommandAudit(access, platform, "conversation_rename", "conversation", convID, "Robot Rename Current Dialog")
	return fmt.Sprintf("Current dialogue has been renamed \"%s\"", title)
}

func (h *RobotHandler) cmdPermissions(platform, userID string) string {
	access, err := h.resolveRobotAccess(platform, userID)
	if err != nil {
		return h.robotAccessDeniedMessage(platform)
	}
	allowed := func(permission string) string {
		if access.Permissions[permission] {
			return "Allow"
		}
		return "Not permitted"
	}
	return fmt.Sprintf("[Current permission]\nExecute Agent: %s\nRead Dialogue: %s\nEdit Dialogue: %s\nDelete Dialogue: %s\nRead Role: %s\nRead Item: %s\nEdit item: %s\nResource range: %s", allowed("agent:execute"), allowed("chat:read"), allowed("chat:write"), allowed("chat:delete"), allowed("roles:read"), allowed("project:read"), allowed("project:write"), access.Scope)
}

func (h *RobotHandler) cmdDoctor() string {
	configured := func(ok bool) string {
		if ok {
			return "Configured"
		}
		return "Not configured"
	}
	enabled := func(ok bool) string {
		if ok {
			return "Enabled"
		}
		return "Disabled"
	}
	enabledInternalTools := 0
	for _, tool := range h.config.Security.Tools {
		if tool.Enabled {
			enabledInternalTools++
		}
	}
	enabledExternal := 0
	for _, server := range h.config.ExternalMCP.Servers {
		if server.ExternalMCPEnable && !server.Disabled {
			enabledExternal++
		}
	}
	return fmt.Sprintf("[Configuration diagnostics]\nMain model: %s\nEino multi-agent: %s\nBuilt-in MCP tools: %d/%d enabled\nHTTP MCP service: %s\nExternal MCP: %d enabled\nKnowledge base: %s\nProjects: %s\nDescription: Built-in tools do not require the HTTP MCP service. This checks configuration only and does not contact external services.", configured(strings.TrimSpace(h.config.OpenAI.Model) != "" && strings.TrimSpace(h.config.OpenAI.BaseURL) != ""), enabled(h.config.MultiAgent.Enabled), enabledInternalTools, len(h.config.Security.Tools), enabled(h.config.MCP.Enabled), enabledExternal, enabled(h.config.Knowledge.Enabled), enabled(h.config.Project.Enabled))
}

func (h *RobotHandler) recordRobotCommandAudit(access *database.RBACAccess, platform, action, resourceType, resourceID, message string) {
	if h.audit == nil || access == nil {
		return
	}
	h.audit.RecordSystem(audit.Entry{Category: "robot", Action: action, Result: "success", Actor: access.User.Username, ResourceType: resourceType, ResourceID: resourceID, Message: message + "（" + platform + "）"})
}

func (h *RobotHandler) cmdRoles() string {
	if h.config.Roles == nil || len(h.config.Roles) == 0 {
		return "No role available."
	}
	names := make([]string, 0, len(h.config.Roles))
	for name, role := range h.config.Roles {
		if role.Enabled {
			names = append(names, name)
		}
	}
	if len(names) == 0 {
		return "No role available."
	}
	sort.Slice(names, func(i, j int) bool {
		if names[i] == "Default" {
			return true
		}
		if names[j] == "Default" {
			return false
		}
		return names[i] < names[j]
	})
	var b strings.Builder
	b.WriteString("[List of character]\n")
	for _, name := range names {
		role := h.config.Roles[name]
		desc := role.Description
		if desc == "" {
			desc = "No description"
		}
		b.WriteString(fmt.Sprintf("· %s — %s\n", name, desc))
	}
	return strings.TrimSuffix(b.String(), "\n")
}

func (h *RobotHandler) cmdSwitchRole(platform, userID, roleName string) string {
	if roleName == "" {
		return "Please specify the name of the role, e.g., the role penetration test"
	}
	if h.config.Roles == nil {
		return "No role available."
	}
	role, exists := h.config.Role(roleName)
	if !exists {
		return fmt.Sprintf("Can not delete folder: %s: No such folder", roleName)
	}
	if !role.Enabled {
		return fmt.Sprintf("Role\"%s\"Disabled.", roleName)
	}
	h.setRole(platform, userID, roleName)
	return fmt.Sprintf("Switched to character: %s\n%s", roleName, role.Description)
}

func robotAgentModeLabel(mode string) string {
	switch config.NormalizeAgentMode(mode) {
	case "deep":
		return "Deep"
	case "plan_execute":
		return "Plan-Execute"
	case "supervisor":
		return "Supervisor"
	default:
		return "Eino Single Agent"
	}
}

func parseRobotAgentMode(input string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(legacytext.Token(input))) {
	case "eino_single", "eino-single", "single", "single-agent", "eino single agent":
		return "eino_single", true
	case "deep":
		return "deep", true
	case "plan_execute", "plan-execute", "planexecute", "pe":
		return "plan_execute", true
	case "supervisor", "super", "sv":
		return "supervisor", true
	default:
		return "", false
	}
}

func (h *RobotHandler) cmdModes(platform, userID string) string {
	current := h.getAgentMode(platform, userID)
	multiStatus := "free"
	if h.config == nil || !h.config.MultiAgent.Enabled {
		multiStatus = "Not available (Eino multiple agents to enable in system settings)"
	}
	return fmt.Sprintf("[Conversation Mode]\nEino Single Agent — Available\n· Deep — %s\n· Plan-Execute — %s\n· Supervisor — %s\n\nCurrent mode: %s\nToggle Example: Mode deep", multiStatus, multiStatus, multiStatus, robotAgentModeLabel(current))
}

func (h *RobotHandler) cmdSwitchMode(platform, userID, input string) string {
	mode, ok := parseRobotAgentMode(input)
	if !ok {
		return fmt.Sprintf("Unsupported conversation mode '%s'. Send 'mode' to list available modes.", strings.TrimSpace(input))
	}
	if mode != "eino_single" && (h.config == nil || !h.config.MultiAgent.Enabled) {
		return fmt.Sprintf("Mode %s is unavailable: enable Eino multi-agent support in system settings first.", robotAgentModeLabel(mode))
	}
	h.setAgentMode(platform, userID, mode)
	return fmt.Sprintf("Dialogue mode switched: %s\nThis model will be used for follow-up messages and new dialogues.", robotAgentModeLabel(mode))
}

func (h *RobotHandler) cmdDelete(platform, userID, convID string) string {
	if convID == "" {
		return "Please specify a dialogue. ID, for example: delete xxx-xxx-xxx"
	}
	access, err := h.resolveRobotAccess(platform, userID)
	if err != nil {
		return "The current platform account has not been bound."
	}
	if !h.db.UserCanAccessResource(access.User.ID, robotPrincipal(access).ScopeFor("chat:delete"), "conversation", convID) {
		return "Conversation does not exist or access is denied."
	}
	h.setPendingConfirmation(platform, userID, "delete_conversation", convID)
	return fmt.Sprintf("⚠️ Upcoming deletion of dialogue ID: %s\nThis operation cannot be revoked. Please send confirmation to continue within 2 minutes, or send Cancel.", convID)
}

func (h *RobotHandler) executeDelete(platform, userID, convID string) string {
	access, err := h.resolveRobotAccess(platform, userID)
	if err != nil || !h.db.UserCanAccessResource(access.User.ID, robotPrincipal(access).ScopeFor("chat:delete"), "conversation", convID) {
		return "Dialogue does not exist or has no right to be deleted."
	}
	sk := h.sessionKey(platform, userID)
	h.mu.RLock()
	currentConvID := h.sessions[sk]
	h.mu.RUnlock()
	if convID == currentConvID {
		// 删除当前对话时，先清空会话绑定
		h.mu.Lock()
		delete(h.sessions, sk)
		delete(h.sessionRoles, sk)
		delete(h.sessionModes, sk)
		h.mu.Unlock()
		h.deleteSessionBinding(sk)
	}
	if h.agentHandler != nil {
		h.agentHandler.CancelRunningTaskForConversation(convID)
	}
	if err := h.db.DeleteConversation(convID); err != nil {
		return "Unable to start task: " + err.Error()
	}
	h.recordRobotCommandAudit(access, platform, "conversation_delete", "conversation", convID, "Robot delete dialogue")
	return fmt.Sprintf("_Other Organiser ID: %s", convID)
}

func (h *RobotHandler) cmdVersion() string {
	v := h.config.Version
	if v == "" {
		v = "unknown"
	}
	return "CyberStrikeAI " + v
}

func (h *RobotHandler) cmdIdentity(platform, userID string) string {
	authorization := h.config.Robots.AuthorizationFor(platform)
	mode := authorization.EffectiveMode()
	modeLabel := "Native user binding (user_binding)"
	if mode == config.RobotAuthModeServiceAccount {
		modeLabel = "Controlled service account (service_account)"
	}
	var b strings.Builder
	b.WriteString("[Robot identity]\n")
	b.WriteString("Platform:" + platform + "\n")
	b.WriteString("Sender ID:" + userID + "\n")
	b.WriteString("Authentication mode: " + modeLabel + "\n")

	access, err := h.resolveRobotAccess(platform, userID)
	if err != nil {
		if mode == config.RobotAuthModeServiceAccount {
			b.WriteString("Authentication status: denied (sender is not allowlisted or service account is unavailable)")
		} else {
			b.WriteString("Authentication status: unbound\n")
			b.WriteString("Create a binding code in the web console and send \"bind XXXX-XXXX\"")
		}
		return b.String()
	}

	name := strings.TrimSpace(legacytext.AccountDisplayName(access.User.ID, access.User.Username, access.User.IsBuiltin, access.User.DisplayName))
	if name == "" {
		name = access.User.Username
	}
	roleNames := make([]string, 0, len(access.Roles))
	for _, role := range access.Roles {
		roleNames = append(roleNames, role.Name)
	}
	if len(roleNames) == 0 {
		roleNames = append(roleNames, "No role assigned")
	}
	b.WriteString("Authentication status: authorized\n")
	b.WriteString("Native user: " + name + " (" + access.User.Username + ")\n")
	b.WriteString("RBAC User ID：" + access.User.ID + "\n")
	b.WriteString("Platform roles: " + strings.Join(roleNames, "、") + "\n")
	b.WriteString("Resource scope: " + access.Scope + "\n")
	b.WriteString(fmt.Sprintf("Effective permissions: %d", len(access.Permissions)))
	return b.String()
}

func robotCommandPermission(text string) (string, bool) {
	text = legacytext.Command(text)
	switch {
	case text == robotCmdHelp || text == "help" || text == "？" || text == "?", text == robotCmdVersion || text == "version", text == robotCmdIdentity || text == "whoami":
		return "", true
	case text == robotCmdList || text == robotCmdListAlt || text == "list",
		strings.HasPrefix(text, robotCmdSwitch+" "), strings.HasPrefix(text, robotCmdContinue+" "),
		strings.HasPrefix(text, "switch "), strings.HasPrefix(text, "continue "),
		text == robotCmdStatus || text == "status", text == robotCmdTask || text == "task":
		return "chat:read", true
	case text == robotCmdNew || text == "new", text == robotCmdClear || text == "clear",
		strings.HasPrefix(text, robotCmdRename+" "), strings.HasPrefix(text, "rename "):
		return "chat:write", true
	case strings.HasPrefix(text, robotCmdDelete+" "), strings.HasPrefix(text, "delete "):
		return "chat:delete", true
	case text == robotCmdStop || text == "stop":
		return "agent:execute", true
	case text == robotCmdRoles || text == robotCmdRolesList || text == "roles",
		strings.HasPrefix(text, robotCmdRoles+" "), strings.HasPrefix(text, robotCmdSwitchRole+" "), strings.HasPrefix(text, "role "):
		return "roles:read", true
	case text == robotCmdModes || text == robotCmdModesList || text == "modes",
		strings.HasPrefix(text, robotCmdModes+" "), strings.HasPrefix(text, robotCmdSwitchMode+" "), strings.HasPrefix(text, "mode "):
		return "agent:execute", true
	case text == robotCmdPermissions || text == "permissions":
		return "", true
	case text == robotCmdConfirm || text == "confirm", text == robotCmdCancel || text == "cancel":
		return "", true
	case text == robotCmdDoctor || text == "doctor":
		return "config:read", true
	case text == robotCmdProjects || text == robotCmdProjectsList || text == "projects":
		return "project:read", true
	case text == robotCmdVulnAlerts || strings.HasPrefix(text, robotCmdVulnAlerts+" "),
		text == "vuln alerts" || strings.HasPrefix(text, "vuln alerts "):
		return "vulnerability:read", true
	case text == robotCmdUnbindProject || text == "unbind project",
		strings.HasPrefix(text, robotCmdNewProject+" "), strings.HasPrefix(text, "new project "),
		strings.HasPrefix(text, robotCmdBindProject+" "), strings.HasPrefix(text, "bind project "):
		return "project:write", true
	default:
		return "", false
	}
}

func (h *RobotHandler) cmdBindUser(platform, userID, code string) string {
	if h.config.Robots.AuthorizationFor(platform).EffectiveMode() != config.RobotAuthModeUserBinding {
		return "The robot uses a controlled service account model and does not accept user binding."
	}
	code = normalizeRobotBindingCode(code)
	if code == "" {
		return "Please provide a code, e.g., ABCD-1234"
	}
	user, err := h.db.ConsumeRobotBindingCode(platform, userID, hashRobotBindingCode(code))
	if err != nil {
		return "The binding failed: the binding code is invalid, used or expired. Please recreate at the end of the page."
	}
	// Never carry an old synthetic-owner conversation into the RBAC identity.
	sk := h.sessionKey(platform, userID)
	h.mu.Lock()
	delete(h.sessions, sk)
	delete(h.sessionRoles, sk)
	delete(h.sessionModes, sk)
	h.mu.Unlock()
	h.deleteSessionBinding(sk)
	name := strings.TrimSpace(user.DisplayName)
	if name == "" {
		name = user.Username
	}
	if h.audit != nil {
		hint := sha256.Sum256([]byte(userID))
		h.audit.RecordSystem(audit.Entry{
			Category: "auth", Action: "robot_bind", Result: "success", Actor: user.Username,
			ResourceType: "robot_binding", ResourceID: platform + ":" + fmt.Sprintf("%x", hint[:4]), Message: "The account number of the robot platform was secured.",
		})
	}
	return fmt.Sprintf("Staple successfully, current identity: %s. Follow-up operations will use the user's RBAC privileges in real time.", name)
}

func (h *RobotHandler) cmdUnbindUser(platform, userID string) string {
	if h.config.Robots.AuthorizationFor(platform).EffectiveMode() != config.RobotAuthModeUserBinding {
		return "This robot uses service account mode; per-user unbinding is unavailable."
	}
	_, accessErr := h.resolveRobotAccess(platform, userID)
	if accessErr != nil {
		return "The current platform account has not been bound."
	}
	h.setPendingConfirmation(platform, userID, "unbind_user", "")
	return "⚠️ The current platform account is about to be untied. Please send confirmation to continue within 2 minutes, or send Cancel."
}

func (h *RobotHandler) executeUnbindUser(platform, userID string) string {
	access, accessErr := h.resolveRobotAccess(platform, userID)
	if accessErr != nil {
		return "The current platform account has not been bound."
	}
	if err := h.db.DeleteRobotIdentityBinding(platform, userID); err != nil {
		return "Untie failed, please try again later."
	}
	sk := h.sessionKey(platform, userID)
	h.mu.Lock()
	delete(h.sessions, sk)
	delete(h.sessionRoles, sk)
	delete(h.sessionModes, sk)
	h.mu.Unlock()
	h.deleteSessionBinding(sk)
	if h.audit != nil {
		hint := sha256.Sum256([]byte(userID))
		h.audit.RecordSystem(audit.Entry{
			Category: "auth", Action: "robot_unbind", Result: "success", Actor: access.User.Username,
			ResourceType: "robot_binding", ResourceID: platform + ":" + fmt.Sprintf("%x", hint[:4]), Message: "The robot platform account was untied.",
		})
	}
	return "The current platform account number has been removed from the CyberStrikeAI user."
}

func (h *RobotHandler) setPendingConfirmation(platform, userID, action, target string) {
	sk := h.sessionKey(platform, userID)
	now := time.Now()
	h.mu.Lock()
	for key, pending := range h.pendingConfirmations {
		if now.After(pending.ExpiresAt) {
			delete(h.pendingConfirmations, key)
		}
	}
	h.pendingConfirmations[sk] = robotPendingConfirmation{Action: action, Target: target, ExpiresAt: now.Add(2 * time.Minute)}
	h.mu.Unlock()
}

func (h *RobotHandler) cmdConfirm(platform, userID string) string {
	sk := h.sessionKey(platform, userID)
	h.mu.Lock()
	pending, ok := h.pendingConfirmations[sk]
	delete(h.pendingConfirmations, sk)
	h.mu.Unlock()
	if !ok || time.Now().After(pending.ExpiresAt) {
		return "There is no pending operation to confirm, or it has expired."
	}
	switch pending.Action {
	case "delete_conversation":
		return h.executeDelete(platform, userID, pending.Target)
	case "unbind_user":
		return h.executeUnbindUser(platform, userID)
	default:
		return "The pending operation is invalid and was cancelled."
	}
}

func (h *RobotHandler) cmdCancelConfirmation(platform, userID string) string {
	sk := h.sessionKey(platform, userID)
	h.mu.Lock()
	_, ok := h.pendingConfirmations[sk]
	delete(h.pendingConfirmations, sk)
	h.mu.Unlock()
	if !ok {
		return "No operation to confirm at this time."
	}
	return "Pending confirmation cancelled."
}

// handleRobotCommand 处理机器人内置命令；若匹配到命令返回 (回复内容, true)，否则返回 ("", false)
func (h *RobotHandler) handleRobotCommand(platform, userID, text string) (string, bool) {
	text = legacytext.Command(text)
	if (strings.HasPrefix(text, robotCmdBindUser+" ") || strings.HasPrefix(text, "bind ")) && !strings.HasPrefix(text, "bind project ") {
		parts := strings.SplitN(text, " ", 2)
		return h.cmdBindUser(platform, userID, strings.TrimSpace(parts[1])), true
	}
	if text == robotCmdUnbindUser || text == "unbind" {
		return h.cmdUnbindUser(platform, userID), true
	}
	if permission, recognized := robotCommandPermission(text); recognized && permission != "" {
		access, err := h.resolveRobotAccess(platform, userID)
		if err != nil {
			return h.robotAccessDeniedMessage(platform), true
		}
		if !access.Permissions[permission] {
			return fmt.Sprintf("Access denied: missing %s permission.", permission), true
		}
	}
	switch {
	case text == robotCmdVulnAlerts || text == "vuln alerts":
		return h.cmdVulnerabilityAlerts(platform, userID, ""), true
	case strings.HasPrefix(text, robotCmdVulnAlerts+" "):
		return h.cmdVulnerabilityAlerts(platform, userID, strings.TrimSpace(text[len(robotCmdVulnAlerts)+1:])), true
	case strings.HasPrefix(text, "vuln alerts "):
		return h.cmdVulnerabilityAlerts(platform, userID, strings.TrimSpace(text[len("vuln alerts "):])), true
	case text == robotCmdHelp || text == "help" || text == "？" || text == "?":
		return h.cmdHelp(platform, userID), true
	case text == robotCmdIdentity || text == "whoami":
		return h.cmdIdentity(platform, userID), true
	case text == robotCmdConfirm || text == "confirm":
		return h.cmdConfirm(platform, userID), true
	case text == robotCmdCancel || text == "cancel":
		return h.cmdCancelConfirmation(platform, userID), true
	case text == robotCmdList || text == robotCmdListAlt || text == "list":
		return h.cmdList(platform, userID), true
	case strings.HasPrefix(text, robotCmdSwitch+" ") || strings.HasPrefix(text, robotCmdContinue+" ") || strings.HasPrefix(text, "switch ") || strings.HasPrefix(text, "continue "):
		var id string
		switch {
		case strings.HasPrefix(text, robotCmdSwitch+" "):
			id = strings.TrimSpace(text[len(robotCmdSwitch)+1:])
		case strings.HasPrefix(text, robotCmdContinue+" "):
			id = strings.TrimSpace(text[len(robotCmdContinue)+1:])
		case strings.HasPrefix(text, "switch "):
			id = strings.TrimSpace(text[7:])
		default:
			id = strings.TrimSpace(text[9:])
		}
		return h.cmdSwitch(platform, userID, id), true
	case text == robotCmdNew || text == "new":
		return h.cmdNew(platform, userID), true
	case text == robotCmdClear || text == "clear":
		return h.cmdClear(platform, userID), true
	case text == robotCmdStatus || text == "status":
		return h.cmdStatus(platform, userID), true
	case text == robotCmdTask || text == "task":
		return h.cmdTask(platform, userID), true
	case strings.HasPrefix(text, robotCmdRename+" ") || strings.HasPrefix(text, "rename "):
		var title string
		if strings.HasPrefix(text, robotCmdRename+" ") {
			title = strings.TrimSpace(text[len(robotCmdRename)+1:])
		} else {
			title = strings.TrimSpace(text[len("rename "):])
		}
		return h.cmdRename(platform, userID, title), true
	case text == robotCmdStop || text == "stop":
		return h.cmdStop(platform, userID), true
	case text == robotCmdRoles || text == robotCmdRolesList || text == "roles":
		return h.cmdRoles(), true
	case strings.HasPrefix(text, robotCmdRoles+" ") || strings.HasPrefix(text, robotCmdSwitchRole+" ") || strings.HasPrefix(text, "role "):
		var roleName string
		switch {
		case strings.HasPrefix(text, robotCmdRoles+" "):
			roleName = strings.TrimSpace(text[len(robotCmdRoles)+1:])
		case strings.HasPrefix(text, robotCmdSwitchRole+" "):
			roleName = strings.TrimSpace(text[len(robotCmdSwitchRole)+1:])
		default:
			roleName = strings.TrimSpace(text[5:])
		}
		return h.cmdSwitchRole(platform, userID, roleName), true
	case text == robotCmdModes || text == robotCmdModesList || text == "modes":
		return h.cmdModes(platform, userID), true
	case strings.HasPrefix(text, robotCmdModes+" ") || strings.HasPrefix(text, robotCmdSwitchMode+" ") || strings.HasPrefix(text, "mode "):
		var mode string
		switch {
		case strings.HasPrefix(text, robotCmdModes+" "):
			mode = strings.TrimSpace(text[len(robotCmdModes)+1:])
		case strings.HasPrefix(text, robotCmdSwitchMode+" "):
			mode = strings.TrimSpace(text[len(robotCmdSwitchMode)+1:])
		default:
			mode = strings.TrimSpace(text[5:])
		}
		return h.cmdSwitchMode(platform, userID, mode), true
	case text == robotCmdPermissions || text == "permissions":
		return h.cmdPermissions(platform, userID), true
	case text == robotCmdDoctor || text == "doctor":
		return h.cmdDoctor(), true
	case strings.HasPrefix(text, robotCmdDelete+" ") || strings.HasPrefix(text, "delete "):
		var convID string
		if strings.HasPrefix(text, robotCmdDelete+" ") {
			convID = strings.TrimSpace(text[len(robotCmdDelete)+1:])
		} else {
			convID = strings.TrimSpace(text[7:])
		}
		return h.cmdDelete(platform, userID, convID), true
	case text == robotCmdVersion || text == "version":
		return h.cmdVersion(), true
	case text == robotCmdProjects || text == robotCmdProjectsList || text == "projects":
		return h.cmdProjects(platform, userID), true
	case text == robotCmdUnbindProject || text == "unbind project":
		return h.cmdUnbindProject(platform, userID), true
	case strings.HasPrefix(text, robotCmdNewProject+" ") || strings.HasPrefix(text, "new project "):
		var name string
		if strings.HasPrefix(text, robotCmdNewProject+" ") {
			name = strings.TrimSpace(text[len(robotCmdNewProject)+1:])
		} else {
			name = strings.TrimSpace(text[len("new project "):])
		}
		return h.cmdNewProject(platform, userID, name), true
	case strings.HasPrefix(text, robotCmdBindProject+" ") || strings.HasPrefix(text, "bind project "):
		var idOrName string
		if strings.HasPrefix(text, robotCmdBindProject+" ") {
			idOrName = strings.TrimSpace(text[len(robotCmdBindProject)+1:])
		} else {
			idOrName = strings.TrimSpace(text[len("bind project "):])
		}
		return h.cmdBindProject(platform, userID, idOrName), true
	default:
		return "", false
	}
}

// —————— 企业微信 ——————

// wecomXML 企业微信回调 XML（明文模式下的简化结构；加密模式需先解密再解析）
type wecomXML struct {
	ToUserName   string `xml:"ToUserName"`
	FromUserName string `xml:"FromUserName"`
	CreateTime   int64  `xml:"CreateTime"`
	MsgType      string `xml:"MsgType"`
	Content      string `xml:"Content"`
	MsgID        string `xml:"MsgId"`
	AgentID      int64  `xml:"AgentID"`
	Encrypt      string `xml:"Encrypt"` // 加密模式下消息在此
}

// wecomReplyXML 被动回复 XML（仅用于兼容，当前使用手动构造 XML）
type wecomReplyXML struct {
	XMLName      xml.Name `xml:"xml"`
	ToUserName   string   `xml:"ToUserName"`
	FromUserName string   `xml:"FromUserName"`
	CreateTime   int64    `xml:"CreateTime"`
	MsgType      string   `xml:"MsgType"`
	Content      string   `xml:"Content"`
}

// wecomRequireToken 企业微信回调必须配置 Token；未配置时拒绝请求，防止未授权触发 Agent。
func (h *RobotHandler) wecomRequireToken(c *gin.Context) (string, bool) {
	token := strings.TrimSpace(h.config.Robots.Wecom.Token)
	if token == "" {
		h.logger.Warn("Enterprise Wire is enabled but not configured token, return call is refused (please set robots.wecom.token in configuration)")
		c.String(http.StatusForbidden, "")
		return "", false
	}
	return token, true
}

// HandleWecomGET 企业微信 URL 校验（GET）
func (h *RobotHandler) HandleWecomGET(c *gin.Context) {
	if !h.config.Robots.Wecom.Enabled {
		c.String(http.StatusNotFound, "")
		return
	}
	token, ok := h.wecomRequireToken(c)
	if !ok {
		return
	}
	// Gin 的 Query() 会自动 URL 解码，拿到的就是正确的 base64 字符串
	echostr := c.Query("echostr")
	msgSignature := c.Query("msg_signature")
	timestamp := c.Query("timestamp")
	nonce := c.Query("nonce")

	// 验证签名：将 token、timestamp、nonce、echostr 四个参数排序后拼接计算 SHA1
	signature := h.signWecomRequest(token, timestamp, nonce, echostr)
	if signature != msgSignature {
		h.logger.Warn("Corporate Wisdom URL Authentication of signature failed", zap.String("expected", msgSignature), zap.String("got", signature))
		c.String(http.StatusBadRequest, "invalid signature")
		return
	}

	if echostr == "" {
		c.String(http.StatusBadRequest, "missing echostr")
		return
	}

	// 如果配置了 EncodingAESKey，说明是加密模式，需要解密 echostr
	if h.config.Robots.Wecom.EncodingAESKey != "" {
		decrypted, err := wecomDecrypt(h.config.Robots.Wecom.EncodingAESKey, echostr)
		if err != nil {
			h.logger.Warn("Enterprise echostr decryption failed", zap.Error(err))
			c.String(http.StatusBadRequest, "decrypt failed")
			return
		}
		c.String(http.StatusOK, string(decrypted))
		return
	}

	// 明文模式直接返回 echostr
	c.String(http.StatusOK, echostr)
}

// signWecomRequest 生成企业微信请求签名
// 企业微信签名算法：将 token、timestamp、nonce、echostr 四个值排序后拼接成字符串，再计算 SHA1
func (h *RobotHandler) signWecomRequest(token, timestamp, nonce, echostr string) string {
	strs := []string{token, timestamp, nonce, echostr}
	sort.Strings(strs)
	s := strings.Join(strs, "")
	hash := sha1.Sum([]byte(s))
	return fmt.Sprintf("%x", hash)
}

// wecomDecrypt 企业微信消息解密（AES-256-CBC，PKCS7，明文格式：16字节随机+4字节长度+消息+corpID）
func wecomDecrypt(encodingAESKey, encryptedB64 string) ([]byte, error) {
	key, err := base64.StdEncoding.DecodeString(encodingAESKey + "=")
	if err != nil {
		return nil, err
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("encoding_aes_key After decoded, read 32 bytes")
	}
	ciphertext, err := base64.StdEncoding.DecodeString(encryptedB64)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	iv := key[:16]
	mode := cipher.NewCBCDecrypter(block, iv)
	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("Secret length is not a multiple of block size")
	}
	plain := make([]byte, len(ciphertext))
	mode.CryptBlocks(plain, ciphertext)
	// 去除 PKCS7 填充
	n := int(plain[len(plain)-1])
	if n < 1 || n > 32 {
		return nil, fmt.Errorf("Invalid PKCS7 Fill")
	}
	plain = plain[:len(plain)-n]
	// 企业微信格式：16 字节随机 + 4 字节长度(大端) + 消息 + corpID
	if len(plain) < 20 {
		return nil, fmt.Errorf("Too short.")
	}
	msgLen := binary.BigEndian.Uint32(plain[16:20])
	if int(20+msgLen) > len(plain) {
		return nil, fmt.Errorf("Messages crossed the line.")
	}
	return plain[20 : 20+msgLen], nil
}

// wecomEncrypt 企业微信消息加密（AES-256-CBC，PKCS7，明文格式：16字节随机+4字节长度+消息+corpID）
func wecomEncrypt(encodingAESKey, message, corpID string) (string, error) {
	key, err := base64.StdEncoding.DecodeString(encodingAESKey + "=")
	if err != nil {
		return "", err
	}
	if len(key) != 32 {
		return "", fmt.Errorf("encoding_aes_key After decoded, read 32 bytes")
	}
	// 构造明文：16 字节随机 + 4 字节长度 (大端) + 消息 + corpID
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		// 降级方案：使用时间戳生成随机数
		for i := range random {
			random[i] = byte(time.Now().UnixNano() % 256)
		}
	}
	msgLen := len(message)
	msgBytes := []byte(message)
	corpBytes := []byte(corpID)
	plain := make([]byte, 16+4+msgLen+len(corpBytes))
	copy(plain[:16], random)
	binary.BigEndian.PutUint32(plain[16:20], uint32(msgLen))
	copy(plain[20:20+msgLen], msgBytes)
	copy(plain[20+msgLen:], corpBytes)
	// PKCS7 填充
	padding := aes.BlockSize - len(plain)%aes.BlockSize
	pad := bytes.Repeat([]byte{byte(padding)}, padding)
	plain = append(plain, pad...)
	// AES-256-CBC 加密
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	iv := key[:16]
	ciphertext := make([]byte, len(plain))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, plain)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// HandleWecomPOST 企业微信消息回调（POST），支持明文与加密模式
func (h *RobotHandler) HandleWecomPOST(c *gin.Context) {
	if !h.config.Robots.Wecom.Enabled {
		h.logger.Debug("Enterprise micro-intelligence robot is not active. Skip request.")
		c.String(http.StatusOK, "")
		return
	}
	// 从 URL 获取签名参数（加密模式回复时需要用到）
	timestamp := c.Query("timestamp")
	nonce := c.Query("nonce")
	msgSignature := c.Query("msg_signature")

	// 先读取请求体，后续解析/签名验证都会用到
	bodyRaw, err := io.ReadAll(c.Request.Body)
	if err != nil {
		h.logger.Warn("Failed to read request for enterprise micro-credit POST", zap.Error(err))
		c.String(http.StatusOK, "")
		return
	}
	h.logger.Debug("Enterprise Micro-Intelligence POST Received Request", zap.String("body", string(bodyRaw)))

	// 验证请求签名防止伪造。企业微信签名算法同 URL 验证，使用 token、timestamp、nonce、 Encrypt 四个字段。
	// 启用企业微信时必须配置 token 并校验签名，避免未授权请求触发 Agent。
	token, ok := h.wecomRequireToken(c)
	if !ok {
		return
	}
	if msgSignature == "" {
		h.logger.Warn("Enterprise Micro-Credit POST missing signature denied (need to ensure return to carry msg_signature)")
		c.String(http.StatusOK, "")
		return
	}
	var tmp wecomXML
	if err := xml.Unmarshal(bodyRaw, &tmp); err != nil {
		h.logger.Warn("Corporate Wisdom POST Organisation XML Failed", zap.Error(err))
		c.String(http.StatusOK, "")
		return
	}
	expected := h.signWecomRequest(token, timestamp, nonce, tmp.Encrypt)
	if expected != msgSignature {
		h.logger.Warn("Corporate Wisdom POST Signature authentication failed", zap.String("expected", expected), zap.String("got", msgSignature))
		c.String(http.StatusOK, "")
		return
	}
	if !h.acceptFreshWecomRequest(timestamp, nonce, msgSignature) {
		h.logger.Warn("Corporate Wisdom POST Time stamp expired or replay requested, Rejected")
		c.String(http.StatusOK, "")
		return
	}

	var body wecomXML
	if err := xml.Unmarshal(bodyRaw, &body); err != nil {
		h.logger.Warn("Corporate Wisdom POST Parsing XML Failed", zap.Error(err))
		c.String(http.StatusOK, "")
		return
	}
	h.logger.Debug("Enterprise Micro-Intelligence XML Parsing Success", zap.String("ToUserName", body.ToUserName), zap.String("FromUserName", body.FromUserName), zap.String("MsgType", body.MsgType), zap.String("Content", body.Content), zap.String("Encrypt", body.Encrypt))

	// 保存企业 ID（用于明文模式回复）
	enterpriseID := body.ToUserName

	// 配置了 EncodingAESKey 时必须走加密消息，拒绝明文 XML 绕过
	if strings.TrimSpace(h.config.Robots.Wecom.EncodingAESKey) != "" && strings.TrimSpace(body.Encrypt) == "" {
		h.logger.Warn("Enterprise Wireless has configured encryption mode but received the specified message, which was rejected")
		c.String(http.StatusOK, "")
		return
	}

	// 加密模式：先解密再解析内层 XML
	if body.Encrypt != "" && h.config.Robots.Wecom.EncodingAESKey != "" {
		h.logger.Debug("Enterprise micro-intelligence into encrypted mode decryption process")
		decrypted, err := wecomDecrypt(h.config.Robots.Wecom.EncodingAESKey, body.Encrypt)
		if err != nil {
			h.logger.Warn("Business messaging failed.", zap.Error(err))
			c.String(http.StatusOK, "")
			return
		}
		h.logger.Debug("Enterprise Wireless Success", zap.String("decrypted", string(decrypted)))
		if err := xml.Unmarshal(decrypted, &body); err != nil {
			h.logger.Warn("XML Parsing Failed", zap.Error(err))
			c.String(http.StatusOK, "")
			return
		}
		h.logger.Debug("Enterprise Micro-Intra-Intelligence XML Parsing Successfully", zap.String("FromUserName", body.FromUserName), zap.String("Content", body.Content))
	}

	tenantKey := strings.TrimSpace(enterpriseID)
	if tenantKey == "" {
		tenantKey = strings.TrimSpace(h.config.Robots.Wecom.CorpID)
	}
	if tenantKey == "" {
		tenantKey = "default"
	}
	rawUserID := strings.TrimSpace(body.FromUserName)
	replyUserID := rawUserID
	userID := ""
	if rawUserID != "" {
		userID = "t:" + tenantKey + "|u:" + rawUserID
	}
	text := strings.TrimSpace(body.Content)
	if userID == "" {
		h.logger.Warn("Enterprise micro-mail message missing user identifier ignored")
		c.String(http.StatusOK, "success")
		return
	}

	// 限制回复内容长度（企业微信限制 2048 字节）
	maxReplyLen := 2000
	limitReply := func(s string) string {
		if len(s) > maxReplyLen {
			return s[:maxReplyLen] + "\n\n(overlong, cut off)"
		}
		return s
	}

	if body.MsgType != "text" {
		h.logger.Debug("The company has received non-text messages.", zap.String("MsgType", body.MsgType))
		h.sendWecomReply(c, replyUserID, enterpriseID, limitReply("For the time being, text messages are supported, please send text."), timestamp, nonce)
		return
	}

	// 文本消息：先判断是否为内置命令（如 帮助/列表/新对话 等），这类命令处理很快，可以直接走被动回复，避免依赖主动发送 API。
	if cmdReply, ok := h.handleRobotCommand("wecom", userID, text); ok {
		h.logger.Debug("The company has received the command message and responded passively.", zap.String("userID", userID), zap.String("text", text))
		h.sendWecomReply(c, replyUserID, enterpriseID, limitReply(cmdReply), timestamp, nonce)
		return
	}

	h.logger.Debug("Corporate Wisdom started processing the news. (A walk. AI) ", zap.String("userID", userID), zap.String("text", text))

	// 企业微信被动回复有 5 秒超时限制，而 AI 调用通常超过该时长。
	// 这里采用推荐做法：立即返回 success（或空串），然后通过主动发送接口推送完整回复。
	c.String(http.StatusOK, "success")

	// 异步处理消息并通过企业微信主动消息接口发送结果
	go func() {
		reply := h.HandleMessage("wecom", userID, text)
		reply = limitReply(reply)
		h.logger.Debug("Corporate messaging is complete.", zap.String("userID", userID), zap.String("reply", reply))
		// 调用企业微信 API 主动发送消息
		h.sendWecomMessageViaAPI(rawUserID, enterpriseID, reply)
	}()
}

// sendWecomReply 发送企业微信回复（加密模式自动加密）
// 参数：toUser=用户 ID, fromUser=企业 ID（明文模式）/CorpID（加密模式）, content=回复内容，timestamp/nonce=请求参数
func (h *RobotHandler) sendWecomReply(c *gin.Context, toUser, fromUser, content, timestamp, nonce string) {
	// 加密模式：判断 EncodingAESKey 是否配置
	if h.config.Robots.Wecom.EncodingAESKey != "" {
		// 加密模式使用 CorpID 进行加密
		corpID := h.config.Robots.Wecom.CorpID
		if corpID == "" {
			h.logger.Warn("The enterprise micro-intelligence mode is missing the CorpID configuration")
			c.String(http.StatusOK, "")
			return
		}

		// 构造完整的明文 XML 回复（格式严格按企业微信文档要求）
		plainResp := fmt.Sprintf(`<xml>
<ToUserName><![CDATA[%s]]></ToUserName>
<FromUserName><![CDATA[%s]]></FromUserName>
<CreateTime>%d</CreateTime>
<MsgType><![CDATA[text]]></MsgType>
<Content><![CDATA[%s]]></Content>
</xml>`, toUser, fromUser, time.Now().Unix(), content)

		encrypted, err := wecomEncrypt(h.config.Robots.Wecom.EncodingAESKey, plainResp, corpID)
		if err != nil {
			h.logger.Warn("Failed to encrypt WeCom reply", zap.Error(err))
			c.String(http.StatusOK, "")
			return
		}
		// 使用请求中的 timestamp/nonce 生成签名（企业微信要求回复时使用与请求相同的 timestamp 和 nonce）
		msgSignature := h.signWecomRequest(h.config.Robots.Wecom.Token, timestamp, nonce, encrypted)

		h.logger.Debug("Enterprise email sent encrypted responses",
			zap.String("Encrypt", encrypted[:50]+"..."),
			zap.String("MsgSignature", msgSignature),
			zap.String("TimeStamp", timestamp),
			zap.String("Nonce", nonce))

		// 加密模式仅返回 4 个核心字段（企业微信官方要求）
		xmlResp := fmt.Sprintf(`<xml><Encrypt><![CDATA[%s]]></Encrypt><MsgSignature><![CDATA[%s]]></MsgSignature><TimeStamp><![CDATA[%s]]></TimeStamp><Nonce><![CDATA[%s]]></Nonce></xml>`, encrypted, msgSignature, timestamp, nonce)
		// also log the final response body so we can cross-check with the
		// network traffic or developer console
		h.logger.Debug("Enterprise Encrypted Response Package", zap.String("xml", xmlResp))
		// for additional confidence, decrypt the payload ourselves and log it
		if dec, err2 := wecomDecrypt(h.config.Robots.Wecom.EncodingAESKey, encrypted); err2 == nil {
			h.logger.Debug("Enterprise encryption back for decryption.", zap.String("plain", string(dec)))
		} else {
			h.logger.Warn("Failed to encrypt decryption check", zap.Error(err2))
		}

		// 使用 c.Writer.Write 直接写入响应，避免 c.String 的转义问题
		c.Writer.WriteHeader(http.StatusOK)
		// use text/xml as that's what WeCom examples show
		c.Writer.Header().Set("Content-Type", "text/xml; charset=utf-8")
		_, _ = c.Writer.Write([]byte(xmlResp))
		h.logger.Debug("Encrypted enterprise reply sent")
		return
	}

	// 明文模式
	h.logger.Debug("Corporate messaging sent express reply", zap.String("ToUserName", toUser), zap.String("FromUserName", fromUser), zap.String("Content", content[:50]+"..."))

	// 手动构造 XML 响应（使用 CDATA 包裹所有字段，并包含 AgentID）
	xmlResp := fmt.Sprintf(`<xml>
<ToUserName><![CDATA[%s]]></ToUserName>
<FromUserName><![CDATA[%s]]></FromUserName>
<CreateTime>%d</CreateTime>
<MsgType><![CDATA[text]]></MsgType>
<Content><![CDATA[%s]]></Content>
</xml>`, toUser, fromUser, time.Now().Unix(), content)

	// log the exact plaintext response for debugging
	h.logger.Debug("Corporate Wireless Response Package", zap.String("xml", xmlResp))

	// use text/xml as recommended by WeCom docs
	c.Header("Content-Type", "text/xml; charset=utf-8")
	c.String(http.StatusOK, xmlResp)
	h.logger.Debug("Corporate micro-clause response sent")
}

// —————— 测试接口（需登录，用于验证机器人逻辑，无需钉钉/飞书客户端） ——————

// CreateRobotBindingCode creates a short-lived, single-use secret for the
// currently authenticated RBAC user. Only its hash is persisted.
func (h *RobotHandler) CreateRobotBindingCode(c *gin.Context) {
	session, ok := security.CurrentSession(c)
	if !ok || strings.TrimSpace(session.UserID) == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}
	random := make([]byte, 5)
	if _, err := rand.Read(random); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate binding codes"})
		return
	}
	raw := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(random)
	code := raw[:4] + "-" + raw[4:]
	expiresAt := time.Now().Add(robotBindingCodeTTL)
	if err := h.db.CreateRobotBindingCode(session.UserID, hashRobotBindingCode(code), expiresAt); err != nil {
		h.logger.Warn("Failed to create robot binding code", zap.String("user_id", session.UserID), zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate binding codes"})
		return
	}
	if h.audit != nil {
		h.audit.Record(c, audit.Entry{Category: "auth", Action: "robot_binding_code_create", Result: "success", ResourceType: "user", ResourceID: session.UserID, Message: "Generate robotic one-time binding codes."})
	}
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusOK, gin.H{
		"code": code, "expires_at": expiresAt.UTC().Format(time.RFC3339), "expires_in_seconds": int(robotBindingCodeTTL.Seconds()),
	})
}

func (h *RobotHandler) ListMyRobotBindings(c *gin.Context) {
	session, ok := security.CurrentSession(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}
	bindings, err := h.db.ListRobotUserBindings(session.UserID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to capture robot binding"})
		return
	}
	items := make([]gin.H, 0, len(bindings))
	for _, binding := range bindings {
		sum := sha256.Sum256([]byte(binding.ExternalUserID))
		items = append(items, gin.H{
			"id": binding.ID, "platform": binding.Platform, "external_user_hint": fmt.Sprintf("%x", sum[:4]),
			"enabled": binding.Enabled, "created_at": binding.CreatedAt, "updated_at": binding.UpdatedAt,
		})
	}
	c.JSON(http.StatusOK, gin.H{"bindings": items})
}

func (h *RobotHandler) DeleteMyRobotBinding(c *gin.Context) {
	session, ok := security.CurrentSession(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}
	if err := h.db.DeleteRobotUserBindingForUser(c.Param("id"), session.UserID); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "The binding doesn't exist."})
		return
	}
	if h.audit != nil {
		h.audit.Record(c, audit.Entry{Category: "auth", Action: "robot_binding_revoke", Result: "success", ResourceType: "robot_binding", ResourceID: c.Param("id"), Message: "Untie the account on the robot platform."})
	}
	c.Status(http.StatusNoContent)
}

// RobotTestRequest 模拟机器人消息请求
type RobotTestRequest struct {
	Platform string `json:"platform"` // 如 "dingtalk"、"lark"、"wecom"
	UserID   string `json:"user_id"`
	Text     string `json:"text"`
}

// HandleRobotTest 供本地验证：POST JSON { "platform", "user_id", "text" }，返回 { "reply": "..." }
func (h *RobotHandler) HandleRobotTest(c *gin.Context) {
	var req RobotTestRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Request must be JSON, containing platform, user_id, text"})
		return
	}
	platform := strings.TrimSpace(req.Platform)
	if platform == "" {
		platform = "test"
	}
	userID := strings.TrimSpace(req.UserID)
	if userID == "" {
		userID = "test_user"
	}
	reply := h.HandleMessage(platform, userID, req.Text)
	c.JSON(http.StatusOK, gin.H{"reply": reply})
}

// sendWecomMessageViaAPI 通过企业微信 API 主动发送消息（用于异步处理后的结果发送）
func (h *RobotHandler) sendWecomMessageViaAPI(toUser, toParty, content string) {
	if !h.config.Robots.Wecom.Enabled {
		return
	}

	secret := h.config.Robots.Wecom.Secret
	corpID := h.config.Robots.Wecom.CorpID
	agentID := h.config.Robots.Wecom.AgentID

	if secret == "" || corpID == "" {
		h.logger.Warn("Corporate Wisdom Initiative API missing secret or corpID configuration")
		return
	}

	// 第 1 步：获取 access_token
	tokenURL := fmt.Sprintf("https://qyapi.weixin.qq.com/cgi-bin/gettoken?corpid=%s&corpsecret=%s", corpID, secret)
	resp, err := http.Get(tokenURL)
	if err != nil {
		h.logger.Warn("Business access token Failed", zap.Error(err))
		return
	}
	defer resp.Body.Close()

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		ErrCode     int    `json:"errcode"`
		ErrMsg      string `json:"errmsg"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		h.logger.Warn("Business Micro-Intelligence token Response Failed", zap.Error(err))
		return
	}
	if tokenResp.ErrCode != 0 {
		h.logger.Warn("Enterprise Micro-credit token Access Error", zap.String("errmsg", tokenResp.ErrMsg), zap.Int("errcode", tokenResp.ErrCode))
		return
	}

	// 第 2 步：构造发送消息请求
	msgReq := map[string]interface{}{
		"touser":  toUser,
		"msgtype": "text",
		"agentid": agentID,
		"text": map[string]interface{}{
			"content": content,
		},
	}

	msgBody, err := json.Marshal(msgReq)
	if err != nil {
		h.logger.Warn("Failed to sequence enterprise micro-intelligence messages", zap.Error(err))
		return
	}

	// 第 3 步：发送消息
	sendURL := fmt.Sprintf("https://qyapi.weixin.qq.com/cgi-bin/message/send?access_token=%s", tokenResp.AccessToken)
	msgResp, err := http.Post(sendURL, "application/json", bytes.NewReader(msgBody))
	if err != nil {
		h.logger.Warn("Corporate micro-mail failed to send the message", zap.Error(err))
		return
	}
	defer msgResp.Body.Close()

	var sendResp struct {
		ErrCode     int    `json:"errcode"`
		ErrMsg      string `json:"errmsg"`
		InvalidUser string `json:"invaliduser"`
		MsgID       string `json:"msgid"`
	}
	if err := json.NewDecoder(msgResp.Body).Decode(&sendResp); err != nil {
		h.logger.Warn("Failed to send enterprise micromail response", zap.Error(err))
		return
	}

	if sendResp.ErrCode == 0 {
		h.logger.Debug("Enterprise Wireless has been successful in sending messages.", zap.String("msgid", sendResp.MsgID))
	} else {
		h.logger.Warn("Corporate micro-mail failed to send the message", zap.String("errmsg", sendResp.ErrMsg), zap.Int("errcode", sendResp.ErrCode), zap.String("invaliduser", sendResp.InvalidUser))
	}
}

// —————— 钉钉 ——————

// HandleDingtalkPOST 钉钉事件回调（流式接入等）；当前为占位，返回 200
func (h *RobotHandler) HandleDingtalkPOST(c *gin.Context) {
	if !h.config.Robots.Dingtalk.Enabled {
		c.JSON(http.StatusOK, gin.H{})
		return
	}
	// 钉钉流式/事件回调格式需按官方文档解析并异步回复，此处仅返回 200
	c.JSON(http.StatusOK, gin.H{"message": "ok"})
}

// —————— 飞书 ——————

// HandleLarkPOST 飞书事件回调；当前为占位，返回 200；验证时需返回 challenge
func (h *RobotHandler) HandleLarkPOST(c *gin.Context) {
	if !h.config.Robots.Lark.Enabled {
		c.JSON(http.StatusOK, gin.H{})
		return
	}
	var body struct {
		Challenge string `json:"challenge"`
	}
	if err := c.ShouldBindJSON(&body); err == nil && body.Challenge != "" {
		c.JSON(http.StatusOK, gin.H{"challenge": body.Challenge})
		return
	}
	c.JSON(http.StatusOK, gin.H{})
}
