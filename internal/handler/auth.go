package handler

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"cyberstrike-ai/internal/audit"
	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/security"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// AuthHandler handles authentication-related endpoints.
type AuthHandler struct {
	manager    *security.AuthManager
	config     *config.Config
	configPath string
	logger     *zap.Logger
	audit      *audit.Service
}

// SetAudit wires platform audit logging.
func (h *AuthHandler) SetAudit(s *audit.Service) {
	h.audit = s
}

// NewAuthHandler creates a new AuthHandler.
func NewAuthHandler(manager *security.AuthManager, cfg *config.Config, configPath string, logger *zap.Logger) *AuthHandler {
	return &AuthHandler{
		manager:    manager,
		config:     cfg,
		configPath: configPath,
		logger:     logger,
	}
}

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password" binding:"required"`
}

type changePasswordRequest struct {
	OldPassword string `json:"oldPassword"`
	NewPassword string `json:"newPassword"`
}

// Login verifies password and returns a session token.
func (h *AuthHandler) Login(c *gin.Context) {
	var req loginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Password is required"})
		return
	}
	req.Username = strings.TrimSpace(req.Username)
	if req.Username == "" || utf8.RuneCountInString(req.Username) > 64 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Username is required and must be at most 64 characters"})
		return
	}

	token, expiresAt, err := h.manager.Authenticate(req.Username, req.Password)
	if err != nil {
		if h.audit != nil {
			h.audit.Record(c, audit.Entry{
				Level:    "warn",
				Category: "auth",
				Action:   "login",
				Result:   "failure",
				Message:  "登录失败：密码错误",
				Actor:    strings.TrimSpace(req.Username),
			})
		}
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid username or password"})
		return
	}
	session, _ := h.manager.ValidateToken(token)

	if h.audit != nil {
		h.audit.Record(c, audit.Entry{
			Category:    "auth",
			Action:      "login",
			Result:      "success",
			SessionHint: audit.HintFromToken(token),
			Message:     "登录成功",
			Actor:       session.Username,
			Detail: map[string]interface{}{
				"expires_at": expiresAt.UTC().Format(time.RFC3339),
			},
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"token":               token,
		"expires_at":          expiresAt.UTC().Format(time.RFC3339),
		"session_duration_hr": h.manager.SessionDurationHours(),
		"user": gin.H{
			"id":           session.UserID,
			"username":     session.Username,
			"display_name": session.DisplayName,
		},
		"roles":             session.Roles,
		"permissions":       permissionKeys(session.Permissions),
		"permission_scopes": session.PermissionScopes,
		"scope":             session.Scope,
	})
}

func accessAssertionMatches(token, email string) bool {
	parts := strings.Split(token, ".")
	if len(parts) != 3 || email == "" {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return false
	}
	var claims struct {
		Email string `json:"email"`
		Exp   int64  `json:"exp"`
	}
	if err := json.Unmarshal(raw, &claims); err != nil {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(claims.Email), email) && claims.Exp > time.Now().Unix()
}

// SSO accepts a Cloudflare Access email and opens the matching local account.
func (h *AuthHandler) SSO(c *gin.Context) {
	email := strings.TrimSpace(strings.ToLower(c.GetHeader("Cf-Access-Authenticated-User-Email")))
	tokenHeader := strings.TrimSpace(c.GetHeader("Cf-Access-Jwt-Assertion"))
	if email == "" || !strings.Contains(email, "@") || !accessAssertionMatches(tokenHeader, email) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Google sign-in is not available for this request"})
		return
	}
	token, expiresAt, err := h.manager.StartSession(email)
	if err != nil {
		if at := strings.Index(email, "@"); at > 0 {
			token, expiresAt, err = h.manager.StartSession(email[:at])
		}
	}
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "This Google account is not a local user. Use the local account."})
		return
	}
	session, _ := h.manager.ValidateToken(token)
	c.JSON(http.StatusOK, gin.H{
		"token":               token,
		"expires_at":          expiresAt.UTC().Format(time.RFC3339),
		"session_duration_hr": h.manager.SessionDurationHours(),
		"user": gin.H{
			"id":           session.UserID,
			"username":     session.Username,
			"display_name": session.DisplayName,
		},
		"roles":             session.Roles,
		"permissions":       permissionKeys(session.Permissions),
		"permission_scopes": session.PermissionScopes,
		"scope":             session.Scope,
	})
}

// Logout revokes the current session token.
func (h *AuthHandler) Logout(c *gin.Context) {
	token := c.GetString(security.ContextAuthTokenKey)
	if token == "" {
		authHeader := c.GetHeader("Authorization")
		if len(authHeader) > 7 && strings.EqualFold(authHeader[:7], "Bearer ") {
			token = strings.TrimSpace(authHeader[7:])
		} else {
			token = strings.TrimSpace(authHeader)
		}
	}

	h.manager.RevokeToken(token)
	if h.audit != nil {
		h.audit.Record(c, audit.Entry{
			Category: "auth",
			Action:   "logout",
			Result:   "success",
			Message:  "退出登录",
		})
	}
	c.JSON(http.StatusOK, gin.H{"message": "Signed out"})
}

// ChangePassword updates the login password.
func (h *AuthHandler) ChangePassword(c *gin.Context) {
	var req changePasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid password change"})
		return
	}

	oldPassword := strings.TrimSpace(req.OldPassword)
	newPassword := strings.TrimSpace(req.NewPassword)

	if oldPassword == "" || newPassword == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Current password and new password are required"})
		return
	}

	if len(newPassword) < 8 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "New password must be at least 8 characters"})
		return
	}

	if oldPassword == newPassword {
		c.JSON(http.StatusBadRequest, gin.H{"error": "New password must be different from the current password"})
		return
	}

	session, _ := security.CurrentSession(c)
	if session.Username == "" {
		session.Username = "admin"
	}
	if !h.manager.CheckUserPassword(session.Username, oldPassword) {
		if h.audit != nil {
			h.audit.Record(c, audit.Entry{
				Level:    "warn",
				Category: "auth",
				Action:   "change_password",
				Result:   "failure",
				Message:  "修改密码失败：当前密码不正确",
			})
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": "Current password is incorrect"})
		return
	}

	if session.UserID == "" {
		session.UserID = "admin"
	}
	if err := h.manager.UpdateUserPassword(session.UserID, newPassword); err != nil {
		if h.logger != nil {
			h.logger.Error("更新用户密码失败", zap.Error(err))
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not update the password"})
		return
	}

	if h.logger != nil {
		h.logger.Info("登录密码已更新，所有会话已失效")
	}

	if h.audit != nil {
		h.audit.Record(c, audit.Entry{
			Category: "auth",
			Action:   "change_password",
			Result:   "success",
			Message:  "登录密码已修改",
		})
	}

	c.JSON(http.StatusOK, gin.H{"message": "Password updated. Sign in again with the new password."})
}

// Validate returns the current session status.
func (h *AuthHandler) Validate(c *gin.Context) {
	token := c.GetString(security.ContextAuthTokenKey)
	if token == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Sign in required"})
		return
	}

	session, ok := h.manager.ValidateToken(token)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Session expired"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"token":      session.Token,
		"expires_at": session.ExpiresAt.UTC().Format(time.RFC3339),
		"user": gin.H{
			"id":           session.UserID,
			"username":     session.Username,
			"display_name": session.DisplayName,
		},
		"roles":             session.Roles,
		"permissions":       permissionKeys(session.Permissions),
		"permission_scopes": session.PermissionScopes,
		"scope":             session.Scope,
	})
}

func permissionKeys(perms map[string]bool) []string {
	keys := make([]string, 0, len(perms))
	for key, ok := range perms {
		if ok {
			keys = append(keys, key)
		}
	}
	return keys
}
