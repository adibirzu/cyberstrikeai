package handler

import (
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
	accessSSO  *security.AccessSSO
}

// SetAudit wires platform audit logging.
func (h *AuthHandler) SetAudit(s *audit.Service) {
	h.audit = s
}

// NewAuthHandler creates a new AuthHandler.
func NewAuthHandler(manager *security.AuthManager, cfg *config.Config, configPath string, logger *zap.Logger) *AuthHandler {
	return &AuthHandler{
		manager:    manager,
		accessSSO:  security.AccessSSOFromEnv(),
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
	if security.AccessSSOOnly() {
		c.JSON(http.StatusGone, gin.H{"error": "Use your verified organization sign-in"})
		return
	}
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
				Message:  "Login failed: incorrect password",
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
			Message:     "Login successful",
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

// SSO exchanges a cryptographically verified Access identity for its existing native RBAC session.
func (h *AuthHandler) SSO(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	if origin := c.GetHeader("Origin"); origin != "" && origin != "https://cyberstrike.pentforge.app" {
		c.JSON(http.StatusForbidden, gin.H{"error": "Invalid sign-in origin"})
		return
	}
	identity, err := h.accessSSO.Verify(c.Request.Context(), strings.TrimSpace(c.GetHeader("Cf-Access-Jwt-Assertion")))
	headerEmail := strings.ToLower(strings.TrimSpace(c.GetHeader("Cf-Access-Authenticated-User-Email")))
	if err != nil || (headerEmail != "" && headerEmail != identity.Email) {
		if h.audit != nil {
			h.audit.Record(c, audit.Entry{Category: "auth", Action: "login", Result: "failure", Message: "Organization SSO assertion rejected"})
		}
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Your organization sign-in could not be verified. Reopen the application from Pentforge."})
		return
	}
	token, expiresAt, err := h.manager.StartSession(identity.Username)
	if err != nil {
		if h.audit != nil {
			h.audit.Record(c, audit.Entry{Category: "auth", Action: "login", Result: "failure", Actor: identity.Username, Message: "Organization identity has no enabled native account"})
		}
		c.JSON(http.StatusForbidden, gin.H{"error": "Your identity is verified, but CyberStrikeAI access has not been assigned. Contact your administrator."})
		return
	}
	session, ok := h.manager.ValidateToken(token)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Sign-in session unavailable"})
		return
	}
	if h.audit != nil {
		h.audit.Record(c, audit.Entry{Category: "auth", Action: "login", Result: "success", Actor: session.Username, SessionHint: audit.HintFromToken(token), Message: "Organization SSO verified", Detail: map[string]interface{}{"method": "cloudflare_access", "expires_at": expiresAt.UTC().Format(time.RFC3339)}})
	}
	c.JSON(http.StatusOK, gin.H{"token": token, "expires_at": expiresAt.UTC().Format(time.RFC3339), "session_duration_hr": h.manager.SessionDurationHours(), "user": gin.H{"id": session.UserID, "username": session.Username, "display_name": session.DisplayName}, "roles": session.Roles, "permissions": permissionKeys(session.Permissions), "permission_scopes": session.PermissionScopes, "scope": session.Scope})
}

// SignInMethods contains no users, mappings, secrets or tenant data.
func (h *AuthHandler) SignInMethods(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusOK, gin.H{"access_sso": h.accessSSO != nil, "sso_only": security.AccessSSOOnly()})
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
			Message:  "Logged out",
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
				Message:  "Password change failed: current password incorrect",
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
			h.logger.Error("Failed to update user password", zap.Error(err))
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not update the password"})
		return
	}

	if h.logger != nil {
		h.logger.Info("Login password updated, all sessions invalid")
	}

	if h.audit != nil {
		h.audit.Record(c, audit.Entry{
			Category: "auth",
			Action:   "change_password",
			Result:   "success",
			Message:  "Login password changed",
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
