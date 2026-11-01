package handler

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// PublicHealth is the unauthenticated status the Pentforge console may read.
// It returns the product name and version only. It does not list tools,
// configuration, or sessions.
func PublicHealth(version string) gin.HandlerFunc {
	version = strings.TrimSpace(version)
	if version == "" {
		version = "v1.0.0"
	}
	body := gin.H{"ok": true, "product": "cyberstrike", "version": version}
	return func(c *gin.Context) {
		c.JSON(http.StatusOK, body)
	}
}
