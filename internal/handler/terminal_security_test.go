//go:build !windows

package handler

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"cyberstrike-ai/internal/c2"
	"cyberstrike-ai/internal/childenv"
	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/security"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"go.uber.org/zap"
)

func streamFixture(t *testing.T) (*database.DB, *security.AuthManager, string) {
	t.Helper()
	db, err := database.NewDB(filepath.Join(t.TempDir(), "synthetic.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	auth := security.NewAuthManager(12)
	_, err = auth.AttachRBACStore(db)
	if err != nil {
		t.Fatal(err)
	}
	hash, err := security.HashPassword("synthetic-stream-password")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.CreateRBACUser("stream-fixture", "Stream Fixture", hash, true, []string{database.RBACSystemRoleViewer}); err != nil {
		t.Fatal(err)
	}
	token, _, err := auth.Authenticate("stream-fixture", "synthetic-stream-password")
	if err != nil {
		t.Fatal(err)
	}
	return db, auth, token
}

func TestTerminalHTTPAndSSEFilterServerEnvironment(t *testing.T) {
	_, auth, token := streamFixture(t)
	t.Setenv("HOME", t.TempDir())
	t.Setenv(childenv.AllowlistVariable, "")
	for _, key := range []string{"OPENAI_API_KEY", "CLAUDE_CODE_OAUTH_TOKEN", "DATABASE_URL"} {
		t.Setenv(key, "synthetic-server-secret")
	}
	h := NewTerminalHandler(zap.NewNop())
	r := gin.New()
	r.Use(security.AuthMiddleware(auth))
	r.POST("/run", h.RunCommand)
	r.POST("/stream", h.RunCommandStream)
	for _, route := range []string{"/run", "/stream"} {
		w := httptest.NewRecorder()
		req := httptest.NewRequest("POST", route, bytes.NewBufferString(`{"command":"printf 'marker:%s:%s:%s:%s' \"$OPENAI_API_KEY\" \"$CLAUDE_CODE_OAUTH_TOKEN\" \"$DATABASE_URL\" \"$LC_ALL\""}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		r.ServeHTTP(w, req)
		if w.Code != 200 || !strings.Contains(w.Body.String(), "marker::::C") || strings.Contains(w.Body.String(), "synthetic-server-secret") {
			t.Fatalf("%s status/output: %d %s", route, w.Code, w.Body)
		}
	}
}

func TestTerminalWSFiltersEnvironmentAndCannotExtendIdentityExpiryWithPongs(t *testing.T) {
	_, auth, _ := streamFixture(t)
	t.Setenv("HOME", t.TempDir())
	t.Setenv(childenv.AllowlistVariable, "")
	t.Setenv("OPENAI_API_KEY", "synthetic-server-secret")
	token, expiry, err := auth.StartSessionUntil("stream-fixture", time.Now().Add(700*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	h := NewTerminalHandler(zap.NewNop())
	r := gin.New()
	r.Use(security.AuthMiddleware(auth))
	r.GET("/ws", h.RunCommandWS)
	server := httptest.NewServer(r)
	defer server.Close()
	headers := http.Header{"Authorization": []string{"Bearer " + token}}
	conn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http")+"/ws", headers)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.WriteMessage(websocket.TextMessage, []byte("printf 'fixture-value:%s:done\\n' \"$OPENAI_API_KEY\"\n")); err != nil {
		t.Fatal(err)
	}
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		ticker := time.NewTicker(20 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				_ = conn.WriteControl(websocket.PongMessage, []byte("alive"), time.Now().Add(time.Second))
			}
		}
	}()
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	var output strings.Builder
	for {
		_, data, err := conn.ReadMessage()
		if err != nil {
			break
		}
		output.Write(data)
	}
	if !strings.Contains(output.String(), "fixture-value::done") || strings.Contains(output.String(), "synthetic-server-secret") {
		t.Fatalf("PTY environment not filtered: %q", output.String())
	}
	if time.Now().After(expiry.Add(time.Second)) {
		t.Fatal("pongs extended absolute session expiry")
	}
}

func TestC2EventStreamEndsOnRevocationDisabledUserAndExpiry(t *testing.T) {
	for _, mode := range []string{"revoke", "disable", "expiry"} {
		t.Run(mode, func(t *testing.T) {
			db, auth, token := streamFixture(t)
			if mode == "expiry" {
				var err error
				token, _, err = auth.StartSessionUntil("stream-fixture", time.Now().Add(400*time.Millisecond))
				if err != nil {
					t.Fatal(err)
				}
			}
			manager := c2.NewManager(db, zap.NewNop(), t.TempDir())
			defer manager.Close()
			h := NewC2Handler(manager, zap.NewNop())
			r := gin.New()
			r.Use(security.AuthMiddleware(auth))
			r.GET("/events", h.EventStream)
			server := httptest.NewServer(r)
			defer server.Close()
			request, _ := http.NewRequest("GET", server.URL+"/events", nil)
			request.Header.Set("Authorization", "Bearer "+token)
			client := &http.Client{Timeout: 4 * time.Second}
			response, err := client.Do(request)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			if response.StatusCode != 200 {
				t.Fatalf("status=%d", response.StatusCode)
			}
			switch mode {
			case "revoke":
				session, _ := auth.ValidateToken(token)
				auth.RevokeUserSessions(session.UserID)
			case "disable":
				enabled := false
				if err := db.UpdateRBACUser(func() string { session, _ := auth.ValidateToken(token); return session.UserID }(), "Stream Fixture", &enabled, nil); err != nil {
					t.Fatal(err)
				}
			}
			started := time.Now()
			_, err = io.ReadAll(response.Body)
			if err != nil || time.Since(started) > 2500*time.Millisecond {
				t.Fatalf("idle stream not closed: %v", err)
			}
		})
	}
}
