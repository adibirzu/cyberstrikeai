package handler

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/security"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const fixtureAudience = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

type accessTestTransport func(*http.Request) (*http.Response, error)

func (f accessTestTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func ssoFixture(t *testing.T, username string, enabled bool) (*gin.Engine, *security.AuthManager, func(map[string]any, bool) string) {
	t.Helper()
	t.Setenv("CYBERSTRIKE_ACCESS_AUD", fixtureAudience)
	t.Setenv("CYBERSTRIKE_ACCESS_USER_MAP", `{"adibirzu@gmail.com":"admin"}`)
	t.Setenv("CYBERSTRIKE_ACCESS_SSO_ONLY", "true")
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	jwks, _ := json.Marshal(map[string]any{"keys": []map[string]string{{"kty": "RSA", "kid": "fixture", "alg": "RS256", "use": "sig", "n": base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes()), "e": "AQAB"}}})
	prior := http.DefaultTransport
	http.DefaultTransport = accessTestTransport(func(r *http.Request) (*http.Response, error) {
		if r.URL.String() != security.AccessIssuer+"/cdn-cgi/access/certs" {
			return nil, fmt.Errorf("unexpected key target")
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(jwks))}, nil
	})
	t.Cleanup(func() { http.DefaultTransport = prior })
	db, err := database.NewDB(filepath.Join(t.TempDir(), "sso.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	manager := security.NewAuthManager(8)
	if _, err = manager.AttachRBACStore(db); err != nil {
		t.Fatal(err)
	}
	if username != "admin" {
		if _, err = db.CreateRBACUser(username, "Test account", "!sso-only", enabled, []string{database.RBACSystemRoleViewer}); err != nil {
			t.Fatal(err)
		}
	}
	handler := NewAuthHandler(manager, &config.Config{}, "", zap.NewNop())
	router := gin.New()
	router.POST("/api/auth/sso", handler.SSO)
	router.POST("/api/auth/login", handler.Login)
	router.GET("/api/auth/methods", handler.SignInMethods)
	sign := func(overrides map[string]any, forged bool) string {
		claims := map[string]any{"iss": security.AccessIssuer, "aud": []string{fixtureAudience}, "sub": "fixture-owner", "email": username, "iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix()}
		for k, v := range overrides {
			claims[k] = v
		}
		body, _ := json.Marshal(claims)
		header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","kid":"fixture"}`))
		raw := header + "." + base64.RawURLEncoding.EncodeToString(body)
		hash := sha256.Sum256([]byte(raw))
		signingKey := key
		if forged {
			signingKey, _ = rsa.GenerateKey(rand.Reader, 2048)
		}
		signature, err := rsa.SignPKCS1v15(rand.Reader, signingKey, crypto.SHA256, hash[:])
		if err != nil {
			t.Fatal(err)
		}
		return raw + "." + base64.RawURLEncoding.EncodeToString(signature)
	}
	return router, manager, sign
}
func ssoCall(router *gin.Engine, token, email string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodPost, "/api/auth/sso", nil)
	request.Header.Set("Origin", "https://cyberstrike.pentforge.app")
	request.Header.Set("Cf-Access-Authenticated-User-Email", email)
	request.Header.Set("Cf-Access-Jwt-Assertion", token)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	return response
}
func TestSSORejectsAnUnsignedIdentityAssertion(t *testing.T) {
	router, _, _ := ssoFixture(t, "adrian.birzu@cyber-sec.ro", true)
	claims := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(`{"email":"adrian.birzu@cyber-sec.ro","exp":%d}`, time.Now().Add(time.Hour).Unix())))
	if r := ssoCall(router, "eyJhbGciOiJub25lIn0."+claims+".forged", "adrian.birzu@cyber-sec.ro"); r.Code != 401 {
		t.Fatalf("unsigned identity created a session: %d", r.Code)
	}
}
func TestAccessSSOPreservesNativeRightsForCorporateIdentities(t *testing.T) {
	for _, email := range []string{"adrian.birzu@cyber-sec.ro", "adrian.birzu@roeltrans.ro"} {
		t.Run(email, func(t *testing.T) {
			router, manager, sign := ssoFixture(t, email, true)
			r := ssoCall(router, sign(nil, false), email)
			if r.Code != 200 {
				t.Fatalf("verified sign-in: %d %s", r.Code, r.Body.String())
			}
			var body struct {
				Token string   `json:"token"`
				Roles []string `json:"roles"`
			}
			json.Unmarshal(r.Body.Bytes(), &body)
			session, ok := manager.ValidateToken(body.Token)
			if !ok || session.Username != email || session.Permissions["users:write"] || strings.Contains(strings.Join(body.Roles, ","), "admin") {
				t.Fatal("corporate user identity or native rights changed")
			}
			if r.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("authentication response cached")
			}
		})
	}
}
func TestAccessSSOUsesExplicitOwnerMappingOnly(t *testing.T) {
	router, manager, sign := ssoFixture(t, "admin", true)
	r := ssoCall(router, sign(map[string]any{"email": "adibirzu@gmail.com"}, false), "adibirzu@gmail.com")
	if r.Code != 200 {
		t.Fatalf("owner mapping failed: %d", r.Code)
	}
	var body struct {
		Token string `json:"token"`
	}
	json.Unmarshal(r.Body.Bytes(), &body)
	session, ok := manager.ValidateToken(body.Token)
	if !ok || session.Username != "admin" {
		t.Fatal("explicit mapping was not used")
	}
	if r := ssoCall(router, sign(map[string]any{"email": "admin@unassigned.example"}, false), "admin@unassigned.example"); r.Code != 403 {
		t.Fatal("email local part must never map to admin")
	}
}
func TestAccessSSORejectsInvalidAssertionsAndDisabledUsers(t *testing.T) {
	cases := []struct {
		name      string
		overrides map[string]any
		forged    bool
		header    string
	}{{"forged signature", nil, true, ""}, {"issuer", map[string]any{"iss": "https://attacker.example"}, false, ""}, {"audience", map[string]any{"aud": []string{"different-app"}}, false, ""}, {"expired", map[string]any{"exp": 1}, false, ""}, {"future", map[string]any{"nbf": time.Now().Add(time.Hour).Unix()}, false, ""}, {"unverified email", map[string]any{"email_verified": false}, false, ""}, {"header mismatch", nil, false, "other@example.test"}, {"missing subject", map[string]any{"sub": ""}, false, ""}}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			email := "adrian.birzu@cyber-sec.ro"
			router, _, sign := ssoFixture(t, email, true)
			header := email
			if test.header != "" {
				header = test.header
			}
			if r := ssoCall(router, sign(test.overrides, test.forged), header); r.Code != 401 {
				t.Fatalf("invalid assertion accepted: %d", r.Code)
			}
		})
	}
	t.Run("disabled account", func(t *testing.T) {
		email := "adrian.birzu@roeltrans.ro"
		router, _, sign := ssoFixture(t, email, false)
		if r := ssoCall(router, sign(nil, false), email); r.Code != 403 {
			t.Fatalf("disabled user signed in: %d", r.Code)
		}
	})
}
func TestAccessSSOOnlyRetiresPasswordLogin(t *testing.T) {
	router, _, _ := ssoFixture(t, "admin", true)
	request := httptest.NewRequest(http.MethodPost, "/api/auth/login", strings.NewReader(`{"username":"admin","password":"irrelevant"}`))
	request.Header.Set("Content-Type", "application/json")
	r := httptest.NewRecorder()
	router.ServeHTTP(r, request)
	if r.Code != 410 {
		t.Fatal("password fallback remains enabled")
	}
}
