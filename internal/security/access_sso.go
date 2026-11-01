package security

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/coreos/go-oidc/v3/oidc"
	"net/http"
	"net/mail"
	"os"
	"regexp"
	"strings"
	"time"
)

const AccessIssuer = "https://pentforge.cloudflareaccess.com"

var audiencePattern = regexp.MustCompile(`^[a-f0-9]{64}$`)
var errAccessIdentity = errors.New("verified Access identity required")

type AccessIdentity struct{ Email, Subject, Username string }
type AccessSSO struct {
	verifier *oidc.IDTokenVerifier
	users    map[string]string
}

// AccessSSOFromEnv fixes issuer, JWKS location and RS256. No token URL controls a request.
func AccessSSOFromEnv() *AccessSSO {
	audience := strings.TrimSpace(os.Getenv("CYBERSTRIKE_ACCESS_AUD"))
	if !audiencePattern.MatchString(audience) {
		return nil
	}
	mappings := map[string]string{}
	if raw := os.Getenv("CYBERSTRIKE_ACCESS_USER_MAP"); raw != "" {
		if json.Unmarshal([]byte(raw), &mappings) != nil {
			return nil
		}
	}
	for email, user := range mappings {
		if email != strings.ToLower(strings.TrimSpace(email)) || !validAccessEmail(email) || strings.TrimSpace(user) == "" {
			return nil
		}
	}
	client := &http.Client{Timeout: 8 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return errors.New("identity key redirect denied") }}
	ctx := oidc.ClientContext(context.Background(), client)
	keys := oidc.NewRemoteKeySet(ctx, AccessIssuer+"/cdn-cgi/access/certs")
	return &AccessSSO{verifier: oidc.NewVerifier(AccessIssuer, keys, &oidc.Config{ClientID: audience, SupportedSigningAlgs: []string{oidc.RS256}}), users: mappings}
}
func validAccessEmail(value string) bool {
	parsed, err := mail.ParseAddress(value)
	return err == nil && parsed.Address == value && len(value) <= 255 && strings.Contains(value, "@")
}
func (s *AccessSSO) Verify(ctx context.Context, raw string) (AccessIdentity, error) {
	if s == nil || s.verifier == nil || len(raw) == 0 || len(raw) > 16384 {
		return AccessIdentity{}, errAccessIdentity
	}
	token, err := s.verifier.Verify(ctx, raw)
	if err != nil || token.Subject == "" {
		return AccessIdentity{}, errAccessIdentity
	}
	var claims struct {
		Email     string `json:"email"`
		Verified  *bool  `json:"email_verified"`
		NotBefore int64  `json:"nbf"`
		IssuedAt  int64  `json:"iat"`
	}
	if token.Claims(&claims) != nil || (claims.Verified != nil && !*claims.Verified) || claims.NotBefore > time.Now().Unix()+30 || claims.IssuedAt > time.Now().Unix()+30 {
		return AccessIdentity{}, errAccessIdentity
	}
	email := strings.ToLower(strings.TrimSpace(claims.Email))
	if !validAccessEmail(email) {
		return AccessIdentity{}, errAccessIdentity
	}
	username := email
	if mapped, ok := s.users[email]; ok {
		username = mapped
	}
	// Exact full email or explicit server mapping only. Never infer a username from the local part.
	return AccessIdentity{Email: email, Subject: token.Subject, Username: username}, nil
}
func AccessSSOOnly() bool { return os.Getenv("CYBERSTRIKE_ACCESS_SSO_ONLY") == "true" }
