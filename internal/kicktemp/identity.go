package kicktemp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"

	"gtm-mcp-server/auth"

	"golang.org/x/oauth2"
)

// IdentityScopes returns scopes plus the OpenID scopes needed to learn which
// Google account logged in.
func IdentityScopes(scopes []string) []string {
	out := slices.Clone(scopes)
	for _, s := range []string{"openid", "email"} {
		if !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	return out
}

// EmailPolicy restricts OAuth logins to KT_ALLOWED_EMAILS.
type EmailPolicy struct {
	allowed  map[string]bool
	clientID string
	now      func() time.Time
}

// NewEmailPolicy builds the policy; clientID is the Google OAuth client the
// id_token must have been issued for.
func NewEmailPolicy(cfg *Config, clientID string) *EmailPolicy {
	p := &EmailPolicy{allowed: map[string]bool{}, clientID: clientID, now: time.Now}
	for _, e := range cfg.AllowedEmails {
		p.allowed[e] = true
	}
	return p
}

// Allowed reports whether email may use the server.
func (p *EmailPolicy) Allowed(email string) bool {
	return p.allowed[strings.ToLower(strings.TrimSpace(email))]
}

type idClaims struct {
	Iss           string `json:"iss"`
	Aud           string `json:"aud"`
	Exp           int64  `json:"exp"`
	Email         string `json:"email"`
	EmailVerified any    `json:"email_verified"`
}

// Verify is the auth.IdentityCheck: it reads the id_token from the Google
// token response and refuses accounts outside the allowlist. The token comes
// straight from Google's token endpoint over TLS, so its signature is not
// re-verified (OpenID Connect Core 3.1.3.7); issuer, audience, expiry and
// email_verified are checked.
func (p *EmailPolicy) Verify(_ context.Context, tok *oauth2.Token) (string, error) {
	raw, _ := tok.Extra("id_token").(string)
	if raw == "" {
		return "", fmt.Errorf("no id_token in Google response")
	}
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("malformed id_token")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("malformed id_token payload")
	}
	var c idClaims
	if err := json.Unmarshal(payload, &c); err != nil {
		return "", fmt.Errorf("malformed id_token claims")
	}
	if c.Iss != "https://accounts.google.com" && c.Iss != "accounts.google.com" {
		return "", fmt.Errorf("id_token issuer %q", c.Iss)
	}
	if c.Aud != p.clientID {
		return "", fmt.Errorf("id_token audience does not match the OAuth client")
	}
	if c.Exp != 0 && p.now().Unix() > c.Exp {
		return "", fmt.Errorf("id_token expired")
	}
	if !verified(c.EmailVerified) {
		return "", fmt.Errorf("email of %q is not verified", c.Email)
	}
	email := strings.ToLower(strings.TrimSpace(c.Email))
	if !p.Allowed(email) {
		return "", fmt.Errorf("account %s is not in KT_ALLOWED_EMAILS", email)
	}
	return email, nil
}

func verified(v any) bool {
	switch t := v.(type) {
	case bool:
		return t
	case string:
		return t == "true"
	}
	return false
}

// checkRequest refuses OAuth requests whose token does not carry an allowed
// account. The service-account bearer key is not an OAuth identity and is
// unaffected. Re-checking on every request means removing an address from the
// list takes effect immediately, and tokens without an email (issued before the
// list existed) are refused.
func (p *EmailPolicy) checkRequest(ctx context.Context) error {
	if p == nil || auth.GetSATokenSource(ctx) != nil {
		return nil
	}
	ti := auth.GetTokenInfo(ctx)
	if ti == nil || ti.Email == "" {
		return fmt.Errorf("this login has no verified Google account; sign in again")
	}
	if !p.Allowed(ti.Email) {
		return fmt.Errorf("account %s is not in KT_ALLOWED_EMAILS", ti.Email)
	}
	return nil
}

// UseEmailPolicy makes the gate check the account of every OAuth request.
func (g *Gate) UseEmailPolicy(p *EmailPolicy) {
	g.emails = p
	g.checks = append([]check{func(ctx context.Context, _ *toolCall) error { return p.checkRequest(ctx) }}, g.checks...)
}
