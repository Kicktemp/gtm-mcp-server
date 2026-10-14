package kicktemp

import (
	"fmt"
	"net/http"
)

// MCPPath is the Streamable HTTP endpoint, identical for every server in the stack.
const MCPPath = "/mcp"

// minAPIKeyBytes is the minimum length of SERVICE_ACCOUNT_API_KEY
// (openssl rand -hex 32 yields 64).
const minAPIKeyBytes = 32

// CheckAuth enforces the authentication policy at startup: there is no
// unauthenticated mode, and the bearer key must be strong.
//
//   - OAuth off (default): SERVICE_ACCOUNT_API_KEY is mandatory (>= 32 bytes).
//   - OAuth on: Google client credentials and KT_ALLOWED_EMAILS are mandatory;
//     a service-account key, if set, must be strong as well.
func (c *Config) CheckAuth(apiKey string, googleClientConfigured bool) error {
	if c.OAuthEnabled && !googleClientConfigured {
		return fmt.Errorf("KT_OAUTH_ENABLED=true requires GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET")
	}
	if c.OAuthEnabled && len(c.AllowedEmails) == 0 {
		return fmt.Errorf("KT_OAUTH_ENABLED=true requires KT_ALLOWED_EMAILS: with an empty list every login is refused")
	}
	if apiKey == "" {
		if c.OAuthEnabled {
			return nil
		}
		return fmt.Errorf("SERVICE_ACCOUNT_API_KEY (or MCP_AUTH_TOKEN) is required: the server does not run without authentication (generate one with: openssl rand -hex 32)")
	}
	if len(apiKey) < minAPIKeyBytes {
		return fmt.Errorf("SERVICE_ACCOUNT_API_KEY/MCP_AUTH_TOKEN is too short (%d bytes, need at least %d): generate one with: openssl rand -hex 32", len(apiKey), minAPIKeyBytes)
	}
	return nil
}

// RouteGuard answers 404 for every path that is not part of the intended
// surface, before any handler (and before authentication) runs:
//
//   - always:      /health and /healthz (no auth) and /mcp (the MCP endpoint, bearer auth)
//   - OAuth on:    additionally the OAuth routes and /.well-known metadata
//   - never:       /llms.txt and everything else
func (c *Config) RouteGuard(next http.Handler) http.Handler {
	allowed := map[string]bool{MCPPath: true, "/health": true, "/healthz": true}
	if c.OAuthEnabled {
		for _, p := range []string{
			"/authorize", "/oauth/callback", "/token", "/register",
			"/.well-known/oauth-protected-resource", "/.well-known/oauth-authorization-server",
		} {
			allowed[p] = true
		}
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !allowed[r.URL.Path] {
			http.NotFound(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}
