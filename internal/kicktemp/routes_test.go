package kicktemp_test

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"gtm-mcp-server/auth"
	"gtm-mcp-server/internal/kicktemp"

	"golang.org/x/oauth2"
)

const testKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// upstreamMux mimics the routes main.go registers in service-account mode.
func upstreamMux(logger *slog.Logger) http.Handler {
	ok := func(body string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, body) }
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", ok("healthy"))
	mux.HandleFunc("GET /llms.txt", ok("llms"))
	mux.HandleFunc("GET /.well-known/oauth-protected-resource", ok("meta"))
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", ok("meta"))
	for _, r := range []string{"GET /authorize", "GET /oauth/callback", "POST /token", "POST /register"} {
		mux.HandleFunc(r, ok("oauth"))
	}
	sa := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "google"})
	mw := auth.Middleware(auth.NewMemoryTokenStore(), nil, logger, "http://localhost:8080", time.Hour, nil, sa, testKey, time.Hour)
	mux.Handle("/", mw(ok("mcp")))
	return mux
}

func status(h http.Handler, method, path, bearer string) (int, string) {
	req := httptest.NewRequest(method, path, nil)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code, strings.TrimSpace(rec.Body.String())
}

func TestRouteGuardOAuthOff(t *testing.T) {
	h := (&kicktemp.Config{}).RouteGuard(upstreamMux(slog.New(slog.NewTextHandler(io.Discard, nil))))
	cases := []struct {
		method, path, bearer string
		code                 int
	}{
		{"GET", "/health", "", 200},
		{"POST", "/", "", 401},                       // no bearer
		{"POST", "/", "wrong-key", 401},              // wrong bearer
		{"POST", "/", testKey[:len(testKey)-1], 401}, // almost right
		{"POST", "/", testKey, 200},
		{"GET", "/authorize", "", 404},
		{"GET", "/authorize", testKey, 404},
		{"GET", "/oauth/callback", "", 404},
		{"POST", "/token", "", 404},
		{"POST", "/register", "", 404},
		{"GET", "/.well-known/oauth-protected-resource", "", 404},
		{"GET", "/.well-known/oauth-authorization-server", "", 404},
		{"GET", "/llms.txt", "", 404},
		{"POST", "/mcp", testKey, 404},
		{"GET", "/anything/else", testKey, 404},
	}
	for _, tc := range cases {
		if got, _ := status(h, tc.method, tc.path, tc.bearer); got != tc.code {
			t.Errorf("%s %s (bearer=%q): status %d, want %d", tc.method, tc.path, tc.bearer, got, tc.code)
		}
	}
}

func TestRouteGuardOAuthOn(t *testing.T) {
	h := (&kicktemp.Config{OAuthEnabled: true}).RouteGuard(upstreamMux(slog.New(slog.NewTextHandler(io.Discard, nil))))
	for path, want := range map[string]int{
		"/health": 200, "/authorize": 200, "/oauth/callback": 200,
		"/.well-known/oauth-protected-resource": 200, "/.well-known/oauth-authorization-server": 200,
		"/llms.txt": 404, "/other": 404,
	} {
		if got, _ := status(h, "GET", path, ""); got != want {
			t.Errorf("GET %s: status %d, want %d", path, got, want)
		}
	}
	for _, p := range []string{"/token", "/register"} {
		if got, _ := status(h, "POST", p, ""); got != 200 {
			t.Errorf("POST %s: status %d, want 200", p, got)
		}
	}
}

func TestCheckAuth(t *testing.T) {
	cases := []struct {
		name    string
		oauth   bool
		key     string
		google  bool
		wantErr string
	}{
		{"default without key: no open mode", false, "", false, "SERVICE_ACCOUNT_API_KEY is required"},
		{"short key", false, "short", false, "too short"},
		{"31 bytes", false, strings.Repeat("a", 31), false, "too short"},
		{"32 bytes ok", false, strings.Repeat("a", 32), false, ""},
		{"generated key ok", false, testKey, false, ""},
		{"oauth on without google client", true, testKey, false, "GOOGLE_CLIENT_ID"},
		{"oauth on with google client, no key", true, "", true, ""},
		{"oauth on, weak key", true, "weak", true, "too short"},
	}
	for _, tc := range cases {
		err := (&kicktemp.Config{OAuthEnabled: tc.oauth}).CheckAuth(tc.key, tc.google)
		switch {
		case tc.wantErr == "" && err != nil:
			t.Errorf("%s: unexpected error %v", tc.name, err)
		case tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)):
			t.Errorf("%s: error %v, want %q", tc.name, err, tc.wantErr)
		}
	}
}

func TestOAuthEnabledParsing(t *testing.T) {
	get := func(v string) func(string) string {
		return func(k string) string {
			if k == "KT_OAUTH_ENABLED" {
				return v
			}
			return ""
		}
	}
	if c, err := kicktemp.Load(get("")); err != nil || c.OAuthEnabled {
		t.Fatalf("default must be false: %+v %v", c, err)
	}
	if c, err := kicktemp.Load(get("true")); err != nil || !c.OAuthEnabled {
		t.Fatalf("true not parsed: %+v %v", c, err)
	}
	if _, err := kicktemp.Load(get("maybe")); err == nil {
		t.Fatal("invalid value must be an error")
	}
}
