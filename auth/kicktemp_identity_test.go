package auth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

func TestCallbackIdentityCheckRefusesLogin(t *testing.T) {
	store := NewMemoryTokenStore()
	defer store.Close()
	google, cleanup := newFakeGoogleProvider(t)
	defer cleanup()
	server := NewServer("http://localhost:8080", google, store, slog.New(slog.NewTextHandler(os.Stdout, nil)), time.Hour)
	server.SetIdentityCheck(func(context.Context, *oauth2.Token) (string, error) {
		return "", errors.New("account not allowed")
	})

	w := runCallbackRaw(t, server)
	if w.Code != http.StatusForbidden {
		t.Fatalf("callback must answer 403 when the identity check refuses, got %d: %s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Header().Get("Location"), "code=") {
		t.Fatal("no authorization code may be issued to a refused account")
	}
}

// runCallbackRaw drives /authorize then /oauth/callback and returns the
// callback response without asserting on it.
func runCallbackRaw(t *testing.T, server *Server) *httptest.ResponseRecorder {
	t.Helper()
	params := url.Values{}
	params.Set("response_type", "code")
	params.Set("client_id", "test-client")
	params.Set("redirect_uri", "https://claude.ai/api/mcp/auth_callback")
	params.Set("state", "claude-state")
	sum := sha256.Sum256([]byte("verifier"))
	params.Set("code_challenge", base64.RawURLEncoding.EncodeToString(sum[:]))
	params.Set("code_challenge_method", "S256")

	w := httptest.NewRecorder()
	server.AuthorizeHandler(w, httptest.NewRequest(http.MethodGet, "/authorize?"+params.Encode(), nil))
	if w.Code != http.StatusFound {
		t.Fatalf("authorize: %d %s", w.Code, w.Body.String())
	}
	googleURL, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	cb := httptest.NewRequest(http.MethodGet, "/oauth/callback?code=google-code&state="+url.QueryEscape(googleURL.Query().Get("state")), nil)
	for _, c := range w.Result().Cookies() {
		cb.AddCookie(c)
	}
	out := httptest.NewRecorder()
	server.CallbackHandler(out, cb)
	return out
}

func TestCallbackIdentityCheckStoresEmail(t *testing.T) {
	store := NewMemoryTokenStore()
	defer store.Close()
	google, cleanup := newFakeGoogleProvider(t)
	defer cleanup()
	server := NewServer("http://localhost:8080", google, store, slog.New(slog.NewTextHandler(os.Stdout, nil)), time.Hour)
	server.SetIdentityCheck(func(context.Context, *oauth2.Token) (string, error) { return "niels@kicktemp.com", nil })

	loc := runAuthorizeCallbackFlow(t, server, "")
	code, err := store.ConsumeAuthorizationCode(loc.Query().Get("code"))
	if err != nil {
		t.Fatal(err)
	}
	if code.Email != "niels@kicktemp.com" {
		t.Fatalf("authorization code carries email %q", code.Email)
	}
}
