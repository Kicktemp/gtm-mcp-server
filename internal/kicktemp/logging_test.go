package kicktemp_test

import (
	"bytes"
	"context"
	"io"
	"log"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"gtm-mcp-server/auth"
	"gtm-mcp-server/gtm"
	"gtm-mcp-server/internal/kicktemp"
	"gtm-mcp-server/middleware"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"golang.org/x/oauth2"
)

// A debug logger and the stdlib logger, both captured.
func captureLogs(t *testing.T) (*slog.Logger, *bytes.Buffer) {
	t.Helper()
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(prev) })
	return slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})), &buf
}

func TestGTMDebugNoLongerDumpsHTTPBodies(t *testing.T) {
	_, buf := captureLogs(t)
	t.Setenv("GTM_DEBUG", "1")
	t.Setenv("BASE_URL", "http://localhost:8080")

	gtmAPI := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"account":[{"accountId":"1","name":"CONFIDENTIAL-ACCOUNT-NAME"}]}`)
	}))
	defer gtmAPI.Close()

	client, err := gtm.NewClient(context.Background(), oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "GOOGLE-ACCESS-TOKEN"}))
	if err != nil {
		t.Fatal(err)
	}
	client.Service.BasePath = gtmAPI.URL + "/"
	if _, err := client.ListAccounts(context.Background()); err != nil {
		t.Fatal(err)
	}
	if out := buf.String(); out != "" {
		t.Fatalf("GTM_DEBUG must not log HTTP traffic any more, got: %s", out)
	}
}

func TestDebugLogsContainNoBearerOrKey(t *testing.T) {
	logger, buf := captureLogs(t)
	const wrong = "attacker-guess-with-secret-looking-value"
	h := (&kicktemp.Config{}).RouteGuard(upstreamMux(logger))
	for _, bearer := range []string{testKey, wrong, ""} {
		status(h, "POST", "/", bearer)
	}
	for _, secret := range []string{testKey, wrong} {
		if strings.Contains(buf.String(), secret) {
			t.Fatalf("debug log leaks a bearer value:\n%s", buf.String())
		}
	}
}

func TestMCPRequestLogDoesNotContainToolArguments(t *testing.T) {
	logger, buf := captureLogs(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	server := mcp.NewServer(&mcp.Implementation{Name: "log-test", Version: "1"}, nil)
	mcp.AddTool(server, &mcp.Tool{Name: "update_tag", Description: "fake"},
		func(_ context.Context, _ *mcp.CallToolRequest, in map[string]any) (*mcp.CallToolResult, fakeTagOut, error) {
			return nil, fakeTagOut{}, nil
		})
	cfg := &kicktemp.Config{AllowAllContainers: true}
	server.AddReceivingMiddleware(kicktemp.NewGate(cfg, kicktemp.NewAllowlist(cfg), nil, nil).Middleware())
	server.AddReceivingMiddleware(middleware.NewLoggingMiddleware(logger))
	st, ct := mcp.NewInMemoryTransports()
	ss, err := server.Connect(ctx, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ss.Close()
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "c", Version: "1"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()
	if _, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "update_tag", Arguments: map[string]any{
		"accountId": "1", "containerId": "2", "apiKey": "ARGUMENT-SECRET", "measurementSecret": "ARGUMENT-SECRET-2",
	}}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "ARGUMENT-SECRET") {
		t.Fatalf("request log leaks tool arguments:\n%s", buf.String())
	}
	if !strings.Contains(buf.String(), "update_tag") {
		t.Fatalf("request log should name the tool:\n%s", buf.String())
	}
}

var _ = auth.GetTokenInfo // keep the auth import used by upstreamMux helpers
