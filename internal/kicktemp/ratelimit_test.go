package kicktemp_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"gtm-mcp-server/gtm"
	"gtm-mcp-server/internal/kicktemp"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"golang.org/x/oauth2"
)

// fakeClock advances only when a limiter sleeps.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *fakeClock) sleep(_ context.Context, d time.Duration) error {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
	return nil
}

func TestLimiter40RequestsInARowNoneFailsAndTakeAMinute(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_000_000, 0)}
	l := kicktemp.NewLimiterWithClock(25, 60*time.Second, clk.now, clk.sleep)
	start := clk.now()
	var sent []time.Time
	for i := 0; i < 40; i++ {
		if err := l.Wait(context.Background()); err != nil {
			t.Fatalf("request %d failed: %v", i+1, err)
		}
		sent = append(sent, clk.now())
	}
	if el := clk.now().Sub(start); el < 59*time.Second {
		t.Fatalf("40 requests took %v, want about a minute or more", el)
	}
	// No 60s window may contain more than 25 requests (API quota is 30/minute).
	for i := range sent {
		n := 0
		for _, s := range sent {
			if !s.Before(sent[i]) && s.Sub(sent[i]) < time.Minute {
				n++
			}
		}
		if n > 25 {
			t.Fatalf("%d requests within one minute starting at request %d", n, i+1)
		}
	}
}

func TestLimiterFailsWhenWaitExceedsMaxWaitWithoutConsumingASlot(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_000_000, 0)}
	l := kicktemp.NewLimiterWithClock(2, 10*time.Second, clk.now, clk.sleep)
	for i := 0; i < 2; i++ {
		if err := l.Wait(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	before := clk.now()
	err := l.Wait(context.Background())
	if !errors.Is(err, kicktemp.ErrRateLimited) || err.Error() != "rate limited, retry later" {
		t.Fatalf("want ErrRateLimited, got %v", err)
	}
	if clk.now() != before {
		t.Error("must fail immediately instead of sleeping")
	}
	// After the window passes the slots are free again.
	clk.sleep(context.Background(), 61*time.Second)
	if err := l.Wait(context.Background()); err != nil {
		t.Fatalf("slot must be free again: %v", err)
	}
}

func TestLimiterConcurrentRealClock(t *testing.T) {
	l := kicktemp.NewLimiter(100000, time.Second)
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _ = l.Wait(context.Background()) }()
	}
	wg.Wait()
}

func TestLimiterCancelsWhileWaiting(t *testing.T) {
	l := kicktemp.NewLimiter(1, 2*time.Minute)
	l.Wait(context.Background())
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := l.Wait(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("want context deadline, got %v", err)
	}
}

// The real GTM client sends every request through the limiter, and a refused
// request surfaces as a rate-limit error.
func TestGTMClientRequestsGoThroughLimiter(t *testing.T) {
	hits := 0
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"account":[]}`)
	}))
	defer api.Close()

	clk := &fakeClock{t: time.Unix(1_000_000, 0)}
	l := kicktemp.NewLimiterWithClock(3, time.Second, clk.now, clk.sleep)
	gtm.TransportWrapper = l.Wrap
	defer func() { gtm.TransportWrapper = nil }()

	client, err := gtm.NewClient(context.Background(), oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "t"}))
	if err != nil {
		t.Fatal(err)
	}
	client.Service.BasePath = api.URL + "/"
	for i := 0; i < 3; i++ {
		if _, err := client.ListAccounts(context.Background()); err != nil {
			t.Fatalf("request %d: %v", i+1, err)
		}
	}
	_, err = client.ListAccounts(context.Background())
	if err == nil || hits != 3 {
		t.Fatalf("4th request must be refused before reaching GTM (hits=%d, err=%v)", hits, err)
	}
}

func TestAuditRecordsAPICalls(t *testing.T) {
	env := auditSession(t)
	// Replace nothing: the fake update_tag makes no HTTP call, so api_calls counts only
	// the fingerprint_before lookup, which the fake fetch does not issue either -> 0.
	env.call("update_tag", tagArgs("9", nil))
	end := env.lines(t)[1]
	if v, ok := end["api_calls"]; !ok || v.(float64) != 0 {
		t.Fatalf("end line must carry api_calls, got %v", end)
	}
}

func TestAuditCountsRequestsMadeDuringACall(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "{}")
	}))
	defer api.Close()
	rt := kicktemp.NewLimiter(1000, time.Second).Wrap(nil)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cfg := &kicktemp.Config{AllowAllContainers: true}
	logPath := t.TempDir() + "/a.jsonl"
	audit, err := kicktemp.OpenAudit(logPath)
	if err != nil {
		t.Fatal(err)
	}
	defer audit.Close()
	server := mcp.NewServer(&mcp.Implementation{Name: "n", Version: "1"}, nil)
	mcp.AddTool(server, &mcp.Tool{Name: "create_tag", Description: "fake"},
		func(ctx context.Context, _ *mcp.CallToolRequest, in map[string]any) (*mcp.CallToolResult, fakeTagOut, error) {
			for i := 0; i < 3; i++ { // three GTM requests inside one tool call
				req, _ := http.NewRequestWithContext(ctx, "GET", api.URL, nil)
				resp, err := rt.RoundTrip(req)
				if err != nil {
					return nil, fakeTagOut{}, err
				}
				resp.Body.Close()
			}
			return nil, fakeTagOut{}, nil
		})
	server.AddReceivingMiddleware(kicktemp.NewGate(cfg, kicktemp.NewAllowlist(cfg), audit, nil).Middleware())
	st, ct := mcp.NewInMemoryTransports()
	ss, _ := server.Connect(ctx, st, nil)
	defer ss.Close()
	cs, _ := mcp.NewClient(&mcp.Implementation{Name: "c", Version: "1"}, nil).Connect(ctx, ct, nil)
	defer cs.Close()
	if _, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "create_tag", Arguments: map[string]any{"accountId": "1", "containerId": "2", "workspaceId": "3"}}); err != nil {
		t.Fatal(err)
	}
	e := &auditEnv{path: logPath}
	lines := e.lines(t)
	if len(lines) != 2 || lines[1]["api_calls"].(float64) != 3 {
		t.Fatalf("end line must count the 3 GTM requests of the call: %v", lines)
	}
}

func TestRateConfig(t *testing.T) {
	get := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	c, err := kicktemp.Load(get(nil))
	if err != nil || c.GTMQPM != 25 || c.GTMMaxWait != 60*time.Second {
		t.Fatalf("defaults: %+v %v", c, err)
	}
	c, err = kicktemp.Load(get(map[string]string{"KT_GTM_QPM": "10", "KT_GTM_MAX_WAIT": "5s"}))
	if err != nil || c.GTMQPM != 10 || c.GTMMaxWait != 5*time.Second {
		t.Fatalf("custom: %+v %v", c, err)
	}
	for _, bad := range []map[string]string{{"KT_GTM_QPM": "0"}, {"KT_GTM_QPM": "x"}, {"KT_GTM_MAX_WAIT": "soon"}, {"KT_GTM_MAX_WAIT": "-1s"}} {
		if _, err := kicktemp.Load(get(bad)); err == nil {
			t.Errorf("%v must be rejected", bad)
		}
	}
}
