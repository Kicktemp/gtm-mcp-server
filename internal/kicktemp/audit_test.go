package kicktemp_test

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gtm-mcp-server/internal/kicktemp"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type fakeTag struct {
	Path        string `json:"path"`
	Name        string `json:"name"`
	Type        string `json:"type"`
	Fingerprint string `json:"fingerprint"`
}
type fakeTagOut struct {
	Tag fakeTag `json:"tag"`
}

type auditEnv struct {
	cs      *mcp.ClientSession
	audit   *kicktemp.Audit
	path    string
	ents    *kicktemp.Entities
	fetched []string
	runs    int // executions of the fake write tool
}

// auditSession runs fake get_tag/update_tag/delete_tag tools behind the gate
// with a real audit log. Only container 1/100 (GTM-AAAA1) is allowed.
func auditSession(t *testing.T) *auditEnv {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	env := &auditEnv{path: filepath.Join(t.TempDir(), "audit.jsonl")}
	var err error
	if env.audit, err = kicktemp.OpenAudit(env.path); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { env.audit.Close() })

	env.ents = kicktemp.NewEntitiesWithFetch(func(_ context.Context, path string) (kicktemp.Entity, error) {
		env.fetched = append(env.fetched, path)
		return kicktemp.Entity{Fingerprint: "fp-fetched", Type: "gaawe"}, nil
	})
	cfg := &kicktemp.Config{AllowDelete: true, AllowedContainers: []string{"GTM-AAAA1"}}
	allow := kicktemp.NewAllowlist(cfg)
	if err := allow.InitWithLister(ctx, &fakeLister{}); err != nil {
		t.Fatal(err)
	}

	type in map[string]any
	tag := func(id, fp string) fakeTagOut {
		return fakeTagOut{Tag: fakeTag{Path: "accounts/1/containers/100/workspaces/5/tags/" + id, Name: "GA4", Type: "gaawe", Fingerprint: fp}}
	}
	server := mcp.NewServer(&mcp.Implementation{Name: "kt-audit", Version: "1"}, nil)
	mcp.AddTool(server, &mcp.Tool{Name: "get_tag", Description: "fake"},
		func(_ context.Context, _ *mcp.CallToolRequest, a in) (*mcp.CallToolResult, fakeTagOut, error) {
			return nil, tag(a["tagId"].(string), "fp-read"), nil
		})
	mcp.AddTool(server, &mcp.Tool{Name: "update_tag", Description: "fake"},
		func(_ context.Context, _ *mcp.CallToolRequest, a in) (*mcp.CallToolResult, fakeTagOut, error) {
			env.runs++
			if a["name"] == "boom" {
				return nil, fakeTagOut{}, context.DeadlineExceeded
			}
			return nil, tag(a["tagId"].(string), "fp-after"), nil
		})
	mcp.AddTool(server, &mcp.Tool{Name: "delete_tag", Description: "fake"},
		func(_ context.Context, _ *mcp.CallToolRequest, a in) (*mcp.CallToolResult, fakeTagOut, error) {
			env.runs++
			return nil, fakeTagOut{}, nil
		})
	server.AddReceivingMiddleware(kicktemp.NewGate(cfg, allow, env.audit, env.ents).Middleware())

	st, ct := mcp.NewInMemoryTransports()
	ss, err := server.Connect(ctx, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ss.Close() })
	if env.cs, err = mcp.NewClient(&mcp.Implementation{Name: "kt-audit", Version: "1"}, nil).Connect(ctx, ct, nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { env.cs.Close() })
	return env
}

func (e *auditEnv) call(tool string, args map[string]any) *mcp.CallToolResult {
	res, err := e.cs.CallTool(context.Background(), &mcp.CallToolParams{Name: tool, Arguments: args})
	if err != nil {
		return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: err.Error()}}}
	}
	return res
}

func (e *auditEnv) lines(t *testing.T) []map[string]any {
	t.Helper()
	f, err := os.Open(e.path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out []map[string]any
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		var m map[string]any
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
			t.Fatalf("audit line is not JSON: %q", sc.Text())
		}
		out = append(out, m)
	}
	return out
}

func tagArgs(id string, extra map[string]any) map[string]any {
	a := map[string]any{"accountId": "1", "containerId": "100", "workspaceId": "5", "tagId": id}
	for k, v := range extra {
		a[k] = v
	}
	return a
}

func TestAuditWriteProducesStartAndEndLine(t *testing.T) {
	env := auditSession(t)
	env.call("get_tag", tagArgs("9", nil)) // read: not logged, fills the cache
	if res := env.call("update_tag", tagArgs("9", map[string]any{"name": "GA4 neu"})); res.IsError {
		t.Fatalf("update_tag failed: %+v", res.Content)
	}

	lines := env.lines(t)
	if len(lines) != 2 {
		t.Fatalf("want start+end line for the write only, got %d: %v", len(lines), lines)
	}
	start, end := lines[0], lines[1]
	if start["event"] != "start" || end["event"] != "end" || start["call_id"] != end["call_id"] {
		t.Fatalf("bad start/end pair: %v / %v", start, end)
	}
	for k, want := range map[string]string{
		"tool": "update_tag", "category": "write", "accountId": "1", "containerId": "100",
		"publicId": "GTM-AAAA1", "workspaceId": "5", "identity": "anonymous",
	} {
		if start[k] != want {
			t.Errorf("start.%s=%v want %s", k, start[k], want)
		}
	}
	ent := start["entity"].(map[string]any)
	if ent["type"] != "tag" || ent["id"] != "9" || ent["path"] != "accounts/1/containers/100/workspaces/5/tags/9" || ent["name"] != "GA4 neu" {
		t.Errorf("entity=%v", ent)
	}
	if start["fingerprint_before"] != "fp-read" {
		t.Errorf("fingerprint_before=%v, want the cached fingerprint from the read", start["fingerprint_before"])
	}
	if end["result"] != "ok" || end["fingerprint_after"] != "fp-after" {
		t.Errorf("end=%v", end)
	}
	if len(env.fetched) != 0 {
		t.Errorf("cache hit must not cost a GTM request, fetched %v", env.fetched)
	}
	if ts, err := time.Parse(time.RFC3339Nano, start["ts"].(string)); err != nil || ts.IsZero() {
		t.Errorf("bad ts %v", start["ts"])
	}
}

func TestAuditFingerprintBeforeFetchesOnlyOnCacheMiss(t *testing.T) {
	env := auditSession(t)
	env.call("update_tag", tagArgs("7", nil)) // miss: 1 GET
	env.call("update_tag", tagArgs("7", nil)) // hit (filled by the previous result)
	env.call("delete_tag", tagArgs("8", map[string]any{"confirm": true}))
	want := []string{
		"accounts/1/containers/100/workspaces/5/tags/7",
		"accounts/1/containers/100/workspaces/5/tags/8",
	}
	if strings.Join(env.fetched, ",") != strings.Join(want, ",") {
		t.Fatalf("fetched %v, want %v", env.fetched, want)
	}
	lines := env.lines(t)
	if lines[0]["fingerprint_before"] != "fp-fetched" || lines[2]["fingerprint_before"] != "fp-after" {
		t.Errorf("fingerprints: %v / %v", lines[0]["fingerprint_before"], lines[2]["fingerprint_before"])
	}
	// A deleted entity leaves the cache.
	env.call("delete_tag", tagArgs("7", map[string]any{"confirm": true}))
	env.call("update_tag", tagArgs("7", nil))
	if got := len(env.fetched); got != 3 {
		t.Errorf("entity 7 must be fetched again after its delete, fetches=%d", got)
	}
}

func TestAuditLogsErrorsAndDenials(t *testing.T) {
	env := auditSession(t)
	env.call("update_tag", tagArgs("9", map[string]any{"name": "boom"}))
	env.call("update_tag", map[string]any{"accountId": "1", "containerId": "101", "workspaceId": "5", "tagId": "9"}) // foreign container

	lines := env.lines(t)
	if len(lines) != 3 {
		t.Fatalf("got %d lines: %v", len(lines), lines)
	}
	if lines[1]["event"] != "end" || lines[1]["result"] != "error" || lines[1]["error"] == "" {
		t.Errorf("failed call not logged as error: %v", lines[1])
	}
	if lines[2]["event"] != "denied" || !strings.Contains(lines[2]["error"].(string), "KT_ALLOWED_CONTAINERS") || lines[2]["containerId"] != "101" {
		t.Errorf("denial not logged: %v", lines[2])
	}
	if env.runs != 1 {
		t.Errorf("denied call must not run, runs=%d", env.runs)
	}
}

func TestAuditRedactsSecretsAndCapsArgs(t *testing.T) {
	env := auditSession(t)
	env.call("update_tag", tagArgs("9", map[string]any{
		"apiKey":        "SECRET-ONE",
		"nested":        map[string]any{"Authorization": "Bearer SECRET-TWO", "ok": "visible"},
		"parameterJson": `{"client_secret":"SECRET-THREE","measurementId":"G-1"}`,
	}))
	raw, _ := os.ReadFile(env.path)
	for _, s := range []string{"SECRET-ONE", "SECRET-TWO", "SECRET-THREE"} {
		if strings.Contains(string(raw), s) {
			t.Errorf("audit log leaks %s: %s", s, raw)
		}
	}
	if !strings.Contains(string(raw), "visible") || !strings.Contains(string(raw), "G-1") {
		t.Errorf("non-secret arguments must stay: %s", raw)
	}

	env2 := auditSession(t)
	env2.call("update_tag", tagArgs("9", map[string]any{"notes": strings.Repeat("x", 40*1024)}))
	l := env2.lines(t)[0]
	if l["args_truncated"] != true {
		t.Fatalf("large args must be marked truncated: %v", l["args_truncated"])
	}
	if s, _ := l["args"].(string); len(s) > 16*1024 {
		t.Errorf("args not capped: %d bytes", len(s))
	}
}

func TestAuditFailureRefusesWrites(t *testing.T) {
	env := auditSession(t)
	env.audit.Close() // simulate a full/unwritable disk
	res := env.call("update_tag", tagArgs("9", nil))
	if !res.IsError || !strings.Contains(res.Content[0].(*mcp.TextContent).Text, "audit log unavailable") {
		t.Fatalf("write must be refused without audit log: %+v", res)
	}
	if env.runs != 0 {
		t.Fatal("the tool ran although the audit line could not be written")
	}
	if res := env.call("get_tag", tagArgs("9", nil)); res.IsError {
		t.Errorf("reads do not need the audit log: %+v", res.Content)
	}
}

func TestOpenAuditPermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "audit.jsonl")
	a, err := kicktemp.OpenAudit(path)
	if err != nil {
		t.Fatal(err)
	}
	a.Close()
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Errorf("new file mode %v, want 0600", fi.Mode().Perm())
	}
	loose := filepath.Join(dir, "loose.jsonl")
	if err := os.WriteFile(loose, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	a, err = kicktemp.OpenAudit(loose)
	if err != nil {
		t.Fatal(err)
	}
	a.Close()
	if fi, _ := os.Stat(loose); fi.Mode().Perm() != 0o600 {
		t.Errorf("existing file mode %v, want 0600", fi.Mode().Perm())
	}
	if _, err := kicktemp.OpenAudit(filepath.Join(dir, "sub", "audit.jsonl", "x")); err == nil {
		t.Error("unwritable path must fail at startup")
	}
	if _, err := kicktemp.OpenAudit(""); err == nil {
		t.Error("empty path must fail")
	}
}

func TestAuditPathDefault(t *testing.T) {
	cfg, err := kicktemp.Load(func(string) string { return "" })
	if err != nil || cfg.AuditLogPath != "/data/audit.jsonl" {
		t.Fatalf("default audit path: %q %v", cfg.AuditLogPath, err)
	}
}
