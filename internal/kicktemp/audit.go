package kicktemp

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"gtm-mcp-server/auth"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// maxAuditArgs caps the size of the logged tool arguments.
const maxAuditArgs = 16 * 1024

// Record is one line of the audit log (JSON Lines).
//
// Every non-read tool call produces a "start" line before the call runs and an
// "end" line with the same call_id afterwards. If the start line cannot be
// written, the call is refused. Refused calls produce a "denied" line.
type Record struct {
	TS                string          `json:"ts"`
	Event             string          `json:"event"` // start | end | denied
	CallID            string          `json:"call_id"`
	Session           string          `json:"session,omitempty"`
	Identity          string          `json:"identity,omitempty"`
	Tool              string          `json:"tool"`
	Category          Category        `json:"category"`
	AccountID         string          `json:"accountId,omitempty"`
	ContainerID       string          `json:"containerId,omitempty"`
	PublicID          string          `json:"publicId,omitempty"`
	WorkspaceID       string          `json:"workspaceId,omitempty"`
	Entity            *entityRef      `json:"entity,omitempty"`
	FingerprintBefore string          `json:"fingerprint_before,omitempty"`
	FingerprintAfter  string          `json:"fingerprint_after,omitempty"`
	Args              json.RawMessage `json:"args,omitempty"`
	ArgsTruncated     bool            `json:"args_truncated,omitempty"`
	Result            string          `json:"result,omitempty"` // ok | error
	Error             string          `json:"error,omitempty"`
}

// Audit appends JSON Lines to a file that only this process can read.
type Audit struct {
	mu  sync.Mutex
	f   *os.File
	now func() time.Time
}

// OpenAudit opens (or creates) the audit log with mode 0600. It fails when the
// file is not writable, so the server never starts without a working audit log.
func OpenAudit(path string) (*Audit, error) {
	if path == "" {
		return nil, fmt.Errorf("audit log path is empty")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("audit log: %w", err)
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("audit log: %w", err)
	}
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return nil, fmt.Errorf("audit log: %w", err)
	}
	return &Audit{f: f, now: time.Now}, nil
}

// Close closes the log file.
func (a *Audit) Close() error { return a.f.Close() }

func (a *Audit) write(rec *Record, sync bool) error {
	rec.TS = a.now().UTC().Format(time.RFC3339Nano)
	b, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, err := a.f.Write(append(b, '\n')); err != nil {
		return err
	}
	if sync {
		return a.f.Sync()
	}
	return nil
}

// pending is a started audit entry, completed by End.
type pending struct {
	rec Record
}

func newCallID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// identity says who made the request: the shared service account, or the
// fingerprint of the OAuth access token.
func identity(ctx context.Context) string {
	if auth.GetSATokenSource(ctx) != nil {
		return "service-account"
	}
	if ti := auth.GetTokenInfo(ctx); ti != nil && ti.AccessToken != "" {
		sum := sha256.Sum256([]byte(ti.AccessToken))
		return "token:" + hex.EncodeToString(sum[:4])
	}
	return "anonymous"
}

func (a *Audit) base(ctx context.Context, req mcp.Request, call *toolCall, allow *Allowlist) Record {
	args, _ := call.Map()
	rec := Record{
		CallID:      newCallID(),
		Identity:    identity(ctx),
		Tool:        call.Name,
		Category:    call.Info.Category,
		AccountID:   str(args, "accountId"),
		ContainerID: str(args, "containerId"),
		WorkspaceID: str(args, "workspaceId"),
	}
	if s := req.GetSession(); s != nil {
		rec.Session = s.ID()
	}
	if allow != nil {
		rec.PublicID = allow.publicIDFor(rec.AccountID, rec.ContainerID)
	}
	rec.Args, rec.ArgsTruncated = redactedArgs(args)
	return rec
}

// Denied logs a refused call. It never blocks the refusal.
func (a *Audit) Denied(ctx context.Context, req mcp.Request, call *toolCall, allow *Allowlist, reason error) {
	if a == nil {
		return
	}
	rec := a.base(ctx, req, call, allow)
	rec.Event, rec.Result, rec.Error = "denied", "error", reason.Error()
	if err := a.write(&rec, false); err != nil {
		slog.Error("audit log write failed", "error", err)
	}
}

// Begin writes the start line of a non-read call. It looks up the fingerprint
// before the change (from the cache; one GET on a miss).
func (a *Audit) Begin(ctx context.Context, req mcp.Request, call *toolCall, allow *Allowlist, ents *Entities) (*pending, error) {
	rec := a.base(ctx, req, call, allow)
	args, _ := call.Map()
	ref := targetOf(call.Name, args)
	rec.Entity = &ref
	if ref.Path != "" && ents != nil {
		if ent, err := ents.Get(ctx, ref.Path); err == nil {
			rec.FingerprintBefore = ent.Fingerprint
		}
	}
	rec.Event = "start"
	if err := a.write(&rec, true); err != nil {
		return nil, err
	}
	return &pending{rec: rec}, nil
}

// End writes the result line of a call started with Begin.
func (a *Audit) End(p *pending, res mcp.Result, callErr error) {
	rec := p.rec
	rec.Event = "end"
	rec.Args, rec.ArgsTruncated, rec.FingerprintBefore = nil, false, ""
	switch {
	case callErr != nil:
		rec.Result, rec.Error = "error", callErr.Error()
	default:
		rec.Result = "ok"
		if ctr, ok := res.(*mcp.CallToolResult); ok && ctr.IsError {
			rec.Result = "error"
			if len(ctr.Content) > 0 {
				if tc, ok := ctr.Content[0].(*mcp.TextContent); ok {
					rec.Error = truncate(tc.Text, 1024)
				}
			}
		} else {
			path := ""
			if rec.Entity != nil {
				path = rec.Entity.Path
			}
			rec.FingerprintAfter = firstFingerprint(res, path)
		}
	}
	if err := a.write(&rec, false); err != nil {
		// The action already happened; all we can do is make noise.
		slog.Error("audit log write failed after call", "call_id", rec.CallID, "tool", rec.Tool, "error", err)
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// sensitiveKey reports keys whose values must not reach the audit log.
func sensitiveKey(k string) bool {
	k = strings.ToLower(k)
	for _, s := range []string{"token", "secret", "key", "password", "authorization"} {
		if strings.Contains(k, s) {
			return true
		}
	}
	return false
}

// redact replaces sensitive values recursively. String values that contain
// JSON (the *Json arguments of several tools) are parsed and redacted too.
func redact(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, e := range t {
			if sensitiveKey(k) {
				out[k] = "[redacted]"
			} else {
				out[k] = redact(e)
			}
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, e := range t {
			out[i] = redact(e)
		}
		return out
	case string:
		if s := strings.TrimSpace(t); len(s) > 1 && (s[0] == '{' || s[0] == '[') {
			var inner any
			if json.Unmarshal([]byte(s), &inner) == nil {
				if b, err := json.Marshal(redact(inner)); err == nil {
					return string(b)
				}
			}
		}
	}
	return v
}

// redactedArgs returns the tool arguments as JSON with secrets removed, capped
// at maxAuditArgs bytes. When capped it returns a JSON string prefix.
func redactedArgs(args map[string]any) (json.RawMessage, bool) {
	if len(args) == 0 {
		return nil, false
	}
	b, err := json.Marshal(redact(args))
	if err != nil {
		return json.RawMessage(`"[unserializable]"`), false
	}
	if len(b) <= maxAuditArgs {
		return b, false
	}
	cut, _ := json.Marshal(truncate(string(b), maxAuditArgs))
	return cut, true
}

func (a *Allowlist) publicIDFor(acct, cont string) string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.byKey[acct+"/"+cont]
}
