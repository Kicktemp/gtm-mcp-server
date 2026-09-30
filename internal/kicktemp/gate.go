package kicktemp

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Allowed reports whether a tool category is enabled by the configuration.
func (c *Config) Allowed(cat Category) bool {
	switch cat {
	case CategoryRead, CategoryWrite:
		return true
	case CategoryPublish:
		return c.AllowPublish
	case CategoryDelete:
		return c.AllowDelete
	case CategoryAdmin:
		return c.AllowAdmin
	}
	return false
}

// flagFor names the environment variable that would enable a category.
func flagFor(cat Category) string {
	switch cat {
	case CategoryPublish:
		return "KT_ALLOW_PUBLISH"
	case CategoryDelete:
		return "KT_ALLOW_DELETE"
	case CategoryAdmin:
		return "KT_ALLOW_ADMIN"
	}
	return ""
}

// FilterTools removes every tool whose category is disabled from the server,
// so it is neither listed nor callable. It runs after tool registration.
func FilterTools(server *mcp.Server, cfg *Config) {
	var remove []string
	for _, name := range Names() {
		info, _ := Lookup(name)
		if !cfg.Allowed(info.Category) {
			remove = append(remove, name)
		}
	}
	server.RemoveTools(remove...)
}

// toolCall is a tools/call request as seen by the policy checks.
type toolCall struct {
	Name string
	Info ToolInfo
	Args json.RawMessage

	args   map[string]any
	parsed bool
	err    error
}

// Map returns the decoded arguments. Undecodable arguments are an error, so a
// check never silently skips a call it cannot read.
func (c *toolCall) Map() (map[string]any, error) {
	if !c.parsed {
		c.parsed = true
		c.args = map[string]any{}
		if len(c.Args) > 0 {
			if err := json.Unmarshal(c.Args, &c.args); err != nil {
				c.err = fmt.Errorf("invalid tool arguments: %w", err)
			}
		}
	}
	return c.args, c.err
}

// check is one policy rule. A non-nil error denies the call.
type check func(ctx context.Context, call *toolCall) error

// after post-processes the result of an allowed call.
type after func(ctx context.Context, call *toolCall, res mcp.Result, err error) (mcp.Result, error)

// Gate is the receiving middleware that enforces the Kicktemp policy.
type Gate struct {
	cfg    *Config
	checks []check
	afters []after
	allow  *Allowlist
	audit  *Audit    // nil disables auditing (tests)
	ents   *Entities // nil disables the entity cache (tests)
	emails *EmailPolicy
}

// NewGate builds the policy middleware for cfg, the container allowlist, the
// audit log and the entity cache.
func NewGate(cfg *Config, allow *Allowlist, audit *Audit, ents *Entities) *Gate {
	g := &Gate{cfg: cfg, allow: allow, audit: audit, ents: ents}
	g.checks = append(g.checks, g.categoryCheck, allow.check)
	g.afters = append(g.afters, allow.after)
	return g
}

// categoryCheck denies tools of a disabled category. This backs up
// FilterTools: even if a tool were registered, calling it is refused.
func (g *Gate) categoryCheck(_ context.Context, call *toolCall) error {
	if g.cfg.Allowed(call.Info.Category) {
		return nil
	}
	return fmt.Errorf("tool %q (%s) is disabled by Kicktemp policy: set %s=true to enable it",
		call.Name, call.Info.Category, flagFor(call.Info.Category))
}

// Middleware returns the mcp.Middleware for server.AddReceivingMiddleware.
func (g *Gate) Middleware() mcp.Middleware {
	return func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
			switch method {
			case "tools/call":
				ctr, ok := req.(*mcp.CallToolRequest)
				if !ok {
					return nil, fmt.Errorf("kicktemp: unexpected tools/call request type %T", req)
				}
				info, _ := Lookup(ctr.Params.Name)
				call := &toolCall{Name: ctr.Params.Name, Info: info, Args: ctr.Params.Arguments}
				for _, c := range g.checks {
					if err := c(ctx, call); err != nil {
						g.audit.Denied(ctx, req, call, g.allow, err)
						return denied(err), nil
					}
				}
				var started *pending
				if g.audit != nil && info.Category != CategoryRead {
					var err error
					if started, err = g.audit.Begin(ctx, req, call, g.allow, g.ents); err != nil {
						return denied(fmt.Errorf("audit log unavailable, refusing to change GTM: %w", err)), nil
					}
				}
				res, err := next(ctx, method, req)
				for _, a := range g.afters {
					res, err = a(ctx, call, res, err)
				}
				if started != nil {
					g.audit.End(started, res, err)
				}
				if g.ents != nil && err == nil {
					g.ents.Observe(res)
					if strings.HasPrefix(call.Name, "delete_") {
						if ref := targetOf(call.Name, call.args); ref.Path != "" {
							g.ents.Forget(ref.Path)
						}
					}
				}
				return res, err
			case "resources/read":
				if err := g.emails.checkRequest(ctx); err != nil {
					return nil, err
				}
				if rr, ok := req.(*mcp.ReadResourceRequest); ok {
					if err := g.allow.checkResource(ctx, rr.Params.URI); err != nil {
						return nil, err
					}
				}
			case "tools/list":
				res, err := next(ctx, method, req)
				if err != nil {
					return res, err
				}
				if lr, ok := res.(*mcp.ListToolsResult); ok {
					kept := lr.Tools[:0:0]
					for _, t := range lr.Tools {
						if info, _ := Lookup(t.Name); g.cfg.Allowed(info.Category) {
							kept = append(kept, t)
						}
					}
					lr.Tools = kept
				}
				return res, nil
			}
			return next(ctx, method, req)
		}
	}
}

// denied turns a policy error into a tool error result the model can read.
func denied(err error) *mcp.CallToolResult {
	msg := err.Error()
	if !strings.Contains(msg, "Kicktemp policy") {
		msg = "refused by Kicktemp policy: " + msg
	}
	return &mcp.CallToolResult{
		IsError: true,
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
	}
}
