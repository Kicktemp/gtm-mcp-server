package kicktemp

import (
	"context"
	"fmt"

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
	Args []byte
}

// check is one policy rule. A non-nil error denies the call.
type check func(ctx context.Context, call *toolCall) error

// Gate is the receiving middleware that enforces the Kicktemp policy.
type Gate struct {
	cfg    *Config
	checks []check
}

// NewGate builds the policy middleware for cfg.
func NewGate(cfg *Config) *Gate {
	g := &Gate{cfg: cfg}
	g.checks = append(g.checks, g.categoryCheck)
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
						return denied(err), nil
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
	return &mcp.CallToolResult{
		IsError: true,
		Content: []mcp.Content{&mcp.TextContent{Text: err.Error()}},
	}
}
