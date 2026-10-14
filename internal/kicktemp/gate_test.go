package kicktemp_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"gtm-mcp-server/gtm"
	"gtm-mcp-server/internal/kicktemp"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// utilityTools are registered by main.go, not by the gtm package.
var utilityTools = map[string]bool{"ping": true, "auth_status": true}

func newSession(t *testing.T, cfg *kicktemp.Config, filter bool) *mcp.ClientSession {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)

	server := mcp.NewServer(&mcp.Implementation{Name: "kt-test", Version: "1"}, nil)
	groups, err := gtm.ParseToolGroups([]string{"all"})
	if err != nil {
		t.Fatal(err)
	}
	gtm.RegisterToolsForGroups(server, groups)
	if filter {
		kicktemp.FilterTools(server, cfg)
	}
	server.AddReceivingMiddleware(kicktemp.NewGate(cfg, kicktemp.NewAllowlist(cfg), nil, nil).Middleware())

	st, ct := mcp.NewInMemoryTransports()
	ss, err := server.Connect(ctx, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ss.Close() })
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "kt-test", Version: "1"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cs.Close() })
	return cs
}

func listNames(t *testing.T, cs *mcp.ClientSession) map[string]bool {
	t.Helper()
	res, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, tool := range res.Tools {
		names[tool.Name] = true
	}
	return names
}

func TestEveryRegisteredToolIsClassified(t *testing.T) {
	cs := newSession(t, &kicktemp.Config{AllowWrite: true, AllowPublish: true, AllowDelete: true, AllowAdmin: true, AllowCustomCode: true, AllowAllContainers: true}, false)
	registered := listNames(t, cs)
	if len(registered) != 94 {
		t.Fatalf("registered tools = %d, want 94 (update categories.go after upstream changes)", len(registered))
	}
	for name := range registered {
		if _, ok := kicktemp.Lookup(name); !ok {
			t.Errorf("tool %q is not classified in categories.go (treated as admin)", name)
		}
	}
	for _, name := range kicktemp.Names() {
		if !registered[name] && !utilityTools[name] {
			t.Errorf("categories.go lists %q, which no longer exists", name)
		}
	}
}

func TestDefaultPolicyHidesPublishDeleteAdmin(t *testing.T) {
	for _, filter := range []bool{true, false} {
		cs := newSession(t, &kicktemp.Config{AllowWrite: true, AllowAllContainers: true}, filter)
		names := listNames(t, cs)
		for _, want := range []string{"list_tags", "create_tag", "update_tag", "create_version"} {
			if !names[want] {
				t.Errorf("filter=%v: %s missing from tools/list", filter, want)
			}
		}
		for _, banned := range []string{
			"publish_version", "set_latest_version", "delete_tag", "delete_workspace",
			"bulk_update_workspace", "resolve_workspace_conflict", "combine_containers",
			"move_tag_id", "link_destination", "delete_environment", "delete_container",
		} {
			if names[banned] {
				t.Errorf("filter=%v: %s must not be listed by default", filter, banned)
			}
		}
	}
}

func TestWriteToolsNeedGTMWriteEnabled(t *testing.T) {
	writes := []string{"create_tag", "update_tag", "create_workspace", "create_version", "create_trigger", "create_variable"}
	for _, filter := range []bool{true, false} {
		cs := newSession(t, &kicktemp.Config{AllowAllContainers: true}, filter) // AllowWrite=false (default)
		names := listNames(t, cs)
		if !names["list_tags"] || !names["list_accounts"] {
			t.Errorf("filter=%v: read tools must stay available without GTM_WRITE_ENABLED", filter)
		}
		if filter {
			for _, w := range writes {
				if names[w] {
					t.Errorf("filter=true: %s must not be registered without GTM_WRITE_ENABLED", w)
				}
			}
		}
		for _, w := range writes {
			res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: w, Arguments: map[string]any{}})
			if err != nil {
				continue // the filtered server may reject unknown tools at protocol level
			}
			if !res.IsError {
				t.Fatalf("filter=%v %s: write call was not refused", filter, w)
			}
			if text := res.Content[0].(*mcp.TextContent).Text; !strings.Contains(text, "GTM_WRITE_ENABLED") {
				t.Errorf("filter=%v %s: refusal must name GTM_WRITE_ENABLED, got %q", filter, w, text)
			}
		}
	}
}

func TestDeniedCallIsRefused(t *testing.T) {
	cases := map[string]string{
		"publish_version":     "KT_ALLOW_PUBLISH",
		"delete_tag":          "KT_ALLOW_DELETE",
		"combine_containers":  "KT_ALLOW_ADMIN",
		"delete_environment":  "KT_ALLOW_ADMIN",
		"some_future_tool_xy": "KT_ALLOW_ADMIN", // unknown tools are admin
	}
	for _, filter := range []bool{true, false} {
		cs := newSession(t, &kicktemp.Config{AllowWrite: true, AllowAllContainers: true}, filter)
		for tool, flag := range cases {
			res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: tool, Arguments: map[string]any{}})
			if err != nil {
				t.Fatalf("filter=%v %s: %v", filter, tool, err)
			}
			if !res.IsError {
				t.Fatalf("filter=%v %s: call was not refused", filter, tool)
			}
			text := res.Content[0].(*mcp.TextContent).Text
			if !strings.Contains(text, "Kicktemp policy") || !strings.Contains(text, flag) {
				t.Errorf("filter=%v %s: unexpected refusal %q", filter, tool, text)
			}
		}
	}
}

func TestAllowedCategoriesAreListedAndCallable(t *testing.T) {
	cs := newSession(t, &kicktemp.Config{AllowWrite: true, AllowPublish: true, AllowDelete: true, AllowAdmin: true, AllowAllContainers: true}, true)
	names := listNames(t, cs)
	for _, want := range []string{"publish_version", "delete_tag", "combine_containers"} {
		if !names[want] {
			t.Errorf("%s should be listed when its category is enabled", want)
		}
	}
	// The call passes the policy and fails later (no credentials in this test).
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "delete_tag", Arguments: map[string]any{}})
	if err == nil && res.IsError {
		if text := res.Content[0].(*mcp.TextContent).Text; strings.Contains(text, "Kicktemp policy") {
			t.Fatalf("delete_tag refused although KT_ALLOW_DELETE=true: %s", text)
		}
	}
}

func TestLoadConfig(t *testing.T) {
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

	cfg, err := kicktemp.Load(env(nil))
	if err != nil || cfg.AllowWrite || cfg.AllowPublish || cfg.AllowDelete || cfg.AllowAdmin {
		t.Fatalf("defaults must all be false, got %+v err=%v", cfg, err)
	}
	cfg, err = kicktemp.Load(env(map[string]string{"KT_ALLOW_PUBLISH": "true", "KT_ALLOW_DELETE": " 1 "}))
	if err != nil || !cfg.AllowPublish || !cfg.AllowDelete || cfg.AllowAdmin {
		t.Fatalf("unexpected config %+v err=%v", cfg, err)
	}
	if _, err = kicktemp.Load(env(map[string]string{"KT_ALLOW_ADMIN": "yes-please"})); err == nil {
		t.Fatal("invalid boolean must be an error")
	}
}
