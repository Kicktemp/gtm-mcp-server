package kicktemp_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"gtm-mcp-server/gtm"
	"gtm-mcp-server/internal/kicktemp"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// fakeLister mimics the GTM directory: account 1 has GTM-AAAA (100) and GTM-BBBB (101),
// account 2 has GTM-CCCC (200).
type fakeLister struct{ calls int }

func (f *fakeLister) ListAccounts(context.Context) ([]gtm.Account, error) {
	f.calls++
	return []gtm.Account{{AccountID: "1"}, {AccountID: "2"}}, nil
}

func (f *fakeLister) ListContainers(_ context.Context, acct string) ([]gtm.Container, error) {
	f.calls++
	if acct == "1" {
		return []gtm.Container{
			{ContainerID: "100", PublicID: "GTM-AAAA1"},
			{ContainerID: "101", PublicID: "GTM-BBBB1"},
		}, nil
	}
	return []gtm.Container{{ContainerID: "200", PublicID: "GTM-CCCC1"}}, nil
}

type fakeListOut struct {
	Containers []gtm.Container `json:"containers"`
}
type fakeLookupOut struct {
	Container gtm.Container `json:"container"`
}

// allowSession runs the real tools plus fake list/lookup tools behind the
// gate, with only GTM-AAAA1 allowed and every tool category enabled.
func allowSession(t *testing.T, allowed ...string) *mcp.ClientSession {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	cfg := &kicktemp.Config{AllowPublish: true, AllowDelete: true, AllowAdmin: true, AllowCustomCode: true, AllowedContainers: allowed}
	allow := kicktemp.NewAllowlist(cfg)
	if err := allow.InitWithLister(ctx, &fakeLister{}); err != nil {
		t.Fatal(err)
	}

	server := mcp.NewServer(&mcp.Implementation{Name: "kt-allow", Version: "1"}, nil)
	groups, _ := gtm.ParseToolGroups([]string{"all"})
	gtm.RegisterToolsForGroups(server, groups)
	server.RemoveTools("list_containers", "lookup_container")
	mcp.AddTool(server, &mcp.Tool{Name: "list_containers", Description: "fake"},
		func(context.Context, *mcp.CallToolRequest, struct {
			AccountID string `json:"accountId"`
		}) (*mcp.CallToolResult, fakeListOut, error) {
			l := &fakeLister{}
			all, _ := l.ListContainers(ctx, "1")
			return nil, fakeListOut{Containers: all}, nil
		})
	mcp.AddTool(server, &mcp.Tool{Name: "lookup_container", Description: "fake"},
		func(_ context.Context, _ *mcp.CallToolRequest, in struct {
			TagID string `json:"tagId"`
		}) (*mcp.CallToolResult, fakeLookupOut, error) {
			pub := map[string]string{"GTM-AAAA1": "100", "GTM-BBBB1": "101"}[in.TagID]
			return nil, fakeLookupOut{Container: gtm.Container{ContainerID: pub, PublicID: in.TagID}}, nil
		})
	server.AddReceivingMiddleware(kicktemp.NewGate(cfg, allow, nil, nil).Middleware())

	st, ct := mcp.NewInMemoryTransports()
	ss, err := server.Connect(ctx, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ss.Close() })
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "kt-allow", Version: "1"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cs.Close() })
	return cs
}

// call returns the refusal text and whether the Kicktemp layer refused it.
func call(t *testing.T, cs *mcp.ClientSession, tool string, args map[string]any) (string, bool) {
	t.Helper()
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: tool, Arguments: args})
	if err != nil {
		return err.Error(), false
	}
	text := ""
	if len(res.Content) > 0 {
		if tc, ok := res.Content[0].(*mcp.TextContent); ok {
			text = tc.Text
		}
	}
	refused := res.IsError && strings.Contains(text, "Kicktemp policy")
	return text, refused
}

func TestAllowlistContainerTools(t *testing.T) {
	cs := allowSession(t, "GTM-AAAA1")
	ws := func(a, c string) map[string]any {
		return map[string]any{"accountId": a, "containerId": c, "workspaceId": "5", "tagId": "1"}
	}
	cases := []struct {
		name string
		tool string
		args map[string]any
		deny bool
	}{
		{"allowed container", "get_tag", ws("1", "100"), false},
		{"other container, same account", "get_tag", ws("1", "101"), true},
		{"right container id, foreign account", "get_tag", ws("2", "100"), true},
		{"foreign container", "list_tags", ws("2", "200"), true},
		{"missing containerId", "get_tag", map[string]any{"accountId": "1", "workspaceId": "5"}, true},
		{"path traversal in workspaceId", "get_tag", map[string]any{"accountId": "1", "containerId": "100", "workspaceId": "5/../../containers/101/workspaces/1", "tagId": "1"}, true},
		{"traversal in containerId", "get_tag", map[string]any{"accountId": "1", "containerId": "100/../101", "workspaceId": "5", "tagId": "1"}, true},
		{"non-string id", "get_tag", map[string]any{"accountId": "1", "containerId": 100, "workspaceId": "5", "tagId": "1"}, true},
		{"version of foreign container", "get_version", map[string]any{"accountId": "1", "containerId": "101", "versionId": "3"}, true},
		{"delete on foreign container", "delete_tag", map[string]any{"accountId": "2", "containerId": "200", "workspaceId": "5", "tagId": "1", "confirm": true}, true},
		{"combine: source outside allowlist", "combine_containers", map[string]any{"accountId": "1", "containerId": "100", "sourceContainerId": "101", "confirm": true}, true},
		{"combine: source inside allowlist", "combine_containers", map[string]any{"accountId": "1", "containerId": "100", "sourceContainerId": "100", "confirm": true}, false},
		{"zone child outside allowlist", "create_zone", map[string]any{"accountId": "1", "containerId": "100", "workspaceId": "5", "name": "z", "childContainers": []any{map[string]any{"publicId": "GTM-BBBB1"}}}, true},
		{"zone child inside allowlist", "create_zone", map[string]any{"accountId": "1", "containerId": "100", "workspaceId": "5", "name": "z", "childContainers": []any{map[string]any{"publicId": "gtm-aaaa1"}}}, false},
		{"conflict entity of foreign container", "resolve_workspace_conflict", map[string]any{"accountId": "1", "containerId": "100", "workspaceId": "5", "fingerprint": "1", "entityJson": `{"tag":{"path":"accounts/1/containers/101/workspaces/5/tags/9"}}`}, true},
		{"conflict entity nested containerId", "resolve_workspace_conflict", map[string]any{"accountId": "1", "containerId": "100", "workspaceId": "5", "fingerprint": "1", "entityJson": `{"tag":{"containerId":"101"}}`}, true},
		{"conflict entity own container", "resolve_workspace_conflict", map[string]any{"accountId": "1", "containerId": "100", "workspaceId": "5", "fingerprint": "1", "entityJson": `{"tag":{"path":"accounts/1/containers/100/workspaces/5/tags/9"}}`}, false},
		{"bulk update entity of foreign account", "bulk_update_workspace", map[string]any{"accountId": "1", "containerId": "100", "workspaceId": "5", "changesJson": `{"changes":[{"tag":{"accountId":"2"}}]}`}, true},
		{"create_container", "create_container", map[string]any{"accountId": "1", "name": "x"}, true},
		{"update_account of allowed account", "update_account", map[string]any{"accountId": "1", "name": "x"}, false},
		{"update_account of other account", "update_account", map[string]any{"accountId": "2", "name": "x"}, true},
		{"list_containers of other account", "list_containers", map[string]any{"accountId": "2"}, true},
		{"account-less tool", "list_accounts", map[string]any{}, false},
	}
	for _, tc := range cases {
		text, refused := call(t, cs, tc.tool, tc.args)
		if refused != tc.deny {
			t.Errorf("%s: refused=%v want %v (%s)", tc.name, refused, tc.deny, text)
		}
	}
}

func TestAllowlistEmptyAllowsNothing(t *testing.T) {
	cs := allowSession(t) // no containers configured
	for _, tool := range []string{"get_tag", "list_tags", "get_workspace"} {
		_, refused := call(t, cs, tool, map[string]any{"accountId": "1", "containerId": "100", "workspaceId": "5", "tagId": "1"})
		if !refused {
			t.Errorf("%s must be refused with an empty allowlist", tool)
		}
	}
}

func TestAllowlistFiltersListAndLookup(t *testing.T) {
	cs := allowSession(t, "GTM-AAAA1")

	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "list_containers", Arguments: map[string]any{"accountId": "1"}})
	if err != nil || res.IsError {
		t.Fatalf("list_containers: %v %+v", err, res)
	}
	var out fakeListOut
	if err := json.Unmarshal([]byte(res.Content[0].(*mcp.TextContent).Text), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Containers) != 1 || out.Containers[0].PublicID != "GTM-AAAA1" {
		t.Fatalf("text content not filtered: %+v", out.Containers)
	}
	sc, _ := json.Marshal(res.StructuredContent)
	if strings.Contains(string(sc), "GTM-BBBB1") {
		t.Fatalf("structured content leaks a foreign container: %s", sc)
	}

	res, _ = cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "lookup_container", Arguments: map[string]any{"tagId": "GTM-AAAA1"}})
	if res.IsError {
		t.Fatalf("lookup of allowed container refused: %+v", res.Content)
	}
	res, _ = cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "lookup_container", Arguments: map[string]any{"tagId": "GTM-BBBB1"}})
	if !res.IsError || !strings.Contains(res.Content[0].(*mcp.TextContent).Text, "KT_ALLOWED_CONTAINERS") {
		t.Fatalf("lookup of foreign container must be refused: %+v", res)
	}
}

func TestAllowlistResources(t *testing.T) {
	cs := allowSession(t, "GTM-AAAA1")
	read := func(uri string) error {
		_, err := cs.ReadResource(context.Background(), &mcp.ReadResourceParams{URI: uri})
		return err
	}
	for _, uri := range []string{
		"gtm://accounts/1/containers/101/workspaces/5/tags",
		"gtm://accounts/2/containers/200/workspaces/1/variables",
		"gtm://accounts/1/containers", // would list foreign containers
		"gtm://accounts/1/containers/100/workspaces/5/../../../101/workspaces/1/tags",
	} {
		if err := read(uri); err == nil || !(strings.Contains(err.Error(), "KT_ALLOWED_CONTAINERS") || strings.Contains(err.Error(), "invalid resource URI")) {
			t.Errorf("%s must be refused by the allowlist, got %v", uri, err)
		}
	}
	// Allowed container: passes the policy (fails later because there are no credentials).
	if err := read("gtm://accounts/1/containers/100/workspaces/5/tags"); err != nil && strings.Contains(err.Error(), "KT_ALLOWED_CONTAINERS") {
		t.Errorf("allowed container refused: %v", err)
	}
	if err := read("gtm://best-practices"); err != nil {
		t.Errorf("static resource must stay readable: %v", err)
	}
}

func TestAllowlistInitFailsForUnknownPublicID(t *testing.T) {
	cfg := &kicktemp.Config{AllowedContainers: []string{"GTM-AAAA1", "GTM-ZZZZ9"}}
	err := kicktemp.NewAllowlist(cfg).InitWithLister(context.Background(), &fakeLister{})
	if err == nil || !strings.Contains(err.Error(), "GTM-ZZZZ9") {
		t.Fatalf("expected startup error naming GTM-ZZZZ9, got %v", err)
	}
}

func TestAllowlistNoExtraRequestsPerCall(t *testing.T) {
	ctx := context.Background()
	l := &fakeLister{}
	cfg := &kicktemp.Config{AllowedContainers: []string{"GTM-AAAA1"}}
	if err := kicktemp.NewAllowlist(cfg).InitWithLister(ctx, l); err != nil {
		t.Fatal(err)
	}
	if l.calls != 3 { // accounts.list + containers.list for each of the 2 accounts
		t.Fatalf("startup used %d GTM requests, want 3", l.calls)
	}
}

func TestIDHygieneAppliesWithWildcard(t *testing.T) {
	cs := newSession(t, &kicktemp.Config{AllowAllContainers: true}, true)
	_, refused := call(t, cs, "get_tag", map[string]any{"accountId": "1", "containerId": "100", "workspaceId": "5/../7", "tagId": "1"})
	if !refused {
		t.Fatal("malformed IDs must be refused even with KT_ALLOWED_CONTAINERS=*")
	}
}

func TestParseContainers(t *testing.T) {
	env := func(v string) func(string) string {
		return func(k string) string {
			if k == "KT_ALLOWED_CONTAINERS" {
				return v
			}
			return ""
		}
	}
	if c, err := kicktemp.Load(env("")); err != nil || c.AllowAllContainers || len(c.AllowedContainers) != 0 {
		t.Fatalf("empty must allow nothing: %+v %v", c, err)
	}
	if c, err := kicktemp.Load(env("*")); err != nil || !c.AllowAllContainers {
		t.Fatalf("* must allow all: %+v %v", c, err)
	}
	c, err := kicktemp.Load(env(" gtm-kvgb2n5l , GTM-ABCD12,GTM-ABCD12 "))
	if err != nil || strings.Join(c.AllowedContainers, ",") != "GTM-KVGB2N5L,GTM-ABCD12" {
		t.Fatalf("list not normalised: %+v %v", c, err)
	}
	for _, bad := range []string{"*,GTM-ABCD12", "12345", "GTM-", "GTM-AB/../C"} {
		if _, err := kicktemp.Load(env(bad)); err == nil {
			t.Errorf("%q must be rejected", bad)
		}
	}
}

func TestAllowlistEmptyNeedsNoGTMRequests(t *testing.T) {
	// With nothing allowed, Init must succeed without credentials and without
	// any GTM request (a nil token source would otherwise be lazy mode).
	a := kicktemp.NewAllowlist(&kicktemp.Config{})
	if err := a.Init(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
}
