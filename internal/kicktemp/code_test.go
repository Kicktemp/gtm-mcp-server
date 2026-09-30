package kicktemp_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"gtm-mcp-server/gtm"
	"gtm-mcp-server/internal/kicktemp"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// codeSession runs the real tools with all containers allowed. existing maps a
// GTM path to the type the (fake) GTM API reports for it.
func codeSession(t *testing.T, cfg *kicktemp.Config, existing map[string]string) (*mcp.ClientSession, *[]string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	var fetched []string
	ents := kicktemp.NewEntitiesWithFetch(func(_ context.Context, path string) (kicktemp.Entity, error) {
		fetched = append(fetched, path)
		typ, ok := existing[path]
		if !ok {
			return kicktemp.Entity{}, fmt.Errorf("404 %s", path)
		}
		return kicktemp.Entity{Fingerprint: "fp", Type: typ}, nil
	})
	cfg.AllowAllContainers = true
	server := mcp.NewServer(&mcp.Implementation{Name: "kt-code", Version: "1"}, nil)
	groups, _ := gtm.ParseToolGroups([]string{"all"})
	gtm.RegisterToolsForGroups(server, groups)
	kicktemp.FilterTools(server, cfg)
	server.AddReceivingMiddleware(kicktemp.NewGate(cfg, kicktemp.NewAllowlist(cfg), nil, ents).Middleware())
	st, ct := mcp.NewInMemoryTransports()
	ss, err := server.Connect(ctx, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ss.Close() })
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "c", Version: "1"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cs.Close() })
	return cs, &fetched
}

func ws(extra map[string]any) map[string]any {
	a := map[string]any{"accountId": "1", "containerId": "100", "workspaceId": "5"}
	for k, v := range extra {
		a[k] = v
	}
	return a
}

const tagPath = "accounts/1/containers/100/workspaces/5/tags/9"
const varPath = "accounts/1/containers/100/workspaces/5/variables/4"

func TestCodeGateBlocksCustomCodeByArguments(t *testing.T) {
	cs, _ := codeSession(t, &kicktemp.Config{AllowDelete: true}, map[string]string{
		tagPath: "html", varPath: "jsm",
		"accounts/1/containers/100/workspaces/5/tags/10":      "gaawe",
		"accounts/1/containers/100/workspaces/5/tags/11":      "cvt_ABC",
		"accounts/1/containers/100/workspaces/5/variables/12": "c",
	})
	cases := []struct {
		name string
		tool string
		args map[string]any
		deny bool
	}{
		{"html tag", "create_tag", ws(map[string]any{"name": "x", "type": "html", "firingTriggerIds": []any{"1"}}), true},
		{"HTML upper case", "create_tag", ws(map[string]any{"name": "x", "type": "HTML", "firingTriggerIds": []any{"1"}}), true},
		{"custom template tag", "create_tag", ws(map[string]any{"name": "x", "type": "cvt_K1234", "firingTriggerIds": []any{"1"}}), true},
		{"GA4 tag", "create_tag", ws(map[string]any{"name": "x", "type": "gaawe", "firingTriggerIds": []any{"1"}}), false},
		{"jsm variable", "create_variable", ws(map[string]any{"name": "x", "type": "jsm"}), true},
		{"constant variable", "create_variable", ws(map[string]any{"name": "x", "type": "c"}), false},

		{"update: type html", "update_tag", ws(map[string]any{"tagId": "10", "type": "html"}), true},
		{"update: existing html tag, no type given", "update_tag", ws(map[string]any{"tagId": "9", "name": "renamed"}), true},
		{"update: existing cvt tag", "update_tag", ws(map[string]any{"tagId": "11", "name": "renamed"}), true},
		{"update: existing GA4 tag", "update_tag", ws(map[string]any{"tagId": "10", "name": "renamed"}), false},
		{"update: existing tag unknown", "update_tag", ws(map[string]any{"tagId": "77", "name": "renamed"}), true},
		{"update variable: existing jsm", "update_variable", ws(map[string]any{"variableId": "4", "name": "n"}), true},
		{"update variable: new type jsm", "update_variable", ws(map[string]any{"variableId": "12", "type": "jsm"}), true},
		{"update variable: existing constant", "update_variable", ws(map[string]any{"variableId": "12", "name": "n"}), false},

		{"bulk: html tag", "bulk_update_workspace", ws(map[string]any{"changesJson": `{"changes":[{"changeStatus":"added","tag":{"name":"x","type":"html"}}]}`}), true},
		{"bulk: jsm variable", "bulk_update_workspace", ws(map[string]any{"changesJson": `{"changes":[{"variable":{"name":"x","type":"jsm"}}]}`}), true},
		{"bulk: custom template", "bulk_update_workspace", ws(map[string]any{"changesJson": `{"changes":[{"customTemplate":{"name":"x","templateData":"..."}}]}`}), true},
		{"bulk: tag without type", "bulk_update_workspace", ws(map[string]any{"changesJson": `{"changes":[{"tag":{"tagId":"9"}}]}`}), true},
		{"bulk: second change is html", "bulk_update_workspace", ws(map[string]any{"changesJson": `{"changes":[{"tag":{"type":"gaawe"}},{"tag":{"type":"html"}}]}`}), true},
		{"bulk: GA4 tag", "bulk_update_workspace", ws(map[string]any{"changesJson": `{"changes":[{"tag":{"type":"gaawe"}}]}`}), false},
		{"bulk: deletion of html tag", "bulk_update_workspace", ws(map[string]any{"changesJson": `{"changes":[{"changeStatus":"deleted","tag":{"type":"html"}}]}`}), false},
		{"conflict: html tag", "resolve_workspace_conflict", ws(map[string]any{"fingerprint": "1", "entityJson": `{"tag":{"type":"html"}}`}), true},
		{"conflict: GA4 tag", "resolve_workspace_conflict", ws(map[string]any{"fingerprint": "1", "entityJson": `{"tag":{"type":"gaawe"}}`}), false},
	}
	for _, tc := range cases {
		text, refused := call(t, cs, tc.tool, tc.args)
		if strings.Contains(text, "disabled by Kicktemp policy: set KT_ALLOW_DELETE") {
			t.Fatalf("test setup: %s hidden by the delete gate", tc.name)
		}
		codeRefusal := refused && strings.Contains(text, "custom code")
		if codeRefusal != tc.deny {
			t.Errorf("%s: code-gate refusal=%v, want %v (%s)", tc.name, codeRefusal, tc.deny, text)
		}
	}
}

func TestCodeGateOpenAllowsCustomCode(t *testing.T) {
	cs, fetched := codeSession(t, &kicktemp.Config{AllowCustomCode: true, AllowDelete: true}, map[string]string{tagPath: "html"})
	for _, tc := range []struct {
		tool string
		args map[string]any
	}{
		{"create_tag", ws(map[string]any{"name": "x", "type": "html", "firingTriggerIds": []any{"1"}})},
		{"update_tag", ws(map[string]any{"tagId": "9", "name": "n"})},
		{"create_variable", ws(map[string]any{"name": "x", "type": "jsm"})},
		{"bulk_update_workspace", ws(map[string]any{"changesJson": `{"changes":[{"tag":{"type":"html"}}]}`})},
	} {
		if text, refused := call(t, cs, tc.tool, tc.args); refused {
			t.Errorf("%s must pass with KT_ALLOW_CUSTOM_CODE=true: %s", tc.tool, text)
		}
	}
	if len(*fetched) != 0 {
		t.Errorf("with the gate open no GTM request is needed, fetched %v", *fetched)
	}
}

func TestTemplateToolsAreCodeCategory(t *testing.T) {
	templateTools := []string{"create_template", "update_template", "import_gallery_template"}
	cs, _ := codeSession(t, &kicktemp.Config{}, nil)
	names := listNames(t, cs)
	for _, n := range templateTools {
		if names[n] {
			t.Errorf("%s must not be listed by default", n)
		}
		text, refused := call(t, cs, n, ws(map[string]any{"templateId": "1"}))
		if !refused || !strings.Contains(text, "KT_ALLOW_CUSTOM_CODE") {
			t.Errorf("%s call must point to KT_ALLOW_CUSTOM_CODE: %s", n, text)
		}
	}
	if names["delete_template"] {
		t.Error("delete_template needs KT_ALLOW_DELETE, not KT_ALLOW_CUSTOM_CODE")
	}
	if !names["get_template"] || !names["list_templates"] {
		t.Error("reading templates stays possible")
	}

	open, _ := codeSession(t, &kicktemp.Config{AllowCustomCode: true}, nil)
	names = listNames(t, open)
	for _, n := range templateTools {
		if !names[n] {
			t.Errorf("%s must be listed with KT_ALLOW_CUSTOM_CODE=true", n)
		}
	}
}

func TestAllowCustomCodeConfig(t *testing.T) {
	get := func(v string) func(string) string {
		return func(k string) string {
			if k == "KT_ALLOW_CUSTOM_CODE" {
				return v
			}
			return ""
		}
	}
	if c, err := kicktemp.Load(get("")); err != nil || c.AllowCustomCode {
		t.Fatalf("default must be false: %+v %v", c, err)
	}
	if c, err := kicktemp.Load(get("true")); err != nil || !c.AllowCustomCode {
		t.Fatalf("true not parsed: %+v %v", c, err)
	}
}
