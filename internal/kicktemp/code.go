package kicktemp

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// Custom code is anything GTM executes as code on a website. It is blocked
// unless KT_ALLOW_CUSTOM_CODE=true:
//
//   - custom template tools (category "code", not registered by default)
//   - tags of type html (Custom HTML) or cvt_* (custom template tags)
//   - variables of type jsm (Custom JavaScript)
//
// Tags and variables are decided on their arguments, not the tool name, and the
// same rules apply to the free-form JSON of bulk_update_workspace and
// resolve_workspace_conflict.

func isCodeTag(t string) bool {
	t = strings.ToLower(strings.TrimSpace(t))
	return t == "html" || strings.HasPrefix(t, "cvt_")
}

func isCodeVariable(t string) bool {
	return strings.ToLower(strings.TrimSpace(t)) == "jsm"
}

func codeDenied(kind, typ string) error {
	return fmt.Errorf("custom code is disabled by Kicktemp policy: %s type %q requires KT_ALLOW_CUSTOM_CODE=true", kind, typ)
}

// codeCheck is the argument-based rule of the code gate.
func (g *Gate) codeCheck(ctx context.Context, call *toolCall) error {
	if g.cfg.AllowCustomCode {
		return nil
	}
	args, err := call.Map()
	if err != nil {
		return err
	}
	switch call.Name {
	case "create_tag":
		if t := str(args, "type"); isCodeTag(t) {
			return codeDenied("tag", t)
		}
	case "update_tag":
		return g.checkExisting(ctx, call, args, "tag", isCodeTag)
	case "create_variable":
		if t := str(args, "type"); isCodeVariable(t) {
			return codeDenied("variable", t)
		}
	case "update_variable":
		return g.checkExisting(ctx, call, args, "variable", isCodeVariable)
	case "bulk_update_workspace":
		return codeInJSON(str(args, "changesJson"), true)
	case "resolve_workspace_conflict":
		return codeInJSON(str(args, "entityJson"), false)
	}
	return nil
}

// checkExisting covers updates: neither the new type nor the type of the entity
// being changed may be custom code, so an existing Custom HTML tag cannot be
// edited while the gate is closed. The existing type comes from the entity
// cache (one GET on a miss); if it cannot be determined the update is refused.
func (g *Gate) checkExisting(ctx context.Context, call *toolCall, args map[string]any, kind string, isCode func(string) bool) error {
	if t := str(args, "type"); isCode(t) {
		return codeDenied(kind, t)
	}
	ref := targetOf(call.Name, args)
	if ref.Path == "" || g.ents == nil {
		return fmt.Errorf("custom code is disabled by Kicktemp policy: cannot determine the current %s type", kind)
	}
	ent, err := g.ents.Get(ctx, ref.Path)
	if err != nil || ent.Type == "" {
		return fmt.Errorf("custom code is disabled by Kicktemp policy: cannot determine the current %s type (refusing the update)", kind)
	}
	if isCode(ent.Type) {
		return codeDenied(kind, ent.Type)
	}
	return nil
}

// codeInJSON scans GTM Entity JSON (a ProposedChange with a "changes" array when
// bulk is true, otherwise one Entity) for custom code. Entities that are being
// deleted are ignored; tags and variables without a type cannot be judged and
// are refused.
func codeInJSON(raw string, bulk bool) error {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		return fmt.Errorf("invalid JSON argument: %w", err)
	}
	if !bulk {
		return codeInEntity(doc)
	}
	changes, _ := doc["changes"].([]any)
	for _, c := range changes {
		e, ok := c.(map[string]any)
		if !ok {
			return fmt.Errorf("invalid entity in changes")
		}
		if err := codeInEntity(e); err != nil {
			return err
		}
	}
	return nil
}

func codeInEntity(e map[string]any) error {
	if str(e, "changeStatus") == "deleted" {
		return nil
	}
	if _, ok := e["customTemplate"]; ok {
		return fmt.Errorf("custom code is disabled by Kicktemp policy: custom templates require KT_ALLOW_CUSTOM_CODE=true")
	}
	if tag, ok := e["tag"].(map[string]any); ok {
		t := str(tag, "type")
		if t == "" {
			return fmt.Errorf("custom code is disabled by Kicktemp policy: a tag in the JSON has no type, so it cannot be checked")
		}
		if isCodeTag(t) {
			return codeDenied("tag", t)
		}
	}
	if v, ok := e["variable"].(map[string]any); ok {
		t := str(v, "type")
		if t == "" {
			return fmt.Errorf("custom code is disabled by Kicktemp policy: a variable in the JSON has no type, so it cannot be checked")
		}
		if isCodeVariable(t) {
			return codeDenied("variable", t)
		}
	}
	return nil
}
