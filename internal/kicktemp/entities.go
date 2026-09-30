package kicktemp

import (
	"context"
	"fmt"
	"regexp"
	"sync"
	"time"

	"gtm-mcp-server/gtm"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// entityTTL bounds how long a cached fingerprint/type is trusted. GTM entities
// can change outside this server (GTM UI, other API clients).
const entityTTL = 10 * time.Minute

// Entity is what the policy layer remembers about a GTM entity.
type Entity struct {
	Fingerprint string
	Type        string // tag/trigger/variable type, when known
	seen        time.Time
}

// Entities caches fingerprints and types of GTM entities. It is filled from
// the results of every tool call, so a write only costs one extra GTM request
// (a GET) when the entity was not seen before.
type Entities struct {
	mu    sync.Mutex
	items map[string]Entity
	fetch func(ctx context.Context, path string) (Entity, error)
	now   func() time.Time

	// Fetches counts GET requests issued on cache misses (for tests and the review).
	Fetches int
}

// NewEntities creates a cache that fetches misses with the request's GTM client.
func NewEntities() *Entities {
	return &Entities{items: map[string]Entity{}, fetch: fetchEntity, now: time.Now}
}

// NewEntitiesWithFetch is NewEntities with a custom fetch function (tests).
func NewEntitiesWithFetch(fetch func(ctx context.Context, path string) (Entity, error)) *Entities {
	return &Entities{items: map[string]Entity{}, fetch: fetch, now: time.Now}
}

// Get returns the entity at path from the cache, or fetches it once.
func (e *Entities) Get(ctx context.Context, path string) (Entity, error) {
	e.mu.Lock()
	it, ok := e.items[path]
	fresh := ok && e.now().Sub(it.seen) < entityTTL
	e.mu.Unlock()
	if fresh {
		return it, nil
	}
	got, err := e.fetch(ctx, path)
	if err != nil {
		return Entity{}, err
	}
	e.mu.Lock()
	e.Fetches++
	got.seen = e.now()
	e.items[path] = got
	e.mu.Unlock()
	return got, nil
}

// Forget drops an entity (after a delete).
func (e *Entities) Forget(path string) {
	e.mu.Lock()
	delete(e.items, path)
	e.mu.Unlock()
}

// Observe records every object with a "path" and a "fingerprint" found in a
// tool result (get, list, create and update results all have this shape).
func (e *Entities) Observe(res mcp.Result) {
	ctr, ok := res.(*mcp.CallToolResult)
	if !ok || ctr.IsError || ctr.StructuredContent == nil {
		return
	}
	doc, err := toMap(ctr.StructuredContent)
	if err != nil {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	collect(doc, func(path, fp, typ string) {
		e.items[path] = Entity{Fingerprint: fp, Type: typ, seen: e.now()}
	})
}

func collect(v any, put func(path, fp, typ string)) {
	switch t := v.(type) {
	case map[string]any:
		path, _ := t["path"].(string)
		fp, _ := t["fingerprint"].(string)
		if path != "" && fp != "" {
			typ, _ := t["type"].(string)
			put(path, fp, typ)
		}
		for _, e := range t {
			collect(e, put)
		}
	case []any:
		for _, e := range t {
			collect(e, put)
		}
	}
}

// firstFingerprint returns the fingerprint of the object at path in a result
// (or, when path is empty or absent, of the first object that has one).
func firstFingerprint(res mcp.Result, path string) string {
	ctr, ok := res.(*mcp.CallToolResult)
	if !ok || ctr.IsError || ctr.StructuredContent == nil {
		return ""
	}
	doc, err := toMap(ctr.StructuredContent)
	if err != nil {
		return ""
	}
	var exact, any string
	collect(doc, func(p, fp, _ string) {
		if p == path && exact == "" {
			exact = fp
		}
		if any == "" {
			any = fp
		}
	})
	if exact != "" {
		return exact
	}
	return any
}

var (
	wsEntityPath = regexp.MustCompile(`^accounts/\d+/containers/\d+/workspaces/\d+/(tags|triggers|variables|folders|templates|clients|transformations|zones|gtag_config)/\d+$`)
	wsPath       = regexp.MustCompile(`^accounts/\d+/containers/\d+/workspaces/\d+$`)
	versionPath  = regexp.MustCompile(`^accounts/\d+/containers/\d+/versions/\d+$`)
	envPath      = regexp.MustCompile(`^accounts/\d+/containers/\d+/environments/\d+$`)
	containerRe  = regexp.MustCompile(`^accounts/\d+/containers/\d+$`)
	accountRe    = regexp.MustCompile(`^accounts/\d+$`)
)

// fetchEntity does one GET for path with the request's GTM client.
func fetchEntity(ctx context.Context, path string) (Entity, error) {
	client, err := gtm.ClientFromContext(ctx)
	if err != nil {
		return Entity{}, err
	}
	svc := client.Service.Accounts
	ws := svc.Containers.Workspaces
	m := wsEntityPath.FindStringSubmatch(path)
	switch {
	case m != nil:
		switch m[1] {
		case "tags":
			r, err := ws.Tags.Get(path).Context(ctx).Do()
			if err != nil {
				return Entity{}, err
			}
			return Entity{Fingerprint: r.Fingerprint, Type: r.Type}, nil
		case "triggers":
			r, err := ws.Triggers.Get(path).Context(ctx).Do()
			if err != nil {
				return Entity{}, err
			}
			return Entity{Fingerprint: r.Fingerprint, Type: r.Type}, nil
		case "variables":
			r, err := ws.Variables.Get(path).Context(ctx).Do()
			if err != nil {
				return Entity{}, err
			}
			return Entity{Fingerprint: r.Fingerprint, Type: r.Type}, nil
		case "folders":
			r, err := ws.Folders.Get(path).Context(ctx).Do()
			if err != nil {
				return Entity{}, err
			}
			return Entity{Fingerprint: r.Fingerprint}, nil
		case "templates":
			r, err := ws.Templates.Get(path).Context(ctx).Do()
			if err != nil {
				return Entity{}, err
			}
			return Entity{Fingerprint: r.Fingerprint, Type: "template"}, nil
		case "clients":
			r, err := ws.Clients.Get(path).Context(ctx).Do()
			if err != nil {
				return Entity{}, err
			}
			return Entity{Fingerprint: r.Fingerprint, Type: r.Type}, nil
		case "transformations":
			r, err := ws.Transformations.Get(path).Context(ctx).Do()
			if err != nil {
				return Entity{}, err
			}
			return Entity{Fingerprint: r.Fingerprint, Type: r.Type}, nil
		case "zones":
			r, err := ws.Zones.Get(path).Context(ctx).Do()
			if err != nil {
				return Entity{}, err
			}
			return Entity{Fingerprint: r.Fingerprint}, nil
		default: // gtag_config
			r, err := ws.GtagConfig.Get(path).Context(ctx).Do()
			if err != nil {
				return Entity{}, err
			}
			return Entity{Fingerprint: r.Fingerprint, Type: r.Type}, nil
		}
	case wsPath.MatchString(path):
		r, err := ws.Get(path).Context(ctx).Do()
		if err != nil {
			return Entity{}, err
		}
		return Entity{Fingerprint: r.Fingerprint}, nil
	case versionPath.MatchString(path):
		r, err := svc.Containers.Versions.Get(path).Context(ctx).Do()
		if err != nil {
			return Entity{}, err
		}
		return Entity{Fingerprint: r.Fingerprint}, nil
	case envPath.MatchString(path):
		r, err := svc.Containers.Environments.Get(path).Context(ctx).Do()
		if err != nil {
			return Entity{}, err
		}
		return Entity{Fingerprint: r.Fingerprint}, nil
	case containerRe.MatchString(path):
		r, err := svc.Containers.Get(path).Context(ctx).Do()
		if err != nil {
			return Entity{}, err
		}
		return Entity{Fingerprint: r.Fingerprint}, nil
	case accountRe.MatchString(path):
		r, err := svc.Get(path).Context(ctx).Do()
		if err != nil {
			return Entity{}, err
		}
		return Entity{Fingerprint: r.Fingerprint}, nil
	}
	return Entity{}, fmt.Errorf("unsupported entity path %q", path)
}

// entityRef describes the entity a tool call targets.
type entityRef struct {
	Type string `json:"type"`
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
	Path string `json:"path,omitempty"`
}

// entityArg maps tools that act on one entity to the entity kind, the ID
// argument and the path segment below the workspace/container.
type entityArg struct {
	kind, idKey, seg string
	level            string // "workspace", "container", "account"
}

var entityTools = func() map[string]entityArg {
	m := map[string]entityArg{}
	ws := func(kind, idKey, seg string, verbs ...string) {
		for _, v := range verbs {
			m[v+"_"+kind] = entityArg{kind: kind, idKey: idKey, seg: seg, level: "workspace"}
		}
	}
	ws("tag", "tagId", "tags", "update", "delete")
	ws("trigger", "triggerId", "triggers", "update", "delete")
	ws("variable", "variableId", "variables", "update", "delete")
	ws("folder", "folderId", "folders", "update", "delete", "revert")
	ws("template", "templateId", "templates", "update", "delete")
	ws("client", "clientId", "clients", "update", "delete")
	ws("transformation", "transformationId", "transformations", "update", "delete")
	ws("zone", "zoneId", "zones", "update", "delete")
	m["update_google_tag_config"] = entityArg{kind: "google_tag_config", idKey: "gtagConfigId", seg: "gtag_config", level: "workspace"}
	m["delete_google_tag_config"] = m["update_google_tag_config"]
	m["update_workspace"] = entityArg{kind: "workspace", level: "workspace"}
	m["delete_workspace"] = m["update_workspace"]
	for _, v := range []string{"update_version", "delete_version", "undelete_version", "publish_version", "set_latest_version"} {
		m[v] = entityArg{kind: "version", idKey: "versionId", seg: "versions", level: "container"}
	}
	for _, v := range []string{"update_environment", "delete_environment", "reauthorize_environment"} {
		m[v] = entityArg{kind: "environment", idKey: "environmentId", seg: "environments", level: "container"}
	}
	m["update_container"] = entityArg{kind: "container", level: "container"}
	m["delete_container"] = m["update_container"]
	m["update_account"] = entityArg{kind: "account", level: "account"}
	return m
}()

// targetOf returns the entity a tool call addresses. path is empty when the
// call has no single existing entity (create, bulk and workspace-level tools).
func targetOf(name string, args map[string]any) entityRef {
	ref := entityRef{Type: kindOf(name), Name: str(args, "name")}
	ea, ok := entityTools[name]
	if !ok {
		return ref
	}
	ref.Type = ea.kind
	acct, cont, w := str(args, "accountId"), str(args, "containerId"), str(args, "workspaceId")
	switch {
	case ea.level == "account" && acct != "":
		ref.Path = "accounts/" + acct
		ref.ID = acct
	case ea.level == "container" && acct != "" && cont != "":
		ref.Path = "accounts/" + acct + "/containers/" + cont
		ref.ID = cont
		if ea.seg != "" {
			if id := str(args, ea.idKey); id != "" {
				ref.ID = id
				ref.Path += "/" + ea.seg + "/" + id
			} else {
				ref.Path = ""
			}
		}
	case ea.level == "workspace" && acct != "" && cont != "" && w != "":
		ref.Path = "accounts/" + acct + "/containers/" + cont + "/workspaces/" + w
		ref.ID = w
		if ea.seg != "" {
			if id := str(args, ea.idKey); id != "" {
				ref.ID = id
				ref.Path += "/" + ea.seg + "/" + id
			} else {
				ref.Path = ""
			}
		}
	}
	return ref
}

var verbPrefix = regexp.MustCompile(`^(create|update|delete|revert|undelete|publish|set|enable|disable|move|sync|resolve|bulk_update|link|reauthorize|combine|import)_?`)

// kindOf derives a readable entity kind from a tool name without an entry in
// entityTools, e.g. create_tag -> tag.
func kindOf(name string) string {
	if k := verbPrefix.ReplaceAllString(name, ""); k != "" {
		return k
	}
	return name
}
