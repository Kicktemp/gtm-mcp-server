package kicktemp

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"gtm-mcp-server/gtm"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"golang.org/x/oauth2"
)

// Lister is the part of the GTM client the allowlist needs to build its
// directory. *gtm.Client implements it.
type Lister interface {
	ListAccounts(ctx context.Context) ([]gtm.Account, error)
	ListContainers(ctx context.Context, accountID string) ([]gtm.Container, error)
}

// lazyReloadAfter throttles directory reloads in lazy (OAuth) mode.
const lazyReloadAfter = 5 * time.Minute

// Allowlist restricts every GTM access to the containers named in
// KT_ALLOWED_CONTAINERS. It resolves public IDs (GTM-XXXX) to the numeric
// account/container IDs the API uses once, at startup, so a check costs no
// GTM request.
type Allowlist struct {
	all    bool
	public map[string]bool // configured public IDs

	mu       sync.RWMutex
	loaded   bool
	loadedAt time.Time
	byKey    map[string]string // "accountId/containerId" -> publicId (allowed containers only)
	accounts map[string]bool   // accounts that own an allowed container

	// lazy mode (no service account at startup): the directory is built from
	// the first request's credentials instead.
	lazy        bool
	listerForCx func(ctx context.Context) (Lister, error)
}

// NewAllowlist creates an allowlist from the configuration. Call Init before
// serving requests.
func NewAllowlist(cfg *Config) *Allowlist {
	a := &Allowlist{all: cfg.AllowAllContainers, public: map[string]bool{}}
	for _, id := range cfg.AllowedContainers {
		a.public[id] = true
	}
	return a
}

// Init builds the container directory. With a service-account token source the
// directory is loaded now, and every configured public ID must be resolvable
// (otherwise startup fails). Without one, loading is deferred to the first
// request (OAuth mode).
func (a *Allowlist) Init(ctx context.Context, sa oauth2.TokenSource) error {
	if a.all {
		return nil
	}
	if sa == nil {
		a.lazy = true
		a.listerForCx = func(ctx context.Context) (Lister, error) { return gtm.ClientFromContext(ctx) }
		return nil
	}
	client, err := gtm.NewClient(ctx, sa)
	if err != nil {
		return fmt.Errorf("allowlist: %w", err)
	}
	return a.InitWithLister(ctx, client)
}

// InitWithLister loads the directory from l and verifies the configured IDs.
func (a *Allowlist) InitWithLister(ctx context.Context, l Lister) error {
	if err := a.load(ctx, l); err != nil {
		return err
	}
	return a.verifyConfigured()
}

// load (re)builds the directory from the GTM API: 1 accounts.list plus one
// containers.list per account.
func (a *Allowlist) load(ctx context.Context, l Lister) error {
	accounts, err := l.ListAccounts(ctx)
	if err != nil {
		return fmt.Errorf("allowlist: list accounts: %w", err)
	}
	byKey := map[string]string{}
	owners := map[string]bool{}
	for _, acc := range accounts {
		containers, err := l.ListContainers(ctx, acc.AccountID)
		if err != nil {
			return fmt.Errorf("allowlist: list containers of account %s: %w", acc.AccountID, err)
		}
		for _, c := range containers {
			pub := strings.ToUpper(c.PublicID)
			if a.public[pub] {
				byKey[acc.AccountID+"/"+c.ContainerID] = pub
				owners[acc.AccountID] = true
			}
		}
	}
	a.mu.Lock()
	a.byKey, a.accounts, a.loaded, a.loadedAt = byKey, owners, true, time.Now()
	a.mu.Unlock()
	return nil
}

// verifyConfigured fails when a configured public ID is not visible to the
// credentials (typo, or the service account has no access yet).
func (a *Allowlist) verifyConfigured() error {
	a.mu.RLock()
	defer a.mu.RUnlock()
	found := map[string]bool{}
	for _, pub := range a.byKey {
		found[pub] = true
	}
	var missing []string
	for id := range a.public {
		if !found[id] {
			missing = append(missing, id)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("KT_ALLOWED_CONTAINERS: unknown or inaccessible container(s): %s", strings.Join(missing, ", "))
	}
	return nil
}

// ensureLoaded loads the directory in lazy mode.
func (a *Allowlist) ensureLoaded(ctx context.Context, force bool) error {
	a.mu.RLock()
	loaded, at := a.loaded, a.loadedAt
	a.mu.RUnlock()
	if loaded && !(force && a.lazy && time.Since(at) > lazyReloadAfter) {
		return nil
	}
	if !a.lazy {
		return fmt.Errorf("container directory not loaded")
	}
	l, err := a.listerForCx(ctx)
	if err != nil {
		return err
	}
	return a.load(ctx, l)
}

func (a *Allowlist) containerAllowed(ctx context.Context, accountID, containerID string) (bool, error) {
	if a.all {
		return true, nil
	}
	if err := a.ensureLoaded(ctx, false); err != nil {
		return false, err
	}
	key := accountID + "/" + containerID
	a.mu.RLock()
	_, ok := a.byKey[key]
	a.mu.RUnlock()
	if ok {
		return true, nil
	}
	// Lazy mode: the container may have been created since the last load.
	if a.lazy {
		if err := a.ensureLoaded(ctx, true); err != nil {
			return false, err
		}
		a.mu.RLock()
		_, ok = a.byKey[key]
		a.mu.RUnlock()
	}
	return ok, nil
}

func (a *Allowlist) accountAllowed(ctx context.Context, accountID string) (bool, error) {
	if a.all {
		return true, nil
	}
	if err := a.ensureLoaded(ctx, false); err != nil {
		return false, err
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.accounts[accountID], nil
}

func (a *Allowlist) publicAllowed(publicID string) bool {
	return a.all || a.public[strings.ToUpper(strings.TrimSpace(publicID))]
}

// idPattern is what GTM IDs look like (numeric IDs, GTM-XXXX, G-XXXX, cvt_x).
var idPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

// checkIDs rejects malformed ID arguments. The upstream tools interpolate IDs
// into API paths without validating them, so "5/../../containers/9" in a
// workspaceId could otherwise address another container.
func checkIDs(args map[string]any) error {
	for k, v := range args {
		lk := strings.ToLower(k)
		if !strings.HasSuffix(lk, "id") && !strings.HasSuffix(lk, "ids") {
			continue
		}
		switch t := v.(type) {
		case nil:
		case string:
			if t != "" && !idPattern.MatchString(t) {
				return fmt.Errorf("argument %q is not a valid ID", k)
			}
		case []any:
			for _, e := range t {
				s, ok := e.(string)
				if !ok || (s != "" && !idPattern.MatchString(s)) {
					return fmt.Errorf("argument %q contains an invalid ID", k)
				}
			}
		default:
			return fmt.Errorf("argument %q must be a string", k)
		}
	}
	return nil
}

func str(args map[string]any, key string) string {
	s, _ := args[key].(string)
	return s
}

func (a *Allowlist) denyContainer(accountID, containerID string) error {
	return fmt.Errorf("container %s/%s is not in KT_ALLOWED_CONTAINERS", accountID, containerID)
}

// check is the pre-call rule of the allowlist.
func (a *Allowlist) check(ctx context.Context, call *toolCall) error {
	args, err := call.Map()
	if err != nil {
		return err
	}
	if err := checkIDs(args); err != nil {
		return err
	}
	if a.all {
		return nil
	}
	switch call.Info.Scope {
	case ScopeNone:
		return nil
	case ScopeLookup:
		if id := str(args, "tagId"); strings.HasPrefix(strings.ToUpper(id), "GTM-") && !a.publicAllowed(id) {
			return fmt.Errorf("container %s is not in KT_ALLOWED_CONTAINERS", id)
		}
		return nil // the result is filtered afterwards
	case ScopeAccount:
		acct := str(args, "accountId")
		if call.Name == "create_container" {
			return fmt.Errorf("create_container is not possible with an explicit KT_ALLOWED_CONTAINERS list: the new container could not be on the list")
		}
		ok, err := a.accountAllowed(ctx, acct)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("account %q has no container in KT_ALLOWED_CONTAINERS", acct)
		}
		return nil
	}

	acct, cont := str(args, "accountId"), str(args, "containerId")
	if acct == "" || cont == "" {
		return fmt.Errorf("accountId and containerId are required")
	}
	ok, err := a.containerAllowed(ctx, acct, cont)
	if err != nil {
		return err
	}
	if !ok {
		return a.denyContainer(acct, cont)
	}
	return a.checkSecondary(ctx, call, args, acct, cont)
}

// checkSecondary covers arguments that reference a second container.
func (a *Allowlist) checkSecondary(ctx context.Context, call *toolCall, args map[string]any, acct, cont string) error {
	switch call.Name {
	case "combine_containers":
		src := str(args, "sourceContainerId")
		ok, err := a.containerAllowed(ctx, acct, src)
		if err != nil {
			return err
		}
		if !ok {
			return a.denyContainer(acct, src)
		}
	case "create_zone", "update_zone":
		children, _ := args["childContainers"].([]any)
		for _, c := range children {
			m, _ := c.(map[string]any)
			if pub := str(m, "publicId"); !a.publicAllowed(pub) {
				return fmt.Errorf("zone child container %q is not in KT_ALLOWED_CONTAINERS", pub)
			}
		}
	case "resolve_workspace_conflict":
		return sameContainer(str(args, "entityJson"), acct, cont)
	case "bulk_update_workspace":
		return sameContainer(str(args, "changesJson"), acct, cont)
	}
	return nil
}

var entityPath = regexp.MustCompile(`^accounts/([^/]+)/containers/([^/]+)(/|$)`)

// sameContainer verifies that free-form entity JSON only refers to the target
// container: every "path" and every accountId/containerId inside must match.
func sameContainer(raw, acct, cont string) error {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	var doc any
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		return fmt.Errorf("invalid JSON argument: %w", err)
	}
	return walk(doc, acct, cont)
}

func walk(v any, acct, cont string) error {
	switch t := v.(type) {
	case map[string]any:
		for k, e := range t {
			if s, ok := e.(string); ok {
				switch {
				case k == "accountId" && s != acct:
					return fmt.Errorf("entity refers to account %s, not %s", s, acct)
				case k == "containerId" && s != cont:
					return fmt.Errorf("entity refers to container %s, not %s", s, cont)
				}
				if m := entityPath.FindStringSubmatch(s); m != nil && (m[1] != acct || m[2] != cont) {
					return fmt.Errorf("entity path %q points outside container %s/%s", s, acct, cont)
				}
				if strings.Contains(s, "..") && strings.HasPrefix(s, "accounts/") {
					return fmt.Errorf("entity path %q is not allowed", s)
				}
				continue
			}
			if err := walk(e, acct, cont); err != nil {
				return err
			}
		}
	case []any:
		for _, e := range t {
			if err := walk(e, acct, cont); err != nil {
				return err
			}
		}
	}
	return nil
}

// after filters results that could reveal containers outside the allowlist.
func (a *Allowlist) after(_ context.Context, call *toolCall, res mcp.Result, err error) (mcp.Result, error) {
	ctr, ok := res.(*mcp.CallToolResult)
	if a.all || err != nil || !ok || ctr.IsError || ctr.StructuredContent == nil {
		return res, err
	}
	switch call.Name {
	case "list_containers":
		return a.filterList(ctr), nil
	case "lookup_container":
		return a.filterLookup(ctr), nil
	}
	return res, err
}

func rewrite(ctr *mcp.CallToolResult, doc map[string]any) *mcp.CallToolResult {
	b, err := json.Marshal(doc)
	if err != nil {
		return denied(fmt.Errorf("kicktemp: cannot filter result: %w", err))
	}
	ctr.StructuredContent = doc
	ctr.Content = []mcp.Content{&mcp.TextContent{Text: string(b)}}
	return ctr
}

func toMap(v any) (map[string]any, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	return m, json.Unmarshal(b, &m)
}

func (a *Allowlist) filterList(ctr *mcp.CallToolResult) *mcp.CallToolResult {
	doc, err := toMap(ctr.StructuredContent)
	if err != nil {
		return denied(fmt.Errorf("kicktemp: cannot filter list_containers result: %w", err))
	}
	list, _ := doc["containers"].([]any)
	kept := []any{}
	for _, c := range list {
		m, _ := c.(map[string]any)
		if a.publicAllowed(str(m, "publicId")) {
			kept = append(kept, c)
		}
	}
	doc["containers"] = kept
	return rewrite(ctr, doc)
}

func (a *Allowlist) filterLookup(ctr *mcp.CallToolResult) *mcp.CallToolResult {
	doc, err := toMap(ctr.StructuredContent)
	if err != nil {
		return denied(fmt.Errorf("kicktemp: cannot filter lookup_container result: %w", err))
	}
	c, _ := doc["container"].(map[string]any)
	if !a.publicAllowed(str(c, "publicId")) {
		return denied(fmt.Errorf("the container found is not in KT_ALLOWED_CONTAINERS"))
	}
	return ctr
}

var resourceURI = regexp.MustCompile(`^gtm://accounts/([^/]+)/containers/([^/]+)(/.*)?$`)

// checkResource guards resources/read: workspace resources address a container,
// and the container-list resource would list all of them.
func (a *Allowlist) checkResource(ctx context.Context, uri string) error {
	if !strings.HasPrefix(uri, "gtm://accounts") {
		return nil // best-practices docs and other static resources
	}
	m := resourceURI.FindStringSubmatch(uri)
	if m != nil {
		if strings.Contains(m[3], "..") || !idPattern.MatchString(m[1]) || !idPattern.MatchString(m[2]) {
			return fmt.Errorf("invalid resource URI")
		}
		for _, seg := range strings.Split(strings.Trim(m[3], "/"), "/") {
			if seg != "" && !idPattern.MatchString(seg) {
				return fmt.Errorf("invalid resource URI")
			}
		}
	}
	if a.all {
		return nil
	}
	if uri == "gtm://accounts" {
		return nil
	}
	if m == nil {
		return fmt.Errorf("resource %q is not available: it would list containers outside KT_ALLOWED_CONTAINERS (use the list_containers tool)", uri)
	}
	ok, err := a.containerAllowed(ctx, m[1], m[2])
	if err != nil {
		return err
	}
	if !ok {
		return a.denyContainer(m[1], m[2])
	}
	return nil
}
