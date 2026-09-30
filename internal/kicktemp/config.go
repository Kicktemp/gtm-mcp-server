// Package kicktemp holds the Kicktemp hardening layer around the upstream GTM
// MCP server. It is kept in its own package so that rebasing onto new upstream
// releases only touches a few hook lines in main.go.
package kicktemp

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Config is the Kicktemp-specific configuration (KT_* environment variables).
// Every invalid value is an error: the server must not start with a policy it
// could not parse.
type Config struct {
	// AllowPublish enables the publish category (KT_ALLOW_PUBLISH).
	AllowPublish bool
	// AllowDelete enables the delete category (KT_ALLOW_DELETE).
	AllowDelete bool
	// AllowAdmin enables the admin category (KT_ALLOW_ADMIN).
	AllowAdmin bool

	// AllowAllContainers is true when KT_ALLOWED_CONTAINERS is "*".
	AllowAllContainers bool
	// AllowedContainers lists the public IDs (GTM-XXXX) that may be read and
	// written. Empty with AllowAllContainers=false means nothing is allowed.
	AllowedContainers []string

	// OAuthEnabled switches the OAuth mode (KT_OAUTH_ENABLED). When false, only
	// the service-account bearer key is accepted and all OAuth routes are gone.
	OAuthEnabled bool

	// AllowedEmails lists the Google accounts that may log in when OAuth is
	// enabled (KT_ALLOWED_EMAILS, lower-cased). Empty means OAuth is refused.
	AllowedEmails []string

	// AuditLogPath is the JSON Lines audit log (KT_AUDIT_LOG_PATH). It cannot
	// be switched off: the server refuses to start if it is not writable.
	AuditLogPath string
}

// Load reads the Kicktemp configuration through getenv (os.Getenv in
// production). Call it after config.Load so that .env files are already applied.
func Load(getenv func(string) string) (*Config, error) {
	cfg := &Config{}
	var err error
	if cfg.AllowPublish, err = envBool(getenv, "KT_ALLOW_PUBLISH", false); err != nil {
		return nil, err
	}
	if cfg.AllowDelete, err = envBool(getenv, "KT_ALLOW_DELETE", false); err != nil {
		return nil, err
	}
	if cfg.AllowAdmin, err = envBool(getenv, "KT_ALLOW_ADMIN", false); err != nil {
		return nil, err
	}
	if cfg.OAuthEnabled, err = envBool(getenv, "KT_OAUTH_ENABLED", false); err != nil {
		return nil, err
	}
	if cfg.AllowAllContainers, cfg.AllowedContainers, err = parseContainers(getenv("KT_ALLOWED_CONTAINERS")); err != nil {
		return nil, err
	}
	for _, e := range strings.Split(getenv("KT_ALLOWED_EMAILS"), ",") {
		e = strings.ToLower(strings.TrimSpace(e))
		if e == "" {
			continue
		}
		if !strings.Contains(e, "@") || strings.ContainsAny(e, " *") {
			return nil, fmt.Errorf("KT_ALLOWED_EMAILS: %q is not an email address", e)
		}
		cfg.AllowedEmails = append(cfg.AllowedEmails, e)
	}
	cfg.AuditLogPath = strings.TrimSpace(getenv("KT_AUDIT_LOG_PATH"))
	if cfg.AuditLogPath == "" {
		cfg.AuditLogPath = "/data/audit.jsonl"
	}
	return cfg, nil
}

var publicIDPattern = regexp.MustCompile(`^GTM-[A-Z0-9]{4,20}$`)

// parseContainers parses KT_ALLOWED_CONTAINERS: "" allows nothing, "*" allows
// everything, otherwise a comma-separated list of container public IDs.
func parseContainers(raw string) (all bool, ids []string, err error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return false, nil, nil
	}
	if raw == "*" {
		return true, nil, nil
	}
	seen := map[string]bool{}
	for _, part := range strings.Split(raw, ",") {
		id := strings.ToUpper(strings.TrimSpace(part))
		if id == "" {
			continue
		}
		if !publicIDPattern.MatchString(id) {
			return false, nil, fmt.Errorf("KT_ALLOWED_CONTAINERS: %q is not a container public ID (GTM-XXXX) or \"*\"", part)
		}
		if !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	return false, ids, nil
}

func envBool(getenv func(string) string, key string, def bool) (bool, error) {
	v := strings.TrimSpace(getenv(key))
	if v == "" {
		return def, nil
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return false, fmt.Errorf("%s: invalid boolean %q", key, v)
	}
	return b, nil
}
