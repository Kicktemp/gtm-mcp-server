// Package kicktemp holds the Kicktemp hardening layer around the upstream GTM
// MCP server. It is kept in its own package so that rebasing onto new upstream
// releases only touches a few hook lines in main.go.
package kicktemp

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
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
	// AllowCustomCode enables everything that creates or changes code GTM
	// executes on websites: custom templates, Custom HTML and custom-template
	// tags, Custom JavaScript variables (KT_ALLOW_CUSTOM_CODE).
	AllowCustomCode bool

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

	// ListenAddr is the HTTP listen address (KT_LISTEN_ADDR). Empty means
	// 127.0.0.1 on the upstream PORT.
	ListenAddr string

	// ServiceAccountKeyFile is a file holding the service-account JSON key
	// (GOOGLE_SERVICE_ACCOUNT_KEY_FILE), e.g. a Docker secret.
	ServiceAccountKeyFile string

	// GTMQPM caps GTM API requests per minute, process-wide (KT_GTM_QPM).
	GTMQPM int
	// GTMMaxWait is how long a request may wait for a free slot before the
	// tool call fails with "rate limited, retry later" (KT_GTM_MAX_WAIT).
	GTMMaxWait time.Duration

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
	if cfg.AllowCustomCode, err = envBool(getenv, "KT_ALLOW_CUSTOM_CODE", false); err != nil {
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
	if cfg.ListenAddr = strings.TrimSpace(getenv("KT_LISTEN_ADDR")); cfg.ListenAddr != "" {
		if _, port, err := net.SplitHostPort(cfg.ListenAddr); err != nil {
			return nil, fmt.Errorf("KT_LISTEN_ADDR: %q is not host:port: %w", cfg.ListenAddr, err)
		} else if p, err := strconv.Atoi(port); err != nil || p < 1 || p > 65535 {
			return nil, fmt.Errorf("KT_LISTEN_ADDR: invalid port in %q", cfg.ListenAddr)
		}
	}
	cfg.ServiceAccountKeyFile = strings.TrimSpace(getenv("GOOGLE_SERVICE_ACCOUNT_KEY_FILE"))
	cfg.GTMQPM = 25
	if v := strings.TrimSpace(getenv("KT_GTM_QPM")); v != "" {
		if cfg.GTMQPM, err = strconv.Atoi(v); err != nil || cfg.GTMQPM < 1 {
			return nil, fmt.Errorf("KT_GTM_QPM: %q is not a positive integer", v)
		}
	}
	cfg.GTMMaxWait = 60 * time.Second
	if v := strings.TrimSpace(getenv("KT_GTM_MAX_WAIT")); v != "" {
		if cfg.GTMMaxWait, err = time.ParseDuration(v); err != nil || cfg.GTMMaxWait < 0 {
			return nil, fmt.Errorf("KT_GTM_MAX_WAIT: %q is not a duration like 60s", v)
		}
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

// ListenAddress returns the address to bind: KT_LISTEN_ADDR, or loopback on
// the given upstream port. The upstream default (all interfaces) is never used.
func (c *Config) ListenAddress(port int) string {
	if c.ListenAddr != "" {
		return c.ListenAddr
	}
	return net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
}

// ListensPublicly reports whether addr binds beyond the loopback interface.
func ListensPublicly(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return true
	}
	if host == "" {
		return true
	}
	if host == "localhost" {
		return false
	}
	ip := net.ParseIP(host)
	return ip == nil || !ip.IsLoopback()
}
