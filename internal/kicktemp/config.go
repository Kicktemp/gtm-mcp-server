// Package kicktemp holds the Kicktemp hardening layer around the upstream GTM
// MCP server. It is kept in its own package so that rebasing onto new upstream
// releases only touches a few hook lines in main.go.
package kicktemp

import (
	"fmt"
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
	return cfg, nil
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
