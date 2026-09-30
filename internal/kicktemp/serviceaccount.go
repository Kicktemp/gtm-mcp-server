package kicktemp

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
)

// maxKeyFileBytes bounds the key file read; real keys are about 2.4 KB.
const maxKeyFileBytes = 64 * 1024

// ServiceAccountKey returns the service-account JSON to use. With
// GOOGLE_SERVICE_ACCOUNT_KEY_FILE set it reads the file (Docker secret) and
// rejects a simultaneous GOOGLE_SERVICE_ACCOUNT_KEY_JSON, so there is only one
// source of truth. Otherwise it returns envJSON unchanged.
//
// Errors never contain file contents.
func (c *Config) ServiceAccountKey(envJSON string) (string, error) {
	if c.ServiceAccountKeyFile == "" {
		return envJSON, nil
	}
	if envJSON != "" {
		return "", fmt.Errorf("GOOGLE_SERVICE_ACCOUNT_KEY_FILE and GOOGLE_SERVICE_ACCOUNT_KEY_JSON are both set: use only one")
	}
	f, err := os.Open(c.ServiceAccountKeyFile)
	if err != nil {
		return "", fmt.Errorf("GOOGLE_SERVICE_ACCOUNT_KEY_FILE: %w", err)
	}
	defer f.Close()
	buf, err := io.ReadAll(io.LimitReader(f, maxKeyFileBytes+1))
	if err != nil || len(buf) == 0 {
		return "", fmt.Errorf("GOOGLE_SERVICE_ACCOUNT_KEY_FILE %q is empty or unreadable", c.ServiceAccountKeyFile)
	}
	n := len(buf)
	if n > maxKeyFileBytes {
		return "", fmt.Errorf("GOOGLE_SERVICE_ACCOUNT_KEY_FILE %q is too large for a service-account key", c.ServiceAccountKeyFile)
	}
	var key struct {
		Type        string `json:"type"`
		ClientEmail string `json:"client_email"`
		PrivateKey  string `json:"private_key"`
	}
	if err := json.Unmarshal(buf[:n], &key); err != nil {
		return "", fmt.Errorf("GOOGLE_SERVICE_ACCOUNT_KEY_FILE %q is not valid JSON", c.ServiceAccountKeyFile)
	}
	if key.Type != "service_account" || key.ClientEmail == "" || key.PrivateKey == "" {
		return "", fmt.Errorf("GOOGLE_SERVICE_ACCOUNT_KEY_FILE %q is not a service-account key (need type, client_email, private_key)", c.ServiceAccountKeyFile)
	}
	return string(buf[:n]), nil
}
