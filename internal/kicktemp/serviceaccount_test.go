package kicktemp_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gtm-mcp-server/internal/kicktemp"
)

const fakeKey = `{"type":"service_account","client_email":"sa@p.iam.gserviceaccount.com","private_key":"-----BEGIN PRIVATE KEY-----\nSUPERSECRETKEYMATERIAL\n-----END PRIVATE KEY-----\n"}`

func keyCfg(t *testing.T, content string) (*kicktemp.Config, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "sa.json")
	if err := os.WriteFile(path, []byte(content), 0o400); err != nil {
		t.Fatal(err)
	}
	return &kicktemp.Config{ServiceAccountKeyFile: path}, path
}

func TestServiceAccountKeyFromFile(t *testing.T) {
	cfg, _ := keyCfg(t, fakeKey)
	got, err := cfg.ServiceAccountKey("")
	if err != nil || got != fakeKey {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestServiceAccountKeyEnvPassThrough(t *testing.T) {
	got, err := (&kicktemp.Config{}).ServiceAccountKey("from-env")
	if err != nil || got != "from-env" {
		t.Fatalf("without a key file the env value must pass through: %q %v", got, err)
	}
}

func TestServiceAccountKeyFileErrors(t *testing.T) {
	cfg, _ := keyCfg(t, fakeKey)
	if _, err := cfg.ServiceAccountKey(`{"env":"too"}`); err == nil || !strings.Contains(err.Error(), "only one") {
		t.Errorf("file and env together must fail: %v", err)
	}
	if _, err := (&kicktemp.Config{ServiceAccountKeyFile: "/nonexistent/sa.json"}).ServiceAccountKey(""); err == nil {
		t.Error("missing file must fail")
	}
	for name, content := range map[string]string{
		"empty":      "",
		"not json":   "SUPERSECRETKEYMATERIAL",
		"wrong type": `{"type":"authorized_user","client_email":"a","private_key":"SUPERSECRETKEYMATERIAL"}`,
		"no key":     `{"type":"service_account","client_email":"a"}`,
		"huge":       strings.Repeat("x", 70*1024),
	} {
		cfg, _ := keyCfg(t, content)
		_, err := cfg.ServiceAccountKey("")
		if err == nil {
			t.Errorf("%s: must fail", name)
			continue
		}
		if strings.Contains(err.Error(), "SUPERSECRETKEYMATERIAL") {
			t.Errorf("%s: error leaks key material: %v", name, err)
		}
	}
}

func TestServiceAccountKeyFileConfig(t *testing.T) {
	get := func(k string) string {
		if k == "GOOGLE_SERVICE_ACCOUNT_KEY_FILE" {
			return " /run/secrets/gtm_sa "
		}
		return ""
	}
	c, err := kicktemp.Load(get)
	if err != nil || c.ServiceAccountKeyFile != "/run/secrets/gtm_sa" {
		t.Fatalf("%+v %v", c, err)
	}
}
