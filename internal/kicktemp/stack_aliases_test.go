package kicktemp_test

import (
	"strings"
	"testing"

	"gtm-mcp-server/internal/kicktemp"
)

func envMap(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestWriteEnabledFlag(t *testing.T) {
	c, err := kicktemp.Load(envMap(nil))
	if err != nil || c.AllowWrite {
		t.Fatalf("GTM_WRITE_ENABLED must default to false, got %+v err=%v", c, err)
	}
	c, err = kicktemp.Load(envMap(map[string]string{"GTM_WRITE_ENABLED": "true"}))
	if err != nil || !c.AllowWrite {
		t.Fatalf("GTM_WRITE_ENABLED=true not honoured: %+v err=%v", c, err)
	}
	if _, err = kicktemp.Load(envMap(map[string]string{"GTM_WRITE_ENABLED": "maybe"})); err == nil {
		t.Fatal("invalid boolean must be an error")
	}
}

func TestAllowlistAlias(t *testing.T) {
	c, err := kicktemp.Load(envMap(map[string]string{"GTM_ALLOWLIST": "gtm-abcd12, GTM-WXYZ99"}))
	if err != nil || len(c.AllowedContainers) != 2 || c.AllowedContainers[0] != "GTM-ABCD12" {
		t.Fatalf("GTM_ALLOWLIST must fill the container allowlist, got %+v err=%v", c, err)
	}
	same := map[string]string{"GTM_ALLOWLIST": "GTM-ABCD12", "KT_ALLOWED_CONTAINERS": "GTM-ABCD12"}
	if _, err = kicktemp.Load(envMap(same)); err != nil {
		t.Fatalf("identical values must be accepted: %v", err)
	}
	diff := map[string]string{"GTM_ALLOWLIST": "GTM-ABCD12", "KT_ALLOWED_CONTAINERS": "GTM-WXYZ99"}
	if _, err = kicktemp.Load(envMap(diff)); err == nil || !strings.Contains(err.Error(), "both set") {
		t.Fatalf("conflicting values must be rejected, got %v", err)
	}
	c, err = kicktemp.Load(envMap(nil))
	if err != nil || c.AllowAllContainers || len(c.AllowedContainers) != 0 {
		t.Fatalf("empty allowlist must allow nothing, got %+v err=%v", c, err)
	}
}

func TestMCPAuthTokenAlias(t *testing.T) {
	c, err := kicktemp.Load(envMap(map[string]string{"MCP_AUTH_TOKEN": testKey}))
	if err != nil || c.APIKey("") != testKey {
		t.Fatalf("MCP_AUTH_TOKEN must act as the API key, got %q err=%v", c.APIKey(""), err)
	}
	if got := c.APIKey("from-upstream-env"); got != "from-upstream-env" {
		t.Errorf("SERVICE_ACCOUNT_API_KEY must stay valid, got %q", got)
	}
	conflict := map[string]string{"MCP_AUTH_TOKEN": testKey, "SERVICE_ACCOUNT_API_KEY": testKey + "x"}
	if _, err = kicktemp.Load(envMap(conflict)); err == nil {
		t.Fatal("different MCP_AUTH_TOKEN and SERVICE_ACCOUNT_API_KEY must be rejected")
	}
}
