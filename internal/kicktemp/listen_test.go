package kicktemp_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"gtm-mcp-server/internal/kicktemp"
)

func TestListenAddress(t *testing.T) {
	get := func(v string) func(string) string {
		return func(k string) string {
			if k == "KT_LISTEN_ADDR" {
				return v
			}
			return ""
		}
	}
	c, _ := kicktemp.Load(get(""))
	if got := c.ListenAddress(8080); got != "127.0.0.1:8080" {
		t.Errorf("default = %q, want loopback (never all interfaces)", got)
	}
	if got := c.ListenAddress(9000); got != "127.0.0.1:9000" {
		t.Errorf("upstream PORT must keep the loopback host, got %q", got)
	}
	c, err := kicktemp.Load(get("0.0.0.0:8080"))
	if err != nil || c.ListenAddress(1) != "0.0.0.0:8080" {
		t.Errorf("explicit address not honoured: %v %v", c, err)
	}
	for _, bad := range []string{"8080", "127.0.0.1", "127.0.0.1:http", "127.0.0.1:0", "127.0.0.1:99999"} {
		if _, err := kicktemp.Load(get(bad)); err == nil {
			t.Errorf("%q must be rejected", bad)
		}
	}
}

func TestListensPublicly(t *testing.T) {
	for addr, want := range map[string]bool{
		"127.0.0.1:8080": false, "[::1]:8080": false, "localhost:8080": false,
		"0.0.0.0:8080": true, ":8080": true, "[::]:8080": true, "192.168.1.5:8080": true,
	} {
		if got := kicktemp.ListensPublicly(addr); got != want {
			t.Errorf("ListensPublicly(%q) = %v, want %v", addr, got, want)
		}
	}
}

func TestHealthcheck(t *testing.T) {
	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/health" {
			http.NotFound(w, r)
		}
	}))
	defer ok.Close()
	if err := kicktemp.Healthcheck(strings.TrimPrefix(ok.URL, "http://")); err != nil {
		t.Errorf("healthy server reported unhealthy: %v", err)
	}

	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "down", http.StatusServiceUnavailable)
	}))
	defer bad.Close()
	if err := kicktemp.Healthcheck(strings.TrimPrefix(bad.URL, "http://")); err == nil {
		t.Error("503 must be unhealthy")
	}
	if err := kicktemp.Healthcheck("127.0.0.1:1"); err == nil {
		t.Error("unreachable server must be unhealthy")
	}
}
