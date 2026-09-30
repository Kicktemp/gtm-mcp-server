package kicktemp

import (
	"fmt"
	"net"
	"net/http"
	"strconv"
	"time"
)

// Healthcheck probes GET /health on the local listener and returns nil when it
// answers 200. It backs the `-healthcheck` flag: the distroless runtime image
// has no wget or curl for a Docker HEALTHCHECK.
func Healthcheck(listenAddr string) error {
	host, port, err := net.SplitHostPort(listenAddr)
	if err != nil {
		return err
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	if _, err := strconv.Atoi(port); err != nil {
		return err
	}
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get("http://" + net.JoinHostPort(host, port) + "/health")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("health check answered %d", resp.StatusCode)
	}
	return nil
}
