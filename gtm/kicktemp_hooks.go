package gtm

import (
	"context"
	"net/http"
)

// ClientFromContext returns the authenticated GTM client for the current
// request. It exposes getClient to the Kicktemp hardening layer
// (internal/kicktemp) without duplicating the credential logic.
func ClientFromContext(ctx context.Context) (*Client, error) {
	return getClient(ctx)
}

// TransportWrapper, when set, wraps the HTTP transport of every GTM API client
// (outside OAuth). The Kicktemp layer uses it for the request rate limit.
var TransportWrapper func(http.RoundTripper) http.RoundTripper
