package gtm

import "context"

// ClientFromContext returns the authenticated GTM client for the current
// request. It exposes getClient to the Kicktemp hardening layer
// (internal/kicktemp) without duplicating the credential logic.
func ClientFromContext(ctx context.Context) (*Client, error) {
	return getClient(ctx)
}
