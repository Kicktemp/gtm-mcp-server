// Package gtm provides a client for the Google Tag Manager API.
package gtm

import (
	"context"
	"fmt"

	"golang.org/x/oauth2"
	"google.golang.org/api/option"
	tagmanager "google.golang.org/api/tagmanager/v2"
)

// Client wraps the Google Tag Manager API service.
type Client struct {
	Service *tagmanager.Service
}

// NewClient creates a GTM client from an OAuth2 token source.
// The token source should handle automatic refresh.
func NewClient(ctx context.Context, tokenSource oauth2.TokenSource) (*Client, error) {
	if tokenSource == nil {
		return nil, fmt.Errorf("token source is required")
	}

	opts := []option.ClientOption{option.WithTokenSource(tokenSource)}

	// Kicktemp fork: the upstream GTM_DEBUG HTTP body dump was removed. It wrote
	// complete GTM request/response bodies to the log; nothing here logs traffic.

	service, err := tagmanager.NewService(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create tagmanager service: %w", err)
	}

	return &Client{Service: service}, nil
}
