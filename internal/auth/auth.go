// Package auth provides authentication strategies for ShellGate.
package auth

import "net/http"

// Authenticator defines the interface for authentication strategies.
type Authenticator interface {
	// Name returns the human-readable name of the auth strategy.
	Name() string

	// Middleware wraps an HTTP handler with authentication checks.
	Middleware(next http.Handler) http.Handler

	// Validate checks if the request is authenticated.
	Validate(r *http.Request) (bool, error)
}

// NoneAuth is a no-op authenticator that allows all requests.
// Only enabled with --auth none --i-know-what-im-doing.
type NoneAuth struct{}

// Name returns the authenticator name.
func (n *NoneAuth) Name() string { return "none" }

// Middleware returns the handler unchanged.
func (n *NoneAuth) Middleware(next http.Handler) http.Handler { return next }

// Validate always returns true.
func (n *NoneAuth) Validate(r *http.Request) (bool, error) { return true, nil }
