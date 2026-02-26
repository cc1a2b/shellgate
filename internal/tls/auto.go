package tls

import (
	"crypto/tls"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/crypto/acme/autocert"
)

// AutoTLSConfig holds the configuration for automatic Let's Encrypt certificates.
type AutoTLSConfig struct {
	Domain   string
	CacheDir string
}

// NewAutoTLS creates a TLS configuration that automatically obtains and renews
// Let's Encrypt certificates for the given domain.
func NewAutoTLS(cfg AutoTLSConfig) (*tls.Config, *autocert.Manager, error) {
	if cfg.Domain == "" {
		return nil, nil, fmt.Errorf("domain is required for auto TLS")
	}

	cacheDir := cfg.CacheDir
	if cacheDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			cacheDir = ".shellgate/certs"
		} else {
			cacheDir = filepath.Join(home, ".shellgate", "certs")
		}
	}

	if err := os.MkdirAll(cacheDir, 0700); err != nil {
		return nil, nil, fmt.Errorf("create cache dir: %w", err)
	}

	manager := &autocert.Manager{
		Cache:      autocert.DirCache(cacheDir),
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(cfg.Domain),
	}

	tlsCfg := manager.TLSConfig()
	tlsCfg.MinVersion = tls.VersionTLS12

	return tlsCfg, manager, nil
}
