package tls

import (
	"crypto/tls"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateSelfSigned(t *testing.T) {
	dir := t.TempDir()

	cfg := SelfSignedConfig{
		CertDir: dir,
		Hosts:   []string{"127.0.0.1", "localhost"},
	}

	tlsCfg, fingerprint, err := GenerateSelfSigned(cfg)
	require.NoError(t, err)
	assert.NotNil(t, tlsCfg)
	assert.NotEmpty(t, fingerprint)
	assert.Len(t, tlsCfg.Certificates, 1)

	// Verify files were created
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")

	_, err = os.Stat(certPath)
	assert.NoError(t, err)

	_, err = os.Stat(keyPath)
	assert.NoError(t, err)

	// Key file should have restrictive permissions
	info, err := os.Stat(keyPath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm())
}

func TestGenerateSelfSigned_NoDir(t *testing.T) {
	cfg := SelfSignedConfig{
		Hosts: []string{"127.0.0.1"},
	}

	tlsCfg, fingerprint, err := GenerateSelfSigned(cfg)
	require.NoError(t, err)
	assert.NotNil(t, tlsCfg)
	assert.NotEmpty(t, fingerprint)
}

func TestGenerateSelfSigned_DefaultSANs(t *testing.T) {
	cfg := SelfSignedConfig{}

	tlsCfg, _, err := GenerateSelfSigned(cfg)
	require.NoError(t, err)
	assert.NotNil(t, tlsCfg)
}

func TestLoadCertificate(t *testing.T) {
	dir := t.TempDir()

	// Generate a certificate first
	genCfg := SelfSignedConfig{
		CertDir: dir,
		Hosts:   []string{"localhost"},
	}
	_, _, err := GenerateSelfSigned(genCfg)
	require.NoError(t, err)

	// Load it back
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")

	tlsCfg, err := LoadCertificate(certPath, keyPath)
	require.NoError(t, err)
	assert.NotNil(t, tlsCfg)
	assert.Equal(t, uint16(tls.VersionTLS12), tlsCfg.MinVersion)
}

func TestLoadCertificate_NotFound(t *testing.T) {
	_, err := LoadCertificate("/nonexistent/cert.pem", "/nonexistent/key.pem")
	assert.Error(t, err)
}

func TestNewAutoTLS(t *testing.T) {
	dir := t.TempDir()

	cfg := AutoTLSConfig{
		Domain:   "example.com",
		CacheDir: dir,
	}

	tlsCfg, manager, err := NewAutoTLS(cfg)
	require.NoError(t, err)
	assert.NotNil(t, tlsCfg)
	assert.NotNil(t, manager)
}

func TestNewAutoTLS_NoDomain(t *testing.T) {
	_, _, err := NewAutoTLS(AutoTLSConfig{})
	assert.Error(t, err)
}
