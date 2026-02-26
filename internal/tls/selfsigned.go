// Package tls provides TLS certificate management for ShellGate.
package tls

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// SelfSignedConfig holds the configuration for self-signed certificate generation.
type SelfSignedConfig struct {
	CertDir  string
	Hosts    []string // IP addresses and hostnames
	ValidFor time.Duration
}

// GenerateSelfSigned creates a self-signed ED25519 certificate.
// Returns the TLS config and the certificate's SHA-256 fingerprint.
func GenerateSelfSigned(cfg SelfSignedConfig) (*tls.Config, string, error) {
	if cfg.ValidFor == 0 {
		cfg.ValidFor = 365 * 24 * time.Hour
	}

	// Generate ED25519 key pair
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, "", fmt.Errorf("generate ed25519 key: %w", err)
	}

	// Create certificate template
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, "", fmt.Errorf("generate serial: %w", err)
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          serialNumber,
		NotBefore:             now,
		NotAfter:              now.Add(cfg.ValidFor),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// Add SANs
	for _, h := range cfg.Hosts {
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
		}
	}

	// Default SANs
	if len(template.IPAddresses) == 0 && len(template.DNSNames) == 0 {
		template.IPAddresses = []net.IP{net.ParseIP("127.0.0.1"), net.IPv6loopback}
		template.DNSNames = []string{"localhost"}
	}

	// Self-sign the certificate
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, pub, priv)
	if err != nil {
		return nil, "", fmt.Errorf("create certificate: %w", err)
	}

	// Compute fingerprint
	fingerprint := sha256.Sum256(certDER)
	fpStr := fmt.Sprintf("%X", fingerprint)

	// Encode to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, "", fmt.Errorf("marshal private key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})

	// Save to disk if CertDir specified
	if cfg.CertDir != "" {
		if err := os.MkdirAll(cfg.CertDir, 0700); err != nil {
			return nil, "", fmt.Errorf("create cert dir: %w", err)
		}

		certPath := filepath.Join(cfg.CertDir, "cert.pem")
		keyPath := filepath.Join(cfg.CertDir, "key.pem")

		if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
			return nil, "", fmt.Errorf("write cert: %w", err)
		}
		if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
			return nil, "", fmt.Errorf("write key: %w", err)
		}
	}

	// Create TLS config
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, "", fmt.Errorf("load key pair: %w", err)
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	return tlsCfg, fpStr, nil
}

// LoadCertificate loads a TLS certificate from the given cert and key files.
func LoadCertificate(certFile, keyFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load certificate: %w", err)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}, nil
}
