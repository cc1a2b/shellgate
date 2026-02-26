// Package config provides Viper-based configuration management for ShellGate.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/viper"
)

// DefaultConfigDir returns the default configuration directory.
func DefaultConfigDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(".", ".shellgate")
	}
	return filepath.Join(home, ".shellgate")
}

// Load reads configuration from file, environment variables, and defaults.
// Priority: flags > env > config file > defaults.
func Load() error {
	configDir := DefaultConfigDir()

	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(configDir)
	viper.AddConfigPath(".")

	// Environment variable mapping
	viper.SetEnvPrefix("SHELLGATE")
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_", ".", "_"))
	viper.AutomaticEnv()

	// Defaults
	viper.SetDefault("host", "0.0.0.0")
	viper.SetDefault("port", 8080)
	viper.SetDefault("auth", "token")
	viper.SetDefault("rate-limit", 10)
	viper.SetDefault("max-sessions", 5)
	viper.SetDefault("timeout", "30m")
	viper.SetDefault("idle-timeout", "10m")
	viper.SetDefault("share-ttl", "1h")
	viper.SetDefault("share-max-viewers", 10)

	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			return nil // Config file not found; ignore
		}
		return fmt.Errorf("read config: %w", err)
	}

	return nil
}

// EnsureConfigDir creates the config directory if it doesn't exist.
func EnsureConfigDir() error {
	dir := DefaultConfigDir()
	return os.MkdirAll(dir, 0700)
}
