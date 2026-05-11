// Package config loads tg-proxy's YAML configuration, applies defaults, and
// validates the result. Unknown fields are rejected to catch typos early.
package config

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// DefaultCAPaths returns the default locations for the CA cert and key under
// os.UserConfigDir/tg-proxy/. Callers should use these when the user has not
// set tls.ca.{cert_path,key_path} in config.
func DefaultCAPaths() (certPath, keyPath string, err error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", "", err
	}
	base := filepath.Join(dir, "tg-proxy")
	return filepath.Join(base, "ca.crt"), filepath.Join(base, "ca.key"), nil
}

// Default returns a Config populated with safe defaults. main uses this when
// no -config flag is supplied.
func Default() *Config {
	return &Config{
		Listen: "127.0.0.1:8080",
		Log:    LogConfig{Level: "info", Format: "text"},
		Limits: LimitsConfig{
			MaxBodySize:   10 * 1024 * 1024,
			ReadTimeoutS:  30,
			WriteTimeoutS: 30,
			IdleTimeoutS:  120,
		},
		TLS: TLSConfig{
			MITM: false,
			CA: CAConfig{
				CertPath:     "", // resolved at runtime via DefaultCAPaths
				KeyPath:      "",
				Organization: "tg-proxy CA",
			},
			LeafCacheSize:   1024,
			UpstreamInsecure: false,
		},
		Scanners: []ScannerConfig{{Name: "pii", Enabled: true}},
		Redactor: RedactorConfig{
			Name:   "mask",
			Config: map[string]any{"placeholder": "[REDACTED]"},
		},
	}
}

type Config struct {
	Listen   string          `yaml:"listen"`
	Log      LogConfig       `yaml:"log"`
	Limits   LimitsConfig    `yaml:"limits"`
	TLS      TLSConfig       `yaml:"tls"`
	Scanners []ScannerConfig `yaml:"scanners"`
	Redactor RedactorConfig  `yaml:"redactor"`
}

type LogConfig struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
}

type LimitsConfig struct {
	MaxBodySize   int64 `yaml:"max_body_size"`
	ReadTimeoutS  int   `yaml:"read_timeout_seconds"`
	WriteTimeoutS int   `yaml:"write_timeout_seconds"`
	IdleTimeoutS  int   `yaml:"idle_timeout_seconds"`
}

type ScannerConfig struct {
	Name    string `yaml:"name"`
	Enabled bool   `yaml:"enabled"`
}

// TLSConfig controls TLS interception. When MITM is true the proxy
// terminates client TLS on CONNECT using a forged leaf certificate signed by
// the CA at CA.CertPath, so request and response bodies can be scanned.
// When false the proxy blind-tunnels HTTPS traffic (M1 behavior).
type TLSConfig struct {
	MITM             bool     `yaml:"mitm"`
	CA               CAConfig `yaml:"ca"`
	LeafCacheSize    int      `yaml:"leaf_cache_size"`
	UpstreamInsecure bool     `yaml:"upstream_insecure"`
}

type CAConfig struct {
	CertPath     string `yaml:"cert_path"`
	KeyPath      string `yaml:"key_path"`
	Organization string `yaml:"organization"`
}

type RedactorConfig struct {
	Name   string         `yaml:"name"`
	Config map[string]any `yaml:"config"`
}

// Load reads, parses, and validates a YAML config file. Unknown fields
// produce an error so typos surface early instead of silently disabling
// behavior.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: read %s: %w", path, err)
	}
	cfg := Default()
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true)
	if err := dec.Decode(cfg); err != nil {
		return nil, fmt.Errorf("config: parse %s: %w", path, err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("config: validate %s: %w", path, err)
	}
	return cfg, nil
}

// Validate enforces invariants the proxy relies on: at least one scanner, a
// configured redactor, sane limits, and a parseable log level.
func (c *Config) Validate() error {
	if c.Listen == "" {
		return errors.New("listen must be set")
	}
	if c.Limits.MaxBodySize <= 0 {
		return errors.New("limits.max_body_size must be > 0")
	}
	if c.Limits.ReadTimeoutS < 0 || c.Limits.WriteTimeoutS < 0 || c.Limits.IdleTimeoutS < 0 {
		return errors.New("timeouts must be >= 0")
	}
	if _, err := ParseLogLevel(c.Log.Level); err != nil {
		return err
	}
	switch c.Log.Format {
	case "", "text", "json":
	default:
		return fmt.Errorf("log.format must be text or json, got %q", c.Log.Format)
	}
	if c.Redactor.Name == "" {
		return errors.New("redactor.name must be set")
	}
	if c.TLS.MITM {
		if c.TLS.CA.CertPath == "" || c.TLS.CA.KeyPath == "" {
			return errors.New("tls.mitm requires tls.ca.cert_path and tls.ca.key_path")
		}
	}
	if c.TLS.LeafCacheSize < 0 {
		return errors.New("tls.leaf_cache_size must be >= 0")
	}
	enabled := 0
	for _, s := range c.Scanners {
		if s.Name == "" {
			return errors.New("scanner entry missing name")
		}
		if s.Enabled {
			enabled++
		}
	}
	if enabled == 0 {
		return errors.New("at least one scanner must be enabled")
	}
	return nil
}

// ParseLogLevel maps a string to slog.Level. Empty input maps to info.
func ParseLogLevel(s string) (slog.Level, error) {
	switch strings.ToLower(s) {
	case "", "info":
		return slog.LevelInfo, nil
	case "debug":
		return slog.LevelDebug, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return 0, fmt.Errorf("invalid log level %q", s)
	}
}

// ReadTimeout returns the read timeout as a time.Duration.
func (l LimitsConfig) ReadTimeout() time.Duration {
	return time.Duration(l.ReadTimeoutS) * time.Second
}

// WriteTimeout returns the write timeout as a time.Duration.
func (l LimitsConfig) WriteTimeout() time.Duration {
	return time.Duration(l.WriteTimeoutS) * time.Second
}

// IdleTimeout returns the idle timeout as a time.Duration.
func (l LimitsConfig) IdleTimeout() time.Duration {
	return time.Duration(l.IdleTimeoutS) * time.Second
}

// EnabledScanners returns the names of scanners marked enabled, preserving
// the order they appear in the config.
func (c *Config) EnabledScanners() []string {
	out := make([]string, 0, len(c.Scanners))
	for _, s := range c.Scanners {
		if s.Enabled {
			out = append(out, s.Name)
		}
	}
	return out
}
