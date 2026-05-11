package config

import (
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func writeTemp(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "config.yaml")
	require.NoError(t, os.WriteFile(p, []byte(body), 0o600))
	return p
}

func TestDefault_IsValid(t *testing.T) {
	require.NoError(t, Default().Validate())
}

func TestLoad_FullValidConfig(t *testing.T) {
	p := writeTemp(t, `
listen: "0.0.0.0:9000"
log:
  level: debug
  format: json
limits:
  max_body_size: 1024
  read_timeout_seconds: 5
  write_timeout_seconds: 6
  idle_timeout_seconds: 7
scanners:
  - name: pii
    enabled: true
  - name: secrets
    enabled: false
redactor:
  name: mask
  config:
    placeholder: "***"
`)
	cfg, err := Load(p)
	require.NoError(t, err)
	assert.Equal(t, "0.0.0.0:9000", cfg.Listen)
	assert.Equal(t, "debug", cfg.Log.Level)
	assert.Equal(t, "json", cfg.Log.Format)
	assert.EqualValues(t, 1024, cfg.Limits.MaxBodySize)
	assert.Equal(t, []string{"pii"}, cfg.EnabledScanners())
	assert.Equal(t, "mask", cfg.Redactor.Name)
	assert.Equal(t, "***", cfg.Redactor.Config["placeholder"])
}

func TestLoad_MissingFile(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "nope.yaml"))
	assert.Error(t, err)
}

func TestLoad_UnknownFieldRejected(t *testing.T) {
	p := writeTemp(t, `
listen: "127.0.0.1:8080"
mystery_field: 42
scanners:
  - name: pii
    enabled: true
redactor:
  name: mask
`)
	_, err := Load(p)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "mystery_field")
}

func TestValidate_RejectsEmptyListen(t *testing.T) {
	c := Default()
	c.Listen = ""
	assert.Error(t, c.Validate())
}

func TestValidate_RejectsNonPositiveMaxBody(t *testing.T) {
	c := Default()
	c.Limits.MaxBodySize = 0
	assert.Error(t, c.Validate())
}

func TestValidate_RejectsNegativeTimeouts(t *testing.T) {
	c := Default()
	c.Limits.ReadTimeoutS = -1
	assert.Error(t, c.Validate())
}

func TestValidate_RejectsBadLogLevel(t *testing.T) {
	c := Default()
	c.Log.Level = "verbose"
	assert.Error(t, c.Validate())
}

func TestValidate_RejectsBadLogFormat(t *testing.T) {
	c := Default()
	c.Log.Format = "xml"
	assert.Error(t, c.Validate())
}

func TestValidate_RejectsMissingRedactor(t *testing.T) {
	c := Default()
	c.Redactor.Name = ""
	assert.Error(t, c.Validate())
}

func TestValidate_RejectsScannerWithoutName(t *testing.T) {
	c := Default()
	c.Scanners = append(c.Scanners, ScannerConfig{Enabled: true})
	assert.Error(t, c.Validate())
}

func TestValidate_RequiresAtLeastOneEnabledScanner(t *testing.T) {
	c := Default()
	for i := range c.Scanners {
		c.Scanners[i].Enabled = false
	}
	assert.Error(t, c.Validate())
}

func TestParseLogLevel(t *testing.T) {
	cases := map[string]slog.Level{
		"":        slog.LevelInfo,
		"info":    slog.LevelInfo,
		"DEBUG":   slog.LevelDebug,
		"warn":    slog.LevelWarn,
		"warning": slog.LevelWarn,
		"error":   slog.LevelError,
	}
	for in, want := range cases {
		got, err := ParseLogLevel(in)
		require.NoError(t, err, in)
		assert.Equal(t, want, got, in)
	}

	_, err := ParseLogLevel("loud")
	assert.Error(t, err)
}

func TestLimits_Durations(t *testing.T) {
	l := LimitsConfig{ReadTimeoutS: 1, WriteTimeoutS: 2, IdleTimeoutS: 3}
	assert.Equal(t, "1s", l.ReadTimeout().String())
	assert.Equal(t, "2s", l.WriteTimeout().String())
	assert.Equal(t, "3s", l.IdleTimeout().String())
}

func TestEnabledScanners_OrderPreserved(t *testing.T) {
	c := &Config{Scanners: []ScannerConfig{
		{Name: "a", Enabled: true},
		{Name: "b", Enabled: false},
		{Name: "c", Enabled: true},
	}}
	assert.Equal(t, []string{"a", "c"}, c.EnabledScanners())
}

func TestValidate_MITMRequiresCAPaths(t *testing.T) {
	c := Default()
	c.TLS.MITM = true
	// Default leaves CertPath/KeyPath empty.
	assert.Error(t, c.Validate())

	c.TLS.CA.CertPath = "/etc/tg-proxy/ca.crt"
	c.TLS.CA.KeyPath = "/etc/tg-proxy/ca.key"
	assert.NoError(t, c.Validate())
}

func TestValidate_NegativeLeafCacheSizeRejected(t *testing.T) {
	c := Default()
	c.TLS.LeafCacheSize = -1
	assert.Error(t, c.Validate())
}

func TestDefaultCAPaths_UnderUserConfigDir(t *testing.T) {
	certPath, keyPath, err := DefaultCAPaths()
	require.NoError(t, err)
	assert.Contains(t, certPath, "tg-proxy")
	assert.Contains(t, keyPath, "tg-proxy")
	assert.True(t, strings.HasSuffix(certPath, "ca.crt"))
	assert.True(t, strings.HasSuffix(keyPath, "ca.key"))
}

func TestLoad_TLSSection(t *testing.T) {
	p := writeTemp(t, `
listen: "127.0.0.1:8080"
tls:
  mitm: true
  leaf_cache_size: 256
  upstream_insecure: true
  ca:
    cert_path: "/srv/tg-proxy/ca.crt"
    key_path: "/srv/tg-proxy/ca.key"
    organization: "Acme CA"
scanners:
  - name: pii
    enabled: true
redactor:
  name: mask
`)
	cfg, err := Load(p)
	require.NoError(t, err)
	assert.True(t, cfg.TLS.MITM)
	assert.Equal(t, 256, cfg.TLS.LeafCacheSize)
	assert.True(t, cfg.TLS.UpstreamInsecure)
	assert.Equal(t, "/srv/tg-proxy/ca.crt", cfg.TLS.CA.CertPath)
	assert.Equal(t, "Acme CA", cfg.TLS.CA.Organization)
}
