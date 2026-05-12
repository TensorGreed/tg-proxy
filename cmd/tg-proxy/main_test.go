package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TensorGreed/tg-proxy/internal/config"
	plug "github.com/TensorGreed/tg-proxy/internal/plugin"
)

func TestLoadConfig_Empty(t *testing.T) {
	cfg, err := loadConfig("")
	require.NoError(t, err)
	assert.Equal(t, "127.0.0.1:8080", cfg.Listen)
}

func TestLoadConfig_FromFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(path, []byte(`
listen: "0.0.0.0:9999"
scanners:
  - name: pii
    enabled: true
redactor:
  name: mask
`), 0o600))

	cfg, err := loadConfig(path)
	require.NoError(t, err)
	assert.Equal(t, "0.0.0.0:9999", cfg.Listen)
}

func TestBuildLogger_TextAndJSON(t *testing.T) {
	for _, format := range []string{"text", "json", ""} {
		t.Run(format, func(t *testing.T) {
			logger, err := buildLogger(config.LogConfig{Level: "info", Format: format})
			require.NoError(t, err)
			assert.NotNil(t, logger)
		})
	}
}

func TestBuildLogger_BadLevel(t *testing.T) {
	_, err := buildLogger(config.LogConfig{Level: "loud"})
	assert.Error(t, err)
}

func TestBuildScanners_RegistersDefaults(t *testing.T) {
	cfg := config.Default()
	host := plug.NewHost(nil)
	t.Cleanup(host.Shutdown)
	scanners, err := buildScanners(context.Background(), cfg, host)
	require.NoError(t, err)
	names := make([]string, len(scanners))
	for i, s := range scanners {
		names[i] = s.Name()
	}
	// Defaults: pii and secrets are enabled; sqli and code are opt-in.
	assert.Contains(t, names, "pii")
	assert.Contains(t, names, "secrets")
	assert.NotContains(t, names, "sqli")
	assert.NotContains(t, names, "code")
}

func TestBuildScanners_UnknownScannerErrors(t *testing.T) {
	cfg := config.Default()
	cfg.Scanners = []config.ScannerConfig{{Name: "wibble", Enabled: true}}
	host := plug.NewHost(nil)
	t.Cleanup(host.Shutdown)
	_, err := buildScanners(context.Background(), cfg, host)
	assert.Error(t, err)
}

func TestBuildScanners_NoEnabledScannersErrors(t *testing.T) {
	cfg := config.Default()
	cfg.Scanners = []config.ScannerConfig{
		{Name: "pii", Enabled: false},
		{Name: "secrets", Enabled: false},
	}
	host := plug.NewHost(nil)
	t.Cleanup(host.Shutdown)
	_, err := buildScanners(context.Background(), cfg, host)
	assert.Error(t, err)
}

func TestBuildRedactor_DefaultMask(t *testing.T) {
	cfg := config.Default()
	host := plug.NewHost(nil)
	t.Cleanup(host.Shutdown)
	r, err := buildRedactor(context.Background(), cfg, host)
	require.NoError(t, err)
	assert.Equal(t, "mask", r.Name())
}

func TestBuildRedactor_UnknownErrors(t *testing.T) {
	cfg := config.Default()
	cfg.Redactor.Name = "wibble"
	host := plug.NewHost(nil)
	t.Cleanup(host.Shutdown)
	_, err := buildRedactor(context.Background(), cfg, host)
	assert.Error(t, err)
}

func TestResolvedVersion_LdflagsWins(t *testing.T) {
	orig := version
	t.Cleanup(func() { version = orig })

	version = "1.2.3"
	assert.Equal(t, "1.2.3", resolvedVersion())
}

func TestResolvedVersion_FallsBackToBuildInfo(t *testing.T) {
	orig := version
	t.Cleanup(func() { version = orig })

	version = "dev"
	// Inside `go test` the main module's BuildInfo version is "(devel)",
	// so resolvedVersion should fall back to "dev". This proves the
	// fallback chain doesn't crash on the dev case.
	assert.Equal(t, "dev", resolvedVersion())
}

func TestBuildCertStore_DisabledReturnsNil(t *testing.T) {
	cfg := config.Default()
	cfg.TLS.MITM = false
	store, err := buildCertStore(cfg)
	require.NoError(t, err)
	assert.Nil(t, store)
}

func TestBuildCertStore_MissingCAErrors(t *testing.T) {
	cfg := config.Default()
	cfg.TLS.MITM = true
	cfg.TLS.CA.CertPath = filepath.Join(t.TempDir(), "missing.crt")
	cfg.TLS.CA.KeyPath = filepath.Join(t.TempDir(), "missing.key")
	_, err := buildCertStore(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "tg-proxy ca generate")
}

func TestBuildCertStore_LoadsAndBuilds(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")
	withInstaller(t, &fakeInstaller{})
	captureCAOutput(t)
	require.NoError(t, runCAGenerate([]string{
		"-cert-path", certPath, "-key-path", keyPath, "-org", "BuildCS CA",
	}))

	cfg := config.Default()
	cfg.TLS.MITM = true
	cfg.TLS.CA.CertPath = certPath
	cfg.TLS.CA.KeyPath = keyPath
	cfg.TLS.LeafCacheSize = 0 // exercises the cacheSize<=0 default branch

	store, err := buildCertStore(cfg)
	require.NoError(t, err)
	require.NotNil(t, store)
	leaf, err := store.LeafFor("example.com")
	require.NoError(t, err)
	assert.NotNil(t, leaf)
}
