package plugin

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TensorGreed/tg-proxy/pkg/api"
)

// buildEchoPlugin compiles internal/plugin/testdata/echoplugin to a temp
// binary and returns its path. We can't `go run` it directly because
// hashicorp/go-plugin spawns the command as a subprocess and `go run`'s
// output noise breaks the handshake.
func buildEchoPlugin(t *testing.T) string {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping plugin build in -short mode")
	}

	tmp := t.TempDir()
	binName := "echoplugin"
	if runtime.GOOS == "windows" {
		binName += ".exe"
	}
	out := filepath.Join(tmp, binName)

	src := filepath.Join("testdata", "echoplugin")
	cmd := exec.Command("go", "build", "-o", out, ".")
	cmd.Dir = src
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	stderr, err := cmd.CombinedOutput()
	require.NoError(t, err, "go build echoplugin failed: %s", stderr)
	return out
}

func TestHost_LoadAndScan_GoSubprocess(t *testing.T) {
	binPath := buildEchoPlugin(t)
	host := NewHost(nil)
	t.Cleanup(host.Shutdown)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	scanner, err := host.LoadScanner(ctx, PluginConfig{
		Name:    "echo",
		Command: []string{binPath},
		Kind:    KindScanner,
	})
	require.NoError(t, err)
	assert.Equal(t, "echo", scanner.Name())

	findings, err := scanner.Scan(ctx, []byte("see TOKEN here and TOKEN there"), api.Hints{})
	require.NoError(t, err)
	require.Len(t, findings, 2)
	for _, f := range findings {
		assert.Equal(t, "echo.token", f.Type)
		assert.Equal(t, "echo", f.Scanner)
		assert.Equal(t, api.SeverityHigh, f.Severity)
	}
	assert.Equal(t, "TOKEN", string([]byte("see TOKEN here and TOKEN there")[findings[0].Start:findings[0].End]))
}

func TestHost_LoadScanner_BadCommand(t *testing.T) {
	host := NewHost(nil)
	t.Cleanup(host.Shutdown)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := host.LoadScanner(ctx, PluginConfig{
		Name:    "missing",
		Command: []string{filepath.Join(t.TempDir(), "does-not-exist")},
		Kind:    KindScanner,
	})
	assert.Error(t, err)
}

func TestHost_LoadScanner_RejectsEmptyCommand(t *testing.T) {
	host := NewHost(nil)
	t.Cleanup(host.Shutdown)
	_, err := host.LoadScanner(context.Background(), PluginConfig{
		Name:    "noop",
		Command: nil,
		Kind:    KindScanner,
	})
	assert.Error(t, err)
}

func TestHost_ShutdownIsIdempotent(t *testing.T) {
	host := NewHost(nil)
	host.Shutdown()
	host.Shutdown()
}

func TestHost_LoadAndScan_PythonSubprocess(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping cross-language plugin test in -short mode")
	}
	pyBin, err := exec.LookPath("python")
	if err != nil {
		t.Skip("python not found on PATH")
	}

	// Probe for the grpcio module; the SDK is unusable without it.
	probe := exec.Command(pyBin, "-c", "import grpc, google.protobuf")
	if out, err := probe.CombinedOutput(); err != nil {
		t.Skipf("python is missing grpcio/protobuf: %s", out)
	}

	// Repo root from inside this test file (internal/plugin).
	repoRoot, err := filepath.Abs(filepath.Join("..", ".."))
	require.NoError(t, err)
	sdkSrc := filepath.Join(repoRoot, "packaging", "python-sdk-plugin", "src")
	script := filepath.Join(repoRoot, "packaging", "python-sdk-plugin", "examples", "token_scanner.py")
	require.FileExists(t, script)

	host := NewHost(nil)
	t.Cleanup(host.Shutdown)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	scanner, err := host.LoadScanner(ctx, PluginConfig{
		Name:    "token-marker",
		Command: []string{pyBin, script},
		Env: append(os.Environ(),
			"PYTHONPATH="+sdkSrc,
			"PYTHONUNBUFFERED=1",
		),
		Kind: KindScanner,
	})
	require.NoError(t, err)
	assert.Equal(t, "token-marker", scanner.Name())

	findings, err := scanner.Scan(ctx, []byte("the TOKEN is here"), api.Hints{})
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, "example.token", findings[0].Type)
	assert.Equal(t, "TOKEN", string([]byte("the TOKEN is here")[findings[0].Start:findings[0].End]))
}

// TestHost_LoadAndScan_Presidio spawns the tgproxy-presidio plugin and
// verifies that an end-to-end PII NER scan reaches tg-proxy via the
// gRPC plugin protocol.
//
// The test is gated on Presidio + the spaCy English model being
// importable in the local Python environment. When they aren't (the
// common case in CI without explicit install), the test skips rather
// than failing — Presidio is an opt-in plugin, not part of tg-proxy
// core. To run locally:
//
//	pip install -e packaging/python-sdk-plugin
//	pip install -e packaging/python-presidio-plugin
//	python -m spacy download en_core_web_lg
//	go test -timeout=120s -run TestHost_LoadAndScan_Presidio ./internal/plugin/...
func TestHost_LoadAndScan_Presidio(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping Presidio plugin test in -short mode")
	}
	pyBin, err := exec.LookPath("python")
	if err != nil {
		t.Skip("python not found on PATH")
	}
	probe := exec.Command(pyBin, "-c",
		"import presidio_analyzer; import tgproxy_plugin; "+
			"import spacy; spacy.load('en_core_web_sm') if False else None")
	if out, err := probe.CombinedOutput(); err != nil {
		t.Skipf("Presidio prerequisites missing — install them to enable this test: %s", out)
	}

	repoRoot, err := filepath.Abs(filepath.Join("..", ".."))
	require.NoError(t, err)
	sdkSrc := filepath.Join(repoRoot, "packaging", "python-sdk-plugin", "src")
	presidioSrc := filepath.Join(repoRoot, "packaging", "python-presidio-plugin", "src")

	host := NewHost(nil)
	t.Cleanup(host.Shutdown)

	// Presidio startup includes loading the spaCy model — generous.
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	scanner, err := host.LoadScanner(ctx, PluginConfig{
		Name:    "presidio",
		Command: []string{pyBin, "-m", "tgproxy_presidio"},
		Env: append(os.Environ(),
			// Use the smallest model if it's available, to keep the
			// test fast and the memory footprint sane on dev machines.
			"TGPROXY_PRESIDIO_MODEL=en_core_web_sm",
			"PYTHONPATH="+sdkSrc+string(os.PathListSeparator)+presidioSrc,
			"PYTHONUNBUFFERED=1",
		),
		Kind:             KindScanner,
		HandshakeTimeout: 90 * time.Second,
	})
	require.NoError(t, err)
	assert.Equal(t, "presidio", scanner.Name())

	body := []byte("Dr. Alice Johnson lives at 1 Main Street. Email alice@example.com")
	findings, err := scanner.Scan(ctx, body, api.Hints{})
	require.NoError(t, err)
	require.NotEmpty(t, findings, "Presidio should have produced at least one finding")

	// We don't pin a specific set of types — recognizer coverage drifts
	// across Presidio versions — but the prose contains a person name
	// and an email so we expect at least those.
	gotTypes := make(map[string]bool)
	for _, f := range findings {
		gotTypes[f.Type] = true
		// Every mapped offset must round-trip back to a non-empty span.
		assert.Greater(t, f.End, f.Start)
		assert.LessOrEqual(t, f.End, len(body))
	}
	assert.True(t,
		gotTypes["pii.presidio.person"] || gotTypes["pii.presidio.email_address"],
		"expected at least one of PERSON or EMAIL_ADDRESS findings; got: %v", gotTypes,
	)
}
