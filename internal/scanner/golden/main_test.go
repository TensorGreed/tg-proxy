// Plugin-backed scanners (Presidio, etc.) are loaded once per `go test`
// invocation in TestMain and folded into scannersUnderTest() alongside the
// in-process scanners. When the plugin's prerequisites aren't installed
// (Python, the SDK, the model) the plugin is silently absent from the
// scanner map — corpus runs in CI without Presidio installed still pass,
// they just don't exercise Presidio's positives/negatives.
//
// To opt in locally:
//
//	pip install -e packaging/python-sdk-plugin
//	pip install -e packaging/python-presidio-plugin
//	python -m spacy download en_core_web_sm   # or _md / _lg
//	go test ./internal/scanner/golden/...
package golden

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	plugin "github.com/TensorGreed/tg-proxy/internal/plugin"
	"github.com/TensorGreed/tg-proxy/pkg/api"
)

// pluginHost and pluginScanners are populated in TestMain and consumed by
// scannersUnderTest. Both are nil/empty when no external plugins are
// available, which is the expected state in CI today.
var (
	pluginHost     *plugin.Host
	pluginScanners = map[string]api.Scanner{}
)

func TestMain(m *testing.M) {
	pluginHost = plugin.NewHost(nil)
	defer pluginHost.Shutdown()

	if s := tryLoadPresidio(pluginHost); s != nil {
		pluginScanners["presidio"] = s
	}

	os.Exit(m.Run())
}

// tryLoadPresidio probes the local environment for an importable
// `tgproxy_presidio` package + a working spaCy English model. If both are
// present, it spawns the plugin via `python -m tgproxy_presidio` and
// returns the loaded api.Scanner. Otherwise it returns nil — the corpus
// then runs without the presidio folder being exercised.
func tryLoadPresidio(host *plugin.Host) api.Scanner {
	pyBin, err := exec.LookPath("python")
	if err != nil {
		return nil
	}

	// Cheap probe: import the plugin module and the smallest spaCy model
	// so we don't pay the AnalyzerEngine startup cost before knowing
	// whether the environment is even usable.
	probe := exec.Command(pyBin, "-c",
		"import tgproxy_presidio, presidio_analyzer; "+
			"import spacy; spacy.util.get_package_path('en_core_web_sm')")
	if out, err := probe.CombinedOutput(); err != nil {
		// One line of debug output so a developer running -v can see
		// why Presidio isn't being exercised, without making the run
		// fail.
		_ = out
		return nil
	}

	// Repo root from this file's location: internal/scanner/golden -> ../../..
	repoRoot, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		return nil
	}
	sdkSrc := filepath.Join(repoRoot, "packaging", "python-sdk-plugin", "src")
	presidioSrc := filepath.Join(repoRoot, "packaging", "python-presidio-plugin", "src")

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	scanner, err := host.LoadScanner(ctx, plugin.PluginConfig{
		Name:    "presidio",
		Command: []string{pyBin, "-m", "tgproxy_presidio"},
		Env: append(os.Environ(),
			// Smallest English model keeps test memory + startup
			// reasonable on dev laptops. Override in CI by exporting
			// TGPROXY_PRESIDIO_MODEL before `go test`.
			modelEnv(),
			"PYTHONPATH="+sdkSrc+string(os.PathListSeparator)+presidioSrc,
			"PYTHONUNBUFFERED=1",
		),
		Kind:             plugin.KindScanner,
		HandshakeTimeout: 90 * time.Second,
	})
	if err != nil {
		return nil
	}
	return scanner
}

func modelEnv() string {
	if v := os.Getenv("TGPROXY_PRESIDIO_MODEL"); v != "" {
		return "TGPROXY_PRESIDIO_MODEL=" + v
	}
	return "TGPROXY_PRESIDIO_MODEL=en_core_web_sm"
}
