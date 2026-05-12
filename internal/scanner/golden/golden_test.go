// Package golden is the regression suite for tg-proxy's built-in scanners.
//
// Each scanner has a corpus under testdata/<scanner>/{positive,negative}/.
//   - positive/<name>.txt + positive/<name>.json
//       The .txt is the body the scanner sees. The .json lists the
//       findings we expect, keyed by `type` and either the literal
//       substring (`match`) or explicit byte offsets (`start`/`end`).
//   - negative/<name>.txt
//       Bodies that must produce zero findings from the scanner that
//       owns this folder. Other scanners may still fire on them.
//
// The test enforces:
//   - every expected finding has an overlapping actual finding of the
//     same type (no false negatives in positives)
//   - no actual findings in negative fixtures (no false positives there)
//
// On -v, a summary table reports per-detector precision and recall so we
// can spot drift as rules evolve.
package golden

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/TensorGreed/tg-proxy/internal/scanner/code"
	"github.com/TensorGreed/tg-proxy/internal/scanner/pii"
	"github.com/TensorGreed/tg-proxy/internal/scanner/secrets"
	"github.com/TensorGreed/tg-proxy/internal/scanner/sqli"
	"github.com/TensorGreed/tg-proxy/pkg/api"
)

// expected describes one finding the fixture author expects to see.
// Either `match` (a substring of the body) or `start`/`end` (explicit byte
// offsets) must be provided. `match` is preferred — easier to author and
// stable across whitespace edits.
type expected struct {
	Type  string `json:"type"`
	Match string `json:"match,omitempty"`
	Start *int   `json:"start,omitempty"`
	End   *int   `json:"end,omitempty"`
}

type sidecar struct {
	Findings []expected `json:"findings"`
	Comment  string     `json:"comment,omitempty"`
}

// scannersUnderTest maps the folder name to the scanner instance.
func scannersUnderTest() map[string]api.Scanner {
	return map[string]api.Scanner{
		"pii":     pii.New(),
		"secrets": secrets.New(),
		"sqli":    sqli.New(),
		"code":    code.New(),
	}
}

// metrics accumulates TP/FP/FN counts per (scanner, finding-type) for the
// summary report. Keys are "<scanner>" and "<scanner>:<type>".
type metrics struct {
	tp, fp, fn map[string]int
}

func newMetrics() *metrics {
	return &metrics{tp: map[string]int{}, fp: map[string]int{}, fn: map[string]int{}}
}

func (m *metrics) addTP(scanner, typ string) {
	m.tp[scanner]++
	m.tp[scanner+":"+typ]++
}
func (m *metrics) addFP(scanner, typ string) {
	m.fp[scanner]++
	m.fp[scanner+":"+typ]++
}
func (m *metrics) addFN(scanner, typ string) {
	m.fn[scanner]++
	m.fn[scanner+":"+typ]++
}

// report renders a human-readable summary table. Per-detector lines are
// emitted only when the scanner had at least one positive or negative
// observation for that type.
func (m *metrics) report() string {
	var b strings.Builder
	b.WriteString("\n==== golden corpus summary ====\n")
	keys := uniqueKeys(m.tp, m.fp, m.fn)
	sort.Strings(keys)

	for _, k := range keys {
		tp, fp, fn := m.tp[k], m.fp[k], m.fn[k]
		precision := safeDiv(tp, tp+fp)
		recall := safeDiv(tp, tp+fn)
		fmt.Fprintf(&b, "  %-48s  P=%.3f  R=%.3f  (TP=%d FP=%d FN=%d)\n",
			k, precision, recall, tp, fp, fn)
	}
	return b.String()
}

func uniqueKeys(maps ...map[string]int) []string {
	seen := map[string]struct{}{}
	for _, m := range maps {
		for k := range m {
			seen[k] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	return out
}

func safeDiv(num, denom int) float64 {
	if denom == 0 {
		return 1.0
	}
	return float64(num) / float64(denom)
}

func TestGolden(t *testing.T) {
	m := newMetrics()
	for name, scanner := range scannersUnderTest() {
		t.Run(name, func(t *testing.T) {
			runPositives(t, name, scanner, m)
			runNegatives(t, name, scanner, m)
		})
	}
	t.Log(m.report())
}

func runPositives(t *testing.T, scannerName string, s api.Scanner, m *metrics) {
	dir := filepath.Join("testdata", scannerName, "positive")
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return
		}
		t.Fatalf("read %s: %v", dir, err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".txt") {
			continue
		}
		name := strings.TrimSuffix(e.Name(), ".txt")
		t.Run("positive/"+name, func(t *testing.T) {
			data, side := loadFixture(t, dir, name)
			findings, err := s.Scan(context.Background(), data, api.Hints{})
			if err != nil {
				t.Fatalf("scan error: %v", err)
			}
			assertExpected(t, scannerName, data, findings, side, m)
		})
	}
}

func runNegatives(t *testing.T, scannerName string, s api.Scanner, m *metrics) {
	dir := filepath.Join("testdata", scannerName, "negative")
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return
		}
		t.Fatalf("read %s: %v", dir, err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".txt") {
			continue
		}
		name := strings.TrimSuffix(e.Name(), ".txt")
		t.Run("negative/"+name, func(t *testing.T) {
			path := filepath.Join(dir, name+".txt")
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read %s: %v", path, err)
			}
			findings, err := s.Scan(context.Background(), data, api.Hints{})
			if err != nil {
				t.Fatalf("scan error: %v", err)
			}
			if len(findings) > 0 {
				m.addFP(scannerName, "*")
				for _, f := range findings {
					t.Errorf("unexpected finding in negative fixture: type=%s match=%q",
						f.Type, snippet(data, f.Start, f.End))
				}
			}
		})
	}
}

func loadFixture(t *testing.T, dir, name string) ([]byte, sidecar) {
	t.Helper()
	txtPath := filepath.Join(dir, name+".txt")
	data, err := os.ReadFile(txtPath)
	if err != nil {
		t.Fatalf("read %s: %v", txtPath, err)
	}
	sidePath := filepath.Join(dir, name+".json")
	sideBytes, err := os.ReadFile(sidePath)
	if err != nil {
		t.Fatalf("read sidecar %s: %v", sidePath, err)
	}
	var side sidecar
	if err := json.Unmarshal(sideBytes, &side); err != nil {
		t.Fatalf("parse sidecar %s: %v", sidePath, err)
	}
	return data, side
}

// resolvedRange converts an expected finding into a concrete byte range
// in data, preferring explicit start/end and falling back to substring
// search on `match`.
func resolvedRange(t *testing.T, data []byte, exp expected) (int, int, bool) {
	t.Helper()
	if exp.Start != nil && exp.End != nil {
		return *exp.Start, *exp.End, true
	}
	if exp.Match == "" {
		t.Errorf("fixture is missing both `match` and `start`/`end` for type %q", exp.Type)
		return 0, 0, false
	}
	idx := strings.Index(string(data), exp.Match)
	if idx < 0 {
		t.Errorf("fixture `match` %q (type=%s) not found in body", exp.Match, exp.Type)
		return 0, 0, false
	}
	return idx, idx + len(exp.Match), true
}

func assertExpected(t *testing.T, scannerName string, data []byte, findings []api.Finding, side sidecar, m *metrics) {
	t.Helper()

	// Walk expectations and try to match each to an actual finding. Greedy
	// match by (type, overlap); each actual finding may satisfy at most
	// one expectation.
	usedActual := make([]bool, len(findings))
	for _, exp := range side.Findings {
		es, ee, ok := resolvedRange(t, data, exp)
		if !ok {
			continue
		}
		matched := false
		for i, f := range findings {
			if usedActual[i] {
				continue
			}
			if f.Type != exp.Type {
				continue
			}
			if overlap(f.Start, f.End, es, ee) {
				usedActual[i] = true
				matched = true
				m.addTP(scannerName, exp.Type)
				break
			}
		}
		if !matched {
			m.addFN(scannerName, exp.Type)
			t.Errorf("expected finding not produced: type=%s match=%q (range=%d..%d)",
				exp.Type, snippet(data, es, ee), es, ee)
		}
	}

	// Anything left unused in `findings` is a finding the fixture didn't
	// claim. We treat that as informational rather than FP, because a
	// positive fixture may legitimately contain extras (e.g. an SSN in
	// the same body as the email we cared about). A truly strict mode is
	// available by listing every finding in the sidecar.
}

func overlap(a1, a2, b1, b2 int) bool {
	return a1 < b2 && b1 < a2
}

func snippet(data []byte, start, end int) string {
	if start < 0 {
		start = 0
	}
	if end > len(data) {
		end = len(data)
	}
	if start >= end {
		return ""
	}
	return string(data[start:end])
}
