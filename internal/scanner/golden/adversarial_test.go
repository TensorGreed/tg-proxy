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

	"github.com/TensorGreed/tg-proxy/pkg/api"
)

// adversarialSidecar mirrors the positive sidecar but renames the field to
// make the semantic shift clear: these are findings the rule SHOULD ideally
// produce, but might not yet. The test reports caught/total stats without
// failing the build.
type adversarialSidecar struct {
	Comment       string     `json:"comment,omitempty"`
	IdealFindings []expected `json:"ideal_findings"`
}

type adversarialStats struct {
	caught, total map[string]int // keyed by "<scanner>" and "<scanner>:<type>"
	graduated     []string       // fixture paths whose ideals are fully caught
}

func newAdversarialStats() *adversarialStats {
	return &adversarialStats{
		caught: map[string]int{},
		total:  map[string]int{},
	}
}

func (s *adversarialStats) record(scanner, typ string, hit bool) {
	s.total[scanner]++
	s.total[scanner+":"+typ]++
	if hit {
		s.caught[scanner]++
		s.caught[scanner+":"+typ]++
	}
}

func (s *adversarialStats) report() string {
	var b strings.Builder
	b.WriteString("\n==== adversarial corpus summary (informational; CI does not gate on these) ====\n")
	keys := make([]string, 0, len(s.total))
	for k := range s.total {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		caught, total := s.caught[k], s.total[k]
		recall := 1.0
		if total > 0 {
			recall = float64(caught) / float64(total)
		}
		fmt.Fprintf(&b, "  %-48s  caught %d/%d  (recall=%.3f)\n", k, caught, total, recall)
	}
	if len(s.graduated) > 0 {
		b.WriteString("\n  Graduation candidates — every ideal finding fires today.\n  Consider moving these to positive/:\n")
		for _, g := range s.graduated {
			fmt.Fprintf(&b, "    %s\n", g)
		}
	}
	return b.String()
}

// TestAdversarial runs the adversarial corpus and reports which ideal
// findings the current rules catch. By design it does not call t.Error /
// t.Fatal on misses — adversarial fixtures are tracked, not gated. Use them
// to measure the rule ceiling and prioritize improvements.
//
// Each scanner has its own testdata/<scanner>/adversarial/ folder. The
// sidecar's `ideal_findings` field lists what the rule SHOULD produce in an
// ideal world. The runner walks every fixture, calls the scanner, and
// counts which ideal findings actually fired.
func TestAdversarial(t *testing.T) {
	stats := newAdversarialStats()
	for name, scanner := range scannersUnderTest() {
		t.Run(name, func(t *testing.T) {
			runAdversarial(t, name, scanner, stats)
		})
	}
	t.Log(stats.report())
}

func runAdversarial(t *testing.T, scannerName string, s api.Scanner, stats *adversarialStats) {
	dir := filepath.Join("testdata", scannerName, "adversarial")
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
		t.Run(name, func(t *testing.T) {
			data, side := loadAdversarial(t, dir, name)
			findings, err := s.Scan(context.Background(), data, api.Hints{})
			if err != nil {
				t.Fatalf("scan error: %v", err)
			}

			// For each ideal finding, did at least one actual finding of
			// the same type overlap the expected range?
			allHit := true
			used := make([]bool, len(findings))
			for _, ideal := range side.IdealFindings {
				es, ee, ok := resolvedRange(t, data, ideal)
				if !ok {
					stats.record(scannerName, ideal.Type, false)
					allHit = false
					continue
				}
				hit := false
				for i, f := range findings {
					if used[i] || f.Type != ideal.Type {
						continue
					}
					if overlap(f.Start, f.End, es, ee) {
						used[i] = true
						hit = true
						break
					}
				}
				stats.record(scannerName, ideal.Type, hit)
				if !hit {
					t.Logf("[adversarial miss] type=%s match=%q", ideal.Type, snippet(data, es, ee))
				} else {
					allHit = false // placeholder so allHit only stays true if EVERY ideal fires
					_ = allHit
				}
			}

			// "Graduation": every ideal fired AND there were ideals to fire.
			if len(side.IdealFindings) > 0 {
				allFired := true
				for _, ideal := range side.IdealFindings {
					es, ee, ok := resolvedRange(t, data, ideal)
					if !ok {
						allFired = false
						break
					}
					found := false
					for _, f := range findings {
						if f.Type == ideal.Type && overlap(f.Start, f.End, es, ee) {
							found = true
							break
						}
					}
					if !found {
						allFired = false
						break
					}
				}
				if allFired {
					stats.graduated = append(stats.graduated,
						filepath.Join("testdata", scannerName, "adversarial", name+".txt"))
				}
			}
		})
	}
}

func loadAdversarial(t *testing.T, dir, name string) ([]byte, adversarialSidecar) {
	t.Helper()
	txtPath := filepath.Join(dir, name+".txt")
	data, err := os.ReadFile(txtPath)
	if err != nil {
		t.Fatalf("read %s: %v", txtPath, err)
	}
	sidePath := filepath.Join(dir, name+".json")
	sideBytes, err := os.ReadFile(sidePath)
	if err != nil {
		t.Fatalf("read %s: %v", sidePath, err)
	}
	var side adversarialSidecar
	if err := json.Unmarshal(sideBytes, &side); err != nil {
		t.Fatalf("parse %s: %v", sidePath, err)
	}
	return data, side
}
