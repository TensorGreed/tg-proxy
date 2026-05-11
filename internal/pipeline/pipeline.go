// Package pipeline orchestrates scanners and the redactor for a single
// request or response body. Scanners run concurrently; the redactor runs once
// on the merged findings.
//
// Pipeline.Process is the all-in-one entry point used for buffered request
// and response bodies. StreamProcessor (stream.go) reuses the same scanner
// fan-out via Scan() and applies the redactor in a sliding window so SSE and
// HTTP/2 streams stay incremental.
package pipeline

import (
	"context"
	"errors"
	"sync"

	"github.com/TensorGreed/tg-proxy/pkg/api"
)

type Pipeline struct {
	scanners []api.Scanner
	redactor api.Redactor
}

// New constructs a Pipeline. scanners may be empty (Process becomes a no-op),
// and redactor may be nil (findings are reported but the body is not
// rewritten).
func New(scanners []api.Scanner, redactor api.Redactor) *Pipeline {
	return &Pipeline{scanners: scanners, redactor: redactor}
}

// Scanners returns the underlying scanners for callers (e.g. StreamProcessor)
// that need to drive scanning themselves while still sharing this pipeline's
// configuration.
func (p *Pipeline) Scanners() []api.Scanner { return p.scanners }

// Redactor returns the configured redactor (may be nil).
func (p *Pipeline) Redactor() api.Redactor { return p.redactor }

// Result is what Process returns: the (possibly redacted) body plus the
// findings the scanners produced.
type Result struct {
	Data     []byte
	Findings []api.Finding
}

// Scan fans out the given data to every configured scanner concurrently and
// returns the merged findings. Scanner errors are joined via errors.Join.
//
// Exported so streaming callers can reuse the same fan-out without going
// through Process (which also runs the redactor).
func (p *Pipeline) Scan(ctx context.Context, data []byte, hints api.Hints) ([]api.Finding, error) {
	if len(data) == 0 || len(p.scanners) == 0 {
		return nil, nil
	}
	return ScanWith(ctx, p.scanners, data, hints)
}

// ScanWith is the underlying scanner fan-out. Exposed so other components
// (e.g. StreamProcessor with its own scanner list) can use the same logic.
func ScanWith(ctx context.Context, scanners []api.Scanner, data []byte, hints api.Hints) ([]api.Finding, error) {
	if len(data) == 0 || len(scanners) == 0 {
		return nil, nil
	}

	type scanResult struct {
		findings []api.Finding
		err      error
	}
	results := make([]scanResult, len(scanners))

	var wg sync.WaitGroup
	for i, s := range scanners {
		wg.Add(1)
		go func(i int, s api.Scanner) {
			defer wg.Done()
			fs, err := s.Scan(ctx, data, hints)
			results[i] = scanResult{findings: fs, err: err}
		}(i, s)
	}
	wg.Wait()

	var allFindings []api.Finding
	var errs []error
	for _, r := range results {
		allFindings = append(allFindings, r.findings...)
		if r.err != nil {
			errs = append(errs, r.err)
		}
	}
	return allFindings, errors.Join(errs...)
}

// Process fans out to every scanner concurrently, then applies the redactor.
//
// Scanner errors are collected and returned via errors.Join alongside any
// findings the other scanners produced — callers can choose fail-open or
// fail-closed semantics. A redactor error is similarly joined, but the
// original (unredacted) data is returned in that case.
func (p *Pipeline) Process(ctx context.Context, data []byte, hints api.Hints) (Result, error) {
	findings, scanErr := p.Scan(ctx, data, hints)

	if len(findings) == 0 || p.redactor == nil {
		return Result{Data: data, Findings: findings}, scanErr
	}

	redacted, err := p.redactor.Redact(ctx, data, findings)
	if err != nil {
		return Result{Data: data, Findings: findings}, errors.Join(scanErr, err)
	}
	return Result{Data: redacted, Findings: findings}, scanErr
}
