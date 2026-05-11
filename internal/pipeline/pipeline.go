// Package pipeline orchestrates scanners and the redactor for a single
// request or response body. Scanners run concurrently; the redactor runs once
// on the merged findings.
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

// Result is what Process returns: the (possibly redacted) body plus the
// findings the scanners produced.
type Result struct {
	Data     []byte
	Findings []api.Finding
}

// Process fans out to every scanner concurrently, then applies the redactor.
//
// Scanner errors are collected and returned via errors.Join alongside any
// findings the other scanners produced — callers can choose fail-open or
// fail-closed semantics. A redactor error is similarly joined, but the
// original (unredacted) data is returned in that case.
func (p *Pipeline) Process(ctx context.Context, data []byte, hints api.Hints) (Result, error) {
	if len(data) == 0 || len(p.scanners) == 0 {
		return Result{Data: data}, nil
	}

	type scanResult struct {
		findings []api.Finding
		err      error
	}
	results := make([]scanResult, len(p.scanners))

	var wg sync.WaitGroup
	for i, s := range p.scanners {
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
	scanErr := errors.Join(errs...)

	if len(allFindings) == 0 || p.redactor == nil {
		return Result{Data: data, Findings: allFindings}, scanErr
	}

	redacted, err := p.redactor.Redact(ctx, data, allFindings)
	if err != nil {
		return Result{Data: data, Findings: allFindings}, errors.Join(scanErr, err)
	}
	return Result{Data: redacted, Findings: allFindings}, scanErr
}
