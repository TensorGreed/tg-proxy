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
	"bytes"
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
// Beyond the raw pass, Scan runs scanners over additional transformed
// views of the body when the corresponding pre-check fires:
//
//   - URL-decoded view (when `%` is present): catches `alice%40example.com`,
//     `ghp%5F...`, `%55%4E%49%4F%4E SELECT`, etc.
//   - NFKC-normalized view (when non-ASCII is present): catches Unicode
//     confusables and lookalikes — `ⅾef foo()` → `def foo()`, `ⅽlass` →
//     `class`, full-width `＠` → `@`, ligatures, fancy digits, etc.
//   - Base64-decoded view (when a 16+ char base64-alphabet run is present
//     and decodes to mostly-printable bytes): catches secrets and code
//     wrapped inside `atob(...)`, env-vars set to base64 blobs, etc.
//   - SQL-comment-stripped view (when `/*` is present): foils MySQL's
//     `/*...*/`-as-whitespace evasion like `UN/**/ION SE/**/LECT`.
//   - Whitespace-stitched view (when ASCII space or tab is present):
//     fuses token-shaped regions broken by single whitespaces back into
//     one token (`alice @ example.com` → `alice@example.com`).
//
// Each pass's findings are mapped back to byte ranges in the original
// buffer and deduped against earlier findings by `(type, range)`.
//
// Exported so streaming callers can reuse the same fan-out without going
// through Process (which also runs the redactor). Note: the streaming
// path (StreamProcessor) calls ScanWith directly and therefore does NOT
// get any of the transformed passes — chunk-boundary-aware versions are
// follow-ups.
func (p *Pipeline) Scan(ctx context.Context, data []byte, hints api.Hints) ([]api.Finding, error) {
	if len(data) == 0 || len(p.scanners) == 0 {
		return nil, nil
	}

	findings, scanErr := ScanWith(ctx, p.scanners, data, hints)

	if containsPercent(data) {
		extra, err := p.transformedPass(ctx, data, hints, urlDecode)
		scanErr = errors.Join(scanErr, err)
		findings = mergeNew(findings, extra)
	}

	if containsNonASCII(data) {
		extra, err := p.transformedPass(ctx, data, hints, nfkcNormalize)
		scanErr = errors.Join(scanErr, err)
		findings = mergeNew(findings, extra)
	}

	if containsBase64Candidate(data) {
		extra, err := p.transformedPass(ctx, data, hints, base64Decode)
		scanErr = errors.Join(scanErr, err)
		findings = mergeNew(findings, extra)
	}

	if containsSlashStarComment(data) {
		extra, err := p.transformedPass(ctx, data, hints, sqliCommentStrip)
		scanErr = errors.Join(scanErr, err)
		findings = mergeNew(findings, extra)
	}

	if containsSpaceOrTab(data) {
		extra, err := p.transformedPass(ctx, data, hints, whitespaceStitch)
		scanErr = errors.Join(scanErr, err)
		findings = mergeNew(findings, extra)
	}

	return findings, scanErr
}

// transformedPass runs scanners over the transform(data) view of the body
// and translates each finding's offsets back to positions in the original
// data via the returned mapping. Returns nil when the transform was a no-op
// (signaled by transform returning nil for origIdx or unchanged bytes).
func (p *Pipeline) transformedPass(
	ctx context.Context,
	data []byte,
	hints api.Hints,
	transform func([]byte) ([]byte, []int),
) ([]api.Finding, error) {
	transformed, origIdx := transform(data)
	if origIdx == nil || bytes.Equal(transformed, data) {
		return nil, nil
	}
	findings, err := ScanWith(ctx, p.scanners, transformed, hints)
	mapped := findings[:0]
	for _, f := range findings {
		if f.Start < 0 || f.End > len(origIdx)-1 || f.Start >= f.End {
			continue
		}
		f.Start = origIdx[f.Start]
		f.End = origIdx[f.End]
		mapped = append(mapped, f)
	}
	return mapped, err
}

// mergeNew appends to existing any finding from extra that doesn't overlap
// an existing finding of the same type. Used to dedupe the raw scan
// against the URL-decode and NFKC passes when the same value appears
// across views.
func mergeNew(existing, extra []api.Finding) []api.Finding {
	for _, f := range extra {
		if !overlapsExisting(existing, f) {
			existing = append(existing, f)
		}
	}
	return existing
}

// overlapsExisting reports whether f overlaps any existing finding of the
// same type.
func overlapsExisting(existing []api.Finding, f api.Finding) bool {
	for _, e := range existing {
		if e.Type == f.Type && e.Start < f.End && f.Start < e.End {
			return true
		}
	}
	return false
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
