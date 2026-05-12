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
	scanners          []api.Scanner
	transformScanners []api.Scanner
	redactor          api.Redactor
}

// transformAware is the opt-in marker for scanners that want to be invoked
// on the pipeline's transformed views of the body (URL-decode, NFKC,
// base64-decode, SQL comment strip, whitespace stitch). Built-in regex
// scanners implement it; plugin scanners default off because they
// typically bring their own context awareness (NER, semantic parsers)
// and don't benefit from synthetic stitched/decoded views — and in
// practice are harmed by them (e.g. NER firing on a fused mega-token
// that pattern-matches as a URL).
type transformAware interface {
	AcceptsTransforms() bool
}

// New constructs a Pipeline. scanners may be empty (Process becomes a no-op),
// and redactor may be nil (findings are reported but the body is not
// rewritten).
func New(scanners []api.Scanner, redactor api.Redactor) *Pipeline {
	var transformScanners []api.Scanner
	for _, s := range scanners {
		if ta, ok := s.(transformAware); ok && ta.AcceptsTransforms() {
			transformScanners = append(transformScanners, s)
		}
	}
	return &Pipeline{
		scanners:          scanners,
		transformScanners: transformScanners,
		redactor:          redactor,
	}
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
//     one token. Runs in two flavors — a broad pass that includes
//     letters in eligibility (catches `alice @ example.com`, AWS keys,
//     Stripe keys) and a narrow pass that treats letters as region
//     blockers (catches `4 1 5 - 5 5 5 - 0 1 8 8` embedded in prose
//     without dragging the prose along).
//
// Each pass's findings are mapped back to byte ranges in the original
// buffer and deduped against earlier findings by `(type, range)`.
//
// Transformed passes only fan out to scanners that implement the
// AcceptsTransforms() bool opt-in. Built-in regex scanners (pii,
// secrets, sqli, code) opt in; external plugins default off so an NER
// model isn't asked to interpret synthetic mega-tokens produced by
// stitching whitespace out of prose.
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

	// Transformed passes only fan out to scanners that opted in via
	// AcceptsTransforms(). Skip the per-transform pre-checks entirely
	// when no scanner wants them — saves a body walk per pre-check.
	if len(p.transformScanners) == 0 {
		return findings, scanErr
	}

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

		// Narrow digit-only stitch runs alongside the broad one. They
		// produce different regions for inputs like
		// `My number is 4 1 5 - …` where the broad stitch fuses the
		// prose with the digits (breaking the phone regex's `\b`),
		// while the narrow stitch picks up just the digit-and-separator
		// span. mergeNew dedupes any overlap by (type, range).
		extra, err = p.transformedPass(ctx, data, hints, digitStitch)
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
	findings, err := ScanWith(ctx, p.transformScanners, transformed, hints)
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
