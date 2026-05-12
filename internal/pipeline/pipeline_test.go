package pipeline

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TensorGreed/tg-proxy/internal/redactor/mask"
	"github.com/TensorGreed/tg-proxy/internal/scanner/pii"
	"github.com/TensorGreed/tg-proxy/pkg/api"
)

type stubScanner struct {
	name     string
	findings []api.Finding
	err      error
	calls    atomic.Int32
}

func (s *stubScanner) Name() string { return s.name }
func (s *stubScanner) Scan(context.Context, []byte, api.Hints) ([]api.Finding, error) {
	s.calls.Add(1)
	return s.findings, s.err
}

type stubRedactor struct {
	out []byte
	err error
}

func (r *stubRedactor) Name() string { return "stub" }
func (r *stubRedactor) Redact(context.Context, []byte, []api.Finding) ([]byte, error) {
	return r.out, r.err
}

func TestProcess_EmptyData(t *testing.T) {
	p := New([]api.Scanner{&stubScanner{name: "s"}}, mask.New(""))
	res, err := p.Process(context.Background(), nil, api.Hints{})
	require.NoError(t, err)
	assert.Nil(t, res.Data)
	assert.Empty(t, res.Findings)
}

func TestProcess_NoScanners(t *testing.T) {
	p := New(nil, mask.New(""))
	res, err := p.Process(context.Background(), []byte("hello"), api.Hints{})
	require.NoError(t, err)
	assert.Equal(t, "hello", string(res.Data))
}

func TestProcess_EndToEnd_WithPII(t *testing.T) {
	// Real PII scanner + real mask redactor exercises the full pipeline.
	p := New([]api.Scanner{pii.New()}, mask.New(""))
	input := []byte("contact alice@example.com or 415-555-0199")
	res, err := p.Process(context.Background(), input, api.Hints{})
	require.NoError(t, err)
	assert.NotContains(t, string(res.Data), "alice@example.com")
	assert.NotContains(t, string(res.Data), "415-555-0199")
	assert.Contains(t, string(res.Data), "[REDACTED]")
	assert.GreaterOrEqual(t, len(res.Findings), 2)
}

func TestProcess_FindingsFromMultipleScannersAreMerged(t *testing.T) {
	a := &stubScanner{name: "a", findings: []api.Finding{{Start: 0, End: 5}}}
	b := &stubScanner{name: "b", findings: []api.Finding{{Start: 6, End: 11}}}
	p := New([]api.Scanner{a, b}, mask.New(""))
	res, err := p.Process(context.Background(), []byte("hello world"), api.Hints{})
	require.NoError(t, err)
	assert.Len(t, res.Findings, 2)
	assert.Equal(t, "[REDACTED] [REDACTED]", string(res.Data))
}

func TestProcess_ScannerErrorIsJoined(t *testing.T) {
	good := &stubScanner{name: "good", findings: []api.Finding{{Start: 0, End: 5}}}
	bad := &stubScanner{name: "bad", err: errors.New("boom")}
	p := New([]api.Scanner{good, bad}, mask.New(""))

	res, err := p.Process(context.Background(), []byte("hello world"), api.Hints{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "boom")
	// Findings from the good scanner must still be redacted.
	assert.Equal(t, "[REDACTED] world", string(res.Data))
}

func TestProcess_RedactorErrorReturnsOriginalData(t *testing.T) {
	s := &stubScanner{name: "s", findings: []api.Finding{{Start: 0, End: 5}}}
	r := &stubRedactor{err: errors.New("nope")}
	p := New([]api.Scanner{s}, r)

	res, err := p.Process(context.Background(), []byte("hello world"), api.Hints{})
	require.Error(t, err)
	assert.Equal(t, "hello world", string(res.Data))
}

func TestProcess_NoRedactor(t *testing.T) {
	s := &stubScanner{name: "s", findings: []api.Finding{{Start: 0, End: 5}}}
	p := New([]api.Scanner{s}, nil)
	res, err := p.Process(context.Background(), []byte("hello world"), api.Hints{})
	require.NoError(t, err)
	assert.Equal(t, "hello world", string(res.Data)) // unchanged
	assert.Len(t, res.Findings, 1)
}

func TestScan_URLDecodeDualPass_CatchesEncodedEmail(t *testing.T) {
	p := New([]api.Scanner{pii.New()}, mask.New(""))
	// alice%40example.com — URL-encoded @. Without the dual pass the raw
	// scan misses it because the email regex requires a literal `@`.
	input := []byte("?email=alice%40example.com&name=bob")
	findings, err := p.Scan(context.Background(), input, api.Hints{})
	require.NoError(t, err)
	require.NotEmpty(t, findings, "URL-decode dual pass should have caught the encoded email")

	var got api.Finding
	for _, f := range findings {
		if f.Type == "pii.email" {
			got = f
			break
		}
	}
	require.Equal(t, "pii.email", got.Type)
	// Mapped-back offsets must point at the original (encoded) span.
	assert.Equal(t, "alice%40example.com", string(input[got.Start:got.End]))
}

func TestScan_URLDecodeDualPass_DedupesIdenticalRawAndDecodedHit(t *testing.T) {
	// `%` is present (triggering the dual pass) but the actual PII match
	// is in the un-encoded portion of the body. The dual pass would
	// re-find it at the same offsets — must dedupe to one finding.
	p := New([]api.Scanner{pii.New()}, mask.New(""))
	input := []byte("email=alice@example.com&pct=100%")
	findings, err := p.Scan(context.Background(), input, api.Hints{})
	require.NoError(t, err)

	emails := 0
	for _, f := range findings {
		if f.Type == "pii.email" {
			emails++
		}
	}
	assert.Equal(t, 1, emails, "the same email must not be reported twice")
}

func TestScan_NoPercentSkipsDualPass(t *testing.T) {
	// Sanity: when no `%` is present the dual pass is skipped entirely.
	// We can't observe "fast path taken" directly, but Pipeline output
	// should be identical to ScanWith.
	p := New([]api.Scanner{pii.New()}, mask.New(""))
	input := []byte("contact alice@example.com please")
	a, err := p.Scan(context.Background(), input, api.Hints{})
	require.NoError(t, err)
	b, err := ScanWith(context.Background(), []api.Scanner{pii.New()}, input, api.Hints{})
	require.NoError(t, err)
	assert.Len(t, a, len(b))
}

func TestScan_NFKCDualPass_CatchesUnicodeLookalikeEmail(t *testing.T) {
	// ＠ is U+FF20 FULLWIDTH COMMERCIAL AT — NFKC-decomposes to @. With
	// the NFKC dual pass the PII email rule now sees the address.
	src := []byte("contact alice＠example.com please")
	p := New([]api.Scanner{pii.New()}, mask.New(""))
	findings, err := p.Scan(context.Background(), src, api.Hints{})
	require.NoError(t, err)
	require.NotEmpty(t, findings, "NFKC dual pass should have caught the full-width @ email")

	// Mapped-back match must include the original full-width @, not the
	// NFKC `@`.
	got := string(src[findings[0].Start:findings[0].End])
	assert.Contains(t, got, "＠")
}

func TestScan_ASCIIOnlySkipsNFKC(t *testing.T) {
	// Pure ASCII input — NFKC pass should be skipped entirely.
	// Behaviorally indistinguishable from a raw ScanWith call.
	src := []byte("contact alice@example.com please")
	p := New([]api.Scanner{pii.New()}, mask.New(""))
	a, err := p.Scan(context.Background(), src, api.Hints{})
	require.NoError(t, err)
	b, err := ScanWith(context.Background(), []api.Scanner{pii.New()}, src, api.Hints{})
	require.NoError(t, err)
	assert.Len(t, a, len(b))
}

// plainRecorder is a scanner that records every body it sees but doesn't
// implement AcceptsTransforms() — represents the plugin-scanner default.
type plainRecorder struct {
	name   string
	bodies *[]string
}

func (p *plainRecorder) Name() string { return p.name }
func (p *plainRecorder) Scan(_ context.Context, data []byte, _ api.Hints) ([]api.Finding, error) {
	*p.bodies = append(*p.bodies, string(data))
	return nil, nil
}

// optInRecorder records every body it sees and implements the
// AcceptsTransforms() opt-in. `wants` controls whether it returns
// true (sees transformed views) or false (excluded).
type optInRecorder struct {
	name   string
	wants  bool
	bodies *[]string
}

func (o *optInRecorder) Name() string             { return o.name }
func (o *optInRecorder) AcceptsTransforms() bool  { return o.wants }
func (o *optInRecorder) Scan(_ context.Context, data []byte, _ api.Hints) ([]api.Finding, error) {
	*o.bodies = append(*o.bodies, string(data))
	return nil, nil
}

func TestPipeline_DefaultScannerIsExcludedFromTransformedPasses(t *testing.T) {
	// A scanner that doesn't implement AcceptsTransforms gets the raw body
	// only — no URL-decoded, NFKC, etc. views. This is what protects NER
	// plugins like Presidio from being asked to interpret synthetic
	// stitched mega-tokens.
	var calls []string
	r := &plainRecorder{name: "default", bodies: &calls}

	p := New([]api.Scanner{r}, nil)
	// Body that would trigger URL-decode, base64 candidate, and
	// whitespace-stitch pre-checks if the scanner had opted in.
	input := []byte("alice%40example.com aGVsbG8gd29ybGQAAAAAAAAA  4 1 5 5 5 5 0 1 8 8")
	_, err := p.Scan(context.Background(), input, api.Hints{})
	require.NoError(t, err)

	require.Len(t, calls, 1, "default scanner must see exactly one body — the raw one")
	assert.Equal(t, string(input), calls[0])
}

func TestPipeline_ExplicitFalseOptOutIsExcluded(t *testing.T) {
	// AcceptsTransforms() returning false is treated the same as not
	// implementing the marker at all.
	var calls []string
	r := &optInRecorder{name: "opted-out", wants: false, bodies: &calls}

	p := New([]api.Scanner{r}, nil)
	_, err := p.Scan(context.Background(), []byte("alice%40example.com"), api.Hints{})
	require.NoError(t, err)

	require.Len(t, calls, 1)
	assert.Equal(t, "alice%40example.com", calls[0])
}

func TestPipeline_OptInScannerSeesTransformedBodies(t *testing.T) {
	// AcceptsTransforms() = true means the URL-decoded view reaches the
	// scanner — observable by recording every body and checking that the
	// decoded form is among them.
	var calls []string
	r := &optInRecorder{name: "opted-in", wants: true, bodies: &calls}

	p := New([]api.Scanner{r}, nil)
	_, err := p.Scan(context.Background(), []byte("alice%40example.com"), api.Hints{})
	require.NoError(t, err)

	assert.GreaterOrEqual(t, len(calls), 2, "opt-in scanner should see raw + at least one transformed view")
	var sawDecoded bool
	for _, b := range calls {
		if b == "alice@example.com" {
			sawDecoded = true
			break
		}
	}
	assert.True(t, sawDecoded, "opt-in scanner should have received the URL-decoded body; got: %v", calls)
}

func TestPipeline_MixedScannersIsolateTransforms(t *testing.T) {
	// Two scanners side by side: one opted in, one not. The transformed
	// pass must fan out only to the opted-in one.
	var inCalls, outCalls []string
	in := &optInRecorder{name: "in", wants: true, bodies: &inCalls}
	out := &plainRecorder{name: "out", bodies: &outCalls}

	p := New([]api.Scanner{in, out}, nil)
	_, err := p.Scan(context.Background(), []byte("alice%40example.com"), api.Hints{})
	require.NoError(t, err)

	// Opted-out scanner sees the raw body only.
	require.Len(t, outCalls, 1)
	assert.Equal(t, "alice%40example.com", outCalls[0])

	// Opted-in scanner sees raw + URL-decoded.
	assert.GreaterOrEqual(t, len(inCalls), 2)
	var sawDecoded bool
	for _, b := range inCalls {
		if b == "alice@example.com" {
			sawDecoded = true
		}
	}
	assert.True(t, sawDecoded)
}

func TestPipeline_AllOptOutShortCircuitsPreChecks(t *testing.T) {
	// When no scanner opts in, the transformed-pass pre-checks never run.
	// We can't directly observe the pre-checks, but the scanner must be
	// called exactly once — which is the production-relevant invariant.
	var calls []string
	r := &plainRecorder{name: "default", bodies: &calls}

	p := New([]api.Scanner{r}, nil)
	// Body that hits every pre-check simultaneously: `%` for URL-decode,
	// non-ASCII (full-width @) for NFKC, base64-eligible run, whitespace
	// for stitch, `/*` for SQL comment strip.
	input := []byte("alice%40＠example.com /* aGVsbG8gd29ybGQAAAA */  x y z")
	_, err := p.Scan(context.Background(), input, api.Hints{})
	require.NoError(t, err)

	assert.Len(t, calls, 1, "no opt-in scanners → exactly one scan, regardless of body content")
}

func TestProcess_ScannersRunConcurrently(t *testing.T) {
	const n = 50
	scanners := make([]api.Scanner, n)
	for i := range scanners {
		scanners[i] = &stubScanner{name: "s"}
	}
	p := New(scanners, mask.New(""))
	_, err := p.Process(context.Background(), []byte("data"), api.Hints{})
	require.NoError(t, err)
	for _, s := range scanners {
		assert.EqualValues(t, 1, s.(*stubScanner).calls.Load())
	}
}
