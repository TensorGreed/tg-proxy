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
