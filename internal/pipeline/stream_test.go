package pipeline

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TensorGreed/tg-proxy/internal/redactor/mask"
	"github.com/TensorGreed/tg-proxy/internal/scanner/pii"
	"github.com/TensorGreed/tg-proxy/pkg/api"
)

// chunkedReader yields its chunks one Read at a time, simulating a slow
// upstream stream where Go's io.Reader contract is exercised the same way
// as a chunked HTTP body.
type chunkedReader struct {
	chunks [][]byte
	idx    int
}

func (r *chunkedReader) Read(p []byte) (int, error) {
	if r.idx >= len(r.chunks) {
		return 0, io.EOF
	}
	c := r.chunks[r.idx]
	r.idx++
	n := copy(p, c)
	if n < len(c) {
		// Buffer must be sized to fit chunks; tests always pass big buffer.
		r.chunks[r.idx-1] = c[n:]
		r.idx--
	}
	return n, nil
}

func newSP(window, maxBuf int) *StreamProcessor {
	return NewStreamProcessor(StreamOptions{
		Scanners:  []api.Scanner{pii.New()},
		Redactor:  mask.New(""),
		Window:    window,
		MaxBuffer: maxBuf,
	})
}

func TestStream_PassesUnscannedDataThrough(t *testing.T) {
	sp := newSP(64, 0)
	var out bytes.Buffer
	err := sp.Pipe(context.Background(), strings.NewReader("hello, world"), &out)
	require.NoError(t, err)
	assert.Equal(t, "hello, world", out.String())
}

func TestStream_RedactsInSingleChunk(t *testing.T) {
	sp := newSP(64, 0)
	var out bytes.Buffer
	src := strings.NewReader("user alice@example.com here")
	require.NoError(t, sp.Pipe(context.Background(), src, &out))
	assert.NotContains(t, out.String(), "alice@example.com")
	assert.Contains(t, out.String(), "[REDACTED]")
}

func TestStream_DetectsPatternSpanningChunks(t *testing.T) {
	// The email is split across two chunks. Without a sliding window the
	// pattern would be missed.
	src := &chunkedReader{chunks: [][]byte{
		[]byte("hello alice"),
		[]byte("@example.com bye"),
	}}
	sp := newSP(64, 0)
	var out bytes.Buffer
	require.NoError(t, sp.Pipe(context.Background(), src, &out))
	assert.NotContains(t, out.String(), "alice@example.com")
	assert.Contains(t, out.String(), "[REDACTED]")
}

func TestStream_PreservesByteOrderAndContent(t *testing.T) {
	src := &chunkedReader{chunks: [][]byte{
		[]byte("AAAA"), []byte("BBBB"), []byte("CCCC"), []byte("DDDD"),
	}}
	sp := newSP(4, 0) // small window, no findings -> output equals input
	var out bytes.Buffer
	require.NoError(t, sp.Pipe(context.Background(), src, &out))
	assert.Equal(t, "AAAABBBBCCCCDDDD", out.String())
}

func TestStream_SSEEventBoundariesPreserved(t *testing.T) {
	// Mimics an LLM SSE stream: events separated by \n\n, each carrying a
	// PII payload. The full plaintext content must round-trip except for
	// the email which is redacted.
	src := strings.NewReader(
		"data: hi alice@example.com\n\n" +
			"data: ok\n\n" +
			"data: ip 8.8.8.8\n\n",
	)
	sp := newSP(64, 0)
	var out bytes.Buffer
	require.NoError(t, sp.Pipe(context.Background(), src, &out))
	got := out.String()
	assert.NotContains(t, got, "alice@example.com")
	assert.NotContains(t, got, "8.8.8.8")
	assert.Contains(t, got, "data: hi [REDACTED]\n\n")
	assert.Contains(t, got, "data: ok\n\n")
}

func TestStream_EOFFinalFlush(t *testing.T) {
	// A finding that sits entirely in the window-sized tail must still be
	// flushed when EOF arrives.
	src := strings.NewReader("a@b.io")
	sp := newSP(128, 0) // window much larger than the body
	var out bytes.Buffer
	require.NoError(t, sp.Pipe(context.Background(), src, &out))
	assert.NotContains(t, out.String(), "a@b.io")
	assert.Contains(t, out.String(), "[REDACTED]")
}

func TestStream_ContextCancelledBeforeStart(t *testing.T) {
	// io.Reader has no native cancellation, so Pipe can only observe ctx
	// between reads. Cancelling before the first Read still works.
	sp := newSP(64, 0)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := sp.Pipe(ctx, strings.NewReader("anything"), io.Discard)
	require.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("boom") }

func TestStream_PropagatesReadError(t *testing.T) {
	sp := newSP(64, 0)
	err := sp.Pipe(context.Background(), errReader{}, io.Discard)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "boom")
}

func TestStream_BufferCapForcesFlush(t *testing.T) {
	// Construct an adversarial stream: an opening "alice@" that keeps
	// looking like the start of an email, then a wall of bytes that never
	// close the pattern. The buffer cap must force-flush rather than
	// growing without bound.
	const window = 32
	const maxBuf = 4 * window
	sp := newSP(window, maxBuf)

	var chunks [][]byte
	chunks = append(chunks, []byte("alice@"))
	// Pad with non-token bytes; no '.' so the email pattern can never close.
	chunks = append(chunks, []byte(strings.Repeat("x", 8*window)))
	src := &chunkedReader{chunks: chunks}

	var out bytes.Buffer
	require.NoError(t, sp.Pipe(context.Background(), src, &out))
	// All input bytes must appear in the output (not redacted, since
	// nothing matched).
	expected := "alice@" + strings.Repeat("x", 8*window)
	assert.Equal(t, expected, out.String())
}

func TestStream_NilRedactorPassesFindingsThroughUnredacted(t *testing.T) {
	sp := NewStreamProcessor(StreamOptions{
		Scanners: []api.Scanner{pii.New()},
		Redactor: nil,
		Window:   32,
	})
	var out bytes.Buffer
	require.NoError(t, sp.Pipe(context.Background(),
		strings.NewReader("email alice@example.com"), &out))
	assert.Equal(t, "email alice@example.com", out.String())
}

func TestStream_NoScannersPassesThrough(t *testing.T) {
	sp := NewStreamProcessor(StreamOptions{Window: 16})
	var out bytes.Buffer
	require.NoError(t, sp.Pipe(context.Background(),
		strings.NewReader("alice@example.com"), &out))
	assert.Equal(t, "alice@example.com", out.String())
}

func TestStream_DefaultsApplied(t *testing.T) {
	sp := NewStreamProcessor(StreamOptions{
		Scanners: []api.Scanner{pii.New()},
		Redactor: mask.New(""),
	})
	assert.Equal(t, DefaultWindow, sp.opts.Window)
	assert.Equal(t, 4*DefaultWindow, sp.opts.MaxBuffer)
}
