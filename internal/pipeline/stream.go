package pipeline

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/TensorGreed/tg-proxy/pkg/api"
)

// DefaultWindow is the sliding-window size used when none is configured. It
// must be at least as large as the longest match any active scanner can
// produce; the built-in PII scanner's worst case (an email) is well under
// 1 KiB so 4 KiB is conservative.
const DefaultWindow = 4096

// StreamOptions configures a StreamProcessor.
type StreamOptions struct {
	Scanners  []api.Scanner
	Redactor  api.Redactor
	Hints     api.Hints
	Window    int // sliding-window byte count; defaults to DefaultWindow
	MaxBuffer int // hard ceiling on the working buffer; defaults to 4*Window
}

// StreamProcessor scans and redacts bytes as they flow from src to dst.
//
// It maintains a working buffer (the "window") of the trailing bytes of the
// stream so patterns spanning chunk boundaries are still detected. After
// each Read it scans the buffer, computes the largest safe-to-flush prefix
// (one that does not split any finding in half), applies the redactor to
// that prefix, writes it to dst, and shrinks the buffer to the residual
// tail. On EOF the remaining buffer is scanned, redacted and flushed.
//
// dst is flushed (when it implements http.Flusher) after every write so SSE
// and HTTP/2 streams remain incremental from the client's point of view.
type StreamProcessor struct {
	opts StreamOptions
}

func NewStreamProcessor(opts StreamOptions) *StreamProcessor {
	if opts.Window <= 0 {
		opts.Window = DefaultWindow
	}
	if opts.MaxBuffer <= 0 || opts.MaxBuffer < opts.Window {
		opts.MaxBuffer = 4 * opts.Window
	}
	return &StreamProcessor{opts: opts}
}

// Pipe streams bytes through the scanner+redactor and copies them to dst.
// It returns when src returns io.EOF (a non-error termination) or when it
// or dst error out.
func (s *StreamProcessor) Pipe(ctx context.Context, src io.Reader, dst io.Writer) error {
	var buf []byte
	chunk := make([]byte, 32*1024)
	flusher, _ := dst.(http.Flusher)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		n, readErr := src.Read(chunk)
		if n > 0 {
			buf = append(buf, chunk[:n]...)
			if err := s.flushPrefix(ctx, &buf, dst); err != nil {
				return err
			}
			if flusher != nil && len(buf) < cap(buf) {
				flusher.Flush()
			}
		}

		if errors.Is(readErr, io.EOF) {
			if err := s.flushFinal(ctx, buf, dst); err != nil {
				return err
			}
			if flusher != nil {
				flusher.Flush()
			}
			return nil
		}
		if readErr != nil {
			return fmt.Errorf("stream: read: %w", readErr)
		}
	}
}

// flushPrefix scans buf, computes the safe-to-emit prefix, applies the
// redactor, writes to dst, and rewrites buf to the residual tail.
func (s *StreamProcessor) flushPrefix(ctx context.Context, buf *[]byte, dst io.Writer) error {
	data := *buf
	if len(data) <= s.opts.Window {
		return nil
	}
	flushable := len(data) - s.opts.Window

	findings, _ := ScanWith(ctx, s.opts.Scanners, data, s.opts.Hints)

	// Don't split a finding: if any finding straddles `flushable`, pull
	// the boundary back to the start of the earliest such finding so the
	// whole match lands in the next flush.
	for _, f := range findings {
		if f.Start < flushable && f.End > flushable {
			if f.Start < flushable {
				flushable = f.Start
			}
		}
	}

	// Hard ceiling: if a straddling finding has pinned us to 0 but we're
	// over the buffer cap, force the original flushable through. Anything
	// else lets adversarial input grow buf without bound.
	if flushable <= 0 && len(data) >= s.opts.MaxBuffer {
		flushable = len(data) - s.opts.Window
	}
	if flushable <= 0 {
		return nil
	}

	// Filter findings entirely within [0, flushable).
	emit := make([]api.Finding, 0, len(findings))
	for _, f := range findings {
		if f.End <= flushable {
			emit = append(emit, f)
		}
	}

	out, err := s.applyRedactor(ctx, data[:flushable], emit)
	if err != nil {
		return err
	}
	if _, err := dst.Write(out); err != nil {
		return fmt.Errorf("stream: write: %w", err)
	}

	// Keep tail.
	residual := make([]byte, len(data)-flushable)
	copy(residual, data[flushable:])
	*buf = residual
	return nil
}

// flushFinal scans and emits everything remaining in buf after the source
// reached EOF.
func (s *StreamProcessor) flushFinal(ctx context.Context, buf []byte, dst io.Writer) error {
	if len(buf) == 0 {
		return nil
	}
	findings, _ := ScanWith(ctx, s.opts.Scanners, buf, s.opts.Hints)
	out, err := s.applyRedactor(ctx, buf, findings)
	if err != nil {
		return err
	}
	if _, err := dst.Write(out); err != nil {
		return fmt.Errorf("stream: write: %w", err)
	}
	return nil
}

func (s *StreamProcessor) applyRedactor(ctx context.Context, data []byte, findings []api.Finding) ([]byte, error) {
	if s.opts.Redactor == nil || len(findings) == 0 {
		return data, nil
	}
	out, err := s.opts.Redactor.Redact(ctx, data, findings)
	if err != nil {
		return nil, fmt.Errorf("stream: redactor: %w", err)
	}
	return out, nil
}
