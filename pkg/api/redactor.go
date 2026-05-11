package api

import "context"

// Redactor rewrites a body using the offsets in a set of findings. The
// returned slice may share storage with the input, so callers must not retain
// the input after the call returns.
//
// Implementations should be tolerant of out-of-order, overlapping, and
// duplicate findings; the pipeline merges results from multiple scanners
// without re-sorting.
type Redactor interface {
	Name() string
	Redact(ctx context.Context, data []byte, findings []Finding) ([]byte, error)
}
