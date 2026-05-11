// Package mask implements the default Redactor: it replaces every byte range
// covered by a Finding with a fixed placeholder string. The implementation
// tolerates out-of-order, overlapping, duplicate, and invalid findings — the
// pipeline merges results from multiple scanners without re-sorting.
package mask

import (
	"bytes"
	"context"
	"sort"

	"github.com/TensorGreed/tg-proxy/pkg/api"
)

const (
	Name               = "mask"
	DefaultPlaceholder = "[REDACTED]"
)

type Redactor struct {
	placeholder []byte
}

// New returns a Redactor that substitutes placeholder for each finding. If
// placeholder is empty, DefaultPlaceholder is used.
func New(placeholder string) *Redactor {
	if placeholder == "" {
		placeholder = DefaultPlaceholder
	}
	return &Redactor{placeholder: []byte(placeholder)}
}

func (r *Redactor) Name() string { return Name }

func (r *Redactor) Redact(_ context.Context, data []byte, findings []api.Finding) ([]byte, error) {
	if len(findings) == 0 || len(data) == 0 {
		return data, nil
	}

	valid := make([]api.Finding, 0, len(findings))
	for _, f := range findings {
		if f.Start < 0 || f.End > len(data) || f.Start >= f.End {
			continue
		}
		valid = append(valid, f)
	}
	if len(valid) == 0 {
		return data, nil
	}

	sort.Slice(valid, func(i, j int) bool {
		if valid[i].Start != valid[j].Start {
			return valid[i].Start < valid[j].Start
		}
		return valid[i].End > valid[j].End
	})

	merged := make([][2]int, 0, len(valid))
	for _, f := range valid {
		if n := len(merged); n > 0 && f.Start < merged[n-1][1] {
			if f.End > merged[n-1][1] {
				merged[n-1][1] = f.End
			}
			continue
		}
		merged = append(merged, [2]int{f.Start, f.End})
	}

	var out bytes.Buffer
	out.Grow(len(data))
	pos := 0
	for _, m := range merged {
		out.Write(data[pos:m[0]])
		out.Write(r.placeholder)
		pos = m[1]
	}
	out.Write(data[pos:])
	return out.Bytes(), nil
}
