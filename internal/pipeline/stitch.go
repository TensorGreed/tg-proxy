package pipeline

import "bytes"

// Whitespace-stitching: a token-shaped region of the body that's been
// broken by single spaces or tabs gets emitted to a parallel view with
// those whitespaces removed, then re-scanned. Catches the family of
// adversarial inputs where the value carrier (email, phone, secret) was
// pasted from a doc that line-wrapped or word-spaced unhelpfully:
//
//	"alice @ example.com"
//	"4 1 5 - 5 5 5 - 0 1 8 8"
//	"AKIA IOSFODNN7EXAMPLE"
//	"sk_live_4HrPbMzZqXk TcWnFsLDaEoBy"
//
// Stitching is deliberately scoped to "regions that already look like one
// token broken by whitespace" so we don't fuse arbitrary prose into
// false-positive-prone strings. A region must:
//
//   - consist of characters from a token-ish alphabet (letters, digits,
//     and the common token punctuation `. _ - + @`),
//   - allow at most one consecutive whitespace char (space or tab) as an
//     internal join — two or more terminates the region,
//   - be at least 12 chars long, and
//   - have at least 50% of its bytes be non-whitespace eligible chars.
//
// The third and fourth conditions exclude short strings (`a b`) and very
// sparse strings (digits with double-spaces between them).

const (
	minStitchLength   = 12
	minStitchRatioPct = 50
)

// isStitchEligible returns true for the characters we'll fuse across
// single whitespaces. We include `.`, `_`, `-`, `+`, `@` so emails,
// snake_case API keys, hyphenated phone numbers, and similar token
// shapes survive intact.
func isStitchEligible(b byte) bool {
	switch {
	case b >= 'A' && b <= 'Z':
		return true
	case b >= 'a' && b <= 'z':
		return true
	case b >= '0' && b <= '9':
		return true
	case b == '.', b == '_', b == '-', b == '+', b == '@':
		return true
	}
	return false
}

// containsSpaceOrTab is the cheap pre-check for whitespaceStitch: bodies
// with no ASCII space or tab can't have stitchable regions.
func containsSpaceOrTab(data []byte) bool {
	return bytes.IndexAny(data, " \t") >= 0
}

// whitespaceStitch emits a view of src where every internal single
// whitespace inside a "stitchable" region has been removed, along with a
// byte-level mapping from output positions back to source positions.
// Returns nil mapping when nothing was stitched.
//
// Bytes outside stitchable regions pass through verbatim, including
// whitespace between regions. Each emitted byte's mapping points at its
// position in src.
func whitespaceStitch(src []byte) ([]byte, []int) {
	if !containsSpaceOrTab(src) {
		return src, nil
	}
	regions := findStitchableRegions(src)
	if len(regions) == 0 {
		return src, nil
	}

	out := make([]byte, 0, len(src))
	idx := make([]int, 0, len(src)+1)

	pos := 0
	for _, r := range regions {
		// Pre-region bytes: 1:1.
		for ; pos < r[0]; pos++ {
			idx = append(idx, pos)
			out = append(out, src[pos])
		}
		// Region bytes: drop internal single whitespace.
		for ; pos < r[1]; pos++ {
			if src[pos] == ' ' || src[pos] == '\t' {
				continue
			}
			idx = append(idx, pos)
			out = append(out, src[pos])
		}
	}
	// Tail.
	for ; pos < len(src); pos++ {
		idx = append(idx, pos)
		out = append(out, src[pos])
	}
	idx = append(idx, pos)

	if bytes.Equal(out, src) {
		return src, nil
	}
	return out, idx
}

// findStitchableRegions returns the half-open [start, end) byte ranges
// in src that qualify as stitchable per the rules described at the top
// of this file.
func findStitchableRegions(src []byte) [][2]int {
	var regions [][2]int
	regionStart := -1
	eligibleCount := 0

	flush := func(end int) {
		if regionStart < 0 {
			return
		}
		length := end - regionStart
		if length >= minStitchLength && eligibleCount*100 >= length*minStitchRatioPct {
			regions = append(regions, [2]int{regionStart, end})
		}
		regionStart = -1
		eligibleCount = 0
	}

	pos := 0
	for pos < len(src) {
		b := src[pos]
		switch {
		case isStitchEligible(b):
			if regionStart < 0 {
				regionStart = pos
			}
			eligibleCount++
			pos++
		case b == ' ' || b == '\t':
			// Look ahead: how many consecutive ws follow?
			ahead := pos + 1
			for ahead < len(src) && (src[ahead] == ' ' || src[ahead] == '\t') {
				ahead++
			}
			wsRun := ahead - pos
			joinable := wsRun == 1 && ahead < len(src) &&
				isStitchEligible(src[ahead]) && regionStart >= 0
			if joinable {
				pos++ // treat the single ws as internal — region continues
			} else {
				flush(pos)
				pos = ahead // skip the whole whitespace run
			}
		default:
			flush(pos)
			pos++
		}
	}
	flush(pos)
	return regions
}
