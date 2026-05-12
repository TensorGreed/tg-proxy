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
// Two passes run independently with different eligibility predicates:
//
//   - whitespaceStitch — broad: letters, digits, and `. _ - + @` are all
//     eligible. Catches mixed-case tokens like AWS keys and Stripe keys
//     that legitimately need letter↔letter joins inside the body.
//
//   - digitStitch — narrow: ONLY digits and `. _ - + @` are eligible
//     (letters block the region). Catches digit-only sequences embedded
//     in prose without dragging the prose along (the phone case the
//     broad stitch couldn't handle without breaking AWS/Stripe).
//
// Both passes share the same region-detection state machine and emit
// logic; only the per-byte eligibility check differs.
//
// A region must:
//
//   - allow at most one consecutive whitespace char (space or tab) as an
//     internal join — two or more terminates the region,
//   - be at least 12 chars long, and
//   - have at least 50% of its bytes be non-whitespace eligible chars.
//
// The third and fourth conditions exclude short strings and sparse runs.

const (
	minStitchLength   = 12
	minStitchRatioPct = 50
)

// isStitchEligible returns true for the broad eligibility set: letters,
// digits, and the common token punctuation `. _ - + @`. Used by
// whitespaceStitch.
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

// isDigitOrSpecial returns true for the narrow eligibility set: digits
// and `. _ - + @` only. Letters explicitly block the region. Used by
// digitStitch.
func isDigitOrSpecial(b byte) bool {
	switch {
	case b >= '0' && b <= '9':
		return true
	case b == '.', b == '_', b == '-', b == '+', b == '@':
		return true
	}
	return false
}

// containsSpaceOrTab is the cheap pre-check for both stitch passes.
func containsSpaceOrTab(data []byte) bool {
	return bytes.IndexAny(data, " \t") >= 0
}

// whitespaceStitch is the broad stitch pass.
func whitespaceStitch(src []byte) ([]byte, []int) {
	return stitchByEligible(src, isStitchEligible)
}

// digitStitch is the narrow stitch pass — useful for digit-only sequences
// pasted with single whitespaces between every digit ("4 1 5 - 5 5 5 …")
// that the broad stitch would over-fuse with surrounding prose.
func digitStitch(src []byte) ([]byte, []int) {
	return stitchByEligible(src, isDigitOrSpecial)
}

// stitchByEligible runs the shared region-detection + emit logic with the
// caller-supplied eligibility predicate.
func stitchByEligible(src []byte, eligible func(byte) bool) ([]byte, []int) {
	if !containsSpaceOrTab(src) {
		return src, nil
	}
	regions := findStitchableRegions(src, eligible)
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
// in src that qualify per the eligibility predicate and the length /
// ratio gates at the top of this file.
func findStitchableRegions(src []byte, eligible func(byte) bool) [][2]int {
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
		case eligible(b):
			if regionStart < 0 {
				regionStart = pos
			}
			eligibleCount++
			pos++
		case b == ' ' || b == '\t':
			ahead := pos + 1
			for ahead < len(src) && (src[ahead] == ' ' || src[ahead] == '\t') {
				ahead++
			}
			wsRun := ahead - pos
			joinable := wsRun == 1 && ahead < len(src) &&
				eligible(src[ahead]) && regionStart >= 0
			if joinable {
				pos++ // single internal whitespace — region continues
			} else {
				flush(pos)
				pos = ahead
			}
		default:
			flush(pos)
			pos++
		}
	}
	flush(pos)
	return regions
}
