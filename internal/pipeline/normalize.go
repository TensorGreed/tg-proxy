package pipeline

import (
	"bytes"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

// containsNonASCII is the cheap pre-check for NFKC normalization. The
// transformation is a no-op on pure-ASCII bodies; for those we skip the
// whole second pass.
func containsNonASCII(data []byte) bool {
	for _, b := range data {
		if b >= 0x80 {
			return true
		}
	}
	return false
}

// nfkcNormalize returns the NFKC-normalized form of src plus a byte-level
// mapping table from the normalized buffer back to the source. NFKC
// collapses Unicode "confusable" / compatibility characters to their
// canonical equivalents — ⅾ → d, ⅽ → c, ＠ → @, ① → 1, ﬁ → fi, etc. —
// so a rule that anchors on ASCII keywords can no longer be evaded by
// pasting a visually-identical Unicode lookalike.
//
// The mapping is built rune-by-rune. For each byte of the normalized
// output, origIdx[i] is the byte offset in src where the source rune that
// produced this normalized byte starts. origIdx has len(normalized)+1
// entries; the last entry equals len(src) and serves as the exclusive
// end for a final finding's range.
//
// Example: src = "ⅾef foo()" (12 bytes; ⅾ is 3 bytes UTF-8)
//
//	normalized = "def foo()"  (9 bytes)
//	origIdx[0] = 0    // 'd' came from the 3-byte 'ⅾ' at src[0..2]
//	origIdx[1] = 3    // 'e' came from src[3]
//	origIdx[2] = 4    // 'f' came from src[4]
//	...
//	origIdx[9] = 12   // sentinel: end-of-src
//
// A finding spanning normalized[0:9] therefore maps to src[0:12], so the
// redactor still rewrites the original Unicode-containing span.
func nfkcNormalize(src []byte) ([]byte, []int) {
	if !containsNonASCII(src) {
		// No-op for pure ASCII; pipeline checks `bytes.Equal(out, src)`
		// after this call and skips the second scan when nothing changed.
		return src, nil
	}

	out := make([]byte, 0, len(src))
	origIdx := make([]int, 0, len(src)+1)

	pos := 0
	for pos < len(src) {
		r, size := utf8.DecodeRune(src[pos:])
		if r == utf8.RuneError && size == 1 {
			// Invalid UTF-8 byte — preserve and advance.
			origIdx = append(origIdx, pos)
			out = append(out, src[pos])
			pos++
			continue
		}
		normalized := norm.NFKC.String(string(r))
		for range []byte(normalized) {
			origIdx = append(origIdx, pos)
		}
		out = append(out, normalized...)
		pos += size
	}
	origIdx = append(origIdx, pos)

	// If normalization left every byte unchanged (e.g. only contained
	// non-ASCII characters that are already in NFKC form), signal that
	// by returning nil for origIdx — Pipeline.Scan uses this as a hint
	// to skip the second scanner pass.
	if bytes.Equal(out, src) {
		return out, nil
	}
	return out, origIdx
}
