package pipeline

import (
	"encoding/base64"
	"regexp"
)

// minBase64Run is the smallest contiguous run of base64-alphabet characters
// we'll consider as a candidate. Short runs are mostly noise (hex digits,
// short IDs, etc.) and decoding them produces garbage that the printability
// filter would reject anyway — better to skip them up front.
const minBase64Run = 16

// printableRatio: the fraction of decoded bytes that must look like ASCII
// text for the candidate to be considered a "real" base64-wrapped string
// rather than image / signature / random binary data. 0.7 keeps the
// adversarial fixtures (encoded ASCII secrets, encoded source snippets)
// while dropping random binary that happens to satisfy the alphabet.
const printableRatio = 0.70

// base64Candidate matches a run of standard base64-alphabet characters
// long enough to plausibly carry a secret, optionally followed by 1–2 `=`
// padding chars. URL-safe base64 (`-` / `_`) is not currently matched —
// extend the class if you need it.
var base64Candidate = regexp.MustCompile(`[A-Za-z0-9+/]{` +
	intToStr(minBase64Run) + `,}={0,2}`)

// containsBase64Candidate is a cheap pre-check that scans for a single
// run of `minBase64Run` consecutive base64-alphabet bytes. Used to skip
// the regex pass entirely on bodies that obviously have nothing to do.
func containsBase64Candidate(data []byte) bool {
	run := 0
	for _, b := range data {
		if isBase64Char(b) {
			run++
			if run >= minBase64Run {
				return true
			}
		} else {
			run = 0
		}
	}
	return false
}

func isBase64Char(b byte) bool {
	switch {
	case b >= 'A' && b <= 'Z':
		return true
	case b >= 'a' && b <= 'z':
		return true
	case b >= '0' && b <= '9':
		return true
	case b == '+', b == '/':
		return true
	}
	return false
}

// base64Decode walks src, locates standard-base64 candidate runs, decodes
// each that round-trips through StdEncoding AND produces mostly-printable
// output, and emits a buffer in which every successful candidate is
// substituted with its decoded form. Non-candidate bytes are emitted
// verbatim so scanners that depend on surrounding context (the OpenAI
// rule's required-key-label, for example) still see it.
//
// origIdx[i] is the byte offset in src that produced decoded[i]. Bytes
// outside candidates map 1:1; bytes inside a candidate map to the start
// of their 4-char base64 group, so a finding's mapped range always
// straddles full base64 groups in the original buffer.
//
// Returns origIdx == nil to signal "no transform happened" (no candidates
// or every candidate was rejected).
func base64Decode(src []byte) ([]byte, []int) {
	candidates := base64Candidate.FindAllIndex(src, -1)
	if len(candidates) == 0 {
		return src, nil
	}

	out := make([]byte, 0, len(src))
	idx := make([]int, 0, len(src)+1)

	pos := 0
	anyDecoded := false
	for _, c := range candidates {
		start, end := c[0], c[1]

		// Emit bytes between the previous emit position and this
		// candidate verbatim, mapping 1:1.
		for ; pos < start; pos++ {
			idx = append(idx, pos)
			out = append(out, src[pos])
		}

		// Try to decode the candidate. Standard-base64 requires the
		// length be divisible by 4; if not, bail to verbatim emit.
		candBytes := src[start:end]
		if len(candBytes)%4 != 0 {
			for ; pos < end; pos++ {
				idx = append(idx, pos)
				out = append(out, src[pos])
			}
			continue
		}
		decoded, err := base64.StdEncoding.DecodeString(string(candBytes))
		if err != nil || !isMostlyPrintable(decoded, printableRatio) {
			for ; pos < end; pos++ {
				idx = append(idx, pos)
				out = append(out, src[pos])
			}
			continue
		}

		// Emit the decoded bytes with each mapped to the start of its
		// source 4-char base64 group within the candidate.
		for i := 0; i < len(decoded); i++ {
			group := i / 3
			idx = append(idx, start+group*4)
			out = append(out, decoded[i])
		}
		pos = end
		anyDecoded = true
	}

	// Tail: bytes after the last candidate.
	for ; pos < len(src); pos++ {
		idx = append(idx, pos)
		out = append(out, src[pos])
	}
	idx = append(idx, pos)

	if !anyDecoded {
		return src, nil
	}
	return out, idx
}

// isMostlyPrintable reports whether at least `threshold` fraction of bytes
// in b look like ASCII text (printable + common control: tab/newline/CR).
// Binary data — image bytes, signatures, encrypted blobs — usually scores
// well below 0.5 and is rejected.
func isMostlyPrintable(b []byte, threshold float64) bool {
	if len(b) == 0 {
		return false
	}
	n := 0
	for _, c := range b {
		if c == '\t' || c == '\n' || c == '\r' || (c >= ' ' && c < 0x7F) {
			n++
		}
	}
	return float64(n)/float64(len(b)) >= threshold
}

// intToStr is a tiny helper so we can compose the regex from a constant
// without pulling in strconv at package init.
func intToStr(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
