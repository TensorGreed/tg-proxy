package pipeline

import "bytes"

// containsPercent is the cheap pre-check that drives URL-decoding in
// Pipeline.Scan. URL-decoding only matters when at least one `%` byte is in
// the body; for the common case (LLM responses, JSON, plain text) the
// pipeline pays only this one byte scan and skips the rest.
func containsPercent(data []byte) bool {
	return bytes.IndexByte(data, '%') >= 0
}

// urlDecode performs a relaxed URL-decode of src. Every well-formed `%XX`
// sequence is decoded to its byte value; malformed sequences (`%` not
// followed by two hex digits) are passed through verbatim.
//
// origIdx is a position-mapping table the caller uses to translate
// offsets in the decoded buffer back to the original buffer. For each
// decoded byte at index i, origIdx[i] is the index in src where that
// decoded byte started. origIdx has len(decoded)+1 entries; the last
// entry equals len(src) and serves as the exclusive end of a final
// finding's range.
//
// Example:
//
//	src     = []byte("?email=alice%40example.com")
//	decoded = []byte("?email=alice@example.com")
//	origIdx = [0 1 2 3 4 5 6 7 8 9 10 11 12 15 16 17 18 19 20 21 22 23 24 25 26]
//
// So decoded[7:24] ("alice@example.com") maps back to
// src[origIdx[7]:origIdx[24]] = src[7:26] ("alice%40example.com").
func urlDecode(src []byte) (decoded []byte, origIdx []int) {
	decoded = make([]byte, 0, len(src))
	origIdx = make([]int, 0, len(src)+1)
	i := 0
	for i < len(src) {
		origIdx = append(origIdx, i)
		if src[i] == '%' && i+2 < len(src) {
			hi, ok1 := hexValue(src[i+1])
			lo, ok2 := hexValue(src[i+2])
			if ok1 && ok2 {
				decoded = append(decoded, byte(hi<<4|lo))
				i += 3
				continue
			}
		}
		decoded = append(decoded, src[i])
		i++
	}
	origIdx = append(origIdx, i)
	return decoded, origIdx
}

func hexValue(c byte) (int, bool) {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0'), true
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10, true
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10, true
	}
	return 0, false
}
