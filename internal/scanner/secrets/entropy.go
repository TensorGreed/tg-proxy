package secrets

import (
	"math"
	"regexp"
)

// shannonEntropy returns the Shannon entropy of b in bits per byte. For a
// random string drawn from the printable-ASCII alphabet this typically lands
// between 4 and 6 bits/char; obvious placeholders (`xxxxxxx...`, `AAAA...`,
// `<your-key>`) score below 2.
func shannonEntropy(b []byte) float64 {
	if len(b) == 0 {
		return 0
	}
	var counts [256]int
	for _, c := range b {
		counts[c]++
	}
	n := float64(len(b))
	var h float64
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h
}

// keyKeywordRE matches a key-like LABEL paired with strong evidence that a
// value follows it. The label alone is too weak — "tokens" appears in
// prose all the time — so we require either:
//
//   * the label is followed (within a few chars) by an assignment-style
//     character (`=`, `:`), as in `OPENAI_API_KEY=…` or `"api_key": "…"`
//   * the label is the HTTP `bearer` convention (label + whitespace +
//     value, no explicit assignment char)
//
// The pattern is case-insensitive and intentionally not word-boundary
// anchored — `\b` would refuse to match across the underscore inside
// `OPENAI_API_KEY` because `_` is a word character in Go's regexp.
var keyKeywordRE = regexp.MustCompile(
	`(?i)(?:(?:api[_-]?keys?|secrets?(?:[_-]?keys?)?|tokens?|passwords?|passwd|pwd|auth(?:orization)?|access[_-]?keys?|private[_-]?keys?|credentials?)\s*["']?\s*[:=]|bearer\s+)`,
)

// hasKeyContext reports whether any key-like keyword appears in the
// `window` bytes immediately preceding `at` in data.
func hasKeyContext(data []byte, at, window int) bool {
	if at <= 0 {
		return false
	}
	start := at - window
	if start < 0 {
		start = 0
	}
	return keyKeywordRE.Match(data[start:at])
}
