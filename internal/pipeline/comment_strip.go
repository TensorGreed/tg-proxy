package pipeline

import (
	"bytes"
	"regexp"
)

// sqliCommentRegex matches a SQL `/*...*/` inline comment, including
// multi-line spans (`.` doesn't match `\n` in Go's RE2; `[\s\S]` does).
// Matched regions are stripped before the sqli detectors re-run, foiling
// the classic MySQL evasion where `UN/**/ION SE/**/LECT` slips past rules
// that anchor on the literal keyword.
//
// We intentionally don't strip `--` line comments or `#` line comments
// here — those are explicit signals the existing `sqli.comment_marker`
// rule already looks for; stripping them would erase its own evidence.
var sqliCommentRegex = regexp.MustCompile(`/\*[\s\S]*?\*/`)

// containsSlashStarComment is the cheap pre-check: a single byte-pair scan
// for `/*`. Bodies without it skip the regex pass entirely.
func containsSlashStarComment(data []byte) bool {
	for i := 0; i+1 < len(data); i++ {
		if data[i] == '/' && data[i+1] == '*' {
			return true
		}
	}
	return false
}

// sqliCommentStrip returns src with every `/*...*/` removed and a
// position-mapping table from each output byte back to its source byte.
// Returns nil mapping when nothing was stripped.
//
// Mapped findings produced by the SQLi scanners on the stripped output
// will land at byte ranges in src that span the comment-bearing original
// text, so a redactor downstream rewrites the entire evaded span (the
// keywords AND the comment markers between them).
func sqliCommentStrip(src []byte) ([]byte, []int) {
	if !containsSlashStarComment(src) {
		return src, nil
	}
	matches := sqliCommentRegex.FindAllIndex(src, -1)
	if len(matches) == 0 {
		return src, nil
	}

	out := make([]byte, 0, len(src))
	idx := make([]int, 0, len(src)+1)

	pos := 0
	for _, m := range matches {
		for ; pos < m[0]; pos++ {
			idx = append(idx, pos)
			out = append(out, src[pos])
		}
		// Skip the matched comment region entirely; we do NOT emit
		// anything for those source bytes, and they have no mapping.
		pos = m[1]
	}
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
