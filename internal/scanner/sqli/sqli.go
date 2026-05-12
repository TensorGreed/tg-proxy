// Package sqli detects classic SQL injection payloads in request and
// response bodies. The patterns are tuned conservatively — they flag
// concrete injection signatures rather than every word that could appear
// in benign English text, so they are appropriate for outbound HTTP
// traffic that is supposed to look like JSON / form data / etc.
//
// This is a heuristic detector, not a parser. False negatives are likely
// against sophisticated payloads; false positives are likely against text
// that legitimately quotes SQL (queries pasted into an LLM prompt, for
// example). Use the URL/Direction hints in your wider config if you want
// to scope it to user-input endpoints.
package sqli

import (
	"context"
	"regexp"
	"strings"

	"github.com/TensorGreed/tg-proxy/pkg/api"
)

const Name = "sqli"

// mustCompile compiles pat after expanding the `\s` shorthand to also
// match Unicode space-separator characters (NBSP, ideographic space,
// narrow no-break space, ...). Without this, a payload that swaps the
// ASCII space between `UNION` and `SELECT` for a U+00A0 trivially evades
// every detector that anchors on `\s+`.
//
// We restrict the expansion to `\s` only; the per-detector character
// classes that already enumerate separators explicitly (e.g. `[\s.\-]`
// in the PII phone rule) are unaffected.
func mustCompile(pat string) *regexp.Regexp {
	return regexp.MustCompile(strings.ReplaceAll(pat, `\s`, `[\s\p{Zs}]`))
}

type detector struct {
	typ        string
	pattern    *regexp.Regexp
	severity   api.Severity
	confidence float32
}

var detectors = []detector{
	{
		// UNION-based extraction. Allow any whitespace between the keywords.
		typ:        "sqli.union_select",
		pattern:    mustCompile(`(?i)\bunion\s+(?:all\s+)?select\b`),
		severity:   api.SeverityHigh,
		confidence: 0.90,
	},
	{
		// Tautology injection — the classic "or 1=1" family. Allows
		// optional quotes so 'or' '1'='1' is also caught.
		typ:        "sqli.tautology",
		pattern:    mustCompile(`(?i)(?:'\s*)?\b(?:or|and)\b\s+'?\d+'?\s*=\s*'?\d+'?`),
		severity:   api.SeverityHigh,
		confidence: 0.85,
	},
	{
		// Statement chaining: "; DROP TABLE", "; DELETE FROM", etc.
		typ:        "sqli.statement_chain",
		pattern:    mustCompile(`(?i);\s*(?:drop|delete|update|insert|truncate|alter)\b`),
		severity:   api.SeverityCritical,
		confidence: 0.90,
	},
	{
		// Comment markers tucked between tokens — used to break out of
		// quoted strings or skip the rest of a statement.
		typ:        "sqli.comment_marker",
		pattern:    mustCompile(`(?:--\s|/\*.*?\*/|#\s+(?:OR|AND)\s+)`),
		severity:   api.SeverityMedium,
		confidence: 0.50,
	},
	{
		// Time-based blind injection. SLEEP, BENCHMARK, and pg_sleep take
		// an argument list with parentheses; WAITFOR DELAY in T-SQL takes
		// a quoted time string instead.
		typ: "sqli.time_based",
		pattern: mustCompile(
			`(?i)\b(?:sleep|benchmark|pg_sleep)\s*\(|\bwaitfor\s+delay\b`,
		),
		severity:   api.SeverityHigh,
		confidence: 0.85,
	},
	{
		// MS-SQL extended stored procedures used for command execution.
		typ:        "sqli.xp_cmdshell",
		pattern:    regexp.MustCompile(`(?i)\bxp_cmdshell\b`),
		severity:   api.SeverityCritical,
		confidence: 0.95,
	},
	{
		// information_schema / sys reconnaissance.
		typ:        "sqli.schema_recon",
		pattern:    regexp.MustCompile(`(?i)\b(?:information_schema|sys\.databases|sys\.tables)\b`),
		severity:   api.SeverityMedium,
		confidence: 0.70,
	},
	{
		// Hex-encoded payloads (0x...).
		typ:        "sqli.hex_payload",
		pattern:    regexp.MustCompile(`\b0x[0-9a-fA-F]{16,}\b`),
		severity:   api.SeverityLow,
		confidence: 0.40,
	},
}

type Scanner struct{}

func New() *Scanner { return &Scanner{} }

func (*Scanner) Name() string { return Name }

func (*Scanner) Scan(_ context.Context, data []byte, _ api.Hints) ([]api.Finding, error) {
	if len(data) == 0 {
		return nil, nil
	}
	var findings []api.Finding
	for _, d := range detectors {
		for _, idx := range d.pattern.FindAllIndex(data, -1) {
			findings = append(findings, api.Finding{
				Type:       d.typ,
				Severity:   d.severity,
				Start:      idx[0],
				End:        idx[1],
				Confidence: d.confidence,
				Scanner:    Name,
			})
		}
	}
	return findings, nil
}
