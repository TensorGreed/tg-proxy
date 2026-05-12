// Package pii implements a regex-driven scanner for common personally
// identifiable information: emails, US SSNs, US phone numbers, IPv4
// addresses, and credit-card numbers (Luhn-validated).
//
// The package uses Go's regexp engine (RE2), which is linear-time and not
// vulnerable to catastrophic backtracking, so it is safe to feed
// attacker-controlled bodies into Scan.
package pii

import (
	"context"
	"regexp"

	"github.com/TensorGreed/tg-proxy/pkg/api"
)

const Name = "pii"

type detector struct {
	typ        string
	pattern    *regexp.Regexp
	severity   api.Severity
	confidence float32
	validate   func(match []byte) bool
}

var detectors = []detector{
	{
		typ:        "pii.email",
		pattern:    regexp.MustCompile(`\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b`),
		severity:   api.SeverityMedium,
		confidence: 0.95,
	},
	{
		typ:        "pii.ssn_us",
		pattern:    regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`),
		severity:   api.SeverityHigh,
		confidence: 0.90,
	},
	{
		// Credit-card-shaped sequences. Luhn validation prunes false
		// positives like phone numbers and random digit runs.
		typ:        "pii.credit_card",
		pattern:    regexp.MustCompile(`\b\d(?:[ \-]?\d){12,18}\b`),
		severity:   api.SeverityCritical,
		confidence: 0.95,
		validate:   luhnValid,
	},
	{
		// Four explicit alternatives so the match boundary is correct for
		// each common format (with/without country code, with/without
		// parens). Requires either parens or at least one separator, so
		// plain 10-digit numbers are not flagged.
		typ: "pii.phone_us",
		pattern: regexp.MustCompile(
			`\+1[\s.\-]?\(\d{3}\)[\s.\-]?\d{3}[\s.\-]?\d{4}\b` +
				`|\+1[\s.\-]\d{3}[\s.\-]\d{3}[\s.\-]\d{4}\b` +
				`|\(\d{3}\)[\s.\-]?\d{3}[\s.\-]?\d{4}\b` +
				`|\b\d{3}[\s.\-]\d{3}[\s.\-]\d{4}\b`,
		),
		severity:   api.SeverityLow,
		confidence: 0.80,
	},
	{
		typ:        "pii.ipv4",
		pattern:    regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b`),
		severity:   api.SeverityLow,
		confidence: 0.85,
	},
}

type Scanner struct{}

func New() *Scanner { return &Scanner{} }

func (s *Scanner) Name() string { return Name }

// AcceptsTransforms opts this scanner in to the pipeline's URL-decode,
// NFKC, base64, whitespace-stitch, etc. passes. Regex PII detection
// reliably benefits — `alice %40 example.com`, `alice @ example.com`,
// `4 1 5-5 5 5-0 1 8 8`, fancy-digit credit cards, etc. all need the
// transformed view to fire.
func (*Scanner) AcceptsTransforms() bool { return true }

func (s *Scanner) Scan(_ context.Context, data []byte, _ api.Hints) ([]api.Finding, error) {
	if len(data) == 0 {
		return nil, nil
	}
	var findings []api.Finding
	for _, d := range detectors {
		for _, idx := range d.pattern.FindAllIndex(data, -1) {
			if d.validate != nil && !d.validate(data[idx[0]:idx[1]]) {
				continue
			}
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

func luhnValid(s []byte) bool {
	sum := 0
	digits := 0
	alt := false
	for i := len(s) - 1; i >= 0; i-- {
		c := s[i]
		if c < '0' || c > '9' {
			continue
		}
		n := int(c - '0')
		if alt {
			n *= 2
			if n > 9 {
				n -= 9
			}
		}
		sum += n
		alt = !alt
		digits++
	}
	if digits < 13 || digits > 19 {
		return false
	}
	return sum%10 == 0
}
