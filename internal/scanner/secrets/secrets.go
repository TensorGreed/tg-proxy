// Package secrets detects credentials and API keys that should never leave
// the organization: cloud-provider access keys, source-control tokens,
// payment-processor keys, LLM API keys, messaging tokens, and PEM-encoded
// private keys.
//
// Every detector matches a format that is unique enough on its own that
// false positives are rare; for the few patterns where the format is too
// permissive (raw 40-char base64 strings, for example) we don't ship a
// rule. Use a custom external scanner for those cases.
package secrets

import (
	"context"
	"regexp"

	"github.com/TensorGreed/tg-proxy/pkg/api"
)

const Name = "secrets"

type detector struct {
	typ        string
	pattern    *regexp.Regexp
	severity   api.Severity
	confidence float32
	validate   func(match []byte) bool
}

var detectors = []detector{
	{
		typ:        "secret.aws_access_key_id",
		pattern:    regexp.MustCompile(`\b(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}\b`),
		severity:   api.SeverityCritical,
		confidence: 0.95,
	},
	{
		// Classic ("ghp_") and refresh / OAuth / app variants.
		typ:        "secret.github_token",
		pattern:    regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{36}\b`),
		severity:   api.SeverityCritical,
		confidence: 0.98,
	},
	{
		typ:        "secret.github_token_fine_grained",
		pattern:    regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}\b`),
		severity:   api.SeverityCritical,
		confidence: 0.99,
	},
	{
		typ:        "secret.stripe_live_key",
		pattern:    regexp.MustCompile(`\bsk_live_[A-Za-z0-9]{24,}\b`),
		severity:   api.SeverityCritical,
		confidence: 0.99,
	},
	{
		typ:        "secret.stripe_test_key",
		pattern:    regexp.MustCompile(`\bsk_test_[A-Za-z0-9]{24,}\b`),
		severity:   api.SeverityHigh,
		confidence: 0.99,
	},
	{
		// Classic 48-char OpenAI keys plus the newer "sk-proj-" project
		// keys. Length is generous to absorb future variants.
		typ:        "secret.openai_api_key",
		pattern:    regexp.MustCompile(`\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b`),
		severity:   api.SeverityCritical,
		confidence: 0.85,
	},
	{
		typ:        "secret.anthropic_api_key",
		pattern:    regexp.MustCompile(`\bsk-ant-(?:api|admin)[0-9]{2}-[A-Za-z0-9_-]{32,}\b`),
		severity:   api.SeverityCritical,
		confidence: 0.99,
	},
	{
		typ:        "secret.slack_token",
		pattern:    regexp.MustCompile(`\bxox[abposr]-[A-Za-z0-9-]{10,}\b`),
		severity:   api.SeverityCritical,
		confidence: 0.95,
	},
	{
		typ:        "secret.google_api_key",
		pattern:    regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}\b`),
		severity:   api.SeverityCritical,
		confidence: 0.95,
	},
	{
		// JWT format (header.payload.signature) where header and payload
		// always start with "eyJ" because they're base64-encoded JSON
		// starting with "{".
		typ:        "secret.jwt",
		pattern:    regexp.MustCompile(`\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b`),
		severity:   api.SeverityHigh,
		confidence: 0.90,
	},
	{
		// PEM-encoded private keys. The header alone is signal enough;
		// match only it so adversaries can't truncate the body and skip
		// the rule.
		typ:        "secret.private_key",
		pattern:    regexp.MustCompile(`-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY( BLOCK)?-----`),
		severity:   api.SeverityCritical,
		confidence: 0.99,
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
