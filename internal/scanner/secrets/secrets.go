// Package secrets detects credentials and API keys that should never leave
// the organization: cloud-provider access keys, source-control tokens,
// payment-processor keys, LLM API keys, messaging tokens, and PEM-encoded
// private keys.
//
// Every detector matches a format that is unique enough on its own that
// false positives are rare; for the few patterns where the format is too
// permissive (raw 40-char base64 strings, for example) we don't ship a
// rule. Use a custom external scanner for those cases.
//
// On top of the regex match every detector can apply two modifiers before
// emitting a finding:
//
//   - minEntropy: rejects the match when its Shannon entropy is too low.
//     This is the cheap filter that prunes placeholders like `ghp_xxxxxxx…`
//     and `sk-AAAA…` that satisfy the format spec but obviously aren't
//     real credentials.
//   - requireKey: requires a key-like label (api_key, token, secret, …) in
//     the bytes immediately preceding the match. We use it on patterns
//     that are otherwise too permissive to emit safely on their own — the
//     OpenAI `sk-…` rule is the canonical example.
//
// Per-detector thresholds are tuned conservatively: any value that passed
// the regex but lands below the threshold is dropped silently. The golden
// corpus under internal/scanner/golden/testdata/secrets/ is the regression
// floor — both real-format positives and low-entropy placeholders that
// must not fire.
package secrets

import (
	"context"
	"regexp"

	"github.com/TensorGreed/tg-proxy/pkg/api"
)

const Name = "secrets"

// contextWindow is how far back from a match we look for a key-like label
// when requireKey is set. 64 bytes covers JSON values, env vars, header
// lines, and most form-encoded fields without straying into unrelated
// content.
const contextWindow = 64

type detector struct {
	typ        string
	pattern    *regexp.Regexp
	severity   api.Severity
	confidence float32

	// validate runs after the regex match. Returning false drops the
	// candidate. Optional; defaults to "always accept".
	validate func(match []byte) bool

	// minEntropy: bits/char floor for the matched substring. 0 disables
	// the check.
	minEntropy float64

	// requireKey: when true, the match must be preceded (within
	// contextWindow bytes) by a key-like label such as "api_key",
	// "token", "secret", "password", etc.
	requireKey bool
}

var detectors = []detector{
	{
		typ:        "secret.aws_access_key_id",
		pattern:    regexp.MustCompile(`\b(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}\b`),
		severity:   api.SeverityCritical,
		confidence: 0.95,
		// AWS canonical example AKIAIOSFODNN7EXAMPLE has ~3.7 bits/char;
		// placeholders like AKIAXXXXXXXXXXXXXXXX land around 1.0.
		minEntropy: 3.0,
	},
	{
		// Classic ("ghp_") and refresh / OAuth / app variants.
		typ:        "secret.github_token",
		pattern:    regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{36}\b`),
		severity:   api.SeverityCritical,
		confidence: 0.98,
		// 36 chars of [A-Za-z0-9] has Hmax ~5.95; real tokens land near
		// that. Threshold of 3.5 rejects ghp_xxxxx… but keeps anything
		// realistic.
		minEntropy: 3.5,
	},
	{
		typ:        "secret.github_token_fine_grained",
		pattern:    regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}\b`),
		severity:   api.SeverityCritical,
		confidence: 0.99,
		minEntropy: 3.5,
	},
	{
		typ:        "secret.stripe_live_key",
		pattern:    regexp.MustCompile(`\bsk_live_[A-Za-z0-9]{24,}\b`),
		severity:   api.SeverityCritical,
		confidence: 0.99,
		minEntropy: 3.5,
	},
	{
		typ:        "secret.stripe_test_key",
		pattern:    regexp.MustCompile(`\bsk_test_[A-Za-z0-9]{24,}\b`),
		severity:   api.SeverityHigh,
		confidence: 0.99,
		minEntropy: 3.5,
	},
	{
		// Classic 48-char OpenAI keys plus the newer "sk-proj-" project
		// keys. Length is generous to absorb future variants, but the
		// raw `sk-...` format is permissive enough that we require both
		// real entropy AND a nearby key-like label.
		typ:        "secret.openai_api_key",
		pattern:    regexp.MustCompile(`\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b`),
		severity:   api.SeverityCritical,
		confidence: 0.85,
		minEntropy: 4.0,
		requireKey: true,
	},
	{
		typ:        "secret.anthropic_api_key",
		pattern:    regexp.MustCompile(`\bsk-ant-(?:api|admin)[0-9]{2}-[A-Za-z0-9_-]{32,}\b`),
		severity:   api.SeverityCritical,
		confidence: 0.99,
		minEntropy: 3.5,
	},
	{
		typ:        "secret.slack_token",
		pattern:    regexp.MustCompile(`\bxox[abposr]-[A-Za-z0-9-]{10,}\b`),
		severity:   api.SeverityCritical,
		confidence: 0.95,
		minEntropy: 3.0,
	},
	{
		typ:        "secret.google_api_key",
		pattern:    regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}\b`),
		severity:   api.SeverityCritical,
		confidence: 0.95,
		minEntropy: 3.5,
	},
	{
		// JWT format (header.payload.signature). The header and payload
		// are base64url JSON so real JWTs always have high entropy. A
		// permissive format demands a stricter entropy floor.
		typ:        "secret.jwt",
		pattern:    regexp.MustCompile(`\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b`),
		severity:   api.SeverityHigh,
		confidence: 0.90,
		minEntropy: 4.0,
	},
	{
		// PEM-encoded private keys. The header alone is signal enough;
		// match only it so adversaries can't truncate the body and skip
		// the rule. Entropy is intentionally not used: the header is
		// fixed text and would always fail an entropy check.
		typ:        "secret.private_key",
		pattern:    regexp.MustCompile(`-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY( BLOCK)?-----`),
		severity:   api.SeverityCritical,
		confidence: 0.99,
	},
	{
		// PEM private-key BODY without the BEGIN/END header — catches
		// attackers (or honest copy-paste accidents) that strip the
		// header. PKCS#8 / RSA / EC private keys all start their base64
		// body with the ASN.1 DER sequence tag `30 82`, which encodes
		// to `MII` + uppercase letter (`MIIE` for RSA-2048, `MIIC` for
		// RSA-1024, `MIIB` for EC, etc.). Requiring 60+ base64 chars on
		// the first line plus a multi-line continuation distinguishes
		// from short single-line base64 strings that happen to start
		// with `MII`.
		//
		// FP risk: an X.509 certificate body without its `-----BEGIN
		// CERTIFICATE-----` header also matches (certs share the DER
		// prefix). We accept that — a leaked cert body is still data
		// that shouldn't be flowing through the proxy unredacted, and
		// it deserves the same handling as a leaked key.
		typ:        "secret.private_key",
		pattern:    regexp.MustCompile(`\bMII[A-Z][A-Za-z0-9+/]{60,}=*(?:\s+[A-Za-z0-9+/=]{20,})+`),
		severity:   api.SeverityCritical,
		confidence: 0.55,
	},

	// --- Source-control & package registries -----------------------------
	{
		typ:        "secret.gitlab_pat",
		pattern:    regexp.MustCompile(`\bglpat-[A-Za-z0-9_-]{20}\b`),
		severity:   api.SeverityCritical,
		confidence: 0.98,
		minEntropy: 3.5,
	},
	{
		typ:        "secret.npm_token",
		pattern:    regexp.MustCompile(`\bnpm_[A-Za-z0-9]{36}\b`),
		severity:   api.SeverityCritical,
		confidence: 0.98,
		minEntropy: 3.5,
	},
	{
		// PyPI macaroon tokens are always prefixed by the literal
		// "pypi-AgEIcHlwaS5vcmcC" (base64 of "pypi.org" macaroon header)
		// before the per-account macaroon body.
		typ:        "secret.pypi_token",
		pattern:    regexp.MustCompile(`\bpypi-AgEIcHlwaS5vcmcC[A-Za-z0-9_-]{50,}\b`),
		severity:   api.SeverityCritical,
		confidence: 0.99,
		minEntropy: 3.5,
	},
	{
		typ:        "secret.huggingface_token",
		pattern:    regexp.MustCompile(`\bhf_[A-Za-z0-9]{34}\b`),
		severity:   api.SeverityCritical,
		confidence: 0.95,
		minEntropy: 3.5,
	},

	// --- Email / messaging providers ------------------------------------
	{
		// SendGrid API key: SG.<22>.<43>.
		typ:        "secret.sendgrid_api_key",
		pattern:    regexp.MustCompile(`\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b`),
		severity:   api.SeverityCritical,
		confidence: 0.98,
		minEntropy: 3.5,
	},
	{
		// Older Mailgun API keys: key-<32 hex>. Newer Mailgun keys are
		// generic base64 with no fixed prefix; we don't ship a rule for
		// those — they need context + entropy and live in the rescue
		// path you'd add separately.
		typ:        "secret.mailgun_api_key",
		pattern:    regexp.MustCompile(`\bkey-[a-f0-9]{32}\b`),
		severity:   api.SeverityCritical,
		confidence: 0.95,
		// Hex alphabet only — max entropy is log2(16)=4, so a more
		// modest floor than the base62 detectors.
		minEntropy: 3.0,
	},
	{
		// Twilio Account SID — AC + 32 lowercase hex chars. Confidence
		// is lower than other detectors because the prefix is short
		// enough to collide with prose; entropy filters the worst FPs.
		typ:        "secret.twilio_account_sid",
		pattern:    regexp.MustCompile(`\bAC[0-9a-f]{32}\b`),
		severity:   api.SeverityHigh,
		confidence: 0.85,
		minEntropy: 3.0,
	},
	{
		// Discord webhook URLs. The path-prefix is the unique signal;
		// no entropy check (the URL prefix dominates the entropy of any
		// match, dragging it well below any useful floor).
		typ:        "secret.discord_webhook",
		pattern:    regexp.MustCompile(`https://(?:discord(?:app)?|canary\.discord)\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+`),
		severity:   api.SeverityHigh,
		confidence: 0.99,
	},
	{
		// Slack incoming-webhook URLs. Note: distinct from
		// secret.slack_token (xox*) — webhooks have no xox prefix and
		// embed the token in the URL.
		typ:        "secret.slack_webhook",
		pattern:    regexp.MustCompile(`https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]{24,}`),
		severity:   api.SeverityHigh,
		confidence: 0.99,
	},

	// --- Cloud / database -----------------------------------------------
	{
		// Azure Storage account key in a connection-string fragment. The
		// `AccountKey=` label is the anchor; without it the 88-char
		// base64 value alone has too many false positives.
		typ:        "secret.azure_storage_key",
		pattern:    regexp.MustCompile(`(?i)AccountKey=[A-Za-z0-9+/]{86,88}={0,2}`),
		severity:   api.SeverityCritical,
		confidence: 0.97,
		minEntropy: 3.5,
	},
	{
		// MongoDB connection URI with embedded credentials. We match
		// only when there's a `user:password@` segment — bare
		// `mongodb://host/db` (no creds) is not a secret leak.
		typ:        "secret.mongodb_uri",
		pattern:    regexp.MustCompile(`\bmongodb(?:\+srv)?://[^:\s/]+:[^@\s]+@[^\s/]+`),
		severity:   api.SeverityCritical,
		confidence: 0.95,
	},
}

type Scanner struct{}

func New() *Scanner { return &Scanner{} }

func (*Scanner) Name() string { return Name }

// AcceptsTransforms opts this scanner in to the pipeline's URL-decode,
// NFKC, base64, whitespace-stitch passes. Secrets routinely arrive
// wrapped — `Authorization: Bearer ghp%5F…`, AWS keys split across two
// lines, JWTs base64-encoded inside another base64 envelope — and the
// transformed views are how we catch them.
func (*Scanner) AcceptsTransforms() bool { return true }

func (*Scanner) Scan(_ context.Context, data []byte, _ api.Hints) ([]api.Finding, error) {
	if len(data) == 0 {
		return nil, nil
	}
	var findings []api.Finding
	for _, d := range detectors {
		for _, idx := range d.pattern.FindAllIndex(data, -1) {
			match := data[idx[0]:idx[1]]
			if d.validate != nil && !d.validate(match) {
				continue
			}
			if d.minEntropy > 0 && shannonEntropy(match) < d.minEntropy {
				continue
			}
			if d.requireKey && !hasKeyContext(data, idx[0], contextWindow) {
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
