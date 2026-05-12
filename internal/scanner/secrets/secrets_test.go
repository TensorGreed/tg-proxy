package secrets

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TensorGreed/tg-proxy/pkg/api"
)

// Test fixtures: realistic-shaped values with high entropy so they pass the
// detector's entropy floor. Every value here is hand-jumbled, obviously
// not a real credential, but structurally indistinguishable from one.
const (
	exampleAWSKeyID          = "AKIAIOSFODNN7EXAMPLE"
	exampleGitHubClassic     = "ghp_2Yz9KqMjL4xR7bN0pVcSwTfHaG3eDlEoBuIn"
	exampleGitHubFineGrained = "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"
	exampleStripeLive        = "sk_live_4HrPbMzZqXkTcWnFsLDaEoBy"
	exampleStripeTest        = "sk_test_4HrPbMzZqXkTcWnFsLDaEoBy"
	exampleOpenAIClassic     = "sk-4mP7yKxQvN3wRfZ8dHcEjBaTuLgI2sObYn1V9pXM5kAtRzFi"
	exampleOpenAIProj        = "sk-proj-4mP7yKxQvN3wRfZ8dHcEjBaTuLgI2sObYn1V9pXM5kAtRzFi"
	exampleAnthropic         = "sk-ant-api03-iL4mP7yKxQvN3wRfZ8dHcEjBaTuLgI2sObYn1V9pXMaRtZk"
	exampleSlackBot          = "xoxb-1234567890-2Yz9KqMjL4xR7bN0pVcSwTfHaG3eDlEoBu"
	exampleGoogleAPI         = "AIzaSy0d4tUbKLpoZAQ_9XmHJnE5w-VqfBcN1Hy"
	exampleJWT               = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

	// New provider examples (M6 expansion).
	exampleGitLabPAT       = "glpat-rJ7nL3pT9mK2vH8qBxYz"
	exampleNPMToken        = "npm_4mP7yKxQvN3wRfZ8dHcEjBaTuLgI2sObYn1V"
	examplePyPIToken       = "pypi-AgEIcHlwaS5vcmcCJDg1MTAzN2I1LWE0OWMtNGYxNS04N2QtNzNkZGYwMzQyNzI4AAILRm"
	exampleHuggingFace     = "hf_4mP7yKxQvN3wRfZ8dHcEjBaTuLgI2sObYn"
	exampleSendGrid        = "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"
	exampleMailgun         = "key-3eb0fb6e1a89d6c4b8f23e7a9d56c01b"
	exampleTwilioSID       = "AC0123456789abcdef0123456789abcdef"
	exampleDiscordWebhook  = "https://discord.com/api/webhooks/123456789012345678/abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ-_"
	exampleSlackWebhook    = "https://hooks.slack.com/services/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"
	exampleAzureStorageKey = "AccountKey=8aBcdefghIJKLmnopQRSTUVWxyzABCDEFGHIJKLMNOPQRSTUVwxyz12345678abcdefghIJKLmnopQRSTUVW+/=="
	exampleMongoURI        = "mongodb+srv://app_user:hZ4mP7yKxQvN@cluster0.example.mongodb.net/app"
)

func scanOf(t *testing.T, typ, input string) []api.Finding {
	t.Helper()
	all, err := New().Scan(context.Background(), []byte(input), api.Hints{})
	require.NoError(t, err)
	var out []api.Finding
	for _, f := range all {
		if f.Type == typ {
			out = append(out, f)
		}
	}
	return out
}

func TestScanner_Name(t *testing.T) {
	assert.Equal(t, "secrets", New().Name())
}

func TestScan_Empty(t *testing.T) {
	f, err := New().Scan(context.Background(), nil, api.Hints{})
	require.NoError(t, err)
	assert.Nil(t, f)
}

func TestScan_AWSAccessKey(t *testing.T) {
	input := "AWS_ACCESS_KEY_ID=" + exampleAWSKeyID
	fs := scanOf(t, "secret.aws_access_key_id", input)
	require.Len(t, fs, 1)
	assert.Equal(t, exampleAWSKeyID, input[fs[0].Start:fs[0].End])
	assert.Equal(t, api.SeverityCritical, fs[0].Severity)
}

func TestScan_GitHubClassicToken(t *testing.T) {
	input := "Authorization: token " + exampleGitHubClassic + " here"
	fs := scanOf(t, "secret.github_token", input)
	require.Len(t, fs, 1)
	assert.Equal(t, exampleGitHubClassic, input[fs[0].Start:fs[0].End])
}

func TestScan_GitHubFineGrainedToken(t *testing.T) {
	input := "header " + exampleGitHubFineGrained + " trailing"
	fs := scanOf(t, "secret.github_token_fine_grained", input)
	require.Len(t, fs, 1)
	assert.Equal(t, exampleGitHubFineGrained, input[fs[0].Start:fs[0].End])
}

func TestScan_StripeKeys(t *testing.T) {
	input := exampleStripeLive + " and " + exampleStripeTest
	live := scanOf(t, "secret.stripe_live_key", input)
	require.Len(t, live, 1)
	assert.Equal(t, exampleStripeLive, input[live[0].Start:live[0].End])
	test := scanOf(t, "secret.stripe_test_key", input)
	require.Len(t, test, 1)
	assert.Equal(t, exampleStripeTest, input[test[0].Start:test[0].End])
	assert.Equal(t, api.SeverityCritical, live[0].Severity)
	assert.Equal(t, api.SeverityHigh, test[0].Severity)
}

func TestScan_OpenAIKey(t *testing.T) {
	// OPENAI_API_KEY label provides the key-context the detector requires.
	input := "OPENAI_API_KEY=" + exampleOpenAIClassic + " and project token = " + exampleOpenAIProj
	fs := scanOf(t, "secret.openai_api_key", input)
	require.GreaterOrEqual(t, len(fs), 2)
}

func TestScan_OpenAIKey_RejectedWithoutContext(t *testing.T) {
	// Same realistic key, but the surrounding text has no key-like label.
	// The detector must NOT fire on bare prose.
	input := "Random alphanumeric tokens in this sentence " + exampleOpenAIClassic + " mean nothing."
	fs := scanOf(t, "secret.openai_api_key", input)
	assert.Empty(t, fs, "OpenAI rule must require a nearby key keyword")
}

func TestScan_OpenAIKey_LowEntropyRejected(t *testing.T) {
	// Has the key context AND the right format, but obviously a placeholder.
	low := "sk-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	input := "OPENAI_API_KEY=" + low
	fs := scanOf(t, "secret.openai_api_key", input)
	assert.Empty(t, fs, "low-entropy values must be filtered out")
}

func TestScan_AnthropicKey(t *testing.T) {
	input := "ANTHROPIC_API_KEY=" + exampleAnthropic
	fs := scanOf(t, "secret.anthropic_api_key", input)
	require.Len(t, fs, 1)
	assert.Equal(t, exampleAnthropic, input[fs[0].Start:fs[0].End])
}

func TestScan_SlackToken(t *testing.T) {
	input := "slack token = " + exampleSlackBot + " end"
	fs := scanOf(t, "secret.slack_token", input)
	require.Len(t, fs, 1)
}

func TestScan_GoogleAPIKey(t *testing.T) {
	input := "GOOGLE_API_KEY=" + exampleGoogleAPI
	fs := scanOf(t, "secret.google_api_key", input)
	require.Len(t, fs, 1)
}

func TestScan_JWT(t *testing.T) {
	input := "Authorization: Bearer " + exampleJWT
	fs := scanOf(t, "secret.jwt", input)
	require.Len(t, fs, 1)
}

func TestScan_PEMPrivateKeyHeader(t *testing.T) {
	for _, header := range []string{
		"-----BEGIN PRIVATE KEY-----",
		"-----BEGIN RSA PRIVATE KEY-----",
		"-----BEGIN EC PRIVATE KEY-----",
		"-----BEGIN OPENSSH PRIVATE KEY-----",
		"-----BEGIN ENCRYPTED PRIVATE KEY-----",
	} {
		input := "found in body:\n" + header + "\nMIIE..."
		fs := scanOf(t, "secret.private_key", input)
		require.Len(t, fs, 1, header)
		assert.Equal(t, header, input[fs[0].Start:fs[0].End])
	}
}

func TestScan_PlaceholdersRejected(t *testing.T) {
	// Each line below has the right regex format but degenerate entropy.
	// All must be filtered out by the entropy modifier.
	input := `
AWS_ACCESS_KEY_ID=AKIAXXXXXXXXXXXXXXXX
GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
ANTHROPIC_API_KEY=sk-ant-api03-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
STRIPE_LIVE_KEY=sk_live_xxxxxxxxxxxxxxxxxxxxxxxxxxxx
GOOGLE_API_KEY=AIzaxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
`
	findings, err := New().Scan(context.Background(), []byte(input), api.Hints{})
	require.NoError(t, err)
	assert.Empty(t, findings, "all entries are placeholders and must not be flagged; got %+v", findings)
}

func TestScan_OffsetsArePrecise(t *testing.T) {
	input := "AWS=" + exampleAWSKeyID + "; GH=" + exampleGitHubClassic +
		"; OAI: OPENAI_API_KEY=" + exampleOpenAIClassic
	findings, err := New().Scan(context.Background(), []byte(input), api.Hints{})
	require.NoError(t, err)
	require.NotEmpty(t, findings)
	for _, f := range findings {
		assert.Greater(t, f.End, f.Start)
		assert.LessOrEqual(t, f.End, len(input))
		assert.NotEmpty(t, input[f.Start:f.End])
		assert.Equal(t, "secrets", f.Scanner)
	}
}

func TestScan_GitLabPAT(t *testing.T) {
	input := "GITLAB_TOKEN=" + exampleGitLabPAT
	fs := scanOf(t, "secret.gitlab_pat", input)
	require.Len(t, fs, 1)
	assert.Equal(t, exampleGitLabPAT, input[fs[0].Start:fs[0].End])
}

func TestScan_NPMToken(t *testing.T) {
	input := "NPM_TOKEN=" + exampleNPMToken
	fs := scanOf(t, "secret.npm_token", input)
	require.Len(t, fs, 1)
	assert.Equal(t, exampleNPMToken, input[fs[0].Start:fs[0].End])
}

func TestScan_PyPIToken(t *testing.T) {
	input := "PYPI_API_TOKEN=" + examplePyPIToken
	fs := scanOf(t, "secret.pypi_token", input)
	require.Len(t, fs, 1)
	assert.Equal(t, examplePyPIToken, input[fs[0].Start:fs[0].End])
}

func TestScan_HuggingFaceToken(t *testing.T) {
	input := "HF_TOKEN=" + exampleHuggingFace
	fs := scanOf(t, "secret.huggingface_token", input)
	require.Len(t, fs, 1)
	assert.Equal(t, exampleHuggingFace, input[fs[0].Start:fs[0].End])
}

func TestScan_SendGrid(t *testing.T) {
	input := "SENDGRID_API_KEY=" + exampleSendGrid
	fs := scanOf(t, "secret.sendgrid_api_key", input)
	require.Len(t, fs, 1)
	assert.Equal(t, exampleSendGrid, input[fs[0].Start:fs[0].End])
}

func TestScan_Mailgun(t *testing.T) {
	input := "MAILGUN_API_KEY=" + exampleMailgun
	fs := scanOf(t, "secret.mailgun_api_key", input)
	require.Len(t, fs, 1)
	assert.Equal(t, exampleMailgun, input[fs[0].Start:fs[0].End])
}

func TestScan_TwilioAccountSID(t *testing.T) {
	input := "TWILIO_ACCOUNT_SID=" + exampleTwilioSID
	fs := scanOf(t, "secret.twilio_account_sid", input)
	require.Len(t, fs, 1)
}

func TestScan_DiscordWebhook(t *testing.T) {
	input := "DISCORD_WEBHOOK=" + exampleDiscordWebhook
	fs := scanOf(t, "secret.discord_webhook", input)
	require.Len(t, fs, 1)
	assert.Equal(t, exampleDiscordWebhook, input[fs[0].Start:fs[0].End])
}

func TestScan_SlackWebhook(t *testing.T) {
	input := "SLACK_WEBHOOK=" + exampleSlackWebhook
	fs := scanOf(t, "secret.slack_webhook", input)
	require.Len(t, fs, 1)
	assert.Equal(t, exampleSlackWebhook, input[fs[0].Start:fs[0].End])
}

func TestScan_AzureStorageKey(t *testing.T) {
	input := "AZURE=DefaultEndpointsProtocol=https;AccountName=mystore;" + exampleAzureStorageKey + ";EndpointSuffix=core.windows.net"
	fs := scanOf(t, "secret.azure_storage_key", input)
	require.Len(t, fs, 1)
	assert.Equal(t, exampleAzureStorageKey, input[fs[0].Start:fs[0].End])
}

func TestScan_MongoDBURIWithCreds(t *testing.T) {
	fs := scanOf(t, "secret.mongodb_uri", "MONGODB_URI="+exampleMongoURI)
	require.Len(t, fs, 1)
}

func TestScan_MongoDBURIWithoutCredsNotFlagged(t *testing.T) {
	// Plain mongodb://host (no embedded creds) is not a leak; the rule
	// must require the user:password@ portion.
	fs := scanOf(t, "secret.mongodb_uri", "MONGODB_URI=mongodb://db.example.io:27017/app")
	assert.Empty(t, fs)
}

func TestScan_PlainTextHasNoFalsePositives(t *testing.T) {
	input := "The quick brown fox jumps over the lazy dog 123 times. " +
		"Plain ABCDEF text without any AKIA-like or ghp_-like prefixes."
	findings, err := New().Scan(context.Background(), []byte(input), api.Hints{})
	require.NoError(t, err)
	assert.Empty(t, findings)
}
