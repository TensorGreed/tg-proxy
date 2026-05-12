package secrets

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TensorGreed/tg-proxy/pkg/api"
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
	input := "AWS key: AKIAIOSFODNN7EXAMPLE here"
	fs := scanOf(t, "secret.aws_access_key_id", input)
	require.Len(t, fs, 1)
	assert.Equal(t, "AKIAIOSFODNN7EXAMPLE", input[fs[0].Start:fs[0].End])
	assert.Equal(t, api.SeverityCritical, fs[0].Severity)
}

func TestScan_GitHubClassicToken(t *testing.T) {
	// ghp_ prefix + 36 chars
	tok := "ghp_" + strings.Repeat("A", 36)
	input := "Authorization: token " + tok + " here"
	fs := scanOf(t, "secret.github_token", input)
	require.Len(t, fs, 1)
	assert.Equal(t, tok, input[fs[0].Start:fs[0].End])
}

func TestScan_GitHubFineGrainedToken(t *testing.T) {
	tok := "github_pat_" + strings.Repeat("A", 22) + "_" + strings.Repeat("B", 59)
	fs := scanOf(t, "secret.github_token_fine_grained", "header "+tok+" trailing")
	require.Len(t, fs, 1)
	assert.Equal(t, tok, ("header " + tok + " trailing")[fs[0].Start:fs[0].End])
}

func TestScan_StripeKeys(t *testing.T) {
	live := "sk_live_" + strings.Repeat("a", 24)
	test := "sk_test_" + strings.Repeat("b", 24)
	input := live + " and " + test
	live_fs := scanOf(t, "secret.stripe_live_key", input)
	require.Len(t, live_fs, 1)
	assert.Equal(t, live, input[live_fs[0].Start:live_fs[0].End])
	test_fs := scanOf(t, "secret.stripe_test_key", input)
	require.Len(t, test_fs, 1)
	assert.Equal(t, test, input[test_fs[0].Start:test_fs[0].End])
	assert.Equal(t, api.SeverityCritical, live_fs[0].Severity)
	assert.Equal(t, api.SeverityHigh, test_fs[0].Severity) // test keys are lower severity
}

func TestScan_OpenAIKey(t *testing.T) {
	classic := "sk-" + strings.Repeat("a", 48)
	proj := "sk-proj-" + strings.Repeat("b", 50)
	input := "openai key: " + classic + " and project: " + proj
	cf := scanOf(t, "secret.openai_api_key", input)
	require.GreaterOrEqual(t, len(cf), 2)
}

func TestScan_AnthropicKey(t *testing.T) {
	key := "sk-ant-api03-" + strings.Repeat("x", 40)
	fs := scanOf(t, "secret.anthropic_api_key", "claude-key: "+key+" end")
	require.Len(t, fs, 1)
	assert.Equal(t, key, ("claude-key: " + key + " end")[fs[0].Start:fs[0].End])
}

func TestScan_SlackToken(t *testing.T) {
	tok := "xoxb-1234567890-abcdefghij"
	fs := scanOf(t, "secret.slack_token", "slack="+tok+" end")
	require.Len(t, fs, 1)
	assert.Equal(t, tok, ("slack=" + tok + " end")[fs[0].Start:fs[0].End])
}

func TestScan_GoogleAPIKey(t *testing.T) {
	key := "AIza" + strings.Repeat("a", 35)
	fs := scanOf(t, "secret.google_api_key", "GOOGLE_KEY="+key)
	require.Len(t, fs, 1)
}

func TestScan_JWT(t *testing.T) {
	// header.payload.signature
	jwt := "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NSJ9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	fs := scanOf(t, "secret.jwt", "Bearer "+jwt+" rest")
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

func TestScan_OffsetsArePrecise(t *testing.T) {
	input := "AWS=AKIAIOSFODNN7EXAMPLE; GH=" + "ghp_" + strings.Repeat("A", 36) +
		"; OAI=sk-" + strings.Repeat("a", 48)
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

func TestScan_PlainTextHasNoFalsePositives(t *testing.T) {
	// A sentence that contains some uppercase letters and digits but
	// nothing matching any of our patterns should produce zero findings.
	input := "The quick brown fox jumps over the lazy dog 123 times. " +
		"Plain ABCDEF text without any AKIA-like or ghp_-like prefixes."
	findings, err := New().Scan(context.Background(), []byte(input), api.Hints{})
	require.NoError(t, err)
	assert.Empty(t, findings)
}
