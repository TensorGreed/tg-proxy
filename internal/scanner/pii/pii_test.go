package pii

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TensorGreed/tg-proxy/pkg/api"
)

func scan(t *testing.T, input string) []api.Finding {
	t.Helper()
	s := New()
	findings, err := s.Scan(context.Background(), []byte(input), api.Hints{})
	require.NoError(t, err)
	return findings
}

// findingsOfType filters by Type for assertions that only care about one
// detector at a time.
func findingsOfType(fs []api.Finding, typ string) []api.Finding {
	var out []api.Finding
	for _, f := range fs {
		if f.Type == typ {
			out = append(out, f)
		}
	}
	return out
}

func TestScanner_Name(t *testing.T) {
	assert.Equal(t, "pii", New().Name())
}

func TestScan_Empty(t *testing.T) {
	findings, err := New().Scan(context.Background(), nil, api.Hints{})
	require.NoError(t, err)
	assert.Nil(t, findings)

	findings, err = New().Scan(context.Background(), []byte(""), api.Hints{})
	require.NoError(t, err)
	assert.Nil(t, findings)
}

func TestScan_Email(t *testing.T) {
	input := "contact me at alice@example.com please"
	fs := findingsOfType(scan(t, input), "pii.email")
	require.Len(t, fs, 1)

	got := input[fs[0].Start:fs[0].End]
	assert.Equal(t, "alice@example.com", got)
	assert.Equal(t, api.SeverityMedium, fs[0].Severity)
	assert.Equal(t, "pii", fs[0].Scanner)
}

func TestScan_MultipleEmails(t *testing.T) {
	input := "a@b.io and c.d+tag@sub.example.co.uk"
	fs := findingsOfType(scan(t, input), "pii.email")
	require.Len(t, fs, 2)
	assert.Equal(t, "a@b.io", input[fs[0].Start:fs[0].End])
	assert.Equal(t, "c.d+tag@sub.example.co.uk", input[fs[1].Start:fs[1].End])
}

func TestScan_SSN(t *testing.T) {
	input := "SSN: 123-45-6789 on file"
	fs := findingsOfType(scan(t, input), "pii.ssn_us")
	require.Len(t, fs, 1)
	assert.Equal(t, "123-45-6789", input[fs[0].Start:fs[0].End])
	assert.Equal(t, api.SeverityHigh, fs[0].Severity)
}

func TestScan_SSN_RequiresHyphens(t *testing.T) {
	// Plain 9-digit number should not be detected as SSN.
	fs := findingsOfType(scan(t, "id 123456789 here"), "pii.ssn_us")
	assert.Empty(t, fs)
}

func TestScan_CreditCard_ValidLuhn(t *testing.T) {
	cases := []string{
		"4111-1111-1111-1111", // Visa
		"4111 1111 1111 1111",
		"4111111111111111",
		"5500-0000-0000-0004", // MasterCard
		"340000000000009",     // Amex (15 digits)
	}
	for _, c := range cases {
		t.Run(c, func(t *testing.T) {
			input := "card: " + c + " on file"
			fs := findingsOfType(scan(t, input), "pii.credit_card")
			require.Len(t, fs, 1, "expected exactly one credit-card finding for %q", c)
			assert.Equal(t, c, input[fs[0].Start:fs[0].End])
			assert.Equal(t, api.SeverityCritical, fs[0].Severity)
		})
	}
}

func TestScan_CreditCard_InvalidLuhnRejected(t *testing.T) {
	input := "card: 4111-1111-1111-1112 on file" // last digit broken
	fs := findingsOfType(scan(t, input), "pii.credit_card")
	assert.Empty(t, fs, "broken-Luhn sequence must not be flagged")
}

func TestScan_PhoneUS(t *testing.T) {
	cases := []string{
		"(415) 555-0199",
		"415-555-0199",
		"415.555.0199",
		"+1 415-555-0199",
	}
	for _, c := range cases {
		t.Run(c, func(t *testing.T) {
			input := "call " + c + " now"
			fs := findingsOfType(scan(t, input), "pii.phone_us")
			require.Len(t, fs, 1, "expected phone match for %q", c)
			assert.Equal(t, c, input[fs[0].Start:fs[0].End])
		})
	}
}

func TestScan_PhoneUS_PlainTenDigitsNotMatched(t *testing.T) {
	fs := findingsOfType(scan(t, "ref 4155550199 here"), "pii.phone_us")
	assert.Empty(t, fs)
}

func TestScan_IPv4(t *testing.T) {
	input := "from 192.168.1.42 and 10.0.0.1"
	fs := findingsOfType(scan(t, input), "pii.ipv4")
	require.Len(t, fs, 2)
	assert.Equal(t, "192.168.1.42", input[fs[0].Start:fs[0].End])
	assert.Equal(t, "10.0.0.1", input[fs[1].Start:fs[1].End])
}

func TestScan_IPv4_RejectsOutOfRangeOctet(t *testing.T) {
	fs := findingsOfType(scan(t, "from 999.1.1.1"), "pii.ipv4")
	assert.Empty(t, fs)
}

func TestScan_OffsetsArePrecise(t *testing.T) {
	// Verify that for every finding, slicing the original bytes by
	// [Start:End] reproduces the matched substring. This invariant is what
	// the redactor relies on.
	input := "email a@b.io, ssn 111-22-3333, ip 8.8.8.8, card 4111111111111111, " +
		"phone 415-555-0199"
	fs := scan(t, input)
	require.NotEmpty(t, fs)
	for _, f := range fs {
		assert.GreaterOrEqual(t, f.Start, 0)
		assert.Greater(t, f.End, f.Start)
		assert.LessOrEqual(t, f.End, len(input))
		// Smoke check: the slice should be non-empty and not contain a
		// newline (none of our detectors match across lines).
		got := input[f.Start:f.End]
		assert.NotEmpty(t, got)
		assert.False(t, strings.ContainsRune(got, '\n'))
	}
}

func TestLuhnValid(t *testing.T) {
	assert.True(t, luhnValid([]byte("4111111111111111")))
	assert.True(t, luhnValid([]byte("4111-1111-1111-1111")))
	assert.False(t, luhnValid([]byte("4111111111111112")))
	assert.False(t, luhnValid([]byte("12345"))) // too short
	assert.False(t, luhnValid([]byte(strings.Repeat("1", 20))))
}
