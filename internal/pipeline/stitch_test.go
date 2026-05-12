package pipeline

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TensorGreed/tg-proxy/internal/redactor/mask"
	"github.com/TensorGreed/tg-proxy/internal/scanner/pii"
	"github.com/TensorGreed/tg-proxy/internal/scanner/secrets"
	"github.com/TensorGreed/tg-proxy/pkg/api"
)

func TestContainsSpaceOrTab(t *testing.T) {
	assert.True(t, containsSpaceOrTab([]byte("a b")))
	assert.True(t, containsSpaceOrTab([]byte("a\tb")))
	assert.False(t, containsSpaceOrTab([]byte("plain")))
	assert.False(t, containsSpaceOrTab(nil))
	// Newlines don't qualify (the stitch is intra-line by design).
	assert.False(t, containsSpaceOrTab([]byte("a\nb")))
}

func TestWhitespaceStitch_NoOpWhenNoRegion(t *testing.T) {
	src := []byte("short")
	out, idx := whitespaceStitch(src)
	assert.Equal(t, string(src), string(out))
	assert.Nil(t, idx)
}

func TestWhitespaceStitch_EmailWithSpaces(t *testing.T) {
	src := []byte("contact alice @ example.com please")
	out, idx := whitespaceStitch(src)
	require.NotNil(t, idx)
	assert.Contains(t, string(out), "alice@example.com")
	// "alice@example.com" doesn't have spaces but the stitched output
	// merged the original "alice @ example.com" — verify the mapping
	// spans the whole original token. (The mapped range may include
	// boundary whitespace when the stitched substring sits inside a
	// larger region; the redactor is fine with redacting a slightly
	// wider span.)
	stitched := []byte("alice@example.com")
	i := indexOf(out, stitched)
	require.GreaterOrEqual(t, i, 0)
	srcStart := idx[i]
	srcEnd := idx[i+len(stitched)]
	mapped := string(src[srcStart:srcEnd])
	assert.Contains(t, mapped, "alice @ example.com")
}

func TestWhitespaceStitch_PhoneDigitSpaced(t *testing.T) {
	src := []byte("call 4 1 5 - 5 5 5 - 0 1 8 8 now")
	out, _ := whitespaceStitch(src)
	assert.Contains(t, string(out), "415-555-0188")
}

func TestWhitespaceStitch_AWSKey(t *testing.T) {
	src := []byte("aws=AKIA IOSFODNN7EXAMPLE here")
	out, _ := whitespaceStitch(src)
	assert.Contains(t, string(out), "AKIAIOSFODNN7EXAMPLE")
}

func TestWhitespaceStitch_DoubleSpaceTerminatesRegion(t *testing.T) {
	// Two consecutive spaces are a hard region boundary: we treat them
	// as "definitely separating distinct tokens", not "internal join".
	src := []byte("alice  bob")
	out, idx := whitespaceStitch(src)
	assert.Equal(t, string(src), string(out))
	assert.Nil(t, idx)
}

func TestWhitespaceStitch_ShortRegionSkipped(t *testing.T) {
	// Region is too short to be a likely token.
	src := []byte("a b c d")
	out, idx := whitespaceStitch(src)
	assert.Equal(t, string(src), string(out))
	assert.Nil(t, idx)
}

func TestWhitespaceStitch_SparseRegionSkipped(t *testing.T) {
	// 8 eligible chars, 7 spaces — 8/15 ≈ 0.53 — meets ratio. Use a
	// sparser case to fall below the ratio.
	src := []byte("a b c d e f g h i j")
	out, idx := whitespaceStitch(src)
	// 10 letters, 9 spaces → 10/19 ≈ 0.53. Still meets 50%. So this is
	// stitched. To get below 50%, double the spacing — but double space
	// terminates the region. So in practice the ratio gate alone is
	// rarely the discriminator; the double-space rule does the heavy
	// lifting. Document by assertion:
	require.NotNil(t, idx)
	assert.Equal(t, "abcdefghij", string(out))
}

func TestWhitespaceStitch_NonEligibleCharTerminatesRegion(t *testing.T) {
	// A `:` in the middle of what otherwise looks like a token breaks
	// the region. Two separate regions; neither qualifies in this case.
	src := []byte("alice : bob")
	out, idx := whitespaceStitch(src)
	assert.Equal(t, string(src), string(out))
	assert.Nil(t, idx)
}

// --- pipeline integration ---------------------------------------------

func TestScan_WhitespaceStitchPass_CatchesAWSWhitespaceSplit(t *testing.T) {
	p := New([]api.Scanner{secrets.New()}, mask.New(""))
	src := []byte("export AWS_ACCESS_KEY_ID=AKIA IOSFODNN7EXAMPLE")
	findings, err := p.Scan(context.Background(), src, api.Hints{})
	require.NoError(t, err)

	var aws bool
	for _, f := range findings {
		if f.Type == "secret.aws_access_key_id" {
			aws = true
			// Mapped range must include the whitespace from the original.
			assert.Contains(t, string(src[f.Start:f.End]), "AKIA IOSFODNN7EXAMPLE")
		}
	}
	assert.True(t, aws, "AWS key must fire after whitespace stitch")
}

func TestScan_WhitespaceStitchPass_CatchesEmailWithSpaces(t *testing.T) {
	p := New([]api.Scanner{pii.New()}, mask.New(""))
	src := []byte("contact alice @ example.com please")
	findings, err := p.Scan(context.Background(), src, api.Hints{})
	require.NoError(t, err)

	var email bool
	for _, f := range findings {
		if f.Type == "pii.email" {
			email = true
			assert.Contains(t, string(src[f.Start:f.End]), "alice @ example.com")
		}
	}
	assert.True(t, email, "email must fire after whitespace stitch")
}

// --- narrow digit-only stitch -----------------------------------------

func TestDigitStitch_PhoneDigitSpacedInProse(t *testing.T) {
	// The case the broad whitespace stitch couldn't handle alone: digits
	// embedded in prose. The narrow pass treats letters as region
	// blockers, so the prose stays separate from the digit cluster.
	src := []byte("My number is 4 1 5 - 5 5 5 - 0 1 8 8, call any time.")
	out, idx := digitStitch(src)
	require.NotNil(t, idx)
	got := string(out)

	// The digit cluster is fused — but the prose is intact.
	assert.Contains(t, got, "415-555-0188")
	assert.Contains(t, got, "My number is")
}

func TestDigitStitch_LeavesLetterTokensAlone(t *testing.T) {
	// An AWS key with broken whitespace — the narrow pass skips it
	// entirely (the broad pass handles that case).
	src := []byte("aws=AKIA IOSFODNN7EXAMPLE here")
	out, idx := digitStitch(src)
	assert.Equal(t, string(src), string(out))
	assert.Nil(t, idx)
}

func TestDigitStitch_LeavesEmailAlone(t *testing.T) {
	// Email with spaces — also handled by broad pass, not narrow.
	src := []byte("contact alice @ example.com please")
	out, idx := digitStitch(src)
	assert.Equal(t, string(src), string(out))
	assert.Nil(t, idx)
}

func TestScan_DigitStitchPass_CatchesPhoneInProse(t *testing.T) {
	p := New([]api.Scanner{pii.New()}, mask.New(""))
	src := []byte("My number is 4 1 5 - 5 5 5 - 0 1 8 8, call any time.")
	findings, err := p.Scan(context.Background(), src, api.Hints{})
	require.NoError(t, err)

	var phone bool
	for _, f := range findings {
		if f.Type == "pii.phone_us" {
			phone = true
			// Mapped range must include the spaces from the original.
			assert.Contains(t, string(src[f.Start:f.End]), "4 1 5 - 5 5 5 - 0 1 8 8")
		}
	}
	assert.True(t, phone, "phone must fire on the digit-stitched view")
}

// indexOf finds the first occurrence of needle in haystack, or -1.
// Tiny helper so the test reads naturally without pulling in bytes.Index.
func indexOf(haystack, needle []byte) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		match := true
		for j := range needle {
			if haystack[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}
