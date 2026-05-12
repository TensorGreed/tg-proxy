package pipeline

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestContainsBase64Candidate(t *testing.T) {
	assert.True(t, containsBase64Candidate([]byte("encoded=QUtJQUlPU0ZPRE5ON0VYQU1QTEU=")))
	assert.True(t, containsBase64Candidate([]byte("AAAAAAAAAAAAAAAA"))) // 16 'A's
	assert.False(t, containsBase64Candidate([]byte("short stuff abc 123")))
	assert.False(t, containsBase64Candidate([]byte(""))) // empty
	assert.False(t, containsBase64Candidate([]byte("AAAA-BBBB-CCCC-DDDD"))) // dashes break the run
}

func TestIsMostlyPrintable(t *testing.T) {
	assert.True(t, isMostlyPrintable([]byte("AKIAIOSFODNN7EXAMPLE"), 0.7))
	assert.True(t, isMostlyPrintable([]byte("def foo(): pass\nreturn 1"), 0.7))
	// Random-binary-shaped bytes (mix of high-bit set and control chars).
	assert.False(t, isMostlyPrintable([]byte{0x00, 0x01, 0xff, 0xfe, 0x80, 0x81, 0x82, 0x83}, 0.7))
	assert.False(t, isMostlyPrintable(nil, 0.7))
}

func TestBase64Decode_NoCandidate_NoOp(t *testing.T) {
	src := []byte("short text without long base64-looking runs")
	out, idx := base64Decode(src)
	assert.Equal(t, string(src), string(out))
	assert.Nil(t, idx, "no candidates → origIdx must be nil to signal no-op")
}

func TestBase64Decode_DecodesAndMapsBackAWSKey(t *testing.T) {
	// QUtJQUlPU0ZPRE5ON0VYQU1QTEU= -> AKIAIOSFODNN7EXAMPLE
	src := []byte("encoded_aws=QUtJQUlPU0ZPRE5ON0VYQU1QTEU= rest")
	out, idx := base64Decode(src)
	require.NotNil(t, idx)
	assert.Contains(t, string(out), "AKIAIOSFODNN7EXAMPLE")

	// The decoded byte just after "encoded_aws=" is 'A' — verify its
	// mapping points at the first byte of the candidate in src.
	prefix := "encoded_aws="
	akiaStartInOut := len(prefix)
	akiaStartInSrc := idx[akiaStartInOut]
	assert.Equal(t, byte('Q'), src[akiaStartInSrc], "mapped src position should be the start of the candidate")
}

func TestBase64Decode_NonPrintableSkipped(t *testing.T) {
	// A long base64 run that decodes to random binary (not "mostly text").
	// Construct one with high-bit bytes in the decoded form.
	// "////////////////" * 2 decodes to 24 bytes of 0xff.
	src := []byte("blob=////////////////////////////////////////")
	out, idx := base64Decode(src)
	assert.Equal(t, string(src), string(out), "non-printable decoded candidates must NOT be substituted")
	assert.Nil(t, idx, "non-printable candidate → signal as no-op")
}

func TestBase64Decode_MultipleCandidates(t *testing.T) {
	src := []byte("a=QUtJQUlPU0ZPRE5ON0VYQU1QTEU=, b=ZGVmIGZvbygpOiBwYXNzCgpyZXR1cm4gMQ==")
	out, idx := base64Decode(src)
	require.NotNil(t, idx)
	assert.Contains(t, string(out), "AKIAIOSFODNN7EXAMPLE")
	assert.Contains(t, string(out), "def foo()")
}

func TestBase64Decode_UnalignedCandidateSkipped(t *testing.T) {
	// 17 chars (not a multiple of 4 with padding) — must not be decoded.
	src := []byte("blob=AAAAAAAAAAAAAAAAA")
	out, idx := base64Decode(src)
	assert.Equal(t, string(src), string(out))
	assert.Nil(t, idx)
}

func TestBase64Decode_PreservesNonCandidateBytes(t *testing.T) {
	src := []byte("HEADER QUtJQUlPU0ZPRE5ON0VYQU1QTEU= TRAILER")
	out, idx := base64Decode(src)
	require.NotNil(t, idx)
	// HEADER + " " + AKIAIOSFODNN7EXAMPLE + " " + TRAILER
	assert.True(t, len(out) < len(src), "candidate should have shrunk")
	assert.True(t, []byte(out)[0] == 'H', "header preserved")
	assert.Contains(t, string(out), "AKIAIOSFODNN7EXAMPLE")
	assert.Contains(t, string(out), "TRAILER")
}
