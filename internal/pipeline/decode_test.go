package pipeline

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestContainsPercent(t *testing.T) {
	assert.True(t, containsPercent([]byte("hello%20world")))
	assert.False(t, containsPercent([]byte("hello world")))
	assert.False(t, containsPercent(nil))
	assert.False(t, containsPercent([]byte("")))
}

func TestUrlDecode_NoEscapes(t *testing.T) {
	src := []byte("plain text 123")
	decoded, origIdx := urlDecode(src)
	assert.Equal(t, src, decoded)
	require.Len(t, origIdx, len(src)+1)
	for i, v := range origIdx {
		assert.Equal(t, i, v, "1-to-1 mapping expected for unencoded input")
	}
}

func TestUrlDecode_PercentSequence(t *testing.T) {
	src := []byte("?email=alice%40example.com")
	decoded, origIdx := urlDecode(src)
	assert.Equal(t, "?email=alice@example.com", string(decoded))

	// Sanity: decoded[7:24] = "alice@example.com" — should map back to
	// src[7:26] = "alice%40example.com".
	require.Greater(t, len(origIdx), 24)
	gotStart, gotEnd := origIdx[7], origIdx[24]
	assert.Equal(t, "alice%40example.com", string(src[gotStart:gotEnd]))
}

func TestUrlDecode_MultipleSequences(t *testing.T) {
	src := []byte("%55%4E%49%4F%4E%20%53%45%4C%45%43%54")
	decoded, origIdx := urlDecode(src)
	assert.Equal(t, "UNION SELECT", string(decoded))

	// decoded[0:12] = "UNION SELECT" maps to src[0:36].
	require.Greater(t, len(origIdx), 12)
	assert.Equal(t, 0, origIdx[0])
	assert.Equal(t, 36, origIdx[12])
	assert.Equal(t, "%55%4E%49%4F%4E%20%53%45%4C%45%43%54", string(src[origIdx[0]:origIdx[12]]))
}

func TestUrlDecode_MalformedPercentPassesThrough(t *testing.T) {
	cases := []string{
		"100%",         // % at end
		"100% off",     // % followed by non-hex
		"%GG",          // %XX where neither is hex
		"a%2X",         // % with one hex one non-hex
		"a%",           // dangling % at end
		"%2",           // % then one digit, no second byte
	}
	for _, c := range cases {
		decoded, _ := urlDecode([]byte(c))
		assert.Equal(t, c, string(decoded), "input %q should pass through unchanged", c)
	}
}

func TestUrlDecode_MixedEncodedAndPlain(t *testing.T) {
	src := []byte("foo%20bar baz")
	decoded, origIdx := urlDecode(src)
	assert.Equal(t, "foo bar baz", string(decoded))

	// Verify byte-by-byte the back-mapping is correct.
	// decoded:    f  o  o     b  a  r     b  a  z
	// idx:        0  1  2  3  4  5  6  7  8  9  10
	// src:        f  o  o  %  2  0  b  a  r     b  a  z
	// src-idx:    0  1  2  3..5     6  7  8  9  10 11 12
	expected := []int{0, 1, 2, 3, 6, 7, 8, 9, 10, 11, 12, 13}
	assert.Equal(t, expected, origIdx)
}

func TestUrlDecode_LowercaseHex(t *testing.T) {
	src := []byte("%2f%2F")
	decoded, _ := urlDecode(src)
	assert.Equal(t, "//", string(decoded))
}
