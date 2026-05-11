package mask

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TensorGreed/tg-proxy/pkg/api"
)

func redact(t *testing.T, input string, findings []api.Finding) string {
	t.Helper()
	r := New("")
	out, err := r.Redact(context.Background(), []byte(input), findings)
	require.NoError(t, err)
	return string(out)
}

func TestRedactor_Name(t *testing.T) {
	assert.Equal(t, "mask", New("").Name())
}

func TestRedact_NoFindings(t *testing.T) {
	out := redact(t, "hello world", nil)
	assert.Equal(t, "hello world", out)
}

func TestRedact_EmptyData(t *testing.T) {
	out := redact(t, "", []api.Finding{{Start: 0, End: 5}})
	assert.Equal(t, "", out)
}

func TestRedact_SingleFinding(t *testing.T) {
	input := "email is alice@example.com here"
	start := len("email is ")
	end := start + len("alice@example.com")
	out := redact(t, input, []api.Finding{{Start: start, End: end}})
	assert.Equal(t, "email is [REDACTED] here", out)
}

func TestRedact_MultipleNonOverlapping(t *testing.T) {
	input := "a@b.io and c@d.io"
	out := redact(t, input, []api.Finding{
		{Start: 0, End: 6},
		{Start: 11, End: 17},
	})
	assert.Equal(t, "[REDACTED] and [REDACTED]", out)
}

func TestRedact_OutOfOrderFindings(t *testing.T) {
	input := "a@b.io and c@d.io"
	out := redact(t, input, []api.Finding{
		{Start: 11, End: 17},
		{Start: 0, End: 6},
	})
	assert.Equal(t, "[REDACTED] and [REDACTED]", out)
}

func TestRedact_OverlappingFindings(t *testing.T) {
	// Two overlapping findings (e.g. email matches alice@1.2.3.4 and the
	// IPv4 inside it also matches) should collapse to a single placeholder.
	input := "value alice@1.2.3.4 end"
	out := redact(t, input, []api.Finding{
		{Start: 6, End: 19}, // alice@1.2.3.4
		{Start: 12, End: 19}, // 1.2.3.4
	})
	assert.Equal(t, "value [REDACTED] end", out)
}

func TestRedact_DuplicateFindings(t *testing.T) {
	input := "secret token"
	dup := api.Finding{Start: 0, End: 6}
	out := redact(t, input, []api.Finding{dup, dup, dup})
	assert.Equal(t, "[REDACTED] token", out)
}

func TestRedact_AdjacentFindingsAreSeparate(t *testing.T) {
	// Adjacent (touching but not overlapping) findings must produce two
	// placeholders, not one merged span.
	input := "AAAABBBB"
	out := redact(t, input, []api.Finding{
		{Start: 0, End: 4},
		{Start: 4, End: 8},
	})
	assert.Equal(t, "[REDACTED][REDACTED]", out)
}

func TestRedact_InvalidFindingsAreSkipped(t *testing.T) {
	input := "hello world"
	out := redact(t, input, []api.Finding{
		{Start: -1, End: 5},          // negative start
		{Start: 0, End: 100},         // end past len
		{Start: 5, End: 5},           // empty
		{Start: 6, End: 3},           // end before start
		{Start: 6, End: 11},          // valid: "world"
	})
	assert.Equal(t, "hello [REDACTED]", out)
}

func TestRedact_FullRange(t *testing.T) {
	input := "all of it"
	out := redact(t, input, []api.Finding{{Start: 0, End: len(input)}})
	assert.Equal(t, "[REDACTED]", out)
}

func TestRedact_CustomPlaceholder(t *testing.T) {
	r := New("***")
	out, err := r.Redact(context.Background(), []byte("hi alice bye"),
		[]api.Finding{{Start: 3, End: 8}})
	require.NoError(t, err)
	assert.Equal(t, "hi *** bye", string(out))
}

func TestRedact_DefaultPlaceholderWhenEmpty(t *testing.T) {
	r := New("")
	out, err := r.Redact(context.Background(), []byte("hi alice bye"),
		[]api.Finding{{Start: 3, End: 8}})
	require.NoError(t, err)
	assert.Contains(t, string(out), "[REDACTED]")
}

func TestRedact_AllFindingsInvalid(t *testing.T) {
	// When every finding is invalid the redactor must return the original
	// data unchanged.
	out := redact(t, "untouched", []api.Finding{
		{Start: -1, End: 5},
		{Start: 100, End: 200},
		{Start: 3, End: 3},
	})
	assert.Equal(t, "untouched", out)
}
