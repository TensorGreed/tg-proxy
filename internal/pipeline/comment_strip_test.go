package pipeline

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TensorGreed/tg-proxy/internal/redactor/mask"
	"github.com/TensorGreed/tg-proxy/internal/scanner/sqli"
	"github.com/TensorGreed/tg-proxy/pkg/api"
)

func TestContainsSlashStarComment(t *testing.T) {
	assert.True(t, containsSlashStarComment([]byte("UN/**/ION")))
	assert.True(t, containsSlashStarComment([]byte("/* normal comment */")))
	assert.True(t, containsSlashStarComment([]byte("trailing/*x")))
	assert.False(t, containsSlashStarComment([]byte("plain text")))
	assert.False(t, containsSlashStarComment([]byte("a / b")))
	assert.False(t, containsSlashStarComment(nil))
}

func TestSqliCommentStrip_NoOp(t *testing.T) {
	src := []byte("SELECT * FROM users WHERE id=1")
	out, idx := sqliCommentStrip(src)
	assert.Equal(t, string(src), string(out))
	assert.Nil(t, idx, "no `/*` present → must signal no-op")
}

func TestSqliCommentStrip_StripsInlineComments(t *testing.T) {
	src := []byte("UN/**/ION SE/**/LECT * FROM users")
	out, idx := sqliCommentStrip(src)
	require.NotNil(t, idx)
	assert.Equal(t, "UNION SELECT * FROM users", string(out))

	// Mapping: out[0..12] = "UNION SELECT" must straddle the original
	// comment-bearing span (20 src bytes for the keywords + comments).
	assert.Equal(t, 0, idx[0])
	assert.Equal(t, 20, idx[12])
}

func TestSqliCommentStrip_MultilineComment(t *testing.T) {
	src := []byte("SE/* multi\nline */LECT")
	out, _ := sqliCommentStrip(src)
	assert.Equal(t, "SELECT", string(out))
}

func TestSqliCommentStrip_UnterminatedCommentPassesThrough(t *testing.T) {
	// `/*` without a matching `*/` — the regex won't match, so output is
	// identical to input.
	src := []byte("SELECT /* dangling comment")
	out, idx := sqliCommentStrip(src)
	assert.Equal(t, string(src), string(out))
	assert.Nil(t, idx)
}

func TestScan_CommentStripPass_CatchesEvadedUnion(t *testing.T) {
	p := New([]api.Scanner{sqli.New()}, mask.New(""))
	src := []byte("id=1 UN/**/ION SE/**/LECT username,password FROM users--")
	findings, err := p.Scan(context.Background(), src, api.Hints{})
	require.NoError(t, err)

	var unionFound bool
	for _, f := range findings {
		if f.Type == "sqli.union_select" {
			unionFound = true
			// Mapped match must include the comment-bearing original span.
			assert.Contains(t, string(src[f.Start:f.End]), "UN/**/ION SE/**/LECT")
		}
	}
	assert.True(t, unionFound, "union_select must fire on the comment-stripped body")
}

func TestScan_CommentStripPass_StillFlagsCommentMarker(t *testing.T) {
	// The comment-strip pass is ADDITIVE — it produces new findings on
	// the stripped view but doesn't suppress findings from the raw scan.
	// In particular the existing sqli.comment_marker rule must still
	// fire on the original `/**/` bytes.
	p := New([]api.Scanner{sqli.New()}, mask.New(""))
	findings, err := p.Scan(context.Background(),
		[]byte("UN/**/ION SE/**/LECT"), api.Hints{})
	require.NoError(t, err)
	var markerFound, unionFound bool
	for _, f := range findings {
		if f.Type == "sqli.comment_marker" {
			markerFound = true
		}
		if f.Type == "sqli.union_select" {
			unionFound = true
		}
	}
	assert.True(t, markerFound, "comment_marker must still fire on raw `/**/`")
	assert.True(t, unionFound, "union_select must fire on stripped view")
}
