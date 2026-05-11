package scanner

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TensorGreed/tg-proxy/pkg/api"
)

type fakeScanner struct{ name string }

func (f *fakeScanner) Name() string { return f.name }
func (f *fakeScanner) Scan(context.Context, []byte, api.Hints) ([]api.Finding, error) {
	return nil, nil
}

func TestRegistry_RegisterAndGet(t *testing.T) {
	r := NewRegistry()
	s := &fakeScanner{name: "demo"}

	require.NoError(t, r.Register(s))

	got, ok := r.Get("demo")
	require.True(t, ok)
	assert.Same(t, s, got)
}

func TestRegistry_RejectsDuplicates(t *testing.T) {
	r := NewRegistry()
	require.NoError(t, r.Register(&fakeScanner{name: "demo"}))
	err := r.Register(&fakeScanner{name: "demo"})
	assert.Error(t, err)
}

func TestRegistry_RejectsEmptyAndNil(t *testing.T) {
	r := NewRegistry()
	assert.Error(t, r.Register(nil))
	assert.Error(t, r.Register(&fakeScanner{name: ""}))
}

func TestRegistry_ListIsSorted(t *testing.T) {
	r := NewRegistry()
	require.NoError(t, r.Register(&fakeScanner{name: "charlie"}))
	require.NoError(t, r.Register(&fakeScanner{name: "alpha"}))
	require.NoError(t, r.Register(&fakeScanner{name: "bravo"}))

	got := r.List()
	require.Len(t, got, 3)
	assert.Equal(t, "alpha", got[0].Name())
	assert.Equal(t, "bravo", got[1].Name())
	assert.Equal(t, "charlie", got[2].Name())
}

func TestRegistry_GetMissing(t *testing.T) {
	r := NewRegistry()
	_, ok := r.Get("nope")
	assert.False(t, ok)
}
