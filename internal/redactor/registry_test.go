package redactor

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TensorGreed/tg-proxy/pkg/api"
)

type fakeRedactor struct{ name string }

func (f *fakeRedactor) Name() string { return f.name }
func (f *fakeRedactor) Redact(context.Context, []byte, []api.Finding) ([]byte, error) {
	return nil, nil
}

func TestRegistry_RegisterAndGet(t *testing.T) {
	r := NewRegistry()
	d := &fakeRedactor{name: "demo"}
	require.NoError(t, r.Register(d))

	got, ok := r.Get("demo")
	require.True(t, ok)
	assert.Same(t, d, got)
}

func TestRegistry_RejectsDuplicates(t *testing.T) {
	r := NewRegistry()
	require.NoError(t, r.Register(&fakeRedactor{name: "demo"}))
	assert.Error(t, r.Register(&fakeRedactor{name: "demo"}))
}

func TestRegistry_RejectsEmptyAndNil(t *testing.T) {
	r := NewRegistry()
	assert.Error(t, r.Register(nil))
	assert.Error(t, r.Register(&fakeRedactor{name: ""}))
}

func TestRegistry_ListIsSorted(t *testing.T) {
	r := NewRegistry()
	require.NoError(t, r.Register(&fakeRedactor{name: "charlie"}))
	require.NoError(t, r.Register(&fakeRedactor{name: "alpha"}))
	require.NoError(t, r.Register(&fakeRedactor{name: "bravo"}))

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
