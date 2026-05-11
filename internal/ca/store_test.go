package ca

import (
	"crypto/x509"
	"strconv"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestStore(t *testing.T, capacity int) *Store {
	t.Helper()
	root, err := NewRoot("test CA")
	require.NoError(t, err)
	s, err := NewStore(root, capacity, "test org")
	require.NoError(t, err)
	return s
}

func TestNewStore_RejectsIncompleteRoot(t *testing.T) {
	_, err := NewStore(nil, 10, "")
	assert.Error(t, err)
	_, err = NewStore(&Root{}, 10, "")
	assert.Error(t, err)
}

func TestNewStore_DefaultsOrgToRootCommonName(t *testing.T) {
	root, err := NewRoot("root CN")
	require.NoError(t, err)
	s, err := NewStore(root, 10, "")
	require.NoError(t, err)
	assert.Equal(t, "root CN", s.org)
}

func TestLeafFor_DNSName(t *testing.T) {
	s := newTestStore(t, 16)
	cert, err := s.LeafFor("example.com")
	require.NoError(t, err)

	require.NotNil(t, cert.Leaf)
	assert.Contains(t, cert.Leaf.DNSNames, "example.com")
	assert.Empty(t, cert.Leaf.IPAddresses)
	assert.Equal(t, "example.com", cert.Leaf.Subject.CommonName)
}

func TestLeafFor_IPAddress(t *testing.T) {
	s := newTestStore(t, 16)
	cert, err := s.LeafFor("203.0.113.5")
	require.NoError(t, err)

	require.NotNil(t, cert.Leaf)
	assert.Empty(t, cert.Leaf.DNSNames)
	require.Len(t, cert.Leaf.IPAddresses, 1)
	assert.Equal(t, "203.0.113.5", cert.Leaf.IPAddresses[0].String())
}

func TestLeafFor_VerifiesAgainstRoot(t *testing.T) {
	s := newTestStore(t, 16)
	cert, err := s.LeafFor("api.example.com")
	require.NoError(t, err)

	roots := x509.NewCertPool()
	roots.AddCert(s.root.Cert)
	_, err = cert.Leaf.Verify(x509.VerifyOptions{
		Roots:   roots,
		DNSName: "api.example.com",
		KeyUsages: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
	})
	assert.NoError(t, err)
}

func TestLeafFor_CacheReturnsSameCert(t *testing.T) {
	s := newTestStore(t, 16)
	a, err := s.LeafFor("cache.example.com")
	require.NoError(t, err)
	b, err := s.LeafFor("cache.example.com")
	require.NoError(t, err)
	assert.Same(t, a, b, "cache hit should return the same *tls.Certificate")
	assert.Equal(t, 1, s.CacheLen())
}

func TestLeafFor_NormalizesHost(t *testing.T) {
	s := newTestStore(t, 16)
	a, err := s.LeafFor("Example.COM:443")
	require.NoError(t, err)
	b, err := s.LeafFor("example.com")
	require.NoError(t, err)
	assert.Same(t, a, b)
	assert.Equal(t, 1, s.CacheLen())
}

func TestLeafFor_LRUEvictsOldest(t *testing.T) {
	s := newTestStore(t, 3)
	for i := 0; i < 5; i++ {
		_, err := s.LeafFor("host" + strconv.Itoa(i) + ".example.com")
		require.NoError(t, err)
	}
	assert.Equal(t, 3, s.CacheLen())

	// The two oldest entries should be gone.
	_, ok := s.cacheGet("host0.example.com")
	assert.False(t, ok)
	_, ok = s.cacheGet("host1.example.com")
	assert.False(t, ok)
	// Newer entries remain.
	_, ok = s.cacheGet("host4.example.com")
	assert.True(t, ok)
}

func TestLeafFor_ZeroCapacityDisablesCache(t *testing.T) {
	s := newTestStore(t, 0)
	a, err := s.LeafFor("nocache.example.com")
	require.NoError(t, err)
	b, err := s.LeafFor("nocache.example.com")
	require.NoError(t, err)
	assert.NotSame(t, a, b, "with capacity=0, every call must mint a new cert")
	assert.Equal(t, 0, s.CacheLen())
}

func TestLeafFor_ConcurrentSafe(t *testing.T) {
	s := newTestStore(t, 64)
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			host := "h" + strconv.Itoa(i%8) + ".example.com"
			for j := 0; j < 20; j++ {
				_, err := s.LeafFor(host)
				assert.NoError(t, err)
			}
		}(i)
	}
	wg.Wait()
	// At most 8 distinct hosts; cache must not exceed that.
	assert.LessOrEqual(t, s.CacheLen(), 8)
}
