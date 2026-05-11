package ca

import (
	"container/list"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

const (
	// leafValidity stays under Apple's 825-day cap so leaf certs are
	// accepted by macOS clients.
	leafValidity = 30 * 24 * time.Hour
)

// Store signs per-host leaf certificates from a Root and caches them in a
// bounded LRU. It is safe for concurrent use.
//
// Generation cost is small (a few ms per cert on a modern machine), so the
// cache is primarily a memory bound, not a CPU optimization.
type Store struct {
	root    *Root
	leafKey crypto.Signer
	org     string

	mu       sync.Mutex
	capacity int
	items    map[string]*list.Element
	order    *list.List
}

type cacheEntry struct {
	host string
	cert *tls.Certificate
}

// NewStore builds a Store backed by root. cacheSize <= 0 disables caching
// (every LeafFor call signs a fresh certificate). org overrides the leaf
// certificate's Organization field; when empty, the root's CommonName is
// used.
func NewStore(root *Root, cacheSize int, org string) (*Store, error) {
	if root == nil || root.Cert == nil || root.Key == nil {
		return nil, errors.New("ca: store requires a populated Root")
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ca: generate leaf key: %w", err)
	}
	if org == "" {
		org = root.Cert.Subject.CommonName
	}
	s := &Store{
		root:     root,
		leafKey:  leafKey,
		org:      org,
		capacity: cacheSize,
		items:    make(map[string]*list.Element),
		order:    list.New(),
	}
	return s, nil
}

// LeafFor returns a *tls.Certificate (cert + key) suitable for inclusion in
// a tls.Config.Certificates slice. The cert's SubjectAltName covers host as
// either a DNS name or an IP address.
func (s *Store) LeafFor(host string) (*tls.Certificate, error) {
	key := normalizeHost(host)
	if cert, ok := s.cacheGet(key); ok {
		return cert, nil
	}
	cert, err := s.signLeaf(key)
	if err != nil {
		return nil, err
	}
	s.cachePut(key, cert)
	return cert, nil
}

// signLeaf produces a freshly-signed leaf certificate without touching the
// cache. It is exported for tests; production code goes through LeafFor.
func (s *Store) signLeaf(host string) (*tls.Certificate, error) {
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   host,
			Organization: []string{s.org},
		},
		NotBefore:   time.Now().Add(-time.Hour),
		NotAfter:    time.Now().Add(leafValidity),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(host); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{host}
	}

	derBytes, err := x509.CreateCertificate(
		rand.Reader, template, s.root.Cert, s.leafKey.Public(), s.root.Key,
	)
	if err != nil {
		return nil, fmt.Errorf("ca: sign leaf for %s: %w", host, err)
	}

	parsed, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, fmt.Errorf("ca: parse leaf: %w", err)
	}
	return &tls.Certificate{
		Certificate: [][]byte{derBytes, s.root.Cert.Raw},
		PrivateKey:  s.leafKey,
		Leaf:        parsed,
	}, nil
}

func (s *Store) cacheGet(key string) (*tls.Certificate, bool) {
	if s.capacity <= 0 {
		return nil, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.items[key]
	if !ok {
		return nil, false
	}
	s.order.MoveToFront(e)
	return e.Value.(*cacheEntry).cert, true
}

func (s *Store) cachePut(key string, cert *tls.Certificate) {
	if s.capacity <= 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if e, ok := s.items[key]; ok {
		s.order.MoveToFront(e)
		e.Value.(*cacheEntry).cert = cert
		return
	}
	e := s.order.PushFront(&cacheEntry{host: key, cert: cert})
	s.items[key] = e
	for s.order.Len() > s.capacity {
		oldest := s.order.Back()
		if oldest == nil {
			break
		}
		s.order.Remove(oldest)
		delete(s.items, oldest.Value.(*cacheEntry).host)
	}
}

// CacheLen returns the current cache occupancy. Useful in tests.
func (s *Store) CacheLen() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.order.Len()
}

// normalizeHost lowercases the hostname and strips any port suffix. SNI
// names are case-insensitive, so this keeps the cache compact.
func normalizeHost(h string) string {
	h = strings.ToLower(h)
	if host, _, err := net.SplitHostPort(h); err == nil {
		return host
	}
	return h
}
