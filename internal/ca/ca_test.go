package ca

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewRoot_GeneratesUsableCA(t *testing.T) {
	r, err := NewRoot("test CA")
	require.NoError(t, err)

	assert.True(t, r.Cert.IsCA)
	assert.True(t, r.Cert.BasicConstraintsValid)
	assert.WithinDuration(t, time.Now().Add(rootValidity), r.Cert.NotAfter, 24*time.Hour)
	assert.Equal(t, "test CA", r.Cert.Subject.CommonName)

	// SubjectKeyIdentifier should be populated and non-empty.
	assert.NotEmpty(t, r.Cert.SubjectKeyId)

	// The cert should self-verify.
	roots := x509.NewCertPool()
	roots.AddCert(r.Cert)
	_, err = r.Cert.Verify(x509.VerifyOptions{Roots: roots})
	require.NoError(t, err)

	// Key should be ECDSA P-256.
	_, ok := r.Key.(*ecdsa.PrivateKey)
	assert.True(t, ok, "expected ECDSA key")
}

func TestNewRoot_DefaultsOrgWhenEmpty(t *testing.T) {
	r, err := NewRoot("")
	require.NoError(t, err)
	assert.Equal(t, "tg-proxy CA", r.Cert.Subject.CommonName)
}

func TestSaveLoadRoot_RoundTrip(t *testing.T) {
	r, err := NewRoot("rt CA")
	require.NoError(t, err)

	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "subdir", "ca.key")

	require.NoError(t, SaveRoot(r, certPath, keyPath))

	// Key file mode must be 0600 (POSIX only; Windows ignores Unix bits).
	if runtime.GOOS != "windows" {
		info, statErr := os.Stat(keyPath)
		require.NoError(t, statErr)
		assert.Equal(t, os.FileMode(0o600), info.Mode().Perm()&0o777)
	}

	r2, err := LoadRoot(certPath, keyPath)
	require.NoError(t, err)

	assert.Equal(t, r.Cert.Raw, r2.Cert.Raw)
	assert.Equal(t, r.Cert.Subject.CommonName, r2.Cert.Subject.CommonName)
}

func TestSaveRoot_RejectsIncomplete(t *testing.T) {
	dir := t.TempDir()
	err := SaveRoot(nil, filepath.Join(dir, "c"), filepath.Join(dir, "k"))
	assert.Error(t, err)
	err = SaveRoot(&Root{}, filepath.Join(dir, "c"), filepath.Join(dir, "k"))
	assert.Error(t, err)
}

func TestLoadRoot_MissingCert(t *testing.T) {
	dir := t.TempDir()
	_, err := LoadRoot(filepath.Join(dir, "nope.crt"), filepath.Join(dir, "nope.key"))
	assert.Error(t, err)
}

func TestLoadRoot_MalformedCert(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "bad.crt")
	key := filepath.Join(dir, "bad.key")
	require.NoError(t, os.WriteFile(cert, []byte("not a pem"), 0o644))
	require.NoError(t, os.WriteFile(key, []byte("also not"), 0o600))

	_, err := LoadRoot(cert, key)
	assert.Error(t, err)
}

func TestLoadRoot_WrongPEMType(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "ca.crt")
	key := filepath.Join(dir, "ca.key")
	other := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: []byte("xxx")})
	require.NoError(t, os.WriteFile(cert, other, 0o644))
	require.NoError(t, os.WriteFile(key, other, 0o600))

	_, err := LoadRoot(cert, key)
	assert.Error(t, err)
}

func TestLoadRoot_MalformedKey(t *testing.T) {
	r, err := NewRoot("")
	require.NoError(t, err)

	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")
	require.NoError(t, SaveRoot(r, certPath, keyPath))

	// Overwrite key with a non-PEM key payload of the right block type.
	bad := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("not der")})
	require.NoError(t, os.WriteFile(keyPath, bad, 0o600))

	_, err = LoadRoot(certPath, keyPath)
	assert.Error(t, err)
}
