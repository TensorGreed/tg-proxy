// Package ca handles certificate authority operations for the MITM proxy:
// generating a root CA, signing per-host leaf certificates on demand, and
// persisting the root to disk in PEM form.
//
// The root CA uses an ECDSA P-256 key (fast, small, modern). Leaf certs
// share an ephemeral leaf key generated once per process lifetime, so the
// key material never persists.
package ca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // SubjectKeyIdentifier is defined as SHA-1 by RFC 5280.
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

const (
	rootValidity = 10 * 365 * 24 * time.Hour
)

// Root is a root CA certificate paired with its private key. Both fields
// must be set; nil entries indicate an unloaded Root.
type Root struct {
	Cert *x509.Certificate
	Key  crypto.Signer
}

// NewRoot generates a fresh ECDSA P-256 root CA valid for ~10 years. org is
// used for the CommonName and Organization fields of the subject.
func NewRoot(org string) (*Root, error) {
	if org == "" {
		org = "tg-proxy CA"
	}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ca: generate key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	skid, err := subjectKeyID(&priv.PublicKey)
	if err != nil {
		return nil, err
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: org, Organization: []string{org}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(rootValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		SubjectKeyId:          skid,
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		return nil, fmt.Errorf("ca: create root cert: %w", err)
	}
	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, fmt.Errorf("ca: parse generated cert: %w", err)
	}
	return &Root{Cert: cert, Key: priv}, nil
}

// SaveRoot writes the root cert (PEM) and key (PKCS#8 PEM) to certPath and
// keyPath, creating parent directories as needed. The key is written with
// mode 0600.
func SaveRoot(r *Root, certPath, keyPath string) error {
	if r == nil || r.Cert == nil || r.Key == nil {
		return errors.New("ca: root is incomplete")
	}
	if err := os.MkdirAll(filepath.Dir(certPath), 0o700); err != nil {
		return fmt.Errorf("ca: mkdir cert: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(keyPath), 0o700); err != nil {
		return fmt.Errorf("ca: mkdir key: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: r.Cert.Raw})
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil { //nolint:gosec // CA certs are public
		return fmt.Errorf("ca: write cert: %w", err)
	}

	keyBytes, err := x509.MarshalPKCS8PrivateKey(r.Key)
	if err != nil {
		return fmt.Errorf("ca: marshal key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes})
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return fmt.Errorf("ca: write key: %w", err)
	}
	return nil
}

// LoadRoot reads a Root previously written by SaveRoot.
func LoadRoot(certPath, keyPath string) (*Root, error) {
	cert, err := loadCertPEM(certPath)
	if err != nil {
		return nil, err
	}
	key, err := loadKeyPEM(keyPath)
	if err != nil {
		return nil, err
	}
	return &Root{Cert: cert, Key: key}, nil
}

func loadCertPEM(path string) (*x509.Certificate, error) {
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("ca: read cert: %w", err)
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("ca: %s does not contain a CERTIFICATE PEM block", path)
	}
	return x509.ParseCertificate(block.Bytes)
}

func loadKeyPEM(path string) (crypto.Signer, error) {
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("ca: read key: %w", err)
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("ca: %s does not contain a PRIVATE KEY PEM block", path)
	}
	keyAny, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("ca: parse key: %w", err)
	}
	signer, ok := keyAny.(crypto.Signer)
	if !ok {
		return nil, errors.New("ca: private key does not implement crypto.Signer")
	}
	return signer, nil
}

func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	n, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("ca: random serial: %w", err)
	}
	return n, nil
}

func subjectKeyID(pub crypto.PublicKey) ([]byte, error) {
	raw, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("ca: marshal public key: %w", err)
	}
	sum := sha1.Sum(raw) //nolint:gosec // RFC 5280 prescribes SHA-1 for SKI.
	return sum[:], nil
}
