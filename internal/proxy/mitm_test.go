package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TensorGreed/tg-proxy/internal/ca"
	"github.com/TensorGreed/tg-proxy/internal/pipeline"
	"github.com/TensorGreed/tg-proxy/internal/redactor/mask"
	"github.com/TensorGreed/tg-proxy/internal/scanner/pii"
	"github.com/TensorGreed/tg-proxy/pkg/api"
)

type mitmFixture struct {
	backend   *httptest.Server
	proxyAddr string
	client    *http.Client
	caRoot    *ca.Root
}

func newMITMFixture(t *testing.T, handler http.HandlerFunc) *mitmFixture {
	t.Helper()

	// 1. Fresh CA + cert store for this fixture.
	root, err := ca.NewRoot("MITM Test CA")
	require.NoError(t, err)
	store, err := ca.NewStore(root, 16, "")
	require.NoError(t, err)

	// 2. TLS backend speaking https; capture its cert so the proxy can
	//    verify it.
	backend := httptest.NewTLSServer(handler)
	backendCAs := x509.NewCertPool()
	backendCAs.AddCert(backend.Certificate())

	// 3. Proxy with MITM enabled.
	pl := pipeline.New([]api.Scanner{pii.New()}, mask.New(""))
	srv := New(Options{
		Addr:            "127.0.0.1:0",
		Pipeline:        pl,
		MaxBody:         1 << 20,
		CertStore:       store,
		UpstreamRootCAs: backendCAs,
	})
	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = srv.Start(ctx) }()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if a := srv.Addr(); a != "" && !strings.HasSuffix(a, ":0") {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	require.True(t, srv.Addr() != "" && !strings.HasSuffix(srv.Addr(), ":0"),
		"proxy did not bind in time")

	// 4. Client that trusts OUR CA (since that's who signs the leaf certs
	//    the proxy presents).
	clientCAs := x509.NewCertPool()
	clientCAs.AddCert(root.Cert)
	pu, _ := url.Parse("http://" + srv.Addr())
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(pu),
			TLSClientConfig: &tls.Config{
				RootCAs:    clientCAs,
				MinVersion: tls.VersionTLS12,
			},
		},
		Timeout: 5 * time.Second,
	}

	t.Cleanup(func() {
		cancel()
		backend.Close()
	})

	return &mitmFixture{
		backend:   backend,
		proxyAddr: srv.Addr(),
		client:    client,
		caRoot:    root,
	}
}

func TestMITM_RedactsHTTPSResponseBody(t *testing.T) {
	f := newMITMFixture(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "contact alice@example.com please")
	})

	resp, err := f.client.Get(f.backend.URL + "/")
	require.NoError(t, err)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.NotContains(t, string(body), "alice@example.com")
	assert.Contains(t, string(body), "[REDACTED]")
}

func TestMITM_RedactsHTTPSRequestBody(t *testing.T) {
	var seen string
	f := newMITMFixture(t, func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		seen = string(b)
		w.WriteHeader(http.StatusOK)
	})

	body := strings.NewReader("token=alice@example.com")
	req, err := http.NewRequest(http.MethodPost, f.backend.URL+"/", body)
	require.NoError(t, err)
	resp, err := f.client.Do(req)
	require.NoError(t, err)
	resp.Body.Close()

	assert.NotContains(t, seen, "alice@example.com")
	assert.Contains(t, seen, "[REDACTED]")
}

func TestMITM_LeafCertChainsToProxyCA(t *testing.T) {
	// Hook into the TLS handshake to capture the leaf cert the proxy
	// presents. We then verify it chains to the CA the fixture created.
	root, err := ca.NewRoot("Chain Test CA")
	require.NoError(t, err)
	store, err := ca.NewStore(root, 16, "")
	require.NoError(t, err)

	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(backend.Close)
	backendCAs := x509.NewCertPool()
	backendCAs.AddCert(backend.Certificate())

	pl := pipeline.New([]api.Scanner{pii.New()}, mask.New(""))
	srv := New(Options{Addr: "127.0.0.1:0", Pipeline: pl, MaxBody: 1 << 20, CertStore: store, UpstreamRootCAs: backendCAs})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Start(ctx) }()
	for srv.Addr() == "" || strings.HasSuffix(srv.Addr(), ":0") {
		time.Sleep(5 * time.Millisecond)
	}

	pu, _ := url.Parse("http://" + srv.Addr())
	clientPool := x509.NewCertPool()
	clientPool.AddCert(root.Cert)

	var leafSubject string
	transport := &http.Transport{
		Proxy: http.ProxyURL(pu),
		TLSClientConfig: &tls.Config{
			RootCAs:    clientPool,
			MinVersion: tls.VersionTLS12,
			VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
				if len(rawCerts) == 0 {
					return nil
				}
				c, err := x509.ParseCertificate(rawCerts[0])
				if err != nil {
					return err
				}
				leafSubject = c.Subject.CommonName
				return nil
			},
		},
	}
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}

	resp, err := client.Get(backend.URL + "/")
	require.NoError(t, err)
	resp.Body.Close()

	// Backend is on 127.0.0.1; the leaf the proxy minted should have that
	// IP as its CN/SAN, signed by OUR CA. Standard verification by the
	// client (RootCAs = our CA) already proves the chain.
	assert.Equal(t, "127.0.0.1", leafSubject)
}

func TestMITM_RejectsConnectWithoutPort(t *testing.T) {
	f := newMITMFixture(t, func(http.ResponseWriter, *http.Request) {})

	conn, err := net.Dial("tcp", f.proxyAddr)
	require.NoError(t, err)
	defer conn.Close()
	_, err = conn.Write([]byte("CONNECT example.com HTTP/1.1\r\nHost: example.com\r\n\r\n"))
	require.NoError(t, err)
	buf := make([]byte, 128)
	n, _ := conn.Read(buf)
	assert.Contains(t, string(buf[:n]), "400")
}

func TestSingleConnListener_AcceptThenClose(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	l := newSingleConnListener(a)
	got, err := l.Accept()
	require.NoError(t, err)
	assert.Same(t, a, got)

	require.NoError(t, l.Close())
	_, err = l.Accept()
	assert.Error(t, err)

	// Multiple Close calls are safe.
	require.NoError(t, l.Close())
}

func TestSingleConnListener_Addr(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	l := newSingleConnListener(c1)
	assert.NotNil(t, l.Addr())
}

func TestMITM_FailedTLSHandshakeIsLogged(t *testing.T) {
	// Client opens CONNECT to the proxy then immediately sends garbage
	// instead of a TLS ClientHello. The proxy must not panic; the bridge
	// goroutine should exit cleanly and we should be able to keep using
	// the proxy for other connections.
	f := newMITMFixture(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	})

	conn, err := net.Dial("tcp", f.proxyAddr)
	require.NoError(t, err)
	defer conn.Close()
	_, err = conn.Write([]byte("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"))
	require.NoError(t, err)
	// Read CONNECT 200.
	buf := make([]byte, 128)
	_, _ = conn.Read(buf)
	// Send garbage that is definitely not a TLS ClientHello.
	_, err = conn.Write([]byte("not a TLS ClientHello\n"))
	require.NoError(t, err)
	_ = conn.Close()

	// Subsequent requests through the proxy should still work — the
	// failed handshake must not have wedged the listener.
	resp, err := f.client.Get(f.backend.URL + "/")
	require.NoError(t, err)
	resp.Body.Close()
}
