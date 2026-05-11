package proxy

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TensorGreed/tg-proxy/internal/pipeline"
	"github.com/TensorGreed/tg-proxy/internal/redactor/mask"
	"github.com/TensorGreed/tg-proxy/internal/scanner/pii"
	"github.com/TensorGreed/tg-proxy/pkg/api"
)

// fixture spins up a backend httptest server and a proxy.Server on an
// ephemeral port, returning a client preconfigured to route through the
// proxy plus a teardown func.
type fixture struct {
	backend  *httptest.Server
	tlsBack  *httptest.Server
	proxy    *Server
	client   *http.Client
	proxyURL *url.URL
}

func newFixture(t *testing.T, handler http.HandlerFunc, tlsHandler http.HandlerFunc) *fixture {
	t.Helper()
	f := &fixture{}
	if handler != nil {
		f.backend = httptest.NewServer(handler)
	}
	if tlsHandler != nil {
		f.tlsBack = httptest.NewTLSServer(tlsHandler)
	}

	pl := pipeline.New([]api.Scanner{pii.New()}, mask.New(""))
	f.proxy = New(Options{Addr: "127.0.0.1:0", Pipeline: pl, MaxBody: 1 << 20})

	ctx, cancel := context.WithCancel(context.Background())
	started := make(chan struct{})
	go func() {
		// Start blocks; we signal "started" once Addr is settled.
		// Poll for a moment before kicking off.
		_ = f.proxy.Start(ctx)
	}()
	// Spin until the proxy has bound its listener.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if a := f.proxy.Addr(); a != "" && !strings.HasSuffix(a, ":0") {
			close(started)
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	select {
	case <-started:
	default:
		cancel()
		t.Fatal("proxy did not bind in time")
	}

	pu, err := url.Parse("http://" + f.proxy.Addr())
	require.NoError(t, err)
	f.proxyURL = pu

	f.client = &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(pu),
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, //nolint:gosec // test only
			},
		},
		Timeout: 5 * time.Second,
	}

	t.Cleanup(func() {
		cancel()
		if f.backend != nil {
			f.backend.Close()
		}
		if f.tlsBack != nil {
			f.tlsBack.Close()
		}
	})
	return f
}

func TestProxy_PlainHTTP_RoundTrip(t *testing.T) {
	f := newFixture(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "hello from backend")
	}, nil)

	resp, err := f.client.Get(f.backend.URL + "/")
	require.NoError(t, err)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, "hello from backend", string(body))
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestProxy_RedactsResponseBody(t *testing.T) {
	f := newFixture(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "user email: alice@example.com")
	}, nil)

	resp, err := f.client.Get(f.backend.URL + "/")
	require.NoError(t, err)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.NotContains(t, string(body), "alice@example.com")
	assert.Contains(t, string(body), "[REDACTED]")
}

func TestProxy_RedactsRequestBody(t *testing.T) {
	var received atomic.Pointer[string]
	f := newFixture(t, func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		s := string(b)
		received.Store(&s)
		w.WriteHeader(http.StatusOK)
	}, nil)

	body := strings.NewReader("contact alice@example.com please")
	req, err := http.NewRequest(http.MethodPost, f.backend.URL+"/", body)
	require.NoError(t, err)
	resp, err := f.client.Do(req)
	require.NoError(t, err)
	resp.Body.Close()

	got := received.Load()
	require.NotNil(t, got)
	assert.NotContains(t, *got, "alice@example.com")
	assert.Contains(t, *got, "[REDACTED]")
}

func TestProxy_HopByHopHeadersStripped(t *testing.T) {
	var sawConnection atomic.Bool
	var sawProxyAuth atomic.Bool
	f := newFixture(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Proxy-Authorization") != "" {
			sawProxyAuth.Store(true)
		}
		if strings.Contains(strings.ToLower(r.Header.Get("Connection")), "x-confidential") {
			sawConnection.Store(true)
		}
		w.WriteHeader(http.StatusOK)
	}, nil)

	req, err := http.NewRequest(http.MethodGet, f.backend.URL+"/", nil)
	require.NoError(t, err)
	req.Header.Set("Proxy-Authorization", "Basic abc")
	req.Header.Set("Connection", "X-Confidential")
	req.Header.Set("X-Confidential", "secret-token")

	resp, err := f.client.Do(req)
	require.NoError(t, err)
	resp.Body.Close()

	assert.False(t, sawProxyAuth.Load(), "Proxy-Authorization must be stripped")
	assert.False(t, sawConnection.Load(), "headers listed in Connection must be stripped")
}

func TestProxy_BodyTooLarge(t *testing.T) {
	// Build a fixture with a tiny body limit to force the error.
	pl := pipeline.New([]api.Scanner{pii.New()}, mask.New(""))
	srv := New(Options{Addr: "127.0.0.1:0", Pipeline: pl, MaxBody: 16})
	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = srv.Start(ctx) }()
	t.Cleanup(cancel)
	for srv.Addr() == "" || strings.HasSuffix(srv.Addr(), ":0") {
		time.Sleep(5 * time.Millisecond)
	}

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(backend.Close)

	pu, _ := url.Parse("http://" + srv.Addr())
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(pu)}}

	bigBody := strings.NewReader(strings.Repeat("A", 1024))
	req, _ := http.NewRequest(http.MethodPost, backend.URL+"/", bigBody)
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusRequestEntityTooLarge, resp.StatusCode)
}

func TestProxy_ConnectTunnel(t *testing.T) {
	f := newFixture(t, nil, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "tls hello")
	})

	resp, err := f.client.Get(f.tlsBack.URL + "/")
	require.NoError(t, err)
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, "tls hello", string(body))
}

func TestProxy_ConnectRejectsMissingPort(t *testing.T) {
	f := newFixture(t, func(w http.ResponseWriter, _ *http.Request) {}, nil)

	// Forge a raw CONNECT with no port; bypass http.Client which would refuse.
	conn, err := net.Dial("tcp", f.proxyURL.Host)
	require.NoError(t, err)
	defer conn.Close()
	_, err = conn.Write([]byte("CONNECT example.com HTTP/1.1\r\nHost: example.com\r\n\r\n"))
	require.NoError(t, err)
	buf := make([]byte, 64)
	n, _ := conn.Read(buf)
	assert.Contains(t, string(buf[:n]), "400")
}

func TestProxy_NonAbsoluteURLRejected(t *testing.T) {
	f := newFixture(t, func(http.ResponseWriter, *http.Request) {}, nil)

	conn, err := net.Dial("tcp", f.proxyURL.Host)
	require.NoError(t, err)
	defer conn.Close()
	_, err = conn.Write([]byte("GET /relative HTTP/1.1\r\nHost: example.com\r\n\r\n"))
	require.NoError(t, err)
	buf := make([]byte, 64)
	n, _ := conn.Read(buf)
	assert.Contains(t, string(buf[:n]), "400")
}

func TestProxy_ConcurrentRequests(t *testing.T) {
	f := newFixture(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}, nil)

	const n = 25
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := f.client.Get(f.backend.URL + "/")
			if err != nil {
				errs <- err
				return
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("concurrent request failed: %v", err)
	}
}

func TestProxy_PreservesStatusCode(t *testing.T) {
	f := newFixture(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	}, nil)

	resp, err := f.client.Get(f.backend.URL + "/")
	require.NoError(t, err)
	resp.Body.Close()
	assert.Equal(t, http.StatusTeapot, resp.StatusCode)
}

func TestReadBodyWithLimit(t *testing.T) {
	r := strings.NewReader("hello")
	got, err := readBodyWithLimit(r, 100)
	require.NoError(t, err)
	assert.Equal(t, "hello", string(got))

	got, err = readBodyWithLimit(strings.NewReader("hello"), 5)
	require.NoError(t, err)
	assert.Equal(t, "hello", string(got))

	_, err = readBodyWithLimit(strings.NewReader("hello"), 4)
	assert.ErrorIs(t, err, ErrBodyTooLarge)

	got, err = readBodyWithLimit(nil, 100)
	require.NoError(t, err)
	assert.Nil(t, got)

	// Zero/negative max disables the limit and falls back to ReadAll.
	got, err = readBodyWithLimit(strings.NewReader("anything"), 0)
	require.NoError(t, err)
	assert.Equal(t, "anything", string(got))
}

func TestNew_DefaultsMaxBodyWhenNonPositive(t *testing.T) {
	pl := pipeline.New(nil, nil)
	s := New(Options{Addr: "127.0.0.1:0", Pipeline: pl, MaxBody: 0})
	assert.EqualValues(t, 10*1024*1024, s.opts.MaxBody)
}

func TestShutdown_BeforeStartReturnsNil(t *testing.T) {
	pl := pipeline.New(nil, nil)
	s := New(Options{Addr: "127.0.0.1:0", Pipeline: pl})
	err := s.Shutdown(context.Background())
	require.NoError(t, err)
}

func TestStart_ListenFailure(t *testing.T) {
	// Bind a port, then ask a second Server to bind the same port.
	first, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer first.Close()

	pl := pipeline.New(nil, nil)
	s := New(Options{Addr: first.Addr().String(), Pipeline: pl})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	err = s.Start(ctx)
	require.Error(t, err)
}

func TestRemoveHopHeaders(t *testing.T) {
	h := http.Header{}
	h.Set("Connection", "X-Custom, X-Other")
	h.Set("X-Custom", "v1")
	h.Set("X-Other", "v2")
	h.Set("Keep-Alive", "timeout=5")
	h.Set("X-Keep", "yes")

	removeHopHeaders(h)

	assert.Empty(t, h.Get("Connection"))
	assert.Empty(t, h.Get("X-Custom"))
	assert.Empty(t, h.Get("X-Other"))
	assert.Empty(t, h.Get("Keep-Alive"))
	assert.Equal(t, "yes", h.Get("X-Keep"))
}
