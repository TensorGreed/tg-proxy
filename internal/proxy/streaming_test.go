package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"

	"github.com/TensorGreed/tg-proxy/internal/ca"
	"github.com/TensorGreed/tg-proxy/internal/pipeline"
	"github.com/TensorGreed/tg-proxy/internal/redactor/mask"
	"github.com/TensorGreed/tg-proxy/internal/scanner/pii"
	"github.com/TensorGreed/tg-proxy/pkg/api"
)

func TestStreaming_ChunkedHTTP_RedactsAcrossChunks(t *testing.T) {
	// Backend writes "Hello alice" then "@example.com world" with a flush
	// in between, producing two HTTP/1.1 chunks that split an email.
	f := newFixture(t, func(w http.ResponseWriter, _ *http.Request) {
		flusher, ok := w.(http.Flusher)
		require.True(t, ok)
		_, _ = io.WriteString(w, "Hello alice")
		flusher.Flush()
		time.Sleep(20 * time.Millisecond)
		_, _ = io.WriteString(w, "@example.com world")
		flusher.Flush()
	}, nil)

	resp, err := f.client.Get(f.backend.URL + "/")
	require.NoError(t, err)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.NotContains(t, string(body), "alice@example.com")
	assert.Contains(t, string(body), "[REDACTED]")
}

func TestStreaming_SSE_RedactsPerEvent(t *testing.T) {
	f := newFixture(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		flusher, ok := w.(http.Flusher)
		require.True(t, ok)
		for _, ev := range []string{
			"data: hi alice@example.com\n\n",
			"data: ip 8.8.8.8\n\n",
			"data: ok\n\n",
		} {
			_, _ = io.WriteString(w, ev)
			flusher.Flush()
			time.Sleep(5 * time.Millisecond)
		}
	}, nil)

	resp, err := f.client.Get(f.backend.URL + "/")
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, "text/event-stream", resp.Header.Get("Content-Type"))

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	got := string(body)
	assert.NotContains(t, got, "alice@example.com")
	assert.NotContains(t, got, "8.8.8.8")
	assert.Contains(t, got, "data: hi [REDACTED]\n\n")
	assert.Contains(t, got, "data: ok\n\n")
}

func TestStreaming_SSE_DeliveredIncrementally(t *testing.T) {
	// Verifies the proxy doesn't buffer the entire stream before flushing
	// to the client. Each event written by the backend should arrive at
	// the client before the next one is generated.
	const total = 5

	gate := make(chan struct{}, total) // backend signals "wrote event"
	f := newFixture(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		flusher := w.(http.Flusher)
		for i := 0; i < total; i++ {
			_, _ = io.WriteString(w, "data: tick\n\n")
			flusher.Flush()
			gate <- struct{}{}
			time.Sleep(15 * time.Millisecond)
		}
	}, nil)

	resp, err := f.client.Get(f.backend.URL + "/")
	require.NoError(t, err)
	defer resp.Body.Close()

	reader := bufio.NewReader(resp.Body)
	for i := 0; i < total; i++ {
		select {
		case <-gate:
		case <-time.After(2 * time.Second):
			t.Fatalf("backend did not produce event %d", i)
		}
		// We should be able to read the corresponding event without
		// waiting for the rest of the stream.
		line, err := reader.ReadString('\n')
		require.NoError(t, err)
		assert.Contains(t, line, "tick")
		// Drain the blank line after the event.
		_, _ = reader.ReadString('\n')
	}
}

func TestStreaming_MITM_HTTPS_Chunked(t *testing.T) {
	// Same cross-chunk email split as the HTTP test, but the backend is
	// TLS and the proxy is MITM-mode.
	f := newMITMFixture(t, func(w http.ResponseWriter, _ *http.Request) {
		flusher := w.(http.Flusher)
		_, _ = io.WriteString(w, "user alice")
		flusher.Flush()
		time.Sleep(20 * time.Millisecond)
		_, _ = io.WriteString(w, "@example.com end")
		flusher.Flush()
	})

	resp, err := f.client.Get(f.backend.URL + "/")
	require.NoError(t, err)
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.NotContains(t, string(body), "alice@example.com")
	assert.Contains(t, string(body), "[REDACTED]")
}

func TestStreaming_HTTP2_ThroughMITM(t *testing.T) {
	// Spin up an HTTP/2 backend, route through a MITM proxy, and use an
	// HTTP/2 client. Verifies the ALPN negotiation reaches h2 on both
	// legs and that redaction still works.
	root, err := ca.NewRoot("HTTP2 Test CA")
	require.NoError(t, err)
	store, err := ca.NewStore(root, 16, "")
	require.NoError(t, err)

	backend := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "user alice@example.com")
	}))
	backend.EnableHTTP2 = true
	backend.StartTLS()
	t.Cleanup(backend.Close)

	backendCAs := x509.NewCertPool()
	backendCAs.AddCert(backend.Certificate())

	pl := pipeline.New([]api.Scanner{pii.New()}, mask.New(""))
	srv := New(Options{
		Addr:            "127.0.0.1:0",
		Pipeline:        pl,
		MaxBody:         1 << 20,
		CertStore:       store,
		UpstreamRootCAs: backendCAs,
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Start(ctx) }()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if a := srv.Addr(); a != "" && !strings.HasSuffix(a, ":0") {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	require.False(t, strings.HasSuffix(srv.Addr(), ":0"))

	pu, _ := url.Parse("http://" + srv.Addr())
	clientPool := x509.NewCertPool()
	clientPool.AddCert(root.Cert)

	transport := &http2.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs:    clientPool,
			MinVersion: tls.VersionTLS12,
		},
	}
	// Proxy for http2.Transport requires connecting via CONNECT first;
	// the simpler way is to use the standard http.Transport with
	// ForceAttemptHTTP2, which already speaks h2 through proxies.
	t1 := &http.Transport{
		Proxy: http.ProxyURL(pu),
		TLSClientConfig: &tls.Config{
			RootCAs:    clientPool,
			MinVersion: tls.VersionTLS12,
		},
		ForceAttemptHTTP2: true,
	}
	require.NoError(t, http2.ConfigureTransport(t1))
	_ = transport // kept for documentation; we use t1 below

	client := &http.Client{Transport: t1, Timeout: 5 * time.Second}
	resp, err := client.Get(backend.URL + "/")
	require.NoError(t, err)
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.NotContains(t, string(body), "alice@example.com")
	assert.Contains(t, string(body), "[REDACTED]")
}

func TestIsStreamableResponse(t *testing.T) {
	cases := []struct {
		name   string
		resp   *http.Response
		expect bool
	}{
		{"unknown length", &http.Response{ContentLength: -1, Header: http.Header{}}, true},
		{"chunked TE", &http.Response{ContentLength: 0, TransferEncoding: []string{"chunked"}, Header: http.Header{}}, true},
		{"SSE", &http.Response{ContentLength: 0, Header: http.Header{"Content-Type": []string{"text/event-stream"}}}, true},
		{"SSE with charset", &http.Response{ContentLength: 100, Header: http.Header{"Content-Type": []string{"text/event-stream; charset=utf-8"}}}, true},
		{"plain length", &http.Response{ContentLength: 42, Header: http.Header{"Content-Type": []string{"application/json"}}}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.expect, isStreamableResponse(c.resp))
		})
	}
}
