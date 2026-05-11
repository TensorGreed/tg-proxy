// Package proxy implements the explicit HTTP(S)_PROXY server. Plain HTTP
// traffic is intercepted, scanned, and (optionally) rewritten by the
// pipeline. HTTPS traffic — opened by the client with CONNECT — is either
// tunneled blind (when CertStore is nil) or intercepted via MITM with an
// on-the-fly leaf certificate (when CertStore is set).
package proxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/TensorGreed/tg-proxy/internal/ca"
	"github.com/TensorGreed/tg-proxy/internal/pipeline"
	"github.com/TensorGreed/tg-proxy/pkg/api"
)

// Options configures a Server. All durations default to sensible production
// values if left at their zero value.
type Options struct {
	Addr         string
	Pipeline     *pipeline.Pipeline
	MaxBody      int64
	Logger       *slog.Logger
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	IdleTimeout  time.Duration

	// CertStore enables TLS MITM on CONNECT requests when non-nil. The
	// proxy terminates the client TLS using a leaf certificate signed by
	// CertStore's CA, then opens its own TLS connection upstream so the
	// request and response can be scanned. When nil, CONNECT just tunnels
	// bytes through unchanged.
	CertStore *ca.Store

	// UpstreamRootCAs is the trust pool used to verify upstream TLS certs
	// when MITM is active. nil means use the system pool.
	UpstreamRootCAs *x509.CertPool

	// UpstreamInsecure disables upstream TLS verification entirely. Only
	// safe in tests or for known self-signed back-ends.
	UpstreamInsecure bool

	// StreamWindow sets the sliding-window byte count used when streaming
	// response bodies through the pipeline. Zero falls back to
	// pipeline.DefaultWindow. Bodies with an unknown Content-Length, with
	// Transfer-Encoding: chunked, or with Content-Type starting "text/event-stream"
	// are always streamed; everything else is buffered up to MaxBody.
	StreamWindow int
}

type Server struct {
	opts   Options
	server *http.Server
	client *http.Client
}

func New(opts Options) *Server {
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.MaxBody <= 0 {
		opts.MaxBody = 10 * 1024 * 1024
	}
	s := &Server{opts: opts}

	transport := &http.Transport{
		Proxy: nil, // never honor env proxy settings — would loop
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig: &tls.Config{
			RootCAs:            opts.UpstreamRootCAs,
			InsecureSkipVerify: opts.UpstreamInsecure, //nolint:gosec // opt-in for tests / self-signed.
			MinVersion:         tls.VersionTLS12,
		},
	}
	s.client = &http.Client{
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	s.server = &http.Server{
		Addr:         opts.Addr,
		Handler:      s,
		ReadTimeout:  opts.ReadTimeout,
		WriteTimeout: opts.WriteTimeout,
		IdleTimeout:  opts.IdleTimeout,
		ErrorLog:     nil,
	}
	return s
}

// Addr returns the resolved listen address. It is only meaningful after
// Start has been called and the listener is bound.
func (s *Server) Addr() string { return s.server.Addr }

// Start binds the listener and serves until ctx is cancelled, returning the
// first non-ErrServerClosed error. The bound listener's address is written
// back to opts.Addr so callers using ":0" can discover the chosen port.
func (s *Server) Start(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.opts.Addr)
	if err != nil {
		return fmt.Errorf("proxy: listen %s: %w", s.opts.Addr, err)
	}
	s.server.Addr = ln.Addr().String()

	errCh := make(chan error, 1)
	go func() {
		if err := s.server.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
			return
		}
		close(errCh)
	}()

	s.opts.Logger.Info("tg-proxy listening", "addr", s.server.Addr)

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return s.server.Shutdown(shutdownCtx)
	case err := <-errCh:
		return err
	}
}

// Shutdown is exposed for tests; production code should cancel the context
// passed to Start instead.
func (s *Server) Shutdown(ctx context.Context) error {
	return s.server.Shutdown(ctx)
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		if s.opts.CertStore != nil {
			s.handleMITMConnect(w, r)
			return
		}
		s.handleConnect(w, r)
		return
	}
	s.handleHTTP(w, r)
}

// handleHTTP services plain-HTTP proxy requests. The request line is an
// absolute URL ("GET http://example.com/foo HTTP/1.1"); we read its body,
// scan + redact, forward to the upstream, then scan + redact the response
// before writing it back to the client.
func (s *Server) handleHTTP(w http.ResponseWriter, r *http.Request) {
	if !r.URL.IsAbs() {
		http.Error(w, "tg-proxy expects absolute-URL proxy requests", http.StatusBadRequest)
		return
	}

	reqBody, err := readBodyWithLimit(r.Body, s.opts.MaxBody)
	if err != nil {
		s.replyError(w, r, err, "read request body")
		return
	}
	_ = r.Body.Close()

	reqResult, err := s.opts.Pipeline.Process(r.Context(), reqBody, api.Hints{
		ContentType: r.Header.Get("Content-Type"),
		URL:         r.URL.String(),
		Method:      r.Method,
		Direction:   api.DirectionRequest,
	})
	if err != nil {
		s.opts.Logger.Warn("scanner error on request body", "err", err, "url", r.URL.String())
	}
	if n := len(reqResult.Findings); n > 0 {
		s.opts.Logger.Info("request findings", "count", n, "url", r.URL.String())
	}

	outReq, err := http.NewRequestWithContext(r.Context(), r.Method, r.URL.String(), bytes.NewReader(reqResult.Data))
	if err != nil {
		s.replyError(w, r, err, "build upstream request")
		return
	}
	copyHeaders(outReq.Header, r.Header)
	removeHopHeaders(outReq.Header)
	outReq.Header.Set("Via", "1.1 tg-proxy")
	outReq.ContentLength = int64(len(reqResult.Data))

	resp, err := s.client.Do(outReq)
	if err != nil {
		s.replyError(w, r, err, "upstream request")
		return
	}
	defer resp.Body.Close()

	hints := api.Hints{
		ContentType: resp.Header.Get("Content-Type"),
		URL:         r.URL.String(),
		Method:      r.Method,
		Direction:   api.DirectionResponse,
	}

	if isStreamableResponse(resp) {
		s.streamResponse(w, r, resp, hints)
		return
	}

	respBody, err := readBodyWithLimit(resp.Body, s.opts.MaxBody)
	if err != nil {
		s.replyError(w, r, err, "read response body")
		return
	}

	respResult, err := s.opts.Pipeline.Process(r.Context(), respBody, hints)
	if err != nil {
		s.opts.Logger.Warn("scanner error on response body", "err", err, "url", r.URL.String())
	}
	if n := len(respResult.Findings); n > 0 {
		s.opts.Logger.Info("response findings", "count", n, "url", r.URL.String())
	}

	dst := w.Header()
	copyHeaders(dst, resp.Header)
	removeHopHeaders(dst)
	dst.Del("Content-Length")
	dst.Del("Transfer-Encoding")
	dst.Set("Content-Length", strconv.Itoa(len(respResult.Data)))
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(respResult.Data)
}

// isStreamableResponse decides whether a response should flow through the
// streaming pipeline instead of being fully buffered. Streaming is required
// for SSE and chunked responses (we don't know the length) and is preferable
// for any response without a known Content-Length.
func isStreamableResponse(resp *http.Response) bool {
	if resp.ContentLength < 0 {
		return true
	}
	for _, te := range resp.TransferEncoding {
		if strings.EqualFold(te, "chunked") {
			return true
		}
	}
	if strings.HasPrefix(strings.ToLower(resp.Header.Get("Content-Type")), "text/event-stream") {
		return true
	}
	return false
}

// streamResponse forwards a streaming response from upstream to the client
// while running it through the scanner+redactor in a sliding window. Headers
// are copied (minus Content-Length, which is unknown) and the body is piped.
func (s *Server) streamResponse(w http.ResponseWriter, r *http.Request, resp *http.Response, hints api.Hints) {
	dst := w.Header()
	copyHeaders(dst, resp.Header)
	removeHopHeaders(dst)
	dst.Del("Content-Length")
	dst.Del("Transfer-Encoding")
	w.WriteHeader(resp.StatusCode)

	sp := pipeline.NewStreamProcessor(pipeline.StreamOptions{
		Scanners: s.opts.Pipeline.Scanners(),
		Redactor: s.opts.Pipeline.Redactor(),
		Hints:    hints,
		Window:   s.opts.StreamWindow,
	})
	if err := sp.Pipe(r.Context(), resp.Body, w); err != nil {
		s.opts.Logger.Warn("stream pipe error", "err", err, "url", r.URL.String())
	}
}

// handleConnect tunnels HTTPS (and any other TLS-wrapped protocol) by
// blindly splicing bytes between client and upstream. M1 cannot inspect
// these bodies; the M2 transparent-MITM path will replace this with a
// cert-on-the-fly bridge.
func (s *Server) handleConnect(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Host
	if host == "" {
		host = r.Host
	}
	if _, _, err := net.SplitHostPort(host); err != nil {
		http.Error(w, "CONNECT target must be host:port", http.StatusBadRequest)
		return
	}

	upstream, err := net.DialTimeout("tcp", host, 10*time.Second)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		_ = upstream.Close()
		http.Error(w, "hijack not supported", http.StatusInternalServerError)
		return
	}
	client, _, err := hj.Hijack()
	if err != nil {
		_ = upstream.Close()
		return
	}

	if _, err := client.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n")); err != nil {
		_ = upstream.Close()
		_ = client.Close()
		return
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go splice(upstream, client, &wg)
	go splice(client, upstream, &wg)
	wg.Wait()
	_ = upstream.Close()
	_ = client.Close()
}

func splice(dst, src net.Conn, wg *sync.WaitGroup) {
	defer wg.Done()
	_, _ = io.Copy(dst, src)
	if tc, ok := dst.(*net.TCPConn); ok {
		_ = tc.CloseWrite()
	}
}

func (s *Server) replyError(w http.ResponseWriter, r *http.Request, err error, op string) {
	status := http.StatusBadGateway
	if errors.Is(err, ErrBodyTooLarge) {
		status = http.StatusRequestEntityTooLarge
	}
	s.opts.Logger.Warn("proxy error", "op", op, "err", err, "url", r.URL.String())
	http.Error(w, fmt.Sprintf("%s: %v", op, err), status)
}

// ErrBodyTooLarge is returned by readBodyWithLimit when the body exceeds the
// configured limit. Callers translate it to HTTP 413.
var ErrBodyTooLarge = errors.New("body exceeds configured limit")

func readBodyWithLimit(r io.Reader, max int64) ([]byte, error) {
	if r == nil {
		return nil, nil
	}
	if max <= 0 {
		return io.ReadAll(r)
	}
	lr := &io.LimitedReader{R: r, N: max + 1}
	body, err := io.ReadAll(lr)
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > max {
		return nil, ErrBodyTooLarge
	}
	return body, nil
}

// hopHeaders is the list from RFC 7230 §6.1, plus Proxy-Connection.
var hopHeaders = []string{
	"Connection",
	"Proxy-Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

func removeHopHeaders(h http.Header) {
	if c := h.Get("Connection"); c != "" {
		for _, name := range strings.Split(c, ",") {
			h.Del(strings.TrimSpace(name))
		}
	}
	for _, name := range hopHeaders {
		h.Del(name)
	}
}

func copyHeaders(dst, src http.Header) {
	for k, vs := range src {
		for _, v := range vs {
			dst.Add(k, v)
		}
	}
}

