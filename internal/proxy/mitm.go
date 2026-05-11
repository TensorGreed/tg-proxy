package proxy

import (
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
)

// handleMITMConnect intercepts a CONNECT request, terminates the client's
// TLS using a forged leaf certificate from CertStore, and then serves HTTP
// over the resulting TLS connection by reusing the regular handleHTTP path.
// Bytes traversing the proxy are decrypted, scanned, redacted, and
// re-encrypted on both legs of the conversation.
func (s *Server) handleMITMConnect(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Host
	if host == "" {
		host = r.Host
	}
	sni, _, err := net.SplitHostPort(host)
	if err != nil {
		http.Error(w, "CONNECT target must be host:port", http.StatusBadRequest)
		return
	}

	leaf, err := s.opts.CertStore.LeafFor(sni)
	if err != nil {
		s.opts.Logger.Warn("mitm: sign leaf", "host", sni, "err", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijack not supported", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hj.Hijack()
	if err != nil {
		return
	}

	if _, err := clientConn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n")); err != nil {
		_ = clientConn.Close()
		return
	}

	tlsConn := tls.Server(clientConn, &tls.Config{
		Certificates: []tls.Certificate{*leaf},
		MinVersion:   tls.VersionTLS12,
	})
	if err := tlsConn.Handshake(); err != nil {
		s.opts.Logger.Warn("mitm: tls handshake", "host", sni, "err", err)
		_ = tlsConn.Close()
		return
	}

	listener := newSingleConnListener(tlsConn)
	handler := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		// The TLS-wrapped request from the client is in origin form
		// ("/path"). Promote it to absolute form so handleHTTP can
		// reuse the same forwarding path as M1 explicit proxying.
		req.URL.Scheme = "https"
		req.URL.Host = host
		s.handleHTTP(w, req)
	})
	inner := &http.Server{
		Handler:      handler,
		ReadTimeout:  s.opts.ReadTimeout,
		WriteTimeout: s.opts.WriteTimeout,
		IdleTimeout:  s.opts.IdleTimeout,
		ErrorLog:     nil,
		ConnState: func(_ net.Conn, state http.ConnState) {
			if state == http.StateClosed {
				_ = listener.Close()
			}
		},
	}
	_ = inner.Serve(listener)
}

// singleConnListener is a net.Listener that yields a single, already-open
// net.Conn exactly once and then blocks (until Close, which unblocks Accept
// with io.EOF). Used to hand a hijacked, TLS-wrapped client connection to
// the standard http.Server machinery.
type singleConnListener struct {
	conn    net.Conn
	accept  chan net.Conn
	closeCh chan struct{}
	once    sync.Once
}

func newSingleConnListener(c net.Conn) *singleConnListener {
	l := &singleConnListener{
		conn:    c,
		accept:  make(chan net.Conn, 1),
		closeCh: make(chan struct{}),
	}
	l.accept <- c
	return l
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	select {
	case c, ok := <-l.accept:
		if !ok {
			return nil, io.EOF
		}
		return c, nil
	case <-l.closeCh:
		return nil, io.EOF
	}
}

func (l *singleConnListener) Close() error {
	l.once.Do(func() {
		close(l.closeCh)
	})
	return nil
}

func (l *singleConnListener) Addr() net.Addr {
	if l.conn != nil {
		return l.conn.LocalAddr()
	}
	return &net.TCPAddr{}
}

// ErrListenerClosed is returned when the singleConnListener is closed before
// any conn could be accepted. Kept for symmetry with net.Listener
// conventions, even though Accept currently uses io.EOF.
var ErrListenerClosed = errors.New("proxy: listener closed")
