package naive

import (
	"encoding/base64"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/mihomo/transport/socks5"

	"github.com/metacubex/http"
)

// Handler receives a ready-to-use stream once the CONNECT tunnel is
// established. It must block until the connection is done.
type Handler func(conn net.Conn, addr socks5.Addr, user string)

type ServerOptions struct {
	Users    map[string]string
	Handler  Handler
	Fallback http.Handler // serves non-proxy requests to hide the proxy (probe resistance)
}

type Server struct {
	options    *ServerOptions
	httpServer *http.Server
}

func NewServer(options *ServerOptions) *Server {
	s := &Server{options: options}
	s.httpServer = &http.Server{
		Handler:     http.HandlerFunc(s.serveHTTP),
		IdleTimeout: 30 * time.Second,
		Protocols:   new(http.Protocols),
	}
	// naive is HTTP/2 only. SetUnencryptedHTTP2 lets the server treat the
	// (already TLS-terminated) connection as h2 without stdlib type checks.
	s.httpServer.Protocols.SetHTTP2(true)
	s.httpServer.Protocols.SetUnencryptedHTTP2(true)
	return s
}

func (s *Server) Serve(l net.Listener) error {
	return s.httpServer.Serve(l)
}

func (s *Server) Close() error {
	return s.httpServer.Close()
}

func (s *Server) serveHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodConnect {
		s.reject(w, r)
		return
	}
	if r.Header.Get("padding") == "" {
		s.reject(w, r)
		return
	}
	user, ok := s.authenticate(r.Header.Get("Proxy-Authorization"))
	if !ok {
		s.reject(w, r)
		return
	}
	target := r.Host
	if target == "" {
		target = r.URL.Host
	}
	addr := socks5.ParseAddr(target)
	if len(addr) == 0 {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	w.Header().Set("Padding", GenerateResponsePaddingHeader())
	w.WriteHeader(http.StatusOK)
	flusher, _ := w.(http.Flusher)
	if flusher != nil {
		flusher.Flush()
	}

	conn := &serverConn{
		body:       r.Body,
		writer:     w,
		flusher:    flusher,
		remoteAddr: remoteAddr(r),
	}
	conn.reader = NewPaddingReader(r.Body)
	conn.paddedWriter = NewPaddingWriter(w)

	s.options.Handler(conn, addr, user)
}

// reject hides the proxy from active probes. Without a fallback the original
// 400/407 responses are kept for compatibility; with one configured, every
// non-proxy request is answered like an ordinary web page so that an unauthed
// probe cannot tell the endpoint apart from a normal site.
func (s *Server) reject(w http.ResponseWriter, r *http.Request) {
	rejectRequest(w, r, s.options.Fallback)
}

// rejectRequest hides the proxy from active probes. Without a fallback the
// original 400/407 responses are kept for compatibility; with one configured,
// every non-proxy request is answered like an ordinary web page so that an
// unauthenticated probe cannot tell the endpoint apart from a normal site.
// Shared by the h2 (Server) and h3 (QUICServer) paths.
func rejectRequest(w http.ResponseWriter, r *http.Request, fallback http.Handler) {
	if fallback == nil {
		if r.Method != http.MethodConnect {
			w.WriteHeader(http.StatusBadRequest)
		} else {
			w.WriteHeader(http.StatusProxyAuthRequired)
		}
		return
	}
	fallback.ServeHTTP(w, r)
}

func (s *Server) authenticate(header string) (string, bool) {
	return authenticateUser(s.options.Users, header)
}

// authenticateUser is the shared Basic-auth verifier for h2 and h3.
func authenticateUser(users map[string]string, header string) (string, bool) {
	if header == "" {
		// Anonymous access is allowed only when no user is configured.
		return "", len(users) == 0
	}
	const prefix = "Basic "
	if !strings.HasPrefix(header, prefix) {
		return "", false
	}
	raw, err := base64.StdEncoding.DecodeString(header[len(prefix):])
	if err != nil {
		return "", false
	}
	user, password, found := strings.Cut(string(raw), ":")
	if !found {
		return "", false
	}
	expected, ok := users[user]
	if !ok || expected != password {
		return "", false
	}
	return user, true
}

type serverConn struct {
	reader io.Reader
	writer http.ResponseWriter

	paddedWriter *PaddingWriter
	flusher      http.Flusher
	body         io.ReadCloser
	remoteAddr   net.Addr

	closeOnce sync.Once
}

func (c *serverConn) Read(b []byte) (int, error) {
	return c.reader.Read(b)
}

func (c *serverConn) Write(b []byte) (int, error) {
	n, err := c.paddedWriter.Write(b)
	if err == nil && c.flusher != nil {
		c.flusher.Flush()
	}
	return n, err
}

func (c *serverConn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		if c.body != nil {
			err = c.body.Close()
		}
	})
	return err
}

func (c *serverConn) LocalAddr() net.Addr  { return c.remoteAddr }
func (c *serverConn) RemoteAddr() net.Addr { return c.remoteAddr }

func (c *serverConn) SetDeadline(t time.Time) error      { return nil }
func (c *serverConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *serverConn) SetWriteDeadline(t time.Time) error { return nil }

func remoteAddr(r *http.Request) net.Addr {
	if addr, err := net.ResolveTCPAddr("tcp", r.RemoteAddr); err == nil {
		return addr
	}
	return &net.TCPAddr{}
}

var _ net.Conn = (*serverConn)(nil)
