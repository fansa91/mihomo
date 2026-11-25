package naive

import (
	"net"
	"sync"
	"time"

	"github.com/metacubex/mihomo/transport/socks5"

	"github.com/metacubex/http"
	"github.com/metacubex/quic-go"
	"github.com/metacubex/quic-go/http3"
	"github.com/metacubex/tls"
)

// QUICServer is the HTTP/3 (QUIC) counterpart of Server. It terminates QUIC,
// serves HTTP/3 CONNECT requests using the same authentication, padding and
// probe-resistant fallback as the h2 path, and hands hijacked bidirectional
// streams to the handler as tunnels.
type QUICServer struct {
	options  *QUICServerOptions
	h3Server *http3.Server

	closeOnce sync.Once
}

type QUICServerOptions struct {
	Users      map[string]string
	Handler    Handler
	Fallback   http.Handler // serves non-proxy requests to hide the proxy (probe resistance)
	TLSConfig  *tls.Config  // must have "h3" in NextProtos
	QUICConfig *quic.Config // optional; nil uses quic-go defaults
}

func NewQUICServer(options *QUICServerOptions) *QUICServer {
	s := &QUICServer{options: options}
	s.h3Server = &http3.Server{
		Handler:    http.HandlerFunc(s.serveHTTP),
		QUICConfig: options.QUICConfig,
	}
	return s
}

// Serve accepts QUIC connections on pc and serves HTTP/3 until closed.
func (s *QUICServer) Serve(pc net.PacketConn) error {
	ln, err := quic.Listen(pc, s.options.TLSConfig, s.options.QUICConfig)
	if err != nil {
		return err
	}
	return s.h3Server.ServeListener(ln)
}

func (s *QUICServer) Close() error {
	var err error
	s.closeOnce.Do(func() {
		err = s.h3Server.Close()
	})
	return err
}

func (s *QUICServer) serveHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodConnect || r.Header.Get("padding") == "" {
		rejectRequest(w, r, s.options.Fallback)
		return
	}
	user, ok := authenticateUser(s.options.Users, r.Header.Get("Proxy-Authorization"))
	if !ok {
		rejectRequest(w, r, s.options.Fallback)
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

	// HTTP/3 CONNECT: the response headers are flushed and the underlying
	// bidirectional QUIC stream is handed over as the raw tunnel.
	streamer, ok := w.(http3.HTTPStreamer)
	if !ok {
		return
	}
	stream := streamer.HTTPStream()

	conn := &quicServerConn{
		stream:       stream,
		reader:       NewPaddingReader(stream),
		paddedWriter: NewPaddingWriter(stream),
		remoteAddr:   remoteAddrUDP(r),
	}
	s.options.Handler(conn, addr, user)
}

// quicServerConn exposes a hijacked HTTP/3 stream as a net.Conn, wrapping
// reads/writes with the same padding framing as the h2 path.
type quicServerConn struct {
	stream       *http3.Stream
	reader       *PaddingReader
	paddedWriter *PaddingWriter
	remoteAddr   net.Addr

	closeOnce sync.Once
}

func (c *quicServerConn) Read(b []byte) (int, error)  { return c.reader.Read(b) }
func (c *quicServerConn) Write(b []byte) (int, error) { return c.paddedWriter.Write(b) }
func (c *quicServerConn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		c.stream.CancelRead(0)
		c.stream.CancelWrite(0)
	})
	return err
}
func (c *quicServerConn) LocalAddr() net.Addr  { return c.remoteAddr }
func (c *quicServerConn) RemoteAddr() net.Addr { return c.remoteAddr }

func (c *quicServerConn) SetDeadline(t time.Time) error {
	_ = c.stream.SetReadDeadline(t)
	return c.stream.SetWriteDeadline(t)
}
func (c *quicServerConn) SetReadDeadline(t time.Time) error  { return c.stream.SetReadDeadline(t) }
func (c *quicServerConn) SetWriteDeadline(t time.Time) error { return c.stream.SetWriteDeadline(t) }

func remoteAddrUDP(r *http.Request) net.Addr {
	if addr, err := net.ResolveUDPAddr("udp", r.RemoteAddr); err == nil {
		return addr
	}
	return &net.UDPAddr{}
}

var _ net.Conn = (*quicServerConn)(nil)
