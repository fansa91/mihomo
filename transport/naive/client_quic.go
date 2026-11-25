package naive

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"sync"
	"time"

	N "github.com/metacubex/mihomo/common/net"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/tuic/common"
	"github.com/metacubex/mihomo/transport/vmess"

	"github.com/metacubex/http"
	"github.com/metacubex/quic-go"
	"github.com/metacubex/quic-go/http3"
	"github.com/metacubex/tls"
)

// QUICClientOptions configures the HTTP/3 (QUIC) naive client.
type QUICClientOptions struct {
	Dialer    C.Dialer
	Server    string // host:port
	TLSConfig *vmess.TLSConfig
	Username  string
	Password  string
	Headers   map[string]string

	RequestTimeout time.Duration
	IdleTimeout    time.Duration

	// CongestionControl is the QUIC congestion controller name ("bbr", "cubic", ...).
	CongestionControl string
	Cwnd              int
	BBRProfile        string
}

// QUICClient implements the naive CONNECT tunnel over HTTP/3. It mirrors the
// naiveproxy h3 path: a single QUIC connection (the equivalent of Chromium's
// SpdySession) is reused for multiple CONNECT streams, and the first 8 reads
// and writes on each stream use the same padding framing as the h2 path.
type QUICClient struct {
	options   *QUICClientOptions
	auth      string
	hasAuth   bool

	mu       sync.Mutex
	hconn    *http3.ClientConn
	quicConn *quic.Conn
	closing  bool
}

// NewQUICClient creates an HTTP/3 naive client.
func NewQUICClient(options *QUICClientOptions) (*QUICClient, error) {
	if options.RequestTimeout <= 0 {
		options.RequestTimeout = 8 * time.Second
	}
	if options.IdleTimeout <= 0 {
		options.IdleTimeout = 90 * time.Second
	}
	// Force the h3 ALPN. naiveproxy's h3 mode always negotiates "h3".
	options.TLSConfig.NextProtos = []string{http3.NextProtoH3}
	return &QUICClient{
		options: options,
		auth:    "Basic " + base64.StdEncoding.EncodeToString([]byte(options.Username+":"+options.Password)),
		hasAuth: options.Username != "" || options.Password != "",
	}, nil
}

func (c *QUICClient) tlsConfig() *tls.Config {
	cfg, err := c.options.TLSConfig.ToStdConfig()
	if err != nil {
		return nil
	}
	return cfg
}

func (c *QUICClient) quicConfig() *quic.Config {
	return &quic.Config{
		Versions:           []quic.Version{quic.Version1},
		MaxIdleTimeout:     c.options.IdleTimeout,
		Allow0RTT:          false,
		EnableDatagrams:    false,
		MaxIncomingStreams: -1, // server never initiates streams
	}
}

// getConn lazily establishes (and reuses) the underlying QUIC + HTTP/3
// connection. All CONNECT streams share it, matching naiveproxy's multiplexed
// SpdySession behaviour.
func (c *QUICClient) getConn(ctx context.Context) (*http3.ClientConn, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closing {
		return nil, net.ErrClosed
	}
	if c.hconn != nil {
		return c.hconn, nil
	}

	tlsCfg := c.tlsConfig()
	if tlsCfg == nil {
		return nil, errors.New("naive(h3): invalid TLS config")
	}
	quicCfg := c.quicConfig()

	_, quicConn, err := common.DialQuic(ctx, c.options.Server, nil, c.options.Dialer, tlsCfg, quicCfg, common.DialQuicOption{Early: false})
	if err != nil {
		return nil, fmt.Errorf("naive(h3): dial quic: %w", err)
	}
	if c.options.CongestionControl != "" {
		common.SetCongestionController(quicConn, c.options.CongestionControl, c.options.Cwnd, c.options.BBRProfile)
	}

	tr := &http3.Transport{
		TLSClientConfig:    tlsCfg,
		QUICConfig:         quicCfg,
		DisableCompression: true,
	}
	hconn := tr.NewClientConn(quicConn)
	c.hconn = hconn
	c.quicConn = quicConn
	return hconn, nil
}

// Dial opens an HTTP/3 CONNECT tunnel to target over a fresh request stream.
func (c *QUICClient) Dial(ctx context.Context, target string) (net.Conn, error) {
	hconn, err := c.getConn(ctx)
	if err != nil {
		return nil, err
	}

	str, err := hconn.OpenRequestStream(ctx)
	if err != nil {
		c.dropConn(err)
		return nil, fmt.Errorf("naive(h3): open stream: %w", err)
	}

	req := &http.Request{
		Method: http.MethodConnect,
		Host:   target, // CONNECT :authority
		Header: make(http.Header),
		URL:    &url.URL{Scheme: "https", Host: target},
	}
	req.Header.Set("padding", GeneratePaddingHeader())
	if c.hasAuth {
		req.Header.Set("Proxy-Authorization", c.auth)
	}
	for k, v := range c.options.Headers {
		req.Header.Set(k, v)
	}
	// h3 has no Fast Open on the wire: the stream is already open, and writing
	// header then payload in one go achieves the same RTT saving. We simply
	// send the padding header and let the caller write immediately after.
	if err := str.SendRequestHeader(req); err != nil {
		str.CancelWrite(0)
		return nil, fmt.Errorf("naive(h3): send request: %w", err)
	}

	res, err := str.ReadResponse()
	if err != nil {
		str.CancelRead(0)
		str.CancelWrite(0)
		return nil, fmt.Errorf("naive(h3): read response: %w", err)
	}
	if res.StatusCode != http.StatusOK {
		_ = str.Close()
		return nil, fmt.Errorf("naive(h3): unexpected status %d", res.StatusCode)
	}
	padded := res.Header.Get("Padding") != ""

	conn := &quicConn{
		stream: str,
		localAddr:  N.NewCustomAddr("naive-h3", c.options.Server, nil),
		remoteAddr: N.NewCustomAddr("naive-h3", target, nil),
	}
	conn.writer = str
	conn.reader = str
	if padded {
		conn.writer = NewPaddingWriter(str)
		conn.reader = NewPaddingReader(str)
	}
	return conn, nil
}

func (c *QUICClient) dropConn(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.quicConn != nil {
		_ = c.quicConn.CloseWithError(0, "")
	}
	c.hconn = nil
	c.quicConn = nil
}

func (c *QUICClient) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closing = true
	if c.quicConn != nil {
		err := c.quicConn.CloseWithError(0, "")
		c.hconn = nil
		c.quicConn = nil
		return err
	}
	return nil
}

// quicConn adapts an HTTP/3 request stream into a net.Conn tunnel.
type quicConn struct {
	stream *http3.RequestStream
	reader io.Reader
	writer io.Writer

	localAddr  net.Addr
	remoteAddr net.Addr

	closeOnce sync.Once
}

func (c *quicConn) Read(b []byte) (int, error)  { return c.reader.Read(b) }
func (c *quicConn) Write(b []byte) (int, error) { return c.writer.Write(b) }

func (c *quicConn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		c.stream.CancelRead(0)
		err = c.stream.Close()
	})
	return err
}

func (c *quicConn) LocalAddr() net.Addr  { return c.localAddr }
func (c *quicConn) RemoteAddr() net.Addr { return c.remoteAddr }

func (c *quicConn) SetDeadline(t time.Time) error      { return c.stream.SetDeadline(t) }
func (c *quicConn) SetReadDeadline(t time.Time) error  { return c.stream.SetReadDeadline(t) }
func (c *quicConn) SetWriteDeadline(t time.Time) error { return c.stream.SetWriteDeadline(t) }

var _ net.Conn = (*quicConn)(nil)
