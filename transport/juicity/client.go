package juicity

import (
	"context"
	"crypto/rand"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/metacubex/mihomo/transport/socks5"
	"github.com/metacubex/mihomo/transport/tuic/types"

	"github.com/metacubex/quic-go"
)

var (
	ErrClientClosed       = errors.New("juicity: client closed")
	ErrTooManyOpenStreams = errors.New("juicity: too many open streams")
)

type ClientOption struct {
	UUID     [16]byte
	Password string

	// DialFn creates a new QUIC connection to the server.
	DialFn func(ctx context.Context) (*quic.Conn, error)

	// DialUnderlayFn creates a dedicated plain UDP socket towards the server,
	// used by full-cone (underlay) UDP relays.
	DialUnderlayFn func(ctx context.Context) (net.PacketConn, net.Addr, error)

	MaxOpenStreams int64
}

type Client struct {
	*ClientOption

	ctx    context.Context
	cancel context.CancelFunc

	mu     sync.Mutex
	conn   *quic.Conn
	closed bool

	underlayAuth chan *UnderlayAuth

	openStreams int64
}

func NewClient(option *ClientOption) *Client {
	ctx, cancel := context.WithCancel(context.Background())
	if option.MaxOpenStreams <= 0 {
		option.MaxOpenStreams = 100
	}
	return &Client{
		ClientOption: option,
		ctx:          ctx,
		cancel:       cancel,
		underlayAuth: make(chan *UnderlayAuth, 64),
	}
}

func (c *Client) getConn(ctx context.Context) (*quic.Conn, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, ErrClientClosed
	}
	if c.conn != nil {
		return c.conn, nil
	}
	conn, err := c.DialFn(ctx)
	if err != nil {
		return nil, err
	}
	c.conn = conn
	c.openStreams = 0
	go c.sendAuthentication(conn)
	return conn, nil
}

// sendAuthentication sends the Authenticate command on a unidirectional
// stream. The stream is intentionally kept open: juicity uses it for
// follow-up underlay (full-cone UDP) authorizations.
func (c *Client) sendAuthentication(conn *quic.Conn) {
	stream, err := conn.OpenUniStream()
	if err != nil {
		c.dropConn(conn, err)
		return
	}
	token, err := GenToken(conn.ConnectionState(), c.UUID, c.Password)
	if err != nil {
		c.dropConn(conn, err)
		return
	}
	if err = NewAuthenticate(c.UUID, token).Pack(stream); err != nil {
		c.dropConn(conn, err)
		return
	}
	for {
		select {
		case <-c.ctx.Done():
			_ = stream.Close()
			return
		case auth := <-c.underlayAuth:
			if err = auth.Pack(stream); err != nil {
				c.dropConn(conn, err)
				return
			}
			auth.markSent()
		}
	}
}

func (c *Client) dropConn(conn *quic.Conn, err error) {
	c.mu.Lock()
	if c.conn == conn {
		c.conn = nil
	}
	c.mu.Unlock()
	if conn != nil {
		_ = conn.CloseWithError(0, "")
	}
}

func (c *Client) addStream() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.openStreams >= c.MaxOpenStreams {
		return ErrTooManyOpenStreams
	}
	c.openStreams++
	return nil
}

func (c *Client) releaseStream(conn *quic.Conn) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.openStreams > 0 {
		c.openStreams--
	}
	if c.closed && c.openStreams == 0 && c.conn == conn {
		c.conn = nil
		go func() { _ = conn.CloseWithError(0, "") }()
	}
}

// DialContext opens a TCP stream to addr.
func (c *Client) DialContext(ctx context.Context, addr socks5.Addr) (net.Conn, error) {
	if err := c.addStream(); err != nil {
		return nil, err
	}
	quicConn, err := c.getConn(ctx)
	if err != nil {
		c.mu.Lock()
		c.openStreams--
		c.mu.Unlock()
		return nil, err
	}
	stream, err := quicConn.OpenStream()
	if err != nil {
		c.mu.Lock()
		c.openStreams--
		c.mu.Unlock()
		c.dropConn(quicConn, err)
		return nil, err
	}
	if err = WriteRequestHeader(stream, NetworkTCP, addr); err != nil {
		_ = stream.Close()
		c.releaseStream(quicConn)
		return nil, err
	}
	return types.NewQuicStreamConn(stream, quicConn.LocalAddr(), quicConn.RemoteAddr(), func() {
		c.releaseStream(quicConn)
	}), nil
}

// ListenPacket opens a UDP-over-stream association to addr.
func (c *Client) ListenPacket(ctx context.Context, addr socks5.Addr) (net.PacketConn, error) {
	if err := c.addStream(); err != nil {
		return nil, err
	}
	quicConn, err := c.getConn(ctx)
	if err != nil {
		c.mu.Lock()
		c.openStreams--
		c.mu.Unlock()
		return nil, err
	}
	stream, err := quicConn.OpenStream()
	if err != nil {
		c.mu.Lock()
		c.openStreams--
		c.mu.Unlock()
		c.dropConn(quicConn, err)
		return nil, err
	}
	if err = WriteRequestHeader(stream, NetworkUDP, addr); err != nil {
		_ = stream.Close()
		c.releaseStream(quicConn)
		return nil, err
	}
	conn := types.NewQuicStreamConn(stream, quicConn.LocalAddr(), quicConn.RemoteAddr(), func() {
		c.releaseStream(quicConn)
	})
	return NewStreamPacketConn(conn), nil
}

// ListenPacketUnderlay opens a full-cone UDP relay. juicity's own client always
// uses this mode: a dedicated UDP socket carries AEAD-sealed datagrams while the
// target is authorized once on the authentication stream.
func (c *Client) ListenPacketUnderlay(ctx context.Context, addr socks5.Addr) (net.PacketConn, error) {
	if c.DialUnderlayFn == nil {
		return nil, errors.New("juicity: underlay relay is not configured")
	}
	if _, err := c.getConn(ctx); err != nil {
		return nil, err
	}
	psk := make([]byte, underlayKeyLen)
	if _, err := rand.Read(psk); err != nil {
		return nil, err
	}
	auth := &UnderlayAuth{
		IV:   newUnderlaySalt(),
		Psk:  psk,
		Addr: addr,
		ack:  make(chan struct{}),
	}
	select {
	case c.underlayAuth <- auth:
	case <-c.ctx.Done():
		return nil, ErrClientClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	select {
	case <-auth.ack:
	case <-c.ctx.Done():
		return nil, ErrClientClosed
	case <-time.After(5 * time.Second):
		return nil, errors.New("juicity: underlay authentication timeout")
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	// Give the server a moment to consume the authorization message. Some
	// implementations read the authentication stream through a buffered reader
	// and drop whatever was prefetched right after the Authenticate command,
	// so sending the first datagram immediately can lose the authorization.
	select {
	case <-time.After(20 * time.Millisecond):
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	conn, serverAddr, err := c.DialUnderlayFn(ctx)
	if err != nil {
		return nil, err
	}
	return NewUnderlayPacketConn(conn, serverAddr, psk, auth.IV, addr), nil
}

func (c *Client) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	conn := c.conn
	c.conn = nil
	c.mu.Unlock()

	c.cancel()
	if conn != nil {
		_ = conn.CloseWithError(0, "")
	}
	return nil
}
