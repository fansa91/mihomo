package juicity

import (
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/metacubex/mihomo/transport/socks5"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// Full-cone UDP ("underlay") parameters. juicity piggybacks on the
// shadowsocks AEAD packet format but with its own HKDF info string, a
// 32-byte salt whose first two bytes are always zero and an all-zero nonce.
const (
	UnderlaySaltLen = 32
	underlayKeyLen  = 32
)

var (
	underlayReusedInfo = []byte("juicity-reused-info")
	zeroNonce          [chacha20poly1305.NonceSize]byte
)

func newUnderlayAEAD(psk, salt []byte) (cipher.AEAD, error) {
	if len(psk) != underlayKeyLen {
		return nil, fmt.Errorf("juicity: invalid underlay psk length %d", len(psk))
	}
	if len(salt) != UnderlaySaltLen {
		return nil, fmt.Errorf("juicity: invalid underlay salt length %d", len(salt))
	}
	subKey := make([]byte, underlayKeyLen)
	if _, err := io.ReadFull(hkdf.New(sha1.New, psk, salt, underlayReusedInfo), subKey); err != nil {
		return nil, err
	}
	return chacha20poly1305.New(subKey)
}

func sealUnderlay(psk, salt, payload []byte) ([]byte, error) {
	aead, err := newUnderlayAEAD(psk, salt)
	if err != nil {
		return nil, err
	}
	buf := make([]byte, UnderlaySaltLen, UnderlaySaltLen+len(payload)+aead.Overhead())
	copy(buf, salt)
	return aead.Seal(buf, zeroNonce[:], payload, nil), nil
}

func openUnderlay(psk, packet []byte) (payload []byte, salt []byte, err error) {
	if len(packet) < UnderlaySaltLen {
		return nil, nil, errors.New("juicity: underlay packet too short")
	}
	salt = packet[:UnderlaySaltLen]
	aead, err := newUnderlayAEAD(psk, salt)
	if err != nil {
		return nil, nil, err
	}
	payload, err = aead.Open(nil, zeroNonce[:], packet[UnderlaySaltLen:], nil)
	if err != nil {
		return nil, nil, err
	}
	return payload, salt, nil
}

func newUnderlaySalt() []byte {
	salt := make([]byte, UnderlaySaltLen)
	_, _ = rand.Read(salt)
	salt[0], salt[1] = 0, 0
	return salt
}

// UnderlayAuth is the client -> server message sent on the authentication
// unidirectional stream to authorize a full-cone UDP relay:
// [iv:32][psk:32][socks5 address].
type UnderlayAuth struct {
	IV   []byte
	Psk  []byte
	Addr socks5.Addr

	// ack is closed once the message has been flushed to the server.
	ack chan struct{}
}

func (a *UnderlayAuth) markSent() {
	if a.ack != nil {
		close(a.ack)
	}
}

func (a *UnderlayAuth) Pack(w io.Writer) error {
	buf := make([]byte, 0, UnderlaySaltLen+underlayKeyLen+len(a.Addr))
	buf = append(buf, a.IV...)
	buf = append(buf, a.Psk...)
	buf = append(buf, a.Addr...)
	_, err := w.Write(buf)
	return err
}

func ReadUnderlayAuth(r io.Reader) (*UnderlayAuth, error) {
	a := &UnderlayAuth{}
	a.IV = make([]byte, UnderlaySaltLen)
	if _, err := io.ReadFull(r, a.IV); err != nil {
		return nil, err
	}
	a.Psk = make([]byte, underlayKeyLen)
	if _, err := io.ReadFull(r, a.Psk); err != nil {
		return nil, err
	}
	buf := make([]byte, socks5.MaxAddrLen)
	addr, err := socks5.ReadAddr(r, buf)
	if err != nil {
		return nil, err
	}
	a.Addr = addr
	return a, nil
}

// UnderlayPacketConn is the client side full-cone UDP association. Datagrams
// are encrypted and sent through a dedicated UDP socket to the server; the
// relay target is fixed by the UnderlayAuth message, so WriteTo ignores addr.
type UnderlayPacketConn struct {
	conn       net.PacketConn
	serverAddr net.Addr
	key        []byte
	target     socks5.Addr

	firstIV []byte
	mu      sync.Mutex
	closeMu sync.Mutex
	closed  bool
}

func NewUnderlayPacketConn(conn net.PacketConn, serverAddr net.Addr, psk, firstIV []byte, target socks5.Addr) *UnderlayPacketConn {
	return &UnderlayPacketConn{
		conn:       conn,
		serverAddr: serverAddr,
		key:        psk,
		firstIV:    firstIV,
		target:     target,
	}
}

func (c *UnderlayPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	c.mu.Lock()
	salt := c.firstIV
	if salt != nil {
		c.firstIV = nil
	} else {
		salt = newUnderlaySalt()
	}
	c.mu.Unlock()

	sealed, err := sealUnderlay(c.key, salt, b)
	if err != nil {
		return 0, err
	}
	if _, err = c.conn.WriteTo(sealed, c.serverAddr); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *UnderlayPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	buf := make([]byte, len(b)+UnderlaySaltLen+chacha20poly1305.Overhead)
	n, _, err := c.conn.ReadFrom(buf)
	if err != nil {
		return 0, nil, err
	}
	payload, _, err := openUnderlay(c.key, buf[:n])
	if err != nil {
		return 0, nil, err
	}
	n = copy(b, payload)
	return n, udpAddr{c.target}.netAddr(), nil
}

func (c *UnderlayPacketConn) Close() error {
	c.closeMu.Lock()
	defer c.closeMu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	return c.conn.Close()
}

func (c *UnderlayPacketConn) LocalAddr() net.Addr { return c.conn.LocalAddr() }

func (c *UnderlayPacketConn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

func (c *UnderlayPacketConn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

func (c *UnderlayPacketConn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

var _ net.PacketConn = (*UnderlayPacketConn)(nil)
