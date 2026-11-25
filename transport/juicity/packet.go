package juicity

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/metacubex/mihomo/transport/socks5"
)

var ErrInvalidAddress = errors.New("juicity: invalid address")

// udpAddr adapts a socks5 address to net.Addr.
type udpAddr struct {
	socks5.Addr
}

func (a udpAddr) Network() string { return "udp" }

// netAddr converts a socks5 address into the *net.UDPAddr that the tunnel
// expects. Domain names are resolved here; juicity peers normally reply with
// the literal address the client sent, so this is only a fallback.
func (a udpAddr) netAddr() net.Addr {
	if a.Addr == nil {
		return a
	}
	if ua, err := net.ResolveUDPAddr("udp", a.Addr.String()); err == nil {
		return ua
	}
	return a
}

// StreamPacketConn carries UDP datagrams inside a QUIC stream using the
// juicity framing: every datagram is [address][length:2][payload].
//
// The stream request header (network byte + initial address) is written by the
// caller, because the client writes it on Dial and the server reads it before
// handing the stream over.
type StreamPacketConn struct {
	conn net.Conn

	writeMu sync.Mutex
	closeMu sync.Mutex
	closed  bool
}

func NewStreamPacketConn(conn net.Conn) *StreamPacketConn {
	return &StreamPacketConn{conn: conn}
}

func (p *StreamPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	buf := make([]byte, socks5.MaxAddrLen)
	addr, err := socks5.ReadAddr(p.conn, buf)
	if err != nil {
		return 0, nil, err
	}
	var l [2]byte
	if _, err = io.ReadFull(p.conn, l[:]); err != nil {
		return 0, nil, err
	}
	length := int(binary.BigEndian.Uint16(l[:]))
	if length <= len(b) {
		n, err := io.ReadFull(p.conn, b[:length])
		if err != nil {
			return 0, nil, err
		}
		return n, udpAddr{addr}.netAddr(), nil
	}
	// Oversized datagram: truncate like the reference implementation does.
	n, err := io.ReadFull(p.conn, b)
	if err != nil {
		return 0, nil, err
	}
	if _, err = io.CopyN(io.Discard, p.conn, int64(length-len(b))); err != nil {
		return 0, nil, err
	}
	return n, udpAddr{addr}.netAddr(), nil
}

func (p *StreamPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	var sAddr socks5.Addr
	if addr != nil {
		if a, ok := addr.(udpAddr); ok {
			sAddr = a.Addr
		} else {
			sAddr = socks5.ParseAddrToSocksAddr(addr)
		}
	}
	if len(sAddr) == 0 {
		return 0, ErrInvalidAddress
	}
	buf := SealUDP(make([]byte, 0, len(sAddr)+2+len(b)), sAddr, b)
	p.writeMu.Lock()
	defer p.writeMu.Unlock()
	if _, err := p.conn.Write(buf); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (p *StreamPacketConn) Close() error {
	p.closeMu.Lock()
	defer p.closeMu.Unlock()
	if p.closed {
		return nil
	}
	p.closed = true
	return p.conn.Close()
}

func (p *StreamPacketConn) LocalAddr() net.Addr  { return p.conn.LocalAddr() }
func (p *StreamPacketConn) RemoteAddr() net.Addr { return p.conn.RemoteAddr() }

func (p *StreamPacketConn) SetDeadline(t time.Time) error {
	return p.conn.SetDeadline(t)
}

func (p *StreamPacketConn) SetReadDeadline(t time.Time) error {
	return p.conn.SetReadDeadline(t)
}

func (p *StreamPacketConn) SetWriteDeadline(t time.Time) error {
	return p.conn.SetWriteDeadline(t)
}

var _ net.PacketConn = (*StreamPacketConn)(nil)
