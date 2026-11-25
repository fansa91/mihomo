package juicity

import (
	"bufio"
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/metacubex/mihomo/adapter/inbound"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/transport/socks5"
	"github.com/metacubex/mihomo/transport/tuic/common"
	"github.com/metacubex/mihomo/transport/tuic/types"

	"github.com/gofrs/uuid/v5"
	"github.com/metacubex/quic-go"
	"github.com/metacubex/tls"
)

const (
	AuthenticationFailed  = 0x01
	AuthenticationTimeout = 0x02

	defaultAuthenticateTimeout = 10 * time.Second
	underlayAuthTTL            = 10 * time.Second
	underlayAuthWaitTimeout    = 1 * time.Second
	underlayEndpointTTL        = 3 * time.Minute
)

type ServerOption struct {
	HandleTcpFn func(conn net.Conn, addr socks5.Addr, additions ...inbound.Addition) error
	HandleUdpFn func(addr socks5.Addr, packet C.UDPPacket, additions ...inbound.Addition) error

	TlsConfig  *tls.Config
	QuicConfig *quic.Config
	Users      map[[16]byte]string

	CongestionController string
	CWND                 int
	BBRProfile           string

	AuthenticateTimeout time.Duration
}

type Server struct {
	*ServerOption

	transport *quic.Transport
	listener  *quic.EarlyListener

	authMu    sync.Mutex
	authTable map[[UnderlaySaltLen]byte]*underlayAuthEntry

	endpointMu sync.Mutex
	endpoints  map[string]*underlayEndpoint
}

type underlayAuthEntry struct {
	psk    []byte
	addr   socks5.Addr
	expire time.Time
}

type underlayEndpoint struct {
	key        []byte
	target     socks5.Addr
	localAddr  net.Addr
	clientAddr *net.UDPAddr
	lastSeen   time.Time
	server     *Server
}

func NewServer(option *ServerOption, pc net.PacketConn) (*Server, error) {
	if option.AuthenticateTimeout <= 0 {
		option.AuthenticateTimeout = defaultAuthenticateTimeout
	}
	transport := &quic.Transport{Conn: pc}
	listener, err := transport.ListenEarly(option.TlsConfig, option.QuicConfig)
	if err != nil {
		return nil, err
	}
	return &Server{
		ServerOption: option,
		transport:    transport,
		listener:     listener,
		authTable:    make(map[[UnderlaySaltLen]byte]*underlayAuthEntry),
		endpoints:    make(map[string]*underlayEndpoint),
	}, nil
}

func (s *Server) Serve() error {
	go s.serveUnderlay()
	for {
		conn, err := s.listener.Accept(context.Background())
		if err != nil {
			return err
		}
		go s.handleConn(conn)
	}
}

func (s *Server) Close() error {
	return s.listener.Close()
}

type authResult struct {
	once sync.Once
	done chan struct{}
	ok   bool
	user string
}

func newAuthResult() *authResult {
	return &authResult{done: make(chan struct{})}
}

func (a *authResult) complete(ok bool, user string) {
	a.once.Do(func() {
		a.ok = ok
		a.user = user
		close(a.done)
	})
}

func (s *Server) handleConn(conn *quic.Conn) {
	common.SetCongestionController(conn, s.CongestionController, s.CWND, s.BBRProfile)
	auth := newAuthResult()
	timer := time.AfterFunc(s.AuthenticateTimeout, func() {
		auth.complete(false, "")
		_ = conn.CloseWithError(AuthenticationTimeout, "authentication timeout")
	})
	defer timer.Stop()

	go s.authenticate(conn, auth)
	// The timeout only guards the handshake: once a user is authenticated the
	// connection is long lived and must not be torn down after 10 seconds.
	go func() {
		<-auth.done
		if auth.ok {
			timer.Stop()
		}
	}()

	for {
		stream, err := conn.AcceptStream(context.Background())
		if err != nil {
			return
		}
		go s.handleStream(conn, stream, auth)
	}
}

func (s *Server) authenticate(conn *quic.Conn, auth *authResult) {
	uniStream, err := conn.AcceptUniStream(context.Background())
	if err != nil {
		auth.complete(false, "")
		return
	}
	reader := bufio.NewReader(uniStream)
	head, err := ReadCommandHead(reader)
	if err != nil {
		auth.complete(false, "")
		return
	}
	if head.VER != VER || head.TYPE != AuthenticateType {
		auth.complete(false, "")
		_ = conn.CloseWithError(AuthenticationFailed, "unexpected authentication header")
		return
	}
	authenticate, err := ReadAuthenticateWithHead(head, reader)
	if err != nil {
		auth.complete(false, "")
		return
	}
	password, ok := s.Users[authenticate.UUID]
	if !ok {
		auth.complete(false, "")
		_ = conn.CloseWithError(AuthenticationFailed, "unknown user")
		return
	}
	token, err := GenToken(conn.ConnectionState(), authenticate.UUID, password)
	if err != nil {
		auth.complete(false, "")
		return
	}
	if token != authenticate.TOKEN {
		auth.complete(false, "")
		_ = conn.CloseWithError(AuthenticationFailed, "authentication failed")
		return
	}
	auth.complete(true, uuidString(authenticate.UUID))

	// Remaining messages on this stream authorize full-cone UDP relays.
	for {
		underlay, err := ReadUnderlayAuth(reader)
		if err != nil {
			return
		}
		s.storeUnderlayAuth(underlay)
	}
}

func (s *Server) handleStream(conn *quic.Conn, stream *quic.Stream, auth *authResult) {
	lConn := types.NewQuicStreamConn(stream, conn.LocalAddr(), conn.RemoteAddr(), nil)
	network, addr, err := ReadRequestHeader(lConn)
	if err != nil {
		_ = lConn.Close()
		return
	}
	select {
	case <-auth.done:
	case <-time.After(s.AuthenticateTimeout):
		_ = lConn.Close()
		return
	}
	if !auth.ok {
		_ = lConn.Close()
		return
	}
	additions := []inbound.Addition{inbound.WithInUser(auth.user)}

	switch network {
	case NetworkTCP:
		if err = s.HandleTcpFn(lConn, addr, additions...); err != nil {
			_ = lConn.Close()
		}
	case NetworkUDP:
		s.handleUDPStream(lConn, additions...)
	default:
		_ = lConn.Close()
	}
}

func (s *Server) handleUDPStream(conn net.Conn, additions ...inbound.Addition) {
	pc := NewStreamPacketConn(conn)
	defer pc.Close()
	buf := make([]byte, 64*1024)
	for {
		n, raddr, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		data := make([]byte, n)
		copy(data, buf[:n])
		var target socks5.Addr
		if a, ok := raddr.(udpAddr); ok {
			target = a.Addr
		} else if raddr != nil {
			target = socks5.ParseAddrToSocksAddr(raddr)
		}
		if len(target) == 0 {
			continue
		}
		packet := &streamUDPPacket{
			data:      data,
			pc:        pc,
			localAddr: conn.RemoteAddr(),
		}
		if err = s.HandleUdpFn(target, packet, additions...); err != nil {
			log.Warnln("juicity: handle udp: %v", err)
		}
	}
}

type streamUDPPacket struct {
	data      []byte
	pc        *StreamPacketConn
	localAddr net.Addr
}

func (p *streamUDPPacket) Data() []byte { return p.data }

func (p *streamUDPPacket) WriteBack(b []byte, addr net.Addr) (int, error) {
	return p.pc.WriteTo(b, addr)
}

func (p *streamUDPPacket) Drop() {}

func (p *streamUDPPacket) LocalAddr() net.Addr { return p.localAddr }

var _ C.UDPPacket = (*streamUDPPacket)(nil)

// ---- underlay (full-cone UDP) ----

func (s *Server) storeUnderlayAuth(a *UnderlayAuth) {
	var key [UnderlaySaltLen]byte
	copy(key[:], a.IV)
	s.authMu.Lock()
	defer s.authMu.Unlock()
	now := time.Now()
	for k, v := range s.authTable {
		if now.After(v.expire) {
			delete(s.authTable, k)
		}
	}
	s.authTable[key] = &underlayAuthEntry{
		psk:    a.Psk,
		addr:   a.Addr,
		expire: now.Add(underlayAuthTTL),
	}
}

func (s *Server) evictUnderlayAuth(iv []byte) *underlayAuthEntry {
	var key [UnderlaySaltLen]byte
	copy(key[:], iv)
	s.authMu.Lock()
	defer s.authMu.Unlock()
	entry, ok := s.authTable[key]
	if !ok {
		return nil
	}
	delete(s.authTable, key)
	if time.Now().After(entry.expire) {
		return nil
	}
	return entry
}

func (s *Server) waitUnderlayAuth(iv []byte) *underlayAuthEntry {
	if entry := s.evictUnderlayAuth(iv); entry != nil {
		return entry
	}
	deadline := time.Now().Add(underlayAuthWaitTimeout)
	for time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
		if entry := s.evictUnderlayAuth(iv); entry != nil {
			return entry
		}
	}
	return nil
}

func (s *Server) serveUnderlay() {
	buf := make([]byte, 64*1024)
	for {
		n, addr, err := s.transport.ReadNonQUICPacket(context.Background(), buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			return
		}
		packet := make([]byte, n)
		copy(packet, buf[:n])
		udpAddr, ok := addr.(*net.UDPAddr)
		if !ok {
			continue
		}
		go s.handleUnderlayPacket(packet, udpAddr)
	}
}

func (s *Server) handleUnderlayPacket(packet []byte, from *net.UDPAddr) {
	if len(packet) < UnderlaySaltLen {
		return
	}
	ep := s.getEndpoint(from)
	if ep == nil {
		// The first datagram can arrive before the authorization message on the
		// (unordered) QUIC stream is processed, so wait briefly for it.
		entry := s.waitUnderlayAuth(packet[:UnderlaySaltLen])
		if entry == nil {
			return
		}
		ep = &underlayEndpoint{
			key:        entry.psk,
			target:     entry.addr,
			localAddr:  from,
			clientAddr: from,
			server:     s,
		}
		s.putEndpoint(from, ep)
	}
	payload, _, err := openUnderlay(ep.key, packet)
	if err != nil {
		return
	}
	ep.touch()
	udpPacket := &underlayUDPPacket{
		data:      payload,
		endpoint:  ep,
		localAddr: ep.localAddr,
	}
	target := ep.target
	if err = s.HandleUdpFn(target, udpPacket); err != nil {
		log.Warnln("juicity: handle underlay udp: %v", err)
	}
}

func (s *Server) getEndpoint(from *net.UDPAddr) *underlayEndpoint {
	key := from.String()
	s.endpointMu.Lock()
	defer s.endpointMu.Unlock()
	ep, ok := s.endpoints[key]
	if !ok {
		return nil
	}
	if time.Since(ep.lastSeen) > underlayEndpointTTL {
		delete(s.endpoints, key)
		return nil
	}
	return ep
}

func (s *Server) putEndpoint(from *net.UDPAddr, ep *underlayEndpoint) {
	key := from.String()
	s.endpointMu.Lock()
	defer s.endpointMu.Unlock()
	// Opportunistic cleanup.
	now := time.Now()
	for k, v := range s.endpoints {
		if now.Sub(v.lastSeen) > underlayEndpointTTL {
			delete(s.endpoints, k)
		}
	}
	s.endpoints[key] = ep
}

func (e *underlayEndpoint) touch() {
	e.lastSeen = time.Now()
}

func (e *underlayEndpoint) WriteTo(b []byte, addr net.Addr) (int, error) {
	salt := newUnderlaySalt()
	sealed, err := sealUnderlay(e.key, salt, b)
	if err != nil {
		return 0, err
	}
	if _, err = e.server.transport.WriteTo(sealed, e.clientAddr); err != nil {
		return 0, err
	}
	return len(b), nil
}

type underlayUDPPacket struct {
	data      []byte
	endpoint  *underlayEndpoint
	localAddr net.Addr
}

func (p *underlayUDPPacket) Data() []byte { return p.data }

func (p *underlayUDPPacket) WriteBack(b []byte, addr net.Addr) (int, error) {
	return p.endpoint.WriteTo(b, addr)
}

func (p *underlayUDPPacket) Drop() {}

func (p *underlayUDPPacket) LocalAddr() net.Addr { return p.localAddr }

var _ C.UDPPacket = (*underlayUDPPacket)(nil)

func uuidString(u [16]byte) string {
	return uuid.UUID(u).String()
}
