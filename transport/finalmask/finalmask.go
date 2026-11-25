// Package finalmask implements Xray's streamSettings.finalmask on the client
// side: a chain of small wrappers applied to the transport connection right
// above the socket, before any protocol handshake.
//
// Wire compatibility matters more than internal similarity, so every mask here
// reproduces the exact byte layout of its Xray counterpart
// (transport/internet/finalmask/*): the server side does not know or care which
// implementation produced the stream.
package finalmask

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

// Option is the config block, shaped like Xray's finalmask object so existing
// server-side configs can be pasted almost verbatim:
//
//	finalmask:
//	  tcp:
//	    - type: fragment
//	      settings:
//	        packets: tlshello
//	        length: 100-200
//	        delay: 10-20
//	  udp:
//	    - type: salamander
//	      settings:
//	        password: secret
type Option struct {
	TCP []MaskOption `proxy:"tcp,omitempty"`
	UDP []MaskOption `proxy:"udp,omitempty"`
}

// MaskOption is one entry of the chain. Settings keeps the raw map because each
// mask has its own schema; lookups accept both camelCase (Xray) and
// kebab-case (mihomo habit) spellings.
type MaskOption struct {
	Type     string         `proxy:"type"`
	Settings map[string]any `proxy:"settings,omitempty"`
}

// TCPMask wraps a stream connection. Masks are applied outermost-first: the
// first entry in the list is the outermost wrapper, matching Xray's ordering
// after its internal slice reversal.
type TCPMask interface {
	WrapConnClient(conn net.Conn) (net.Conn, error)
}

// UDPMask wraps a packet connection. remote is the destination the socket is
// already connected to (mihomo hands out connected sockets).
type UDPMask interface {
	WrapPacketConnClient(pc net.PacketConn, remote net.Addr) (net.PacketConn, error)
}

// Dialer mirrors constant.Dialer. Declaring it here keeps this package free of
// a dependency on the constant package; the two are assignment-compatible
// because the method sets are identical.
type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
	ListenPacket(ctx context.Context, network, address string, rAddrPort netip.AddrPort) (net.PacketConn, error)
}

// Mask is a parsed, ready-to-use chain. A nil or empty Mask is a no-op.
type Mask struct {
	tcp []TCPMask
	udp []UDPMask
	// desc is kept for logging and for the API surface.
	desc string
}

// Parse turns the config block into a chain. An empty config yields a nil Mask
// and no error, so callers can skip the wrapper entirely.
func Parse(opt *Option) (*Mask, error) {
	if opt == nil || (len(opt.TCP) == 0 && len(opt.UDP) == 0) {
		return nil, nil
	}
	m := &Mask{}
	var names []string
	for i, item := range opt.TCP {
		t, err := newTCPMask(item)
		if err != nil {
			return nil, fmt.Errorf("finalmask tcp[%d] (%s): %w", i, item.Type, err)
		}
		m.tcp = append(m.tcp, t)
		names = append(names, "tcp:"+strings.ToLower(item.Type))
	}
	for i, item := range opt.UDP {
		u, err := newUDPMask(item)
		if err != nil {
			return nil, fmt.Errorf("finalmask udp[%d] (%s): %w", i, item.Type, err)
		}
		m.udp = append(m.udp, u)
		names = append(names, "udp:"+strings.ToLower(item.Type))
	}
	m.desc = strings.Join(names, ",")
	return m, nil
}

func newTCPMask(item MaskOption) (TCPMask, error) {
	switch strings.ToLower(strings.TrimSpace(item.Type)) {
	case "fragment":
		return newFragmentMask(item.Settings)
	case "proxy-protocol", "proxyprotocol":
		return newProxyProtocolMask(item.Settings)
	default:
		return nil, fmt.Errorf("unsupported tcp mask %q (supported: fragment, proxy-protocol)", item.Type)
	}
}

func newUDPMask(item MaskOption) (UDPMask, error) {
	switch strings.ToLower(strings.TrimSpace(item.Type)) {
	case "salamander":
		return newSalamanderMask(item.Settings)
	default:
		return nil, fmt.Errorf("unsupported udp mask %q (supported: salamander)", item.Type)
	}
}

// String describes the chain, for logs.
func (m *Mask) String() string {
	if m == nil {
		return ""
	}
	return m.desc
}

// WrapConn applies the TCP chain to an established connection. Entries are
// wrapped from the last to the first so that the first configured mask ends up
// outermost, the same layer order Xray builds.
func (m *Mask) WrapConn(conn net.Conn) (net.Conn, error) {
	if m == nil || len(m.tcp) == 0 {
		return conn, nil
	}
	var err error
	for i := len(m.tcp) - 1; i >= 0; i-- {
		conn, err = m.tcp[i].WrapConnClient(conn)
		if err != nil {
			_ = conn.Close()
			return nil, err
		}
	}
	return conn, nil
}

// WrapPacketConn applies the UDP chain. Salamander is symmetric, so client and
// server use the same wrapper.
func (m *Mask) WrapPacketConn(pc net.PacketConn, remote net.Addr) (net.PacketConn, error) {
	if m == nil || len(m.udp) == 0 {
		return pc, nil
	}
	var err error
	for i := len(m.udp) - 1; i >= 0; i-- {
		pc, err = m.udp[i].WrapPacketConnClient(pc, remote)
		if err != nil {
			_ = pc.Close()
			return nil, err
		}
	}
	return pc, nil
}

// WrapDialer returns a Dialer that masks every connection it opens. The
// listener side is untouched: masks only change what goes on the wire towards
// the proxy server.
func WrapDialer(d Dialer, m *Mask) Dialer {
	if m == nil || (len(m.tcp) == 0 && len(m.udp) == 0) {
		return d
	}
	return &maskedDialer{Dialer: d, mask: m}
}

type maskedDialer struct {
	Dialer
	mask *Mask
}

func (d *maskedDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	conn, err := d.Dialer.DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	if strings.HasPrefix(network, "udp") && len(d.mask.udp) > 0 {
		// mihomo's datagram transports (mkcp, for instance) call DialContext
		// with "udp" and get a connected socket back. Wrap it as a PacketConn so
		// datagram masks apply there too, then expose it as a Conn again.
		pc, ok := conn.(net.PacketConn)
		if !ok {
			return conn, nil
		}
		wrapped, err := d.mask.WrapPacketConn(pc, conn.RemoteAddr())
		if err != nil {
			_ = conn.Close()
			return nil, err
		}
		return newPacketConnAdapter(wrapped, conn.RemoteAddr()), nil
	}
	if len(d.mask.tcp) == 0 {
		return conn, nil
	}
	return d.mask.WrapConn(conn)
}

func (d *maskedDialer) ListenPacket(ctx context.Context, network, address string, rAddrPort netip.AddrPort) (net.PacketConn, error) {
	pc, err := d.Dialer.ListenPacket(ctx, network, address, rAddrPort)
	if err != nil {
		return nil, err
	}
	if len(d.mask.udp) == 0 {
		return pc, nil
	}
	return d.mask.WrapPacketConn(pc, net.UDPAddrFromAddrPort(rAddrPort))
}

// setting reads a mask setting by any of the accepted spellings. Xray's
// configs use camelCase, mihomo configs usually kebab-case; both work.
func setting(settings map[string]any, names ...string) (any, bool) {
	for _, name := range names {
		if v, ok := settings[name]; ok {
			return v, true
		}
	}
	return nil, false
}

func settingString(settings map[string]any, names ...string) string {
	v, ok := setting(settings, names...)
	if !ok || v == nil {
		return ""
	}
	switch s := v.(type) {
	case string:
		return s
	case fmt.Stringer:
		return s.String()
	default:
		return fmt.Sprint(s)
	}
}

func settingInt(settings map[string]any, names ...string) (int, bool, error) {
	v, ok := setting(settings, names...)
	if !ok || v == nil {
		return 0, false, nil
	}
	switch n := v.(type) {
	case int:
		return n, true, nil
	case int64:
		return int(n), true, nil
	case uint64:
		return int(n), true, nil
	case float64:
		return int(n), true, nil
	case string:
		i, err := strconv.Atoi(strings.TrimSpace(n))
		if err != nil {
			return 0, true, fmt.Errorf("invalid integer %q", n)
		}
		return i, true, nil
	default:
		return 0, true, fmt.Errorf("invalid integer type %T", v)
	}
}

// int32Range is Xray's Int32Range: a single value ("100") or an inclusive
// range ("100-200"), also accepted as a [low, high] array.
type int32Range struct {
	From int
	To   int
}

func (r int32Range) valid() bool { return r.From > 0 || r.To > 0 }

func parseRangeValue(v any) (int32Range, error) {
	switch t := v.(type) {
	case int:
		return int32Range{From: t, To: t}, nil
	case int64:
		return int32Range{From: int(t), To: int(t)}, nil
	case float64:
		return int32Range{From: int(t), To: int(t)}, nil
	case string:
		return parseRangeString(t)
	case []any:
		if len(t) == 0 {
			return int32Range{}, nil
		}
		from, err := parseRangeValue(t[0])
		if err != nil {
			return int32Range{}, err
		}
		if len(t) == 1 {
			return int32Range{From: from.From, To: from.From}, nil
		}
		to, err := parseRangeValue(t[1])
		if err != nil {
			return int32Range{}, err
		}
		return int32Range{From: from.From, To: to.From}, nil
	default:
		return int32Range{}, fmt.Errorf("invalid range type %T", v)
	}
}

func parseRangeString(s string) (int32Range, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return int32Range{}, nil
	}
	from, to, found := strings.Cut(s, "-")
	if !found {
		n, err := strconv.Atoi(s)
		if err != nil {
			return int32Range{}, fmt.Errorf("invalid range %q", s)
		}
		return int32Range{From: n, To: n}, nil
	}
	lo, err := strconv.Atoi(strings.TrimSpace(from))
	if err != nil {
		return int32Range{}, fmt.Errorf("invalid range %q", s)
	}
	hi, err := strconv.Atoi(strings.TrimSpace(to))
	if err != nil {
		return int32Range{}, fmt.Errorf("invalid range %q", s)
	}
	if hi < lo {
		lo, hi = hi, lo
	}
	return int32Range{From: lo, To: hi}, nil
}

func settingRange(settings map[string]any, names ...string) (int32Range, bool, error) {
	v, ok := setting(settings, names...)
	if !ok || v == nil {
		return int32Range{}, false, nil
	}
	r, err := parseRangeValue(v)
	return r, true, err
}

func settingRangeList(settings map[string]any, names ...string) ([]int32Range, bool, error) {
	v, ok := setting(settings, names...)
	if !ok || v == nil {
		return nil, false, nil
	}
	list, ok := v.([]any)
	if !ok {
		return nil, true, fmt.Errorf("%v must be a list", names[0])
	}
	out := make([]int32Range, 0, len(list))
	for _, item := range list {
		r, err := parseRangeValue(item)
		if err != nil {
			return nil, true, err
		}
		out = append(out, r)
	}
	return out, true, nil
}

// packetConnAdapter exposes a connected PacketConn as a net.Conn, which is what
// DialContext must return for datagram transports.
type packetConnAdapter struct {
	net.PacketConn
	remote net.Addr
}

func newPacketConnAdapter(pc net.PacketConn, remote net.Addr) net.Conn {
	return &packetConnAdapter{PacketConn: pc, remote: remote}
}

func (c *packetConnAdapter) Read(p []byte) (int, error) {
	n, _, err := c.PacketConn.ReadFrom(p)
	return n, err
}

func (c *packetConnAdapter) Write(p []byte) (int, error) {
	return c.PacketConn.WriteTo(p, c.remote)
}

func (c *packetConnAdapter) RemoteAddr() net.Addr { return c.remote }
