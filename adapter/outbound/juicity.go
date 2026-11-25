package outbound

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/metacubex/mihomo/component/ca"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/juicity"
	"github.com/metacubex/mihomo/transport/socks5"
	"github.com/metacubex/mihomo/transport/tuic/common"

	"github.com/gofrs/uuid/v5"
	"github.com/metacubex/quic-go"
	"github.com/metacubex/tls"
)

type Juicity struct {
	*Base
	option     *JuicityOption
	client     *juicity.Client
	tlsConfig  *tls.Config
	quicConfig *quic.Config
}

type JuicityOption struct {
	BasicOption
	Name                 string     `proxy:"name"`
	Server               string     `proxy:"server"`
	Port                 int        `proxy:"port"`
	UUID                 string     `proxy:"uuid"`
	Password             string     `proxy:"password"`
	Ip                   string     `proxy:"ip,omitempty"`
	SNI                  string     `proxy:"sni,omitempty"`
	ALPN                 []string   `proxy:"alpn,omitempty"`
	CongestionController string     `proxy:"congestion-controller,omitempty"`
	UDPRelayMode         string     `proxy:"udp-relay-mode,omitempty"`
	HeartbeatInterval    int        `proxy:"heartbeat-interval,omitempty"`
	RequestTimeout       int        `proxy:"request-timeout,omitempty"`
	MaxOpenStreams       int        `proxy:"max-open-streams,omitempty"`
	CWND                 int        `proxy:"cwnd,omitempty"`
	BBRProfile           string     `proxy:"bbr-profile,omitempty"`
	ReceiveWindowConn    int        `proxy:"recv-window-conn,omitempty"`
	ReceiveWindow        int        `proxy:"recv-window,omitempty"`
	DisableMTUDiscovery  bool       `proxy:"disable-mtu-discovery,omitempty"`
	SkipCertVerify       bool       `proxy:"skip-cert-verify,omitempty"`
	NameCertVerify       string     `proxy:"name-cert-verify,omitempty"`
	Fingerprint          string     `proxy:"fingerprint,omitempty"`
	Certificate          string     `proxy:"certificate,omitempty"`
	PrivateKey           string     `proxy:"private-key,omitempty"`
	ECHOpts              ECHOptions `proxy:"ech-opts,omitempty"`
}

// DialContext implements C.ProxyAdapter
func (j *Juicity) DialContext(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
	conn, err := j.client.DialContext(ctx, socks5.Addr(serializesSocksAddr(metadata)))
	if err != nil {
		return nil, err
	}
	return NewConn(conn, j), nil
}

// ListenPacketContext implements C.ProxyAdapter
func (j *Juicity) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (_ C.PacketConn, err error) {
	if err = j.ResolveUDP(ctx, metadata); err != nil {
		return nil, err
	}
	addr := socks5.Addr(serializesSocksAddr(metadata))
	var pc net.PacketConn
	if j.option.UDPRelayMode == "quic" {
		pc, err = j.client.ListenPacket(ctx, addr)
	} else {
		pc, err = j.client.ListenPacketUnderlay(ctx, addr)
	}
	if err != nil {
		return nil, err
	}
	return NewPacketConn(pc, j), nil
}

func (j *Juicity) dialQuic(ctx context.Context) (*quic.Conn, error) {
	_, conn, err := common.DialQuic(ctx, j.addr, j.DialOptions(), j.dialer, j.tlsConfig, j.quicConfig, common.DialQuicOption{})
	if err != nil {
		return nil, err
	}
	common.SetCongestionController(conn, j.option.CongestionController, j.option.CWND, j.option.BBRProfile)
	return conn, nil
}

func (j *Juicity) dialUnderlay(ctx context.Context) (net.PacketConn, net.Addr, error) {
	addrPort, err := resolveUDPAddr(ctx, "udp", j.addr, j.option.IPVersion)
	if err != nil {
		return nil, nil, err
	}
	pc, err := j.dialer.ListenPacket(ctx, "udp", "", addrPort.AddrPort())
	if err != nil {
		return nil, nil, err
	}
	return pc, net.UDPAddrFromAddrPort(addrPort.AddrPort()), nil
}

// ProxyInfo implements C.ProxyAdapter
func (j *Juicity) ProxyInfo() C.ProxyInfo {
	info := j.Base.ProxyInfo()
	info.DialerProxy = j.option.DialerProxy
	return info
}

func NewJuicity(option JuicityOption) (*Juicity, error) {
	addr := net.JoinHostPort(option.Server, strconv.Itoa(option.Port))
	serverName := option.Server
	if option.SNI != "" {
		serverName = option.SNI
	}
	if option.Ip != "" {
		addr = net.JoinHostPort(option.Ip, strconv.Itoa(option.Port))
	}

	tlsConfig, err := ca.GetTLSConfig(ca.Option{
		TLSConfig: &tls.Config{
			ServerName:         serverName,
			InsecureSkipVerify: option.SkipCertVerify,
			MinVersion:         tls.VersionTLS13,
		},
		Fingerprint:    option.Fingerprint,
		NameCertVerify: option.NameCertVerify,
		Certificate:    option.Certificate,
		PrivateKey:     option.PrivateKey,
	})
	if err != nil {
		return nil, err
	}
	if option.ALPN != nil {
		tlsConfig.NextProtos = option.ALPN
	} else {
		tlsConfig.NextProtos = []string{"h3"}
	}
	if option.SNI == "" && option.Ip != "" {
		// Keep the original hostname for SNI when dialing a fixed IP.
		tlsConfig.ServerName = option.Server
	}

	if option.HeartbeatInterval <= 0 {
		option.HeartbeatInterval = 10000
	}
	if option.MaxOpenStreams <= 0 {
		option.MaxOpenStreams = 100
	}
	if option.CWND == 0 {
		option.CWND = 10
	}
	if option.UDPRelayMode == "" {
		// Match juicity's own client: datagrams travel inside the QUIC stream
		// unless full-cone ("native") relay is explicitly requested.
		option.UDPRelayMode = "quic"
	}
	if option.UDPRelayMode != "native" && option.UDPRelayMode != "quic" {
		return nil, fmt.Errorf("juicity %s: unknown udp-relay-mode %q", addr, option.UDPRelayMode)
	}

	quicConfig := &quic.Config{
		InitialStreamReceiveWindow:     uint64(option.ReceiveWindowConn),
		MaxStreamReceiveWindow:         uint64(option.ReceiveWindowConn),
		InitialConnectionReceiveWindow: uint64(option.ReceiveWindow),
		MaxConnectionReceiveWindow:     uint64(option.ReceiveWindow),
		MaxIncomingStreams:             int64(option.MaxOpenStreams),
		MaxIncomingUniStreams:          int64(option.MaxOpenStreams),
		KeepAlivePeriod:                time.Duration(option.HeartbeatInterval) * time.Millisecond,
		DisablePathMTUDiscovery:        option.DisableMTUDiscovery,
		EnableDatagrams:                false,
	}
	if option.ReceiveWindowConn == 0 {
		quicConfig.InitialStreamReceiveWindow = 2 * 1024 * 1024 / 10
		quicConfig.MaxStreamReceiveWindow = 2 * 1024 * 1024
	}
	if option.ReceiveWindow == 0 {
		quicConfig.InitialConnectionReceiveWindow = 8 * 1024 * 1024 / 10
		quicConfig.MaxConnectionReceiveWindow = 8 * 1024 * 1024
	}

	userUUID := uuid.FromStringOrNil(option.UUID)

	j := &Juicity{
		Base: NewBase(BaseOption{
			Name:         option.Name,
			Addr:         addr,
			Type:         C.Juicity,
			ProviderName: option.ProviderName,
			UDP:          true,
			TFO:          option.TFO,
			Interface:    option.Interface,
			RoutingMark:  option.RoutingMark,
			Prefer:       option.IPVersion,
		}),
		option:     &option,
		tlsConfig:  tlsConfig,
		quicConfig: quicConfig,
	}
	j.dialer = option.NewDialer(j.DialOptions())

	j.client = juicity.NewClient(&juicity.ClientOption{
		UUID:           [16]byte(userUUID),
		Password:       option.Password,
		MaxOpenStreams: int64(option.MaxOpenStreams),
		DialFn:         j.dialQuic,
		DialUnderlayFn: j.dialUnderlay,
	})
	return j, nil
}
