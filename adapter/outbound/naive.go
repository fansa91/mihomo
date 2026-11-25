package outbound

import (
	"context"
	"net"
	"strconv"
	"strings"
	"time"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/naive"
	"github.com/metacubex/mihomo/transport/vmess"

	M "github.com/metacubex/sing/common/metadata"
	"github.com/metacubex/sing/common/uot"
)

// naiveTunnel is implemented by both the h2 and h3 naive clients.
type naiveTunnel interface {
	Dial(ctx context.Context, target string) (net.Conn, error)
	Close() error
}

type Naive struct {
	*Base
	option *NaiveOption
	client naiveTunnel
}

type NaiveOption struct {
	BasicOption
	Name                 string            `proxy:"name"`
	Server               string            `proxy:"server"`
	Port                 int               `proxy:"port"`
	Username             string            `proxy:"username,omitempty"`
	Password             string            `proxy:"password,omitempty"`
	SNI                  string            `proxy:"sni,omitempty"`
	SkipCertVerify       bool              `proxy:"skip-cert-verify,omitempty"`
	Fingerprint          string            `proxy:"fingerprint,omitempty"`
	ClientFingerprint    string            `proxy:"client-fingerprint,omitempty"`
	Certificate          string            `proxy:"certificate,omitempty"`
	PrivateKey           string            `proxy:"private-key,omitempty"`
	Headers              map[string]string `proxy:"headers,omitempty"`
	UDPOverTCP           bool              `proxy:"udp-over-tcp,omitempty"`
	UDPOverTCPVersion    int               `proxy:"udp-over-tcp-version,omitempty"`
	FastOpen             bool              `proxy:"fast-open,omitempty"`
	RequestTimeout       int               `proxy:"request-timeout,omitempty"`
	IdleTimeout          int               `proxy:"idle-timeout,omitempty"`
	Network              string            `proxy:"network,omitempty"`
	CongestionController string            `proxy:"congestion-controller,omitempty"`
	CWND                 int               `proxy:"cwnd,omitempty"`
	BBRProfile           string            `proxy:"bbr-profile,omitempty"`
}

// DialContext implements C.ProxyAdapter
func (n *Naive) DialContext(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
	conn, err := n.client.Dial(ctx, metadata.RemoteAddress())
	if err != nil {
		return nil, err
	}
	return NewConn(conn, n), nil
}

// ListenPacketContext implements C.ProxyAdapter
//
// naiveproxy has no native UDP transport; when enabled, datagrams are carried
// over a TCP tunnel using sing's UDP-over-TCP framing.
func (n *Naive) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (_ C.PacketConn, err error) {
	if !n.option.UDPOverTCP {
		return nil, C.ErrNotSupport
	}
	if err = n.ResolveUDP(ctx, metadata); err != nil {
		return nil, err
	}
	uotDestination := uot.RequestDestination(uint8(n.option.UDPOverTCPVersion))
	uotMetadata := *metadata
	uotMetadata.Host = uotDestination.Fqdn
	uotMetadata.DstPort = uotDestination.Port
	c, err := n.DialContext(ctx, &uotMetadata)
	if err != nil {
		return nil, err
	}
	destination := M.SocksaddrFromNet(metadata.UDPAddr())
	if n.option.UDPOverTCPVersion == uot.LegacyVersion {
		return NewPacketConn(uot.NewConn(c, uot.Request{Destination: destination}), n), nil
	}
	return NewPacketConn(uot.NewLazyConn(c, uot.Request{Destination: destination}), n), nil
}

// ProxyInfo implements C.ProxyAdapter
func (n *Naive) ProxyInfo() C.ProxyInfo {
	info := n.Base.ProxyInfo()
	info.DialerProxy = n.option.DialerProxy
	return info
}

func NewNaive(option NaiveOption) (*Naive, error) {
	addr := net.JoinHostPort(option.Server, strconv.Itoa(option.Port))
	serverName := option.Server
	if option.SNI != "" {
		serverName = option.SNI
	}

	switch option.UDPOverTCPVersion {
	case uot.Version, uot.LegacyVersion:
	case 0:
		option.UDPOverTCPVersion = uot.LegacyVersion
	}

	n := &Naive{
		Base: NewBase(BaseOption{
			Name:         option.Name,
			Addr:         addr,
			Type:         C.Naive,
			ProviderName: option.ProviderName,
			UDP:          option.UDPOverTCP,
			TFO:          option.TFO,
			Interface:    option.Interface,
			RoutingMark:  option.RoutingMark,
			Prefer:       option.IPVersion,
		}),
		option: &option,
	}
	n.dialer = option.NewDialer(n.DialOptions())

	// network: h3 selects the HTTP/3 (QUIC) naive path; anything else is h2.
	isH3 := strings.EqualFold(option.Network, "h3") || strings.EqualFold(option.Network, "http/3")

	alpn := "h2"
	if isH3 {
		alpn = "h3"
	}
	tlsConfig := &vmess.TLSConfig{
		Host:              serverName,
		SkipCertVerify:    option.SkipCertVerify,
		FingerPrint:       option.Fingerprint,
		ClientFingerprint: option.ClientFingerprint,
		Certificate:       option.Certificate,
		PrivateKey:        option.PrivateKey,
		NextProtos:        []string{alpn},
	}

	requestTimeout := time.Duration(option.RequestTimeout) * time.Second
	idleTimeout := time.Duration(option.IdleTimeout) * time.Second

	if isH3 {
		client, err := naive.NewQUICClient(&naive.QUICClientOptions{
			Dialer:            n.dialer,
			Server:            addr,
			TLSConfig:         tlsConfig,
			Username:          option.Username,
			Password:          option.Password,
			Headers:           option.Headers,
			RequestTimeout:    requestTimeout,
			IdleTimeout:       idleTimeout,
			CongestionControl: option.CongestionController,
			Cwnd:              option.CWND,
			BBRProfile:        option.BBRProfile,
		})
		if err != nil {
			return nil, err
		}
		n.client = client
		return n, nil
	}

	client, err := naive.NewClient(&naive.ClientOptions{
		Dialer:         n.dialer,
		Server:         addr,
		TLSConfig:      tlsConfig,
		Username:       option.Username,
		Password:       option.Password,
		Headers:        option.Headers,
		FastOpen:       option.FastOpen,
		RequestTimeout: requestTimeout,
		IdleTimeout:    idleTimeout,
	})
	if err != nil {
		return nil, err
	}
	n.client = client
	return n, nil
}
