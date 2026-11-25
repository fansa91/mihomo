package juicity

import (
	"context"
	"net"
	"strings"
	"time"

	"github.com/metacubex/mihomo/adapter/inbound"
	"github.com/metacubex/mihomo/common/sockopt"
	"github.com/metacubex/mihomo/component/ca"
	"github.com/metacubex/mihomo/component/ech"
	C "github.com/metacubex/mihomo/constant"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/listener/sing"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/ntp"
	"github.com/metacubex/mihomo/transport/juicity"
	"github.com/metacubex/mihomo/transport/socks5"

	"github.com/gofrs/uuid/v5"
	"github.com/metacubex/quic-go"
	"github.com/metacubex/tls"
	"golang.org/x/exp/slices"
)

const ServerMaxIncomingStreams = (1 << 32) - 1

type Listener struct {
	closed       bool
	config       LC.JuicityServer
	udpListeners []net.PacketConn
	servers      []*juicity.Server
}

func New(config LC.JuicityServer, lc C.InboundListenConfig, tunnel C.Tunnel, additions ...inbound.Addition) (*Listener, error) {
	if len(additions) == 0 {
		additions = []inbound.Addition{
			inbound.WithInName("DEFAULT-JUICITY"),
			inbound.WithSpecialRules(""),
		}
	}
	h, err := sing.NewListenerHandler(sing.ListenerConfig{
		Tunnel:    tunnel,
		Type:      C.JUICITY,
		Additions: additions,
		MuxOption: config.MuxOption,
	})
	if err != nil {
		return nil, err
	}

	tlsConfig := &tls.Config{
		Time:       ntp.Now,
		MinVersion: tls.VersionTLS13,
	}
	certLoader, err := ca.NewTLSKeyPairLoader(config.Certificate, config.PrivateKey)
	if err != nil {
		return nil, err
	}
	tlsConfig.GetCertificate = func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		return certLoader()
	}
	tlsConfig.ClientAuth = ca.ClientAuthTypeFromString(config.ClientAuthType)
	if len(config.ClientAuthCert) > 0 {
		if tlsConfig.ClientAuth == tls.NoClientCert {
			tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
		}
	}
	if tlsConfig.ClientAuth == tls.VerifyClientCertIfGiven || tlsConfig.ClientAuth == tls.RequireAndVerifyClientCert {
		pool, err := ca.LoadCertificates(config.ClientAuthCert)
		if err != nil {
			return nil, err
		}
		tlsConfig.ClientCAs = pool
	}
	if config.EchKey != "" {
		if err = ech.LoadECHKey(config.EchKey, tlsConfig); err != nil {
			return nil, err
		}
	}
	if len(config.ALPN) > 0 {
		tlsConfig.NextProtos = config.ALPN
	} else {
		tlsConfig.NextProtos = []string{"h3"}
	}

	if config.MaxIdleTime == 0 {
		config.MaxIdleTime = 30000
	}
	if config.MaxOpenStreams == 0 {
		config.MaxOpenStreams = 1024
	}
	if config.AuthenticationTimeout == 0 {
		config.AuthenticationTimeout = 10000
	}
	if config.CWND == 0 {
		config.CWND = 10
	}

	quicConfig := &quic.Config{
		MaxIdleTimeout:                 time.Duration(config.MaxIdleTime) * time.Millisecond,
		MaxIncomingStreams:             ServerMaxIncomingStreams,
		MaxIncomingUniStreams:          ServerMaxIncomingStreams,
		EnableDatagrams:                false,
		Allow0RTT:                      false,
		DisablePathManager:             true, // for port hopping
		InitialStreamReceiveWindow:     2 * 1024 * 1024 / 10,
		MaxStreamReceiveWindow:         2 * 1024 * 1024,
		InitialConnectionReceiveWindow: 8 * 1024 * 1024 / 10,
		MaxConnectionReceiveWindow:     8 * 1024 * 1024,
	}

	users := make(map[[16]byte]string, len(config.Users))
	for _uuid, password := range config.Users {
		users[[16]byte(uuid.FromStringOrNil(_uuid))] = password
	}

	handleTcpFn := func(conn net.Conn, addr socks5.Addr, _additions ...inbound.Addition) error {
		go h.HandleSocket(addr, conn, _additions...)
		return nil
	}
	handleUdpFn := func(addr socks5.Addr, packet C.UDPPacket, _additions ...inbound.Addition) error {
		newAdditions := additions
		if len(_additions) > 0 {
			newAdditions = slices.Clip(additions)
			newAdditions = append(newAdditions, _additions...)
		}
		tunnel.HandleUDPPacket(inbound.NewPacket(addr, packet, C.JUICITY, newAdditions...))
		return nil
	}

	option := &juicity.ServerOption{
		HandleTcpFn:          handleTcpFn,
		HandleUdpFn:          handleUdpFn,
		TlsConfig:            tlsConfig,
		QuicConfig:           quicConfig,
		Users:                users,
		CongestionController: config.CongestionController,
		CWND:                 config.CWND,
		BBRProfile:           config.BBRProfile,
		AuthenticateTimeout:  time.Duration(config.AuthenticationTimeout) * time.Millisecond,
	}

	sl := &Listener{config: config}

	for _, addr := range strings.Split(config.Listen, ",") {
		addr := addr
		ul, err := lc.ListenPacket(context.Background(), "udp", addr)
		if err != nil {
			return nil, err
		}
		if err = sockopt.UDPReuseaddr(ul); err != nil {
			log.Warnln("Failed to Reuse UDP Address: %s", err)
		}
		sl.udpListeners = append(sl.udpListeners, ul)

		server, err := juicity.NewServer(option, ul)
		if err != nil {
			return nil, err
		}
		sl.servers = append(sl.servers, server)

		go func() {
			if err := server.Serve(); err != nil {
				if !sl.closed {
					log.Warnln("juicity server serve: %v", err)
				}
			}
		}()
	}
	return sl, nil
}

func (l *Listener) Close() error {
	l.closed = true
	var retErr error
	for _, server := range l.servers {
		if err := server.Close(); err != nil {
			retErr = err
		}
	}
	for _, lis := range l.udpListeners {
		if err := lis.Close(); err != nil {
			retErr = err
		}
	}
	return retErr
}

func (l *Listener) Config() LC.JuicityServer {
	return l.config
}

func (l *Listener) AddrList() (addrList []net.Addr) {
	for _, lis := range l.udpListeners {
		addrList = append(addrList, lis.LocalAddr())
	}
	return
}
