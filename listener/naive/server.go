package naive

import (
	"context"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/metacubex/http"
	"github.com/metacubex/mihomo/adapter/inbound"
	"github.com/metacubex/mihomo/component/ca"
	"github.com/metacubex/mihomo/component/ech"
	C "github.com/metacubex/mihomo/constant"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/listener/inner"
	"github.com/metacubex/mihomo/listener/sing"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/ntp"
	"github.com/metacubex/mihomo/transport/naive"
	"github.com/metacubex/mihomo/transport/socks5"

	"github.com/metacubex/http/httputil"
	"github.com/metacubex/quic-go/http3"
	E "github.com/metacubex/sing/common/exceptions"
	"github.com/metacubex/tls"
)

type Listener struct {
	closed      bool
	config      LC.NaiveServer
	listeners   []net.Listener
	servers     []*naive.Server
	packetConns []net.PacketConn
	quicServers []*naive.QUICServer
}

func New(config LC.NaiveServer, lc C.InboundListenConfig, tunnel C.Tunnel, additions ...inbound.Addition) (*Listener, error) {
	if len(additions) == 0 {
		additions = []inbound.Addition{
			inbound.WithInName("DEFAULT-NAIVE"),
			inbound.WithSpecialRules(""),
		}
	}
	h, err := sing.NewListenerHandler(sing.ListenerConfig{
		Tunnel:    tunnel,
		Type:      C.NAIVE,
		Additions: additions,
		MuxOption: config.MuxOption,
	})
	if err != nil {
		return nil, err
	}

	certLoader, err := ca.NewTLSKeyPairLoader(config.Certificate, config.PrivateKey)
	if err != nil {
		return nil, err
	}
	newTLSConfig := func(nextProtos ...string) (*tls.Config, error) {
		tlsConfig := &tls.Config{
			Time:       ntp.Now,
			MinVersion: tls.VersionTLS12,
			NextProtos: nextProtos,
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
		return tlsConfig, nil
	}
	h2TLSConfig, err := newTLSConfig("h2")
	if err != nil {
		return nil, err
	}

	var fallbackHandler http.Handler
	if config.Fallback != "" {
		fallbackURL, err := url.Parse(config.Fallback)
		if err != nil {
			return nil, E.Cause(err, "parse naive fallback URL")
		}
		switch fallbackURL.Scheme {
		case "file":
			fallbackHandler = http.FileServer(http.Dir(fallbackURL.Path))
		case "http", "https":
			fallbackHandler = &httputil.ReverseProxy{
				Rewrite: func(r *httputil.ProxyRequest) {
					r.SetURL(fallbackURL)
					r.Out.Host = r.In.Host
				},
				ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
					w.WriteHeader(http.StatusBadGateway)
				},
				Transport: &http.Transport{
					TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
					ForceAttemptHTTP2:     true,
					MaxIdleConns:          100,
					IdleConnTimeout:       90 * time.Second,
					TLSHandshakeTimeout:   10 * time.Second,
					ExpectContinueTimeout: 1 * time.Second,
					DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
						return inner.HandleTcp(tunnel, address, "")
					},
				},
			}
		default:
			return nil, E.New("unsupported naive fallback scheme: ", fallbackURL.Scheme)
		}
	}

	dl := &Listener{config: config}
	tunnelHandler := func(conn net.Conn, addr socks5.Addr, user string) {
		var userAdditions []inbound.Addition
		if user != "" {
			userAdditions = append(userAdditions, inbound.WithInUser(user))
		}
		// HandleSocket blocks until the tunnel is closed, which is what the
		// HTTP handler needs to keep the request stream alive (h2 or h3).
		h.HandleSocket(addr, conn, userAdditions...)
	}

	server := naive.NewServer(&naive.ServerOptions{
		Users:       config.Users,
		Fallback:    fallbackHandler,
		Handler:     tunnelHandler,
		IdleTimeout: time.Duration(config.IdleTimeout) * time.Second,
	})
	dl.servers = append(dl.servers, server)

	// HTTP/3 server shares users, fallback and tunnel handler with h2; only the
	// ALPN differs (h3 vs h2). Created lazily only when enabled.
	var quicServer *naive.QUICServer
	if config.HTTP3 {
		h3TLSConfig, err := newTLSConfig(http3.NextProtoH3)
		if err != nil {
			return nil, err
		}
		quicServer = naive.NewQUICServer(&naive.QUICServerOptions{
			Users:     config.Users,
			Fallback:  fallbackHandler,
			TLSConfig: h3TLSConfig,
			Handler:   tunnelHandler,
		})
		dl.quicServers = append(dl.quicServers, quicServer)
	}

	for _, addr := range strings.Split(config.Listen, ",") {
		addr := addr
		l, err := lc.Listen(context.Background(), "tcp", addr)
		if err != nil {
			return nil, err
		}
		tlsListener := tls.NewListener(l, h2TLSConfig)
		dl.listeners = append(dl.listeners, tlsListener)
		go func() {
			if serveErr := server.Serve(tlsListener); serveErr != nil {
				if !dl.closed {
					log.Warnln("naive server serve: %v", serveErr)
				}
			}
		}()

		if quicServer != nil {
			pc, err := lc.ListenPacket(context.Background(), "udp", addr)
			if err != nil {
				return nil, err
			}
			dl.packetConns = append(dl.packetConns, pc)
			go func() {
				if serveErr := quicServer.Serve(pc); serveErr != nil {
					if !dl.closed {
						log.Warnln("naive h3 server serve: %v", serveErr)
					}
				}
			}()
		}
	}
	return dl, nil
}

func (l *Listener) Close() error {
	l.closed = true
	var retErr error
	for _, server := range l.servers {
		if err := server.Close(); err != nil {
			retErr = err
		}
	}
	for _, qs := range l.quicServers {
		if err := qs.Close(); err != nil {
			retErr = err
		}
	}
	for _, lis := range l.listeners {
		if err := lis.Close(); err != nil {
			retErr = err
		}
	}
	for _, pc := range l.packetConns {
		if err := pc.Close(); err != nil {
			retErr = err
		}
	}
	return retErr
}

func (l *Listener) Config() LC.NaiveServer {
	return l.config
}

func (l *Listener) AddrList() (addrList []net.Addr) {
	for _, lis := range l.listeners {
		addrList = append(addrList, lis.Addr())
	}
	return
}
