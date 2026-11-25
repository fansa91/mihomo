package inbound

import (
	"strings"

	C "github.com/metacubex/mihomo/constant"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/listener/juicity"
	"github.com/metacubex/mihomo/log"
)

type JuicityOption struct {
	BaseOption
	Users                 map[string]string `inbound:"users"`
	Certificate           string            `inbound:"certificate"`
	PrivateKey            string            `inbound:"private-key"`
	ClientAuthType        string            `inbound:"client-auth-type,omitempty"`
	ClientAuthCert        string            `inbound:"client-auth-cert,omitempty"`
	EchKey                string            `inbound:"ech-key,omitempty"`
	CongestionController  string            `inbound:"congestion-controller,omitempty"`
	MaxIdleTime           int               `inbound:"max-idle-time,omitempty"`
	MaxOpenStreams        int               `inbound:"max-open-streams,omitempty"`
	AuthenticationTimeout int               `inbound:"authentication-timeout,omitempty"`
	ALPN                  []string          `inbound:"alpn,omitempty"`
	CWND                  int               `inbound:"cwnd,omitempty"`
	BBRProfile            string            `inbound:"bbr-profile,omitempty"`
	MuxOption             MuxOption         `inbound:"mux-option,omitempty"`
}

func (o JuicityOption) Equal(config C.InboundConfig) bool {
	return optionToString(o) == optionToString(config)
}

type Juicity struct {
	*Base
	config *JuicityOption
	l      *juicity.Listener
	ts     LC.JuicityServer
}

func NewJuicity(options *JuicityOption) (*Juicity, error) {
	base, err := NewBase(&options.BaseOption)
	if err != nil {
		return nil, err
	}
	return &Juicity{
		Base:   base,
		config: options,
		ts: LC.JuicityServer{
			Enable:                true,
			Listen:                base.RawAddress(),
			Users:                 options.Users,
			Certificate:           options.Certificate,
			PrivateKey:            options.PrivateKey,
			ClientAuthType:        options.ClientAuthType,
			ClientAuthCert:        options.ClientAuthCert,
			EchKey:                options.EchKey,
			CongestionController:  options.CongestionController,
			MaxIdleTime:           options.MaxIdleTime,
			MaxOpenStreams:        options.MaxOpenStreams,
			AuthenticationTimeout: options.AuthenticationTimeout,
			ALPN:                  options.ALPN,
			CWND:                  options.CWND,
			BBRProfile:            options.BBRProfile,
			MuxOption:             options.MuxOption.Build(),
		},
	}, nil
}

// Config implements constant.InboundListener
func (t *Juicity) Config() C.InboundConfig {
	return t.config
}

// Address implements constant.InboundListener
func (t *Juicity) Address() string {
	var addrList []string
	if t.l != nil {
		for _, addr := range t.l.AddrList() {
			addrList = append(addrList, addr.String())
		}
	}
	return strings.Join(addrList, ",")
}

// Listen implements constant.InboundListener
func (t *Juicity) Listen(tunnel C.Tunnel) error {
	var err error
	t.l, err = juicity.New(t.ts, t.ListenConfig(), tunnel, t.Additions()...)
	if err != nil {
		return err
	}
	log.Infoln("Juicity[%s] proxy listening at: %s", t.Name(), t.Address())
	return nil
}

// Close implements constant.InboundListener
func (t *Juicity) Close() error {
	return t.l.Close()
}

var _ C.InboundListener = (*Juicity)(nil)
