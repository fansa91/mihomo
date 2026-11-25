package inbound

import (
	"strings"

	C "github.com/metacubex/mihomo/constant"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/listener/naive"
	"github.com/metacubex/mihomo/log"
)

type NaiveOption struct {
	BaseOption
	Users          map[string]string `inbound:"users"`
	Certificate    string            `inbound:"certificate"`
	PrivateKey     string            `inbound:"private-key"`
	ClientAuthType string            `inbound:"client-auth-type,omitempty"`
	ClientAuthCert string            `inbound:"client-auth-cert,omitempty"`
	EchKey         string            `inbound:"ech-key,omitempty"`
	Fallback       string            `inbound:"fallback,omitempty"`
	HTTP3          bool              `inbound:"http3,omitempty"`
	MuxOption      MuxOption         `inbound:"mux-option,omitempty"`
}

func (o NaiveOption) Equal(config C.InboundConfig) bool {
	return optionToString(o) == optionToString(config)
}

type Naive struct {
	*Base
	config *NaiveOption
	l      *naive.Listener
	ts     LC.NaiveServer
}

func NewNaive(options *NaiveOption) (*Naive, error) {
	base, err := NewBase(&options.BaseOption)
	if err != nil {
		return nil, err
	}
	return &Naive{
		Base:   base,
		config: options,
		ts: LC.NaiveServer{
			Enable:         true,
			Listen:         base.RawAddress(),
			Users:          options.Users,
			Certificate:    options.Certificate,
			PrivateKey:     options.PrivateKey,
			ClientAuthType: options.ClientAuthType,
			ClientAuthCert: options.ClientAuthCert,
			EchKey:         options.EchKey,
			Fallback:       options.Fallback,
			HTTP3:          options.HTTP3,
			MuxOption:      options.MuxOption.Build(),
		},
	}, nil
}

// Config implements constant.InboundListener
func (t *Naive) Config() C.InboundConfig {
	return t.config
}

// Address implements constant.InboundListener
func (t *Naive) Address() string {
	var addrList []string
	if t.l != nil {
		for _, addr := range t.l.AddrList() {
			addrList = append(addrList, addr.String())
		}
	}
	return strings.Join(addrList, ",")
}

// Listen implements constant.InboundListener
func (t *Naive) Listen(tunnel C.Tunnel) error {
	var err error
	t.l, err = naive.New(t.ts, t.ListenConfig(), tunnel, t.Additions()...)
	if err != nil {
		return err
	}
	log.Infoln("Naive[%s] proxy listening at: %s", t.Name(), t.Address())
	return nil
}

// Close implements constant.InboundListener
func (t *Naive) Close() error {
	return t.l.Close()
}

var _ C.InboundListener = (*Naive)(nil)
