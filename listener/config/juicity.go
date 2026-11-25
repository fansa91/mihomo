package config

import (
	"encoding/json"

	"github.com/metacubex/mihomo/listener/sing"
)

type JuicityServer struct {
	Enable                bool              `yaml:"enable" json:"enable"`
	Listen                string            `yaml:"listen" json:"listen"`
	Users                 map[string]string `yaml:"users" json:"users"`
	Certificate           string            `yaml:"certificate" json:"certificate"`
	PrivateKey            string            `yaml:"private-key" json:"private-key"`
	ClientAuthType        string            `yaml:"client-auth-type" json:"client-auth-type,omitempty"`
	ClientAuthCert        string            `yaml:"client-auth-cert" json:"client-auth-cert,omitempty"`
	EchKey                string            `yaml:"ech-key" json:"ech-key"`
	CongestionController  string            `yaml:"congestion-controller" json:"congestion-controller,omitempty"`
	MaxIdleTime           int               `yaml:"max-idle-time" json:"max-idle-time,omitempty"`
	MaxOpenStreams        int               `yaml:"max-open-streams" json:"max-open-streams,omitempty"`
	AuthenticationTimeout int               `yaml:"authentication-timeout" json:"authentication-timeout,omitempty"`
	ALPN                  []string          `yaml:"alpn" json:"alpn,omitempty"`
	CWND                  int               `yaml:"cwnd" json:"cwnd,omitempty"`
	BBRProfile            string            `yaml:"bbr-profile" json:"bbr-profile,omitempty"`
	MuxOption             sing.MuxOption    `yaml:"mux-option" json:"mux-option,omitempty"`
}

func (t JuicityServer) String() string {
	b, _ := json.Marshal(t)
	return string(b)
}
