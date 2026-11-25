package config

import (
	"encoding/json"

	"github.com/metacubex/mihomo/listener/sing"
)

type NaiveServer struct {
	Enable         bool              `yaml:"enable" json:"enable"`
	Listen         string            `yaml:"listen" json:"listen"`
	Users          map[string]string `yaml:"users" json:"users"`
	Certificate    string            `yaml:"certificate" json:"certificate"`
	PrivateKey     string            `yaml:"private-key" json:"private-key"`
	ClientAuthType string            `yaml:"client-auth-type" json:"client-auth-type,omitempty"`
	ClientAuthCert string            `yaml:"client-auth-cert" json:"client-auth-cert,omitempty"`
	EchKey         string            `yaml:"ech-key" json:"ech-key"`
	Fallback       string            `yaml:"fallback" json:"fallback,omitempty"`
	HTTP3          bool              `yaml:"http3" json:"http3,omitempty"`
	// IdleTimeout is the h2 tunnel idle timeout in seconds; 0 means the
	// default (24h), which keeps the server from closing a tunnel before the
	// client recycles it.
	IdleTimeout int            `yaml:"idle-timeout" json:"idle-timeout,omitempty"`
	MuxOption   sing.MuxOption `yaml:"mux-option" json:"mux-option,omitempty"`
}

func (t NaiveServer) String() string {
	b, _ := json.Marshal(t)
	return string(b)
}
