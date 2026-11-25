package outbound

import (
	"crypto/ecdh"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"

	tlsC "github.com/metacubex/mihomo/component/tls"
)

type RealityOptions struct {
	PublicKey string `proxy:"public-key"`
	ShortID   string `proxy:"short-id,omitempty"`

	// SupportX25519MLKEM768 is tri-state: nil means "follow the default", which
	// is enabled since Xray v26.9.8 servers require the hybrid key share.
	// An explicit false still disables it, so old configs keep working.
	SupportX25519MLKEM768 *bool `proxy:"support-x25519mlkem768,omitempty"`
	// DisableX25519MLKEM768 is an explicit opt-out alias for support-x25519mlkem768: false.
	DisableX25519MLKEM768 bool `proxy:"disable-x25519mlkem768,omitempty"`
}

func (o RealityOptions) Parse() (*tlsC.RealityConfig, error) {
	if o.PublicKey != "" {
		config := new(tlsC.RealityConfig)
		switch {
		case o.DisableX25519MLKEM768:
			config.SupportX25519MLKEM768 = false
		case o.SupportX25519MLKEM768 != nil:
			config.SupportX25519MLKEM768 = *o.SupportX25519MLKEM768
		default:
			config.SupportX25519MLKEM768 = true
		}

		const x25519ScalarSize = 32
		publicKey, err := base64.RawURLEncoding.DecodeString(o.PublicKey)
		if err != nil || len(publicKey) != x25519ScalarSize {
			return nil, errors.New("invalid REALITY public key")
		}
		config.PublicKey, err = ecdh.X25519().NewPublicKey(publicKey)
		if err != nil {
			return nil, fmt.Errorf("fail to create REALITY public key: %w", err)
		}

		n := hex.DecodedLen(len(o.ShortID))
		if n > tlsC.RealityMaxShortIDLen {
			return nil, errors.New("invalid REALITY short id")
		}
		n, err = hex.Decode(config.ShortID[:], []byte(o.ShortID))
		if err != nil || n > tlsC.RealityMaxShortIDLen {
			return nil, errors.New("invalid REALITY short ID")
		}

		return config, nil
	}
	return nil, nil
}
