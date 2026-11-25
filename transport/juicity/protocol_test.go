package juicity

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"

	"github.com/metacubex/mihomo/transport/socks5"
)

func TestRequestHeaderRoundTrip(t *testing.T) {
	cases := []string{
		"example.com:443",
		"1.2.3.4:53",
		"[2001:db8::1]:8080",
	}
	for _, c := range cases {
		addr := socks5.ParseAddr(c)
		if len(addr) == 0 {
			t.Fatalf("parse %s", c)
		}
		var buf bytes.Buffer
		if err := WriteRequestHeader(&buf, NetworkTCP, addr); err != nil {
			t.Fatal(err)
		}
		network, got, err := ReadRequestHeader(&buf)
		if err != nil {
			t.Fatal(err)
		}
		if network != NetworkTCP {
			t.Fatalf("network = %d", network)
		}
		if got.String() != c {
			t.Fatalf("addr = %s, want %s", got.String(), c)
		}
	}
}

func TestSealOpenUDP(t *testing.T) {
	psk := make([]byte, underlayKeyLen)
	_, _ = rand.Read(psk)
	salt := newUnderlaySalt()
	if salt[0] != 0 || salt[1] != 0 {
		t.Fatal("salt prefix must be zero")
	}
	payload := []byte("dns query payload")
	sealed, err := sealUnderlay(psk, salt, payload)
	if err != nil {
		t.Fatal(err)
	}
	if len(sealed) != UnderlaySaltLen+len(payload)+16 {
		t.Fatalf("sealed length = %d", len(sealed))
	}
	got, gotSalt, err := openUnderlay(psk, sealed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload mismatch: %q", got)
	}
	if !bytes.Equal(gotSalt, salt) {
		t.Fatal("salt mismatch")
	}
	// Wrong key must fail authentication.
	wrong := make([]byte, underlayKeyLen)
	if _, _, err = openUnderlay(wrong, sealed); err == nil {
		t.Fatal("expected auth failure")
	}
}

func TestUnderlayAuthRoundTrip(t *testing.T) {
	auth := &UnderlayAuth{
		IV:   newUnderlaySalt(),
		Psk:  bytes.Repeat([]byte{7}, underlayKeyLen),
		Addr: socks5.ParseAddr("example.com:443"),
	}
	var buf bytes.Buffer
	if err := auth.Pack(&buf); err != nil {
		t.Fatal(err)
	}
	got, err := ReadUnderlayAuth(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.IV, auth.IV) || !bytes.Equal(got.Psk, auth.Psk) || got.Addr.String() != auth.Addr.String() {
		t.Fatal("underlay auth mismatch")
	}
	if _, err = io.ReadAll(&buf); err != nil {
		t.Fatal(err)
	}
}
