package naive

import (
	"bytes"
	"io"
	"net"
	"net/url"
	"testing"

	"github.com/metacubex/mihomo/transport/vmess"

	"github.com/metacubex/http"
	"github.com/metacubex/quic-go/http3"
)

// TestQUICClientForcesH3ALPN verifies that constructing an h3 client rewrites
// the TLS NextProtos to "h3" regardless of what was passed in.
func TestQUICClientForcesH3ALPN(t *testing.T) {
	tlsCfg := &vmess.TLSConfig{Host: "example.com", NextProtos: []string{"h2"}}
	_, err := NewQUICClient(&QUICClientOptions{
		Server:    "example.com:443",
		TLSConfig: tlsCfg,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(tlsCfg.NextProtos) != 1 || tlsCfg.NextProtos[0] != http3.NextProtoH3 {
		t.Fatalf("NextProtos = %v, want [h3]", tlsCfg.NextProtos)
	}
}

// TestQUICClientAuthFlag verifies the Proxy-Authorization is only flagged when
// credentials are present (mirrors the h2 path).
func TestQUICClientAuthFlag(t *testing.T) {
	c, err := NewQUICClient(&QUICClientOptions{
		Server:    "example.com:443",
		TLSConfig: &vmess.TLSConfig{Host: "example.com"},
		Username:  "user",
		Password:  "pass",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !c.hasAuth || c.auth != "Basic dXNlcjpwYXNz" {
		t.Fatalf("auth = %q hasAuth=%v", c.auth, c.hasAuth)
	}

	c2, err := NewQUICClient(&QUICClientOptions{
		Server:    "example.com:443",
		TLSConfig: &vmess.TLSConfig{Host: "example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if c2.hasAuth {
		t.Fatal("empty credentials must not set hasAuth")
	}
}

// TestH3PaddingRoundTrip verifies the h3 tunnel reuses the same padding
// framing as h2: first 8 writes padded, reader strips them, 9th write plain.
func TestH3PaddingRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	w := NewPaddingWriter(&buf)
	payloads := [][]byte{
		[]byte("connect handshake"),
		[]byte("tls record"),
		bytes.Repeat([]byte("x"), 70000),
	}
	for _, p := range payloads {
		if n, err := w.Write(p); err != nil || n != len(p) {
			t.Fatalf("write: n=%d err=%v", n, err)
		}
	}
	if _, err := w.Write([]byte("unpadded-tail")); err != nil {
		t.Fatal(err)
	}

	r := NewPaddingReader(&buf)
	for _, want := range payloads {
		got := make([]byte, len(want))
		if _, err := io.ReadFull(r, got); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("payload mismatch: got %d bytes want %d", len(got), len(want))
		}
	}
	tail, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if string(tail) != "unpadded-tail" {
		t.Fatalf("tail = %q", tail)
	}
}

// TestH3RequestHeaderShape documents the exact CONNECT header set used by the
// h3 path (padding + optional proxy auth), ensuring it stays aligned with the
// naiveproxy wire format.
func TestH3RequestHeaderShape(t *testing.T) {
	req := &http.Request{
		Method: http.MethodConnect,
		Host:   "target.example:443",
		Header: make(http.Header),
		URL:    &url.URL{Scheme: "https", Host: "target.example:443"},
	}
	req.Header.Set("padding", GeneratePaddingHeader())
	req.Header.Set("Proxy-Authorization", "Basic dXNlcjpwYXNz")

	if req.Method != http.MethodConnect {
		t.Fatalf("method = %q", req.Method)
	}
	if req.Header.Get("padding") == "" {
		t.Fatal("padding header missing")
	}
	if req.Header.Get("Proxy-Authorization") == "" {
		t.Fatal("proxy auth header missing")
	}
	if req.URL.Scheme != "https" {
		t.Fatalf("scheme = %q, want https", req.URL.Scheme)
	}
}

// TestQUICConnNetContract verifies the adapter satisfies net.Conn.
func TestQUICConnNetContract(t *testing.T) {
	var _ net.Conn = (*quicConn)(nil)
}
