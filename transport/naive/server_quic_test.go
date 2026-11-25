package naive

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/transport/socks5"
	"github.com/metacubex/mihomo/transport/vmess"

	"github.com/metacubex/http"
	"github.com/metacubex/quic-go/http3"
	mtls "github.com/metacubex/tls"
)

// startTestQUICServer starts a real QUICServer (the h3 inbound) on an ephemeral
// UDP port and returns its address. The handler echoes all tunnel traffic back.
func startTestQUICServer(t *testing.T, users map[string]string, fallback http.Handler) string {
	t.Helper()
	cert := selfSignedCert(t)

	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	tlsConf := &mtls.Config{
		Certificates: []mtls.Certificate{cert},
		NextProtos:   []string{http3.NextProtoH3},
	}
	qs := NewQUICServer(&QUICServerOptions{
		Users:     users,
		Fallback:  fallback,
		TLSConfig: tlsConf,
		Handler: func(conn net.Conn, addr socks5.Addr, user string) {
			defer conn.Close()
			buf := make([]byte, 4096)
			for {
				n, err := conn.Read(buf)
				if n > 0 {
					if _, werr := conn.Write(buf[:n]); werr != nil {
						return
					}
				}
				if err != nil {
					return
				}
			}
		},
	})
	go func() {
		_ = qs.Serve(udpConn)
	}()
	t.Cleanup(func() {
		_ = qs.Close()
		_ = udpConn.Close()
	})
	return udpConn.LocalAddr().String()
}

func newTestQUICClient(t *testing.T, server, user, pass string) *QUICClient {
	t.Helper()
	c, err := NewQUICClient(&QUICClientOptions{
		Dialer:         dialer.NewDialer(),
		Server:         server,
		TLSConfig:      &vmess.TLSConfig{Host: "localhost", SkipCertVerify: true},
		Username:       user,
		Password:       pass,
		RequestTimeout: 3 * time.Second,
		IdleTimeout:    5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// TestH3InboundTunnel validates the real h3 inbound against the h3 outbound:
// CONNECT + padding + auth, bidirectional data echo, and stream reuse.
func TestH3InboundTunnel(t *testing.T) {
	server := startTestQUICServer(t, map[string]string{"user1": "pass1"}, nil)
	client := newTestQUICClient(t, server, "user1", "pass1")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := client.Dial(ctx, "example.com:443")
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	payload := []byte("h3 inbound tunnel payload")
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("Write: %v", err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("Read: %v", err)
	}
	if string(got) != string(payload) {
		t.Fatalf("echo = %q, want %q", got, payload)
	}

	// second stream reuses the same QUIC connection
	conn2, err := client.Dial(ctx, "second.example:443")
	if err != nil {
		t.Fatalf("second Dial: %v", err)
	}
	defer conn2.Close()
	if _, err := conn2.Write(payload); err != nil {
		t.Fatalf("second Write: %v", err)
	}
	got2 := make([]byte, len(payload))
	if _, err := io.ReadFull(conn2, got2); err != nil {
		t.Fatalf("second Read: %v", err)
	}
	if string(got2) != string(payload) {
		t.Fatalf("second echo = %q", got2)
	}
}

// TestH3InboundWrongAuth verifies wrong credentials are rejected (no tunnel)
// instead of being accepted silently.
func TestH3InboundWrongAuth(t *testing.T) {
	server := startTestQUICServer(t, map[string]string{"user1": "pass1"}, nil)
	client := newTestQUICClient(t, server, "user1", "wrong")

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := client.Dial(ctx, "example.com:443")
	if err == nil {
		conn.Close()
		t.Fatal("expected auth failure, but tunnel was established")
	}
}

// TestH3InboundFallback verifies a plain GET (active probe) is answered by the
// configured fallback handler rather than a proxy-specific 400/407 response.
func TestH3InboundFallback(t *testing.T) {
	fallback := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "cover site")
	})
	server := startTestQUICServer(t, map[string]string{"user1": "pass1"}, fallback)

	rt := &http3.Transport{
		TLSClientConfig: &mtls.Config{InsecureSkipVerify: true},
	}
	defer rt.Close()

	req, err := http.NewRequest(http.MethodGet, "https://"+server+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatalf("probe GET: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(body) != "cover site" {
		t.Fatalf("probe response = %d %q, want 200 cover site", resp.StatusCode, body)
	}
}
