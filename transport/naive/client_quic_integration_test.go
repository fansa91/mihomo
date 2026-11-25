package naive

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/transport/vmess"

	"github.com/metacubex/http"
	"github.com/metacubex/quic-go"
	"github.com/metacubex/quic-go/http3"
	mtls "github.com/metacubex/tls"
)

// TestH3TunnelRoundTrip is an end-to-end test of the naive h3 tunnel:
// a local HTTP/3 server implements the naive CONNECT + padding protocol and
// echoes padded payloads back. The client must establish the QUIC connection,
// send the CONNECT with padding header, parse the 200, and round-trip data
// through the padding framing.
func TestH3TunnelRoundTrip(t *testing.T) {
	cert := selfSignedCert(t)

	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	addr := udpConn.LocalAddr().String()

	tlsConf := &mtls.Config{
		Certificates: []mtls.Certificate{cert},
		NextProtos:   []string{http3.NextProtoH3},
	}
	quicLn, err := quic.Listen(udpConn, tlsConf, &quic.Config{MaxIdleTimeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}

	serverErr := make(chan error, 1)
	h3server := &http3.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodConnect {
				http.Error(w, "need CONNECT", http.StatusBadRequest)
				return
			}
			if r.Header.Get("padding") == "" {
				http.Error(w, "need padding", http.StatusBadRequest)
				return
			}
			// Signal padding capability and hijack the stream as a tunnel.
			w.Header().Set("Padding", GenerateResponsePaddingHeader())
			w.WriteHeader(http.StatusOK)
			stream := w.(http3.HTTPStreamer).HTTPStream()
			pr := NewPaddingReader(stream)
			pw := NewPaddingWriter(stream)
			buf := make([]byte, 4096)
			for {
				n, err := pr.Read(buf)
				if n > 0 {
					if _, werr := pw.Write(buf[:n]); werr != nil {
						return
					}
				}
				if err != nil {
					return
				}
			}
		}),
	}
	go func() { serverErr <- h3server.ServeListener(quicLn) }()
	t.Cleanup(func() {
		_ = h3server.Close()
		_ = udpConn.Close()
	})

	client, err := NewQUICClient(&QUICClientOptions{
		Dialer:         dialer.NewDialer(),
		Server:         addr,
		TLSConfig:      &vmess.TLSConfig{Host: "localhost", SkipCertVerify: true},
		RequestTimeout: 5 * time.Second,
		IdleTimeout:    10 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := client.Dial(ctx, "example.com:443")
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	payload := []byte("hello naive h3 tunnel over QUIC")
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

	// A second CONNECT stream must reuse the same QUIC connection.
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

func selfSignedCert(t *testing.T) mtls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "naive-h3-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return mtls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
	}
}
