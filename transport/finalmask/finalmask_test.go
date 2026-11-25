package finalmask

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"testing"
)

type fakeConn struct {
	net.Conn
	writes [][]byte
	read   bytes.Buffer
}

func (c *fakeConn) Write(p []byte) (int, error) {
	c.writes = append(c.writes, append([]byte(nil), p...))
	return len(p), nil
}
func (c *fakeConn) Read(p []byte) (int, error) { return c.read.Read(p) }
func (c *fakeConn) Close() error               { return nil }
func (c *fakeConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 1234}
}
func (c *fakeConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(198, 51, 100, 7), Port: 443}
}

func TestFragmentTLSHelloSplitsRecord(t *testing.T) {
	m, err := Parse(&Option{TCP: []MaskOption{{
		Type: "fragment",
		Settings: map[string]any{
			"packets":  "tlshello",
			"length":   "10-10",
			"delay":    "1-1",
			"maxSplit": "0",
		},
	}}})
	if err != nil {
		t.Fatal(err)
	}

	body := bytes.Repeat([]byte{0xAB}, 50)
	record := append([]byte{0x16, 0x03, 0x01, 0, byte(len(body))}, body...)

	raw := &fakeConn{}
	conn, err := m.WrapConn(raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(record); err != nil {
		t.Fatal(err)
	}

	if len(raw.writes) < 2 {
		t.Fatalf("expected the record to be split, got %d write(s)", len(raw.writes))
	}
	var joined []byte
	for i, w := range raw.writes {
		if w[0] != 0x16 {
			t.Fatalf("write %d lost the TLS record type: %x", i, w[:5])
		}
		declared := int(w[3])<<8 | int(w[4])
		if declared != len(w)-5 {
			t.Fatalf("write %d declares %d payload bytes, has %d", i, declared, len(w)-5)
		}
		joined = append(joined, w[5:]...)
	}
	if !bytes.Equal(joined, body) {
		t.Fatal("reassembled payload differs from the original")
	}
}

func TestFragmentPassesNonTLSAndLaterWrites(t *testing.T) {
	m, err := Parse(&Option{TCP: []MaskOption{{
		Type:     "fragment",
		Settings: map[string]any{"packets": "tlshello", "length": "10-10"},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	raw := &fakeConn{}
	conn, _ := m.WrapConn(raw)

	// Not a handshake record: must go out untouched.
	if _, err := conn.Write([]byte("GET / HTTP/1.1\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	if len(raw.writes) != 1 || !bytes.HasPrefix(raw.writes[0], []byte("GET ")) {
		t.Fatalf("non-TLS write was altered: %q", raw.writes)
	}

	record := append([]byte{0x16, 0x03, 0x01, 0, 20}, bytes.Repeat([]byte{1}, 20)...)
	raw.writes = nil
	conn.Write(record)
	if len(raw.writes) != 1 {
		t.Fatalf("tlshello must only touch the first write, got %d writes", len(raw.writes))
	}
}

func TestProxyProtocolV1(t *testing.T) {
	conn := &fakeConn{}
	mask, err := newProxyProtocolMask(map[string]any{"version": 1})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mask.WrapConnClient(conn); err != nil {
		t.Fatal(err)
	}
	got := string(conn.writes[0])
	want := "PROXY TCP4 192.0.2.1 198.51.100.7 1234 443\r\n"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestProxyProtocolV2(t *testing.T) {
	conn := &fakeConn{}
	mask, err := newProxyProtocolMask(nil) // default is v2
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mask.WrapConnClient(conn); err != nil {
		t.Fatal(err)
	}
	h := conn.writes[0]
	if len(h) != 28 {
		t.Fatalf("header length = %d, want 28", len(h))
	}
	if !bytes.Equal(h[:12], proxyV2Signature) {
		t.Fatalf("bad signature: %x", h[:12])
	}
	if h[12] != 0x21 {
		t.Fatalf("ver/cmd = %#x, want 0x21", h[12])
	}
	if h[13] != 0x11 {
		t.Fatalf("family = %#x, want 0x11 (TCP over IPv4)", h[13])
	}
	if l := binary.BigEndian.Uint16(h[14:16]); l != 12 {
		t.Fatalf("address block length = %d, want 12", l)
	}
	if !bytes.Equal(h[16:20], net.IPv4(192, 0, 2, 1).To4()) {
		t.Fatalf("source address = %v", h[16:20])
	}
	if p := binary.BigEndian.Uint16(h[24:26]); p != 1234 {
		t.Fatalf("source port = %d, want 1234", p)
	}
	if p := binary.BigEndian.Uint16(h[26:28]); p != 443 {
		t.Fatalf("dest port = %d, want 443", p)
	}
}

func TestSalamanderRoundTrip(t *testing.T) {
	obfs, err := newSalamanderObfuscator([]byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("hello salamander")
	out := make([]byte, len(payload)+salamanderSaltLen)
	if n := obfs.obfuscate(payload, out); n != len(payload)+salamanderSaltLen {
		t.Fatalf("obfuscate returned %d", n)
	}
	if bytes.Contains(out[salamanderSaltLen:], payload) {
		t.Fatal("payload is not obfuscated")
	}

	// A second obfuscation of the same payload must use a fresh salt.
	out2 := make([]byte, len(payload)+salamanderSaltLen)
	obfs.obfuscate(payload, out2)
	if bytes.Equal(out[:salamanderSaltLen], out2[:salamanderSaltLen]) {
		t.Fatal("salt repeated")
	}

	plain := obfs.deobfuscate(out)
	if !bytes.Equal(plain, payload) {
		t.Fatalf("round trip mismatch: %q", plain)
	}

	wrong, _ := newSalamanderObfuscator([]byte("wrong"))
	if bytes.Equal(wrong.deobfuscate(out), payload) {
		t.Fatal("wrong password decrypted successfully")
	}
}

func TestSalamanderRequiresPassword(t *testing.T) {
	if _, err := newSalamanderMask(map[string]any{}); err == nil {
		t.Fatal("expected an error for a missing password")
	}
	if _, err := newSalamanderMask(map[string]any{"password": "ab"}); err == nil {
		t.Fatal("expected an error for a too short password")
	}
	if _, err := newSalamanderMask(map[string]any{
		"password":   "secret",
		"packetSize": "512-1200",
	}); err == nil {
		t.Fatal("gecko mode should be reported as unsupported")
	}
}

func TestParseErrorsAndEmpty(t *testing.T) {
	if m, err := Parse(nil); err != nil || m != nil {
		t.Fatalf("nil option: mask=%v err=%v", m, err)
	}
	if m, err := Parse(&Option{}); err != nil || m != nil {
		t.Fatalf("empty option: mask=%v err=%v", m, err)
	}
	if _, err := Parse(&Option{TCP: []MaskOption{{Type: "nope"}}}); err == nil {
		t.Fatal("unknown tcp mask accepted")
	}
	if _, err := Parse(&Option{UDP: []MaskOption{{Type: "nope"}}}); err == nil {
		t.Fatal("unknown udp mask accepted")
	}
}

func TestParseAcceptsKebabCase(t *testing.T) {
	m, err := Parse(&Option{TCP: []MaskOption{{
		Type:     "FRAGMENT",
		Settings: map[string]any{"packets": "tlshello", "length": "100-200", "max-split": "2"},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	if m == nil || m.String() != "tcp:fragment" {
		t.Fatalf("unexpected mask: %v", m)
	}
	f := m.tcp[0].(*fragmentMask)
	if f.maxSplitMax != 2 {
		t.Fatalf("max-split = %d, want 2", f.maxSplitMax)
	}
}

func TestWrapConnChainOrder(t *testing.T) {
	// proxy-protocol writes its header immediately; fragment wraps outside it,
	// so with the default order the header must be written first and, in
	// tlshello mode, be left alone.
	m, err := Parse(&Option{TCP: []MaskOption{
		{Type: "proxy-protocol", Settings: map[string]any{"version": 1}},
		{Type: "fragment", Settings: map[string]any{"packets": "tlshello", "length": "10-10"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	raw := &fakeConn{}
	conn, err := m.WrapConn(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw.writes) != 1 || !bytes.HasPrefix(raw.writes[0], []byte("PROXY ")) {
		t.Fatalf("proxy header not written first: %q", raw.writes)
	}
	if _, ok := conn.(*fragmentConn); !ok {
		t.Fatalf("outermost mask should be fragment, got %T", conn)
	}
}

var _ io.Writer = (*fragmentConn)(nil)

func TestFragmentMergeWithoutDelay(t *testing.T) {
	// With no delay Xray gathers the split records and writes them at once;
	// the segmentation is left to the kernel.
	m, err := Parse(&Option{TCP: []MaskOption{{
		Type:     "fragment",
		Settings: map[string]any{"packets": "tlshello", "length": "10-10"},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	body := bytes.Repeat([]byte{0xCD}, 30)
	record := append([]byte{0x16, 0x03, 0x01, 0, byte(len(body))}, body...)
	raw := &fakeConn{}
	conn, _ := m.WrapConn(raw)
	if _, err := conn.Write(record); err != nil {
		t.Fatal(err)
	}
	if len(raw.writes) != 1 {
		t.Fatalf("merge mode should produce one write, got %d", len(raw.writes))
	}
	// The merged buffer still contains one record header per segment, so it is
	// longer than the original but carries the same payload.
	out := raw.writes[0]
	var joined []byte
	records := 0
	for len(out) > 5 {
		l := int(out[3])<<8 | int(out[4])
		if out[0] != 0x16 || 5+l > len(out) {
			t.Fatalf("malformed record at offset %d: %x", records, out[:minInt(5, len(out))])
		}
		joined = append(joined, out[5:5+l]...)
		out = out[5+l:]
		records++
	}
	if records < 2 {
		t.Fatalf("expected several records, got %d", records)
	}
	if !bytes.Equal(joined, body) {
		t.Fatal("merged payload differs from the original")
	}
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
