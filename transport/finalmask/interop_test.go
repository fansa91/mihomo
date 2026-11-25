package finalmask

import (
	"bytes"
	"crypto/rand"
	"testing"

	"golang.org/x/crypto/blake2b"
)

// The helpers below are a direct transcription of Xray's salamander
// implementation (transport/internet/finalmask/salamander). They exist only to
// prove that the wire format is identical in both directions: a packet produced
// here must decode there and vice versa. Keep them byte-for-byte faithful when
// updating.

func xrayObfuscate(psk, payload []byte) []byte {
	out := make([]byte, 8+len(payload))
	if _, err := rand.Read(out[:8]); err != nil {
		panic(err)
	}
	keyInput := make([]byte, 0, len(psk)+8)
	keyInput = append(keyInput, psk...)
	keyInput = append(keyInput, out[:8]...)
	key := blake2b.Sum256(keyInput)
	for i, c := range payload {
		out[8+i] = c ^ key[i%blake2b.Size256]
	}
	return out
}

func xrayDeobfuscate(psk, in []byte) []byte {
	if len(in) <= 8 {
		return nil
	}
	keyInput := make([]byte, 0, len(psk)+8)
	keyInput = append(keyInput, psk...)
	keyInput = append(keyInput, in[:8]...)
	key := blake2b.Sum256(keyInput)
	out := make([]byte, len(in)-8)
	for i, c := range in[8:] {
		out[i] = c ^ key[i%blake2b.Size256]
	}
	return out
}

func TestSalamanderInteropWithXray(t *testing.T) {
	psk := []byte("interop-test-password")
	payload := []byte("a QUIC Initial packet would live here")

	// Our encoder -> Xray decoder.
	obfs, err := newSalamanderObfuscator(psk)
	if err != nil {
		t.Fatal(err)
	}
	ours := make([]byte, len(payload)+salamanderSaltLen)
	obfs.obfuscate(payload, ours)
	if got := xrayDeobfuscate(psk, ours); !bytes.Equal(got, payload) {
		t.Fatalf("Xray could not decode our packet: %q", got)
	}

	// Xray encoder -> our decoder.
	theirs := xrayObfuscate(psk, payload)
	if got := obfs.deobfuscate(theirs); !bytes.Equal(got, payload) {
		t.Fatalf("we could not decode Xray's packet: %q", got)
	}
}

func TestFragmentMatchesXrayRecordLayout(t *testing.T) {
	// Xray rebuilds the 5-byte TLS record header for every segment; check that
	// a 100-byte record split at 40-byte lengths produces exactly the layout
	// its code produces: same type/version, per-segment length, contiguous
	// payload.
	m, err := Parse(&Option{TCP: []MaskOption{{
		Type: "fragment",
		Settings: map[string]any{
			"packets":  "tlshello",
			"length":   "40-40",
			"delay":    "1-1",
			"maxSplit": "0",
		},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	body := bytes.Repeat([]byte{0x5A}, 100)
	record := append([]byte{0x16, 0x03, 0x01, 0, byte(len(body))}, body...)

	raw := &fakeConn{}
	conn, _ := m.WrapConn(raw)
	if _, err := conn.Write(record); err != nil {
		t.Fatal(err)
	}

	var sizes []int
	var joined []byte
	for _, w := range raw.writes {
		if w[0] != 0x16 || w[1] != 0x03 || w[2] != 0x01 {
			t.Fatalf("segment lost the record header: %x", w[:3])
		}
		l := int(w[3])<<8 | int(w[4])
		sizes = append(sizes, l)
		joined = append(joined, w[5:]...)
	}
	if !bytes.Equal(joined, body) {
		t.Fatal("payload mismatch after reassembly")
	}
	// 100 bytes at 40 per segment -> 40, 40, 20.
	want := []int{40, 40, 20}
	if len(sizes) != len(want) {
		t.Fatalf("segments = %v, want %v", sizes, want)
	}
	for i := range want {
		if sizes[i] != want[i] {
			t.Fatalf("segments = %v, want %v", sizes, want)
		}
	}
}
