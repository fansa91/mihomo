package naive

import (
	"bytes"
	"io"
	"testing"
)

func TestPaddingWriterReader(t *testing.T) {
	var buf bytes.Buffer

	writer := NewPaddingWriter(&buf)
	payload1 := []byte("hello naive proxy")
	payload2 := bytes.Repeat([]byte("x"), 70000) // spans multiple frames
	if n, err := writer.Write(payload1); err != nil || n != len(payload1) {
		t.Fatalf("write1: n=%d err=%v", n, err)
	}
	if n, err := writer.Write(payload2); err != nil || n != len(payload2) {
		t.Fatalf("write2: n=%d err=%v", n, err)
	}
	// 9th write must not be padded
	if _, err := writer.Write([]byte("plain")); err != nil {
		t.Fatal(err)
	}

	reader := NewPaddingReader(&buf)
	got1 := make([]byte, len(payload1))
	if _, err := io.ReadFull(reader, got1); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got1, payload1) {
		t.Fatalf("payload1 mismatch")
	}
	got2 := make([]byte, len(payload2))
	if _, err := io.ReadFull(reader, got2); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got2, payload2) {
		t.Fatalf("payload2 mismatch")
	}
	rest, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if string(rest) != "plain" {
		t.Fatalf("rest = %q", rest)
	}
}

func TestPaddingHeader(t *testing.T) {
	for i := 0; i < 200; i++ {
		header := GeneratePaddingHeader()
		if len(header) < 16 || len(header) > 32 {
			t.Fatalf("unexpected padding header length %d", len(header))
		}
		for j := 0; j < 16; j++ {
			if !bytes.ContainsRune([]byte(PaddingHeaderAlphabet), rune(header[j])) {
				t.Fatalf("byte %d not in HPACK alphabet: %q", j, header[j])
			}
		}
		for j := 16; j < len(header); j++ {
			if header[j] != '~' {
				t.Fatalf("byte %d is not '~'", j)
			}
		}
	}
}
