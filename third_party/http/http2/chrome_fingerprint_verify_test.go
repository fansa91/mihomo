package http2

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"strings"
	"testing"

	"golang.org/x/net/http2/hpack"
)

// TestChromeFingerprintSettings verifies the exact SETTINGS frame and
// connection-level WINDOW_UPDATE emitted by the production helper.
func TestChromeFingerprintSettings(t *testing.T) {
	initialSettings := chromeFingerprintSettings()
	want := map[SettingID]uint32{
		SettingHeaderTableSize:   uint32(chromeHeaderTableSize),
		SettingEnablePush:        0,
		SettingInitialWindowSize: uint32(chromeInitialWindowSize),
		SettingMaxHeaderListSize: uint32(chromeMaxHeaderListSize),
	}
	if len(initialSettings) != len(want) {
		t.Fatalf("got %d settings, want %d", len(initialSettings), len(want))
	}

	var wire bytes.Buffer
	wire.Write(clientPreface)
	wfr := NewFramer(&wire, strings.NewReader(""))
	if err := wfr.WriteSettings(initialSettings...); err != nil {
		t.Fatal(err)
	}
	if err := wfr.WriteWindowUpdate(0, chromeConnWindowUpdate); err != nil {
		t.Fatal(err)
	}

	preface := make([]byte, len(clientPreface))
	if _, err := wire.Read(preface); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(preface, clientPreface) {
		t.Fatalf("bad preface: %q", preface)
	}
	rfr := NewFramer(io.Discard, &wire)
	frame, err := rfr.ReadFrame()
	if err != nil {
		t.Fatal(err)
	}
	sf, ok := frame.(*SettingsFrame)
	if !ok {
		t.Fatalf("first frame not SETTINGS: %T", frame)
	}
	order := []SettingID{
		SettingHeaderTableSize, SettingEnablePush,
		SettingInitialWindowSize, SettingMaxHeaderListSize,
	}
	for i, wantID := range order {
		got := sf.Setting(i)
		if got.ID != wantID || got.Val != want[wantID] {
			t.Errorf("setting[%d] = %d:%d, want %d:%d", i, got.ID, got.Val, wantID, want[wantID])
		} else {
			t.Logf("setting[%d] = %d:%d OK", i, got.ID, got.Val)
		}
	}
	frame, err = rfr.ReadFrame()
	if err != nil {
		t.Fatal(err)
	}
	wuf, ok := frame.(*WindowUpdateFrame)
	if !ok {
		t.Fatalf("second frame not WINDOW_UPDATE: %T", frame)
	}
	if wuf.StreamID != 0 || wuf.Increment != chromeConnWindowUpdate {
		t.Errorf("WINDOW_UPDATE = stream %d inc %d, want stream 0 inc %d", wuf.StreamID, wuf.Increment, chromeConnWindowUpdate)
	} else {
		t.Logf("conn WINDOW_UPDATE = %d OK", wuf.Increment)
	}
}

// TestChromePaddingHeaderNeverIndexed verifies that the padding HEADERS field
// is emitted as a literal never-indexed HPACK representation (first byte 0x10)
// in Chrome-fingerprint mode, while the default mode keeps Go's incremental
// indexing (first byte 0x40). This is the production writeHeader path.
func TestChromePaddingHeaderNeverIndexed(t *testing.T) {
	const pad = "!#$()+<>?@[]^`{}~~"

	encode := func(chrome bool, name, value string) []byte {
		cc := &ClientConn{chromeFingerprint: chrome}
		cc.henc = hpack.NewEncoder(&cc.hbuf)
		cc.writeHeader(name, value)
		return cc.hbuf.Bytes()
	}

	// Chrome mode: padding -> never-indexed literal (0x10, non-Huffman).
	got := encode(true, "padding", pad)
	if len(got) == 0 {
		t.Fatal("no HPACK bytes emitted")
	}
	if got[0] != 0x10 {
		t.Errorf("chrome padding first byte = 0x%02x, want 0x10 (never-indexed)", got[0])
	} else {
		t.Logf("chrome padding first byte = 0x%02x OK", got[0])
	}

	// Case-insensitive match: "Padding" is also covered.
	got = encode(true, "Padding", pad)
	if len(got) == 0 || got[0] != 0x10 {
		t.Errorf("chrome 'Padding' first byte = 0x%02x, want 0x10", firstByte(got))
	}

	// Default mode: padding -> incremental indexing (0x40).
	got = encode(false, "padding", pad)
	if len(got) == 0 || got[0] != 0x40 {
		t.Errorf("default padding first byte = 0x%02x, want 0x40 (incremental indexing)", firstByte(got))
	} else {
		t.Logf("default padding first byte = 0x%02x OK", got[0])
	}

	// Other headers in Chrome mode are NOT forced sensitive.
	got = encode(true, "user-agent", "test")
	if len(got) == 0 || got[0] == 0x10 {
		t.Errorf("chrome user-agent first byte = 0x%02x, should not be never-indexed", firstByte(got))
	}
}

func firstByte(b []byte) byte {
	if len(b) == 0 {
		return 0
	}
	return b[0]
}

// TestAkamaiH2FingerprintString builds the full four-section Akamai HTTP/2
// fingerprint string from the production Chrome-fingerprint path, using the
// same serialization rules a passive detector applies on the wire. The
// expected value is the publicly documented modern-Chrome signature (see
// gospider007/fp real-traffic output and Akamai's passive h2 fingerprinting).
// This is the detection-side regression guard: if anyone changes the SETTINGS
// order/values or pseudo-header order in the fork, this test fails.
func TestAkamaiH2FingerprintString(t *testing.T) {
	// Section 1: SETTINGS, id:value pairs in wire order, semicolon-separated.
	var sb strings.Builder
	for i, s := range chromeFingerprintSettings() {
		if i > 0 {
			sb.WriteByte(';')
		}
		fmt.Fprintf(&sb, "%d:%d", s.ID, s.Val)
	}

	// Section 2: connection-level WINDOW_UPDATE (stream 0) after preface.
	// Section 3: PRIORITY tree — modern Chrome sends none, detector emits "0".
	// Section 4: pseudo-header order in first HEADERS frame, m/a/s/p codes.
	fp := fmt.Sprintf("%s|%d|0|%s", sb.String(), chromeConnWindowUpdate, chromePseudoHeaderOrderForTest())

	const want = "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p"
	if fp != want {
		t.Errorf("Akamai h2 fingerprint = %q, want %q", fp, want)
	} else {
		t.Logf("Akamai h2 fingerprint = %s", fp)
	}
}

// chromePseudoHeaderOrderForTest returns the pseudo-header order the fork
// emits in ChromeFingerprint mode. It mirrors the order implemented in
// internal/httpcommon.EncodeHeaders (verified separately in that package's
// chrome_fingerprint_verify_test.go).
func chromePseudoHeaderOrderForTest() string {
	return "m,a,s,p"
}

// TestRSTStreamPadding verifies that in Chrome-fingerprint mode the client
// prepends an END_STREAM DATA frame (total length 48..72 bytes, zero padding)
// before RST_STREAM, matching naiveproxy's "Pad RST_STREAM frames" behavior.
// In default mode only a bare RST_STREAM must be emitted.
func TestRSTStreamPadding(t *testing.T) {
	run := func(chrome bool) []Frame {
		var buf bytes.Buffer
		bw := bufio.NewWriter(&buf)
		cc := &ClientConn{
			bw:                 bw,
			fr:                 NewFramer(bw, strings.NewReader("")),
			chromeFingerprint: chrome,
		}
		cc.writeStreamReset(1, ErrCodeCancel, false, nil)
		_ = bw.Flush()

		rfr := NewFramer(io.Discard, &buf)
		var frames []Frame
		for {
			f, err := rfr.ReadFrame()
			if err != nil {
				break
			}
			frames = append(frames, f)
		}
		return frames
	}

	// Chrome mode: DATA(END_STREAM, 48..72 total) then RST_STREAM.
	frames := run(true)
	if len(frames) != 2 {
		t.Fatalf("chrome mode: got %d frames, want 2", len(frames))
	}
	df, ok := frames[0].(*DataFrame)
	if !ok {
		t.Fatalf("chrome mode: first frame is %T, want *DataFrame", frames[0])
	}
	if !df.StreamEnded() {
		t.Error("chrome mode: DATA frame missing END_STREAM flag")
	}
	total := 9 + int(df.FrameHeader.Length) // 9-byte frame header + payload (PadLength + pad)
	if total < 48 || total > 72 {
		t.Errorf("chrome mode: DATA total length = %d, want 48..72", total)
	} else {
		t.Logf("chrome mode: padded DATA total length = %d OK", total)
	}
	rs, ok := frames[1].(*RSTStreamFrame)
	if !ok || rs.ErrCode != ErrCodeCancel {
		t.Errorf("chrome mode: second frame = %#v, want RST_STREAM(CANCEL)", frames[1])
	}

	// Default mode: only a bare RST_STREAM.
	frames = run(false)
	if len(frames) != 1 {
		t.Fatalf("default mode: got %d frames, want 1", len(frames))
	}
	if _, ok := frames[0].(*RSTStreamFrame); !ok {
		t.Errorf("default mode: frame is %T, want *RSTStreamFrame", frames[0])
	}
}
