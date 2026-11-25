package naive

import (
	"encoding/binary"
	"io"
	"math/rand"
	"sync"
)

// PaddingCount is the number of frames (in each direction) that are padded.
// naiveproxy calls this "padding type 1": the first frames of the stream carry
// a [length:2][padding:1] header followed by zero padding.
const PaddingCount = 8

// PaddingHeaderAlphabet is the subset of the HPACK non-indexed literal
// alphabet naiveproxy picks the first 16 bytes of the request "padding" header
// from.
const PaddingHeaderAlphabet = "!#$()+<>?@[]^`{}"

// GeneratePaddingHeader builds the "padding" request header value: 16 random
// characters from the HPACK alphabet followed by '~' up to a random length.
func GeneratePaddingHeader() string {
	n := rand.Intn(17) + 16 // 16..32
	padding := make([]byte, n)
	for i := 0; i < 16; i++ {
		padding[i] = PaddingHeaderAlphabet[rand.Intn(len(PaddingHeaderAlphabet))]
	}
	for i := 16; i < n; i++ {
		padding[i] = '~'
	}
	return string(padding)
}

// GenerateResponsePaddingHeader builds the "Padding" response header value.
// naiveproxy does not constrain its length as long as it is non-empty.
func GenerateResponsePaddingHeader() string {
	n := rand.Intn(33) + 30 // 30..62
	padding := make([]byte, n)
	for i := 0; i < 16; i++ {
		padding[i] = PaddingHeaderAlphabet[rand.Intn(len(PaddingHeaderAlphabet))]
	}
	for i := 16; i < n; i++ {
		padding[i] = '~'
	}
	return string(padding)
}

// PaddingReader strips the padding framing from the first PaddingCount frames
// of a stream.
type PaddingReader struct {
	r io.Reader

	frames           int
	remaining        int
	paddingRemaining int
}

func NewPaddingReader(r io.Reader) *PaddingReader {
	return &PaddingReader{r: r}
}

func (p *PaddingReader) Read(b []byte) (int, error) {
	if p.remaining > 0 {
		if len(b) > p.remaining {
			b = b[:p.remaining]
		}
		n, err := p.r.Read(b)
		p.remaining -= n
		return n, err
	}
	if p.paddingRemaining > 0 {
		if err := skipN(p.r, p.paddingRemaining); err != nil {
			return 0, err
		}
		p.paddingRemaining = 0
	}
	if p.frames < PaddingCount {
		var header [3]byte
		if _, err := io.ReadFull(p.r, header[:]); err != nil {
			return 0, err
		}
		size := int(binary.BigEndian.Uint16(header[:2]))
		paddingSize := int(header[2])
		if len(b) > size {
			b = b[:size]
		}
		n, err := p.r.Read(b)
		p.frames++
		p.remaining = size - n
		p.paddingRemaining = paddingSize
		return n, err
	}
	return p.r.Read(b)
}

// PaddingWriter adds the padding framing to the first PaddingCount frames.
type PaddingWriter struct {
	w io.Writer

	mu     sync.Mutex
	frames int
}

func NewPaddingWriter(w io.Writer) *PaddingWriter {
	return &PaddingWriter{w: w}
}

func (p *PaddingWriter) Write(b []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.frames >= PaddingCount {
		return p.w.Write(b)
	}
	written := 0
	for len(b) > 0 {
		chunk := b
		if len(chunk) > 0xFFFF {
			chunk = b[:0xFFFF]
		}
		b = b[len(chunk):]
		paddingSize := rand.Intn(256)
		frame := make([]byte, 3+len(chunk)+paddingSize)
		binary.BigEndian.PutUint16(frame, uint16(len(chunk)))
		frame[2] = byte(paddingSize)
		copy(frame[3:], chunk)
		if _, err := p.w.Write(frame); err != nil {
			return written, err
		}
		written += len(chunk)
		p.frames++
		if p.frames >= PaddingCount {
			if len(b) > 0 {
				n, err := p.w.Write(b)
				written += n
				return written, err
			}
			break
		}
	}
	return written, nil
}

func skipN(r io.Reader, n int) error {
	const bufSize = 512
	buf := make([]byte, bufSize)
	for n > 0 {
		chunk := n
		if chunk > bufSize {
			chunk = bufSize
		}
		if _, err := io.ReadFull(r, buf[:chunk]); err != nil {
			return err
		}
		n -= chunk
	}
	return nil
}
