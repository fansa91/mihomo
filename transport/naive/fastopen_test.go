package naive

import (
	"bytes"
	"io"
	"strings"
	"testing"
	"time"
)

// TestEarlyReaderResolve verifies the deferred response reader used by Fast
// Open: reads block until the CONNECT result arrives, then decode padding;
// errors and timeouts propagate.
func TestEarlyReaderResolve(t *testing.T) {
	t.Run("success with padding", func(t *testing.T) {
		ch := make(chan dialResult, 1)
		timer := time.NewTimer(5 * time.Second)
		defer timer.Stop()
		e := &earlyReader{ch: ch, timeout: timer, padded: true}

		// Prepare a padded response body using the padding writer.
		var body bytes.Buffer
		pw := NewPaddingWriter(&body)
		_, _ = pw.Write([]byte("early-response"))

		done := make(chan struct{})
		go func() {
			ch <- dialResult{body: io.NopCloser(&body), padded: true}
			close(done)
		}()
		<-done

		got := make([]byte, len("early-response"))
		if _, err := io.ReadFull(e, got); err != nil {
			t.Fatalf("read: %v", err)
		}
		if string(got) != "early-response" {
			t.Errorf("got %q, want early-response", got)
		}
	})

	t.Run("error propagates", func(t *testing.T) {
		ch := make(chan dialResult, 1)
		timer := time.NewTimer(5 * time.Second)
		defer timer.Stop()
		e := &earlyReader{ch: ch, timeout: timer}

		ch <- dialResult{err: io.ErrUnexpectedEOF}

		_, err := e.Read(make([]byte, 4))
		if err != io.ErrUnexpectedEOF {
			t.Errorf("got err %v, want io.ErrUnexpectedEOF", err)
		}
	})

	t.Run("timeout", func(t *testing.T) {
		ch := make(chan dialResult, 1)
		timer := time.NewTimer(50 * time.Millisecond)
		defer timer.Stop()
		e := &earlyReader{ch: ch, timeout: timer}

		start := time.Now()
		_, err := e.Read(make([]byte, 4))
		if err == nil || !strings.Contains(err.Error(), "timeout") {
			t.Errorf("got err %v, want timeout error", err)
		}
		if time.Since(start) > 2*time.Second {
			t.Error("timeout took too long")
		}
	})

	t.Run("closeBody after resolve", func(t *testing.T) {
		ch := make(chan dialResult, 1)
		timer := time.NewTimer(5 * time.Second)
		defer timer.Stop()
		e := &earlyReader{ch: ch, timeout: timer, padded: false}

		tracked := &trackedReadCloser{Reader: strings.NewReader("ok")}
		ch <- dialResult{body: tracked, padded: false}
		_, _ = e.Read(make([]byte, 2))

		if err := e.closeBody(); err != nil {
			t.Fatalf("closeBody: %v", err)
		}
		if !tracked.closed {
			t.Error("body was not closed")
		}
	})
}

type trackedReadCloser struct {
	io.Reader
	closed bool
}

func (t *trackedReadCloser) Close() error {
	t.closed = true
	return nil
}
