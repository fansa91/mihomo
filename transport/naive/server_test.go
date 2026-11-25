package naive

import (
	"testing"
	"time"
)

func TestServerIdleTimeout(t *testing.T) {
	// Default: keep idle tunnels far longer than the client's 90s pool
	// timeout, so the server never closes a tunnel that the client still
	// considers usable.
	s := NewServer(&ServerOptions{})
	if s.httpServer.IdleTimeout != DefaultIdleTimeout {
		t.Fatalf("default IdleTimeout = %v, want %v", s.httpServer.IdleTimeout, DefaultIdleTimeout)
	}
	if DefaultIdleTimeout <= 90*time.Second {
		t.Fatalf("DefaultIdleTimeout %v is not longer than the client IdleConnTimeout", DefaultIdleTimeout)
	}

	// Explicit override wins.
	s = NewServer(&ServerOptions{IdleTimeout: 5 * time.Minute})
	if s.httpServer.IdleTimeout != 5*time.Minute {
		t.Fatalf("custom IdleTimeout = %v, want 5m", s.httpServer.IdleTimeout)
	}

	// Non-positive values fall back to the default instead of disabling the
	// timeout entirely.
	s = NewServer(&ServerOptions{IdleTimeout: -time.Second})
	if s.httpServer.IdleTimeout != DefaultIdleTimeout {
		t.Fatalf("negative IdleTimeout = %v, want default %v", s.httpServer.IdleTimeout, DefaultIdleTimeout)
	}
}
