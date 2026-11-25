package naive

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"sync"
	"time"

	N "github.com/metacubex/mihomo/common/net"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/vmess"

	"github.com/metacubex/http"
)

type ClientOptions struct {
	Dialer    C.Dialer
	Server    string
	TLSConfig *vmess.TLSConfig
	Username  string
	Password  string
	Headers   map[string]string

	// FastOpen enables Chromium-style CONNECT Fast Open: the CONNECT request
	// carries a "fastopen" header and early (padded) payload is sent before the
	// 200 response arrives, saving one RTT. Only enable it when the server is
	// known to support padding (the first connection to a server must not use
	// it, per the naiveproxy spec). Default false for compatibility.
	FastOpen bool

	RequestTimeout time.Duration
	IdleTimeout    time.Duration
}

type Client struct {
	options      *ClientOptions
	roundTripper *http.Transport
	auth         string
}

// dialResult is the outcome of the CONNECT RoundTrip, resolved in a goroutine.
type dialResult struct {
	body   io.ReadCloser
	padded bool
	err    error
}

// earlyReader defers reading the response body until the CONNECT response
// arrives. It is used only in Fast Open mode, where Dial returns before the
// 200 and the caller may already be writing early data. Reads block until the
// result channel delivers the response body or an error/timeout.
type earlyReader struct {
	ch      <-chan dialResult
	timeout *time.Timer
	padded  bool

	mu     sync.Mutex
	reader io.Reader    // resolved response reader (plain or padding-wrapped)
	body   io.ReadCloser // resolved response body, closed by conn.Close
	done   bool
	err    error
}

// closeBody closes the resolved response body, if any.
func (e *earlyReader) closeBody() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.body != nil {
		return e.body.Close()
	}
	return nil
}

func (e *earlyReader) resolve() (io.Reader, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.reader != nil || e.err != nil {
		return e.reader, e.err
	}
	if e.done {
		return nil, io.EOF
	}
	select {
	case r := <-e.ch:
		e.done = true
		if r.err != nil {
			e.err = r.err
			return nil, r.err
		}
		e.body = r.body
		if e.padded {
			e.reader = NewPaddingReader(r.body)
		} else {
			e.reader = r.body
		}
		return e.reader, nil
	case <-e.timeout.C:
		e.done = true
		e.err = errors.New("naive: fast-open response timeout")
		return nil, e.err
	}
}

func (e *earlyReader) Read(b []byte) (int, error) {
	r, err := e.resolve()
	if err != nil {
		return 0, err
	}
	return r.Read(b)
}

func NewClient(options *ClientOptions) (*Client, error) {
	if options.RequestTimeout <= 0 {
		options.RequestTimeout = 8 * time.Second
	}
	if options.IdleTimeout <= 0 {
		options.IdleTimeout = 90 * time.Second
	}
	protocols := new(http.Protocols)
	protocols.SetUnencryptedHTTP2(true)

	c := &Client{
		options: options,
		auth:    "Basic " + base64.StdEncoding.EncodeToString([]byte(options.Username+":"+options.Password)),
	}
	c.roundTripper = &http.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			conn, err := options.Dialer.DialContext(ctx, network, options.Server)
			if err != nil {
				return nil, err
			}
			tlsConn, err := vmess.StreamTLSConn(ctx, conn, options.TLSConfig)
			if err != nil {
				_ = conn.Close()
				return nil, err
			}
			return tlsConn, nil
		},
		Protocols:       protocols,
		IdleConnTimeout: options.IdleTimeout,
		// Mimic Chromium's HTTP/2 SETTINGS and pseudo-header order so the
		// tunnel is indistinguishable from a regular Chrome connection.
		HTTP2: &http.HTTP2Config{ChromeFingerprint: true},
	}
	return c, nil
}

// Dial opens an HTTP/2 CONNECT tunnel to target.
func (c *Client) Dial(ctx context.Context, target string) (net.Conn, error) {
	pipeReader, pipeWriter := io.Pipe()

	request := &http.Request{
		Method: http.MethodConnect,
		URL: &url.URL{
			Scheme: "https",
			Host:   c.options.Server, // keep the pool key stable
		},
		Header: make(http.Header),
		Host:   target, // CONNECT :authority
		Body:   pipeReader,
	}
	request.Header.Set("padding", GeneratePaddingHeader())
	if c.options.Username != "" || c.options.Password != "" {
		request.Header.Set("Proxy-Authorization", c.auth)
	}
	if c.options.FastOpen {
		// Chromium's fork advertises early-data capability with this header.
		request.Header.Set("fastopen", "1")
	}
	for key, value := range c.options.Headers {
		request.Header.Set(key, value)
	}

	reqCtx, cancel := context.WithCancel(context.Background()) // lives as long as the tunnel
	request = request.WithContext(reqCtx)

	ready := make(chan dialResult, 1)
	go func() {
		response, err := c.roundTripper.RoundTrip(request)
		if err != nil {
			_ = pipeWriter.CloseWithError(err)
			ready <- dialResult{err: err}
			return
		}
		if response.StatusCode != http.StatusOK {
			_ = response.Body.Close()
			err = fmt.Errorf("naive: unexpected status %d", response.StatusCode)
			_ = pipeWriter.CloseWithError(err)
			ready <- dialResult{err: err}
			return
		}
		ready <- dialResult{body: response.Body, padded: response.Header.Get("Padding") != ""}
	}()

	timeout := time.NewTimer(c.options.RequestTimeout)

	var (
		body    io.ReadCloser
		padded  bool
		early   bool
		earlyCh = ready // fast-open reader resolves against this channel
	)
	if c.options.FastOpen {
		// The timer now belongs to the returned conn (stopped in Close), so
		// that earlyReader can still time out waiting for the response.
		early = true
		padded = true
	} else {
		defer timeout.Stop()
		select {
		case <-ctx.Done():
			cancel()
			_ = pipeWriter.CloseWithError(ctx.Err())
			return nil, ctx.Err()
		case <-timeout.C:
			cancel()
			_ = pipeWriter.CloseWithError(errors.New("naive: request timeout"))
			return nil, errors.New("naive: request timeout")
		case r := <-ready:
			if r.err != nil {
				cancel()
				return nil, r.err
			}
			body = r.body
			padded = r.padded
		}
	}

	conn := &conn{
		pipeWriter: pipeWriter,
		cancel:     cancel,
		localAddr:  N.NewCustomAddr("naive", c.options.Server, nil),
		remoteAddr: N.NewCustomAddr("naive", target, nil),
		timeout:    timeout,
	}
	conn.writer = pipeWriter
	if early {
		// padded is always true in early mode (server padding support is a
		// precondition for Fast Open).
		conn.early = &earlyReader{ch: earlyCh, timeout: timeout, padded: padded}
		conn.reader = conn.early
	} else {
		conn.body = body
		conn.reader = body
		if padded {
			conn.reader = NewPaddingReader(body)
		}
	}
	if padded {
		conn.writer = NewPaddingWriter(pipeWriter)
	}
	return conn, nil
}

func (c *Client) Close() error {
	c.roundTripper.CloseIdleConnections()
	return nil
}

type conn struct {
	reader io.Reader
	writer io.Writer

	body       io.ReadCloser
	pipeWriter *io.PipeWriter
	cancel     context.CancelFunc
	timeout    *time.Timer  // fast-open response timer, nil in normal mode
	early      *earlyReader // fast-open deferred reader, nil in normal mode

	localAddr  net.Addr
	remoteAddr net.Addr

	closeOnce sync.Once
}

func (c *conn) Read(b []byte) (int, error) {
	return c.reader.Read(b)
}

func (c *conn) Write(b []byte) (int, error) {
	return c.writer.Write(b)
}

func (c *conn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		_ = c.pipeWriter.Close()
		if c.body != nil {
			err = c.body.Close()
		}
		if c.early != nil {
			if e := c.early.closeBody(); err == nil {
				err = e
			}
		}
		if c.timeout != nil {
			c.timeout.Stop()
		}
		c.cancel()
	})
	return err
}

func (c *conn) LocalAddr() net.Addr  { return c.localAddr }
func (c *conn) RemoteAddr() net.Addr { return c.remoteAddr }

func (c *conn) SetDeadline(t time.Time) error      { return nil }
func (c *conn) SetReadDeadline(t time.Time) error  { return nil }
func (c *conn) SetWriteDeadline(t time.Time) error { return nil }

var _ net.Conn = (*conn)(nil)
