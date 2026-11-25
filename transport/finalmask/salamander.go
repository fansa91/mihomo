package finalmask

import (
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"sync"

	"golang.org/x/crypto/blake2b"
)

const (
	salamanderSaltLen = 8
	salamanderKeyLen  = blake2b.Size256
	salamanderMinPSK  = 4
)

// salamanderMask obfuscates every datagram with a keyed stream derived from the
// password: [8-byte random salt][payload XOR blake2b256(psk || salt)]. It is the
// same construction Hysteria2 uses for its "salamander" obfs and the one Xray's
// udp mask of the same name implements, so it interoperates with both.
type salamanderMask struct {
	obfs *salamanderObfuscator
}

func newSalamanderMask(settings map[string]any) (UDPMask, error) {
	password := settingString(settings, "password")
	if password == "" {
		return nil, errors.New("salamander requires a password")
	}
	if r, ok, err := settingRange(settings, "packetSize", "packet-size"); err != nil {
		return nil, err
	} else if ok && r.To > 0 {
		return nil, errors.New("salamander packetSize (gecko mode) is not implemented; remove packetSize to use plain salamander")
	}
	obfs, err := newSalamanderObfuscator([]byte(password))
	if err != nil {
		return nil, err
	}
	return &salamanderMask{obfs: obfs}, nil
}

func (m *salamanderMask) WrapPacketConnClient(pc net.PacketConn, remote net.Addr) (net.PacketConn, error) {
	return &salamanderConn{PacketConn: pc, obfs: m.obfs, remote: remote}, nil
}

type salamanderConn struct {
	net.PacketConn
	obfs   *salamanderObfuscator
	remote net.Addr

	mu  sync.Mutex
	buf []byte
}

var salamanderPool = sync.Pool{
	New: func() any {
		b := make([]byte, 2048)
		return &b
	},
}

// ReadFrom decrypts one datagram. Packets shorter than the salt are dropped,
// which is what the receiver does on a wrong password: nothing decrypts, the
// stream simply stalls instead of erroring loudly.
func (c *salamanderConn) ReadFrom(p []byte) (int, net.Addr, error) {
	size := len(p) + salamanderSaltLen
	if size < 2048 {
		size = 2048
	}
	bp := salamanderPool.Get().(*[]byte)
	buf := *bp
	if cap(buf) < size {
		buf = make([]byte, size)
	}
	buf = buf[:size]
	defer func() {
		*bp = buf
		salamanderPool.Put(bp)
	}()

	for {
		n, addr, err := c.PacketConn.ReadFrom(buf)
		if err != nil {
			return 0, addr, err
		}
		if n <= salamanderSaltLen {
			continue
		}
		out := c.obfs.deobfuscate(buf[:n])
		if len(out) == 0 {
			continue
		}
		return copy(p, out), addr, nil
	}
}

func (c *salamanderConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if addr == nil {
		addr = c.remote
	}
	out := make([]byte, len(p)+salamanderSaltLen)
	c.obfs.obfuscate(p, out)
	if _, err := c.PacketConn.WriteTo(out, addr); err != nil {
		return 0, err
	}
	return len(p), nil
}

// salamanderObfuscator keeps one reusable key-input buffer; the salt is written
// into its tail for every packet.
type salamanderObfuscator struct {
	psk      []byte
	keyInput []byte

	mu sync.Mutex
}

func newSalamanderObfuscator(psk []byte) (*salamanderObfuscator, error) {
	if len(psk) < salamanderMinPSK {
		return nil, fmt.Errorf("salamander password must be at least %d bytes", salamanderMinPSK)
	}
	keyInput := make([]byte, len(psk)+salamanderSaltLen)
	copy(keyInput, psk)
	return &salamanderObfuscator{psk: append([]byte(nil), psk...), keyInput: keyInput}, nil
}

func (o *salamanderObfuscator) key(salt []byte) [salamanderKeyLen]byte {
	o.mu.Lock()
	copy(o.keyInput[len(o.psk):], salt[:salamanderSaltLen])
	sum := blake2b.Sum256(o.keyInput)
	o.mu.Unlock()
	return sum
}

// obfuscate writes salt||xor(payload) into out and returns its length.
func (o *salamanderObfuscator) obfuscate(in, out []byte) int {
	if len(out) < len(in)+salamanderSaltLen {
		return 0
	}
	if _, err := rand.Read(out[:salamanderSaltLen]); err != nil {
		return 0
	}
	key := o.key(out[:salamanderSaltLen])
	for i, b := range in {
		out[i+salamanderSaltLen] = b ^ key[i%salamanderKeyLen]
	}
	return len(in) + salamanderSaltLen
}

// deobfuscate returns the plaintext slice of in (a view, not a copy).
func (o *salamanderObfuscator) deobfuscate(in []byte) []byte {
	if len(in) <= salamanderSaltLen {
		return nil
	}
	key := o.key(in[:salamanderSaltLen])
	out := in[salamanderSaltLen:]
	for i := range out {
		out[i] ^= key[i%salamanderKeyLen]
	}
	return out
}
