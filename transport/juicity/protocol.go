package juicity

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/metacubex/mihomo/common/utils"
	"github.com/metacubex/mihomo/transport/socks5"

	"github.com/metacubex/quic-go"
)

// juicity keeps the TUIC command framing but uses its own version byte (0x00
// instead of TUIC v5's 0x05) and only ever sends Authenticate on the
// unidirectional authentication stream.
const VER byte = 0x00

type CommandType byte

const (
	AuthenticateType CommandType = 0x00
)

func (c CommandType) String() string {
	switch c {
	case AuthenticateType:
		return "Authenticate"
	default:
		return fmt.Sprintf("UnknownCommand:%#x", byte(c))
	}
}

// CommandHead is [VER][TYPE].
type CommandHead struct {
	VER  byte
	TYPE CommandType
}

func NewCommandHead(t CommandType) CommandHead {
	return CommandHead{VER: VER, TYPE: t}
}

func ReadCommandHead(r io.Reader) (CommandHead, error) {
	var buf [2]byte
	if _, err := io.ReadFull(r, buf[:]); err != nil {
		return CommandHead{}, err
	}
	return CommandHead{VER: buf[0], TYPE: CommandType(buf[1])}, nil
}

func (c CommandHead) Pack(w io.Writer) error {
	_, err := w.Write([]byte{c.VER, byte(c.TYPE)})
	return err
}

// Authenticate is [head][uuid:16][token:32].
type Authenticate struct {
	CommandHead
	UUID  [16]byte
	TOKEN [32]byte
}

func NewAuthenticate(uuid [16]byte, token [32]byte) Authenticate {
	return Authenticate{
		CommandHead: NewCommandHead(AuthenticateType),
		UUID:        uuid,
		TOKEN:       token,
	}
}

func (c Authenticate) Pack(w io.Writer) error {
	buf := make([]byte, 0, 2+16+32)
	buf = append(buf, c.VER, byte(c.TYPE))
	buf = append(buf, c.UUID[:]...)
	buf = append(buf, c.TOKEN[:]...)
	_, err := w.Write(buf)
	return err
}

func ReadAuthenticateWithHead(head CommandHead, r io.Reader) (Authenticate, error) {
	c := Authenticate{CommandHead: head}
	if head.TYPE != AuthenticateType {
		return c, fmt.Errorf("juicity: unexpected command type %s", head.TYPE)
	}
	if _, err := io.ReadFull(r, c.UUID[:]); err != nil {
		return c, fmt.Errorf("juicity: read uuid: %w", err)
	}
	if _, err := io.ReadFull(r, c.TOKEN[:]); err != nil {
		return c, fmt.Errorf("juicity: read token: %w", err)
	}
	return c, nil
}

// GenToken derives the authentication token from the TLS exporter, exactly as
// TUIC v5 and juicity do. The UUID (raw bytes) is the exporter label and the
// password is the context.
func GenToken(state quic.ConnectionState, uuid [16]byte, password string) (token [32]byte, err error) {
	tokenBytes, err := state.TLS.ExportKeyingMaterial(utils.StringFromImmutableBytes(uuid[:]), utils.ImmutableBytesFromString(password), 32)
	if err != nil {
		return
	}
	copy(token[:], tokenBytes)
	return
}

// Request header network values, matching trojan's NetworkToByte.
const (
	NetworkTCP byte = 1
	NetworkUDP byte = 3
)

func NetworkString(n byte) string {
	switch n {
	case NetworkTCP:
		return "tcp"
	case NetworkUDP:
		return "udp"
	default:
		return ""
	}
}

// WriteRequestHeader writes [network][socks5/trojan address].
func WriteRequestHeader(w io.Writer, network byte, addr socks5.Addr) error {
	buf := make([]byte, 0, 1+len(addr))
	buf = append(buf, network)
	buf = append(buf, addr...)
	_, err := w.Write(buf)
	return err
}

// ReadRequestHeader reads [network][socks5/trojan address].
func ReadRequestHeader(r io.Reader) (network byte, addr socks5.Addr, err error) {
	var n [1]byte
	if _, err = io.ReadFull(r, n[:]); err != nil {
		return 0, nil, err
	}
	if NetworkString(n[0]) == "" {
		return 0, nil, fmt.Errorf("juicity: invalid network %#x", n[0])
	}
	buf := make([]byte, socks5.MaxAddrLen)
	addr, err = socks5.ReadAddr(r, buf)
	if err != nil {
		return 0, nil, fmt.Errorf("juicity: read address: %w", err)
	}
	return n[0], addr, nil
}

// SealUDP appends [addr][len:2][payload] to dst and returns the appended part.
func SealUDP(dst []byte, addr socks5.Addr, payload []byte) []byte {
	start := len(dst)
	dst = append(dst, addr...)
	dst = binary.BigEndian.AppendUint16(dst, uint16(len(payload)))
	dst = append(dst, payload...)
	return dst[start:]
}
