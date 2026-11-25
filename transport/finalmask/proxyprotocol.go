package finalmask

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
)

// proxyProtocolMask prepends a PROXY protocol header to the stream, which lets
// a fronting proxy (Caddy, nginx, HAProxy, or Xray itself) see the real client
// address instead of the proxy's. Both v1 (text) and v2 (binary) are
// implemented from the specification; the bytes match
// github.com/pires/go-proxyproto, which Xray uses.
type proxyProtocolMask struct {
	version int
}

func newProxyProtocolMask(settings map[string]any) (TCPMask, error) {
	v, ok, err := settingInt(settings, "version")
	if err != nil {
		return nil, err
	}
	if !ok || v == 0 {
		v = 2
	}
	if v != 1 && v != 2 {
		return nil, fmt.Errorf("PROXY protocol version must be 1 or 2")
	}
	return &proxyProtocolMask{version: v}, nil
}

func (m *proxyProtocolMask) WrapConnClient(conn net.Conn) (net.Conn, error) {
	header, err := buildProxyHeader(m.version, conn.LocalAddr(), conn.RemoteAddr())
	if err != nil {
		return nil, err
	}
	if _, err := conn.Write(header); err != nil {
		return nil, fmt.Errorf("failed to write PROXY protocol header: %w", err)
	}
	return conn, nil
}

var proxyV2Signature = []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A}

func buildProxyHeader(version int, source, dest net.Addr) ([]byte, error) {
	srcIP, srcPort, ok := splitTCPAddr(source)
	if !ok {
		// Unknown address family: v1 has an explicit UNKNOWN form, v2 has an
		// unspecified family with a zero-length address block.
		if version == 1 {
			return []byte("PROXY UNKNOWN\r\n"), nil
		}
		header := make([]byte, 16)
		copy(header, proxyV2Signature)
		header[12] = 0x20 // version 2, command LOCAL
		header[13] = 0x00 // UNSPEC
		return header, nil
	}
	dstIP, dstPort, ok := splitTCPAddr(dest)
	if !ok {
		dstIP, dstPort = net.IPv4zero, 0
	}

	if version == 1 {
		family := "TCP4"
		if srcIP.To4() == nil || dstIP.To4() == nil {
			family = "TCP6"
		}
		line := "PROXY " + family + " " + srcIP.String() + " " + dstIP.String() + " " +
			strconv.Itoa(int(srcPort)) + " " + strconv.Itoa(int(dstPort)) + "\r\n"
		return []byte(line), nil
	}

	src4, dst4 := srcIP.To4(), dstIP.To4()
	var addrBlock []byte
	if src4 != nil && dst4 != nil {
		addrBlock = make([]byte, 0, 12)
		addrBlock = append(addrBlock, src4...)
		addrBlock = append(addrBlock, dst4...)
	} else {
		addrBlock = make([]byte, 0, 36)
		addrBlock = append(addrBlock, srcIP.To16()...)
		addrBlock = append(addrBlock, dstIP.To16()...)
	}
	addrBlock = binary.BigEndian.AppendUint16(addrBlock, srcPort)
	addrBlock = binary.BigEndian.AppendUint16(addrBlock, dstPort)

	header := make([]byte, 16, 16+len(addrBlock))
	copy(header, proxyV2Signature)
	header[12] = 0x21 // version 2, command PROXY
	if src4 != nil && dst4 != nil {
		header[13] = 0x11 // AF_INET + STREAM
	} else {
		header[13] = 0x21 // AF_INET6 + STREAM
	}
	binary.BigEndian.PutUint16(header[14:16], uint16(len(addrBlock)))
	return append(header, addrBlock...), nil
}

func splitTCPAddr(addr net.Addr) (net.IP, uint16, bool) {
	tcp, ok := addr.(*net.TCPAddr)
	if !ok || tcp == nil || tcp.IP == nil {
		return nil, 0, false
	}
	return tcp.IP, uint16(tcp.Port), true
}
