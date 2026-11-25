package finalmask

import (
	"crypto/rand"
	"errors"
	"math/big"
	"net"
	"strings"
	"time"
)

var (
	errPacketsFromZero = errors.New("packets range must not start at 0 unless it is 0-1")
	errLastLengthZero  = errors.New("the last length entry must be greater than 0")
)

// fragmentMask splits the first bytes written on a connection into several TCP
// segments, optionally pausing between them. The classic use is to cut the TLS
// ClientHello so that a middlebox never sees the SNI in one packet, which is
// exactly what Xray's fragment mask does; the wire result is plain TLS spread
// over more segments, so no server-side counterpart is needed.
type fragmentMask struct {
	packetsFrom int64
	packetsTo   int64

	lengthsMin []int64
	lengthsMax []int64
	delaysMin  []int64
	delaysMax  []int64

	maxSplitMin int64
	maxSplitMax int64
}

func newFragmentMask(settings map[string]any) (TCPMask, error) {
	m := &fragmentMask{}

	switch packets := lowerTrim(settingString(settings, "packets")); packets {
	case "tlshello":
		// Only the first write, and only when it is a TLS handshake record.
		m.packetsFrom, m.packetsTo = 0, 1
	case "":
		m.packetsFrom, m.packetsTo = 0, 0
	default:
		r, err := parseRangeString(packets)
		if err != nil {
			return nil, err
		}
		m.packetsFrom, m.packetsTo = int64(r.From), int64(r.To)
		if m.packetsFrom == 0 {
			return nil, errPacketsFromZero
		}
	}

	lengths, ok, err := settingRangeList(settings, "lengths")
	if err != nil {
		return nil, err
	}
	if !ok {
		r, has, err := settingRange(settings, "length", "lengthRange")
		if err != nil {
			return nil, err
		}
		if !has || !r.valid() {
			// Xray defaults to 0 which is rejected; use a sane 100-200 split
			// instead of failing on a missing field.
			r = int32Range{From: 100, To: 200}
		}
		lengths = []int32Range{r}
	}
	for _, r := range lengths {
		m.lengthsMin = append(m.lengthsMin, int64(r.From))
		m.lengthsMax = append(m.lengthsMax, int64(r.To))
	}
	if len(m.lengthsMin) == 0 || m.lengthsMin[len(m.lengthsMin)-1] == 0 {
		return nil, errLastLengthZero
	}

	delays, ok, err := settingRangeList(settings, "delays")
	if err != nil {
		return nil, err
	}
	if !ok {
		r, _, err := settingRange(settings, "delay", "delayRange")
		if err != nil {
			return nil, err
		}
		delays = []int32Range{r}
	}
	for _, r := range delays {
		m.delaysMin = append(m.delaysMin, int64(r.From))
		m.delaysMax = append(m.delaysMax, int64(r.To))
	}

	r, _, err := settingRange(settings, "maxSplit", "max-split")
	if err != nil {
		return nil, err
	}
	m.maxSplitMin, m.maxSplitMax = int64(r.From), int64(r.To)

	return m, nil
}

func (m *fragmentMask) WrapConnClient(conn net.Conn) (net.Conn, error) {
	return &fragmentConn{Conn: conn, mask: m}, nil
}

type fragmentConn struct {
	net.Conn
	mask  *fragmentMask
	count uint64
}

func (c *fragmentConn) lengthForSegment(idx int) (int64, int64) {
	if idx >= len(c.mask.lengthsMin) {
		idx = len(c.mask.lengthsMin) - 1
	}
	return c.mask.lengthsMin[idx], c.mask.lengthsMax[idx]
}

func (c *fragmentConn) delayForSegment(idx int) (int64, int64) {
	if idx >= len(c.mask.delaysMin) {
		idx = len(c.mask.delaysMin) - 1
	}
	return c.mask.delaysMin[idx], c.mask.delaysMax[idx]
}

// mergeTlsHelloSegments reports whether the split records should be gathered
// and written in one go, which happens when no delay is configured.
func (c *fragmentConn) mergeTlsHelloSegments() bool {
	return len(c.mask.delaysMax) == 1 && c.mask.delaysMax[0] == 0
}

func (c *fragmentConn) Write(p []byte) (int, error) {
	c.count++

	// tlshello mode: only the very first write, and only if it starts with a
	// TLS handshake record (0x16).
	if c.mask.packetsFrom == 0 && c.mask.packetsTo == 1 {
		if c.count != 1 || len(p) <= 5 || p[0] != 22 {
			return c.Conn.Write(p)
		}
		recordLen := 5 + ((int(p[3]) << 8) | int(p[4]))
		if len(p) < recordLen {
			return c.Conn.Write(p)
		}
		return c.writeTLSHello(p, recordLen)
	}

	if c.mask.packetsFrom != 0 && (c.count < uint64(c.mask.packetsFrom) || c.count > uint64(c.mask.packetsTo)) {
		return c.Conn.Write(p)
	}
	return c.writeSplit(p)
}

// writeTLSHello splits the body of the first TLS record while rebuilding the
// 5-byte record header for each piece, so every segment looks like a complete
// (smaller) record.
func (c *fragmentConn) writeTLSHello(p []byte, recordLen int) (int, error) {
	data := p[5:recordLen]
	buff := make([]byte, 2048)
	var hello []byte
	merge := c.mergeTlsHelloSegments()
	maxSplit := randBetween(c.mask.maxSplitMin, c.mask.maxSplitMax)
	var splitNum int64

	for from := 0; ; {
		lengthMin, lengthMax := c.lengthForSegment(int(splitNum))
		to := from + int(randBetween(lengthMin, lengthMax))
		if to > len(data) || (maxSplit > 0 && splitNum+1 >= maxSplit) {
			to = len(data)
		}
		if to <= from {
			// A zero-length segment would never advance the loop.
			to = from + 1
			if to > len(data) {
				to = len(data)
			}
		}
		l := to - from
		if 5+l > len(buff) {
			buff = make([]byte, 5+l)
		}
		copy(buff[:3], p)
		copy(buff[5:], data[from:to])
		from = to
		buff[3] = byte(l >> 8)
		buff[4] = byte(l)
		if merge {
			hello = append(hello, buff[:5+l]...)
		} else {
			delayMin, delayMax := c.delayForSegment(int(splitNum))
			if _, err := c.Conn.Write(buff[:5+l]); err != nil {
				return 0, err
			}
			if delayMax > 0 {
				time.Sleep(time.Duration(randBetween(delayMin, delayMax)) * time.Millisecond)
			}
		}
		splitNum++
		if from == len(data) {
			if len(hello) > 0 {
				if _, err := c.Conn.Write(hello); err != nil {
					return 0, err
				}
			}
			if len(p) > recordLen {
				n, err := c.Conn.Write(p[recordLen:])
				if err != nil {
					return recordLen + n, err
				}
			}
			return len(p), nil
		}
	}
}

func (c *fragmentConn) writeSplit(p []byte) (int, error) {
	maxSplit := randBetween(c.mask.maxSplitMin, c.mask.maxSplitMax)
	var splitNum int64
	for from := 0; ; {
		lengthMin, lengthMax := c.lengthForSegment(int(splitNum))
		to := from + int(randBetween(lengthMin, lengthMax))
		if to > len(p) || (maxSplit > 0 && splitNum+1 >= maxSplit) {
			to = len(p)
		}
		if to <= from {
			to = from + 1
			if to > len(p) {
				to = len(p)
			}
		}
		n, err := c.Conn.Write(p[from:to])
		from += n
		if err != nil {
			return from, err
		}
		delayMin, delayMax := c.delayForSegment(int(splitNum))
		if delayMax > 0 {
			time.Sleep(time.Duration(randBetween(delayMin, delayMax)) * time.Millisecond)
		}
		splitNum++
		if from >= len(p) {
			return from, nil
		}
	}
}

// randBetween returns a value in [min, max). When max <= min the lower bound is
// returned, matching Xray's common/crypto helper.
func randBetween(min, max int64) int64 {
	if max <= min {
		return min
	}
	n, err := rand.Int(rand.Reader, big.NewInt(max-min))
	if err != nil {
		return min
	}
	return min + n.Int64()
}

func lowerTrim(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}
