package dns

import (
	"encoding/binary"
	"errors"
)

const (
	headerLen    = 12
	maxUDP       = 4096
	minUDP       = 512
	maxMsg       = 65535
	blockTTL     = 300
	typeA        = 1
	typeAAAA     = 28
	typeOPT      = 41
	classIN      = 1
	flagQR       = 0x8000
	flagTC       = 0x0200
	flagRD       = 0x0100
	flagRA       = 0x0080
	flagCD       = 0x0010
	rcodeNX      = 3
	rcodeRefused = 5
)

var errMalformed = errors.New("malformed dns message")

type Query struct {
	ID      uint16
	Flags   uint16
	Name    string
	Type    uint16
	Class   uint16
	End     int
	UDPSize int
	EDNS    bool
	Plain   bool
}

func ParseQuery(b []byte) (Query, error) {
	var q Query
	if len(b) < headerLen || len(b) > maxMsg {
		return q, errMalformed
	}
	q.ID = binary.BigEndian.Uint16(b[0:])
	q.Flags = binary.BigEndian.Uint16(b[2:])
	if q.Flags&flagQR != 0 || (q.Flags>>11)&0xf != 0 {
		return q, errMalformed
	}
	qd := binary.BigEndian.Uint16(b[4:])
	an := binary.BigEndian.Uint16(b[6:])
	ns := binary.BigEndian.Uint16(b[8:])
	ar := binary.BigEndian.Uint16(b[10:])
	if qd != 1 || an != 0 || ns != 0 {
		return q, errMalformed
	}
	name, plain, off, err := readQName(b, headerLen)
	if err != nil {
		return q, err
	}
	if off+4 > len(b) {
		return q, errMalformed
	}
	q.Name, q.Plain = name, plain
	q.Type = binary.BigEndian.Uint16(b[off:])
	q.Class = binary.BigEndian.Uint16(b[off+2:])
	off += 4
	q.End = off
	for i := 0; i < int(ar); i++ {
		start := off
		off, err = skipName(b, off)
		if err != nil {
			return q, err
		}
		if off+10 > len(b) {
			return q, errMalformed
		}
		typ := binary.BigEndian.Uint16(b[off:])
		class := binary.BigEndian.Uint16(b[off+2:])
		rdlen := int(binary.BigEndian.Uint16(b[off+8:]))
		off += 10
		if off+rdlen > len(b) {
			return q, errMalformed
		}
		off += rdlen
		if typ == typeOPT {
			if q.EDNS || off-rdlen-10 != start+1 {
				return q, errMalformed
			}
			q.EDNS = true
			q.UDPSize = int(class)
		}
	}
	if off != len(b) {
		return q, errMalformed
	}
	return q, nil
}

func readQName(b []byte, off int) (string, bool, int, error) {
	buf := make([]byte, 0, 64)
	plain := true
	wire := 0
	for {
		if off >= len(b) {
			return "", false, 0, errMalformed
		}
		n := int(b[off])
		off++
		wire++
		if n == 0 {
			break
		}
		if n > 63 {
			return "", false, 0, errMalformed
		}
		wire += n
		if wire > 255 || off+n > len(b) {
			return "", false, 0, errMalformed
		}
		if len(buf) > 0 {
			buf = append(buf, '.')
		}
		for _, c := range b[off : off+n] {
			switch {
			case c >= 'A' && c <= 'Z':
				c += 'a' - 'A'
			case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_':
			default:
				plain = false
			}
			buf = append(buf, c)
		}
		off += n
	}
	return string(buf), plain, off, nil
}

func skipName(b []byte, off int) (int, error) {
	wire := 0
	for {
		if off >= len(b) {
			return 0, errMalformed
		}
		n := int(b[off])
		switch {
		case n == 0:
			return off + 1, nil
		case n&0xc0 == 0xc0:
			if off+2 > len(b) {
				return 0, errMalformed
			}
			ptr := int(binary.BigEndian.Uint16(b[off:]) & 0x3fff)
			if ptr < headerLen || ptr >= off {
				return 0, errMalformed
			}
			return off + 2, nil
		case n > 63:
			return 0, errMalformed
		}
		wire += n + 1
		if wire > 255 || off+1+n > len(b) {
			return 0, errMalformed
		}
		off += 1 + n
	}
}

func (q Query) ClientUDPSize() int {
	if !q.EDNS || q.UDPSize < minUDP {
		return minUDP
	}
	if q.UDPSize > maxUDP {
		return maxUDP
	}
	return q.UDPSize
}

func reply(b []byte, q Query, rcode uint16, extra uint16, answer []byte) []byte {
	out := make([]byte, headerLen, q.End+len(answer)+11)
	flags := flagQR | flagRA | extra | q.Flags&(flagRD|flagCD) | rcode
	binary.BigEndian.PutUint16(out[0:], q.ID)
	binary.BigEndian.PutUint16(out[2:], flags)
	binary.BigEndian.PutUint16(out[4:], 1)
	if answer != nil {
		binary.BigEndian.PutUint16(out[6:], 1)
	}
	out = append(out, b[headerLen:q.End]...)
	out = append(out, answer...)
	if q.EDNS {
		binary.BigEndian.PutUint16(out[10:], 1)
		out = append(out, 0, 0, typeOPT, byte(maxUDP>>8), byte(maxUDP&0xff), 0, 0, 0, 0, 0, 0)
	}
	return out
}

func BlockedReply(b []byte, q Query) []byte {
	if q.Class == classIN && (q.Type == typeA || q.Type == typeAAAA) {
		size := 4
		if q.Type == typeAAAA {
			size = 16
		}
		ans := make([]byte, 12+size)
		ans[0], ans[1] = 0xc0, headerLen
		binary.BigEndian.PutUint16(ans[2:], q.Type)
		binary.BigEndian.PutUint16(ans[4:], classIN)
		binary.BigEndian.PutUint32(ans[6:], blockTTL)
		binary.BigEndian.PutUint16(ans[10:], uint16(size))
		return reply(b, q, 0, 0, ans)
	}
	return reply(b, q, rcodeNX, 0, nil)
}

func truncatedReply(b []byte, q Query) []byte {
	return reply(b, q, 0, flagTC, nil)
}

func refusedReply(b []byte, q Query) []byte {
	return reply(b, q, rcodeRefused, 0, nil)
}

func validResponse(resp []byte, id uint16) bool {
	return len(resp) >= headerLen && binary.BigEndian.Uint16(resp) == id && resp[2]&0x80 != 0
}
