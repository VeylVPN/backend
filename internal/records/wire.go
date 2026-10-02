package records

import (
	"encoding/binary"
	"errors"
	"net"
	"strings"
)

const (
	TypeA     uint16 = 1
	TypeNS    uint16 = 2
	TypeCNAME uint16 = 5
	TypeSOA   uint16 = 6
	TypeTXT   uint16 = 16
	TypeAAAA  uint16 = 28
	TypeCAA   uint16 = 257

	classIN = 1

	RcodeOK       = 0
	RcodeServFail = 2
	RcodeNXDomain = 3
	RcodeRefused  = 5

	maxMsg     = 65535
	maxRecords = 512
	maxName    = 255
	maxHops    = 64
)

var (
	ErrFormat = errors.New("malformed dns message")
	ErrName   = errors.New("invalid dns name")
)

type CAA struct {
	Flags uint8  `json:"flags"`
	Tag   string `json:"tag"`
	Value string `json:"value"`
}

type RR struct {
	Name   string   `json:"name"`
	Type   uint16   `json:"type"`
	Class  uint16   `json:"class"`
	TTL    uint32   `json:"ttl"`
	IP     net.IP   `json:"ip,omitempty"`
	Target string   `json:"target,omitempty"`
	TXT    []string `json:"txt,omitempty"`
	CAA    *CAA     `json:"caa,omitempty"`
	MinTTL uint32   `json:"min_ttl,omitempty"`
}

type Question struct {
	Name  string
	Type  uint16
	Class uint16
}

type Msg struct {
	ID         uint16
	Response   bool
	Authority  bool
	Truncated  bool
	Rcode      int
	Question   []Question
	Answer     []RR
	NS         []RR
	Additional []RR
}

func CanonicalName(name string) (string, error) {
	name = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
	if name == "" {
		return ".", nil
	}
	if len(name) > 253 {
		return "", ErrName
	}
	for _, l := range strings.Split(name, ".") {
		if l == "" || len(l) > 63 {
			return "", ErrName
		}
		for i := 0; i < len(l); i++ {
			c := l[i]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return "", ErrName
			}
		}
	}
	return name, nil
}

func BuildQuery(id uint16, name string, qtype uint16, recursion bool) ([]byte, error) {
	n, err := CanonicalName(name)
	if err != nil {
		return nil, err
	}
	b := make([]byte, 12, 12+len(n)+2+4+11)
	binary.BigEndian.PutUint16(b[0:], id)
	if recursion {
		binary.BigEndian.PutUint16(b[2:], 0x0100)
	}
	binary.BigEndian.PutUint16(b[4:], 1)
	binary.BigEndian.PutUint16(b[10:], 1)
	if n != "." {
		for _, l := range strings.Split(n, ".") {
			b = append(b, byte(len(l)))
			b = append(b, l...)
		}
	}
	b = append(b, 0, byte(qtype>>8), byte(qtype), 0, classIN)
	b = append(b, 0, 0, 41, 0x04, 0xd0, 0, 0, 0, 0, 0, 0)
	return b, nil
}

func readName(m []byte, off int) (string, int, error) {
	var sb strings.Builder
	end := -1
	hops := 0
	total := 0
	for {
		if off < 0 || off >= len(m) {
			return "", 0, ErrFormat
		}
		l := int(m[off])
		switch {
		case l == 0:
			if end < 0 {
				end = off + 1
			}
			if sb.Len() == 0 {
				return ".", end, nil
			}
			return sb.String(), end, nil
		case l&0xc0 == 0xc0:
			if off+1 >= len(m) {
				return "", 0, ErrFormat
			}
			hops++
			if hops > maxHops {
				return "", 0, ErrFormat
			}
			ptr := int(binary.BigEndian.Uint16(m[off:]) & 0x3fff)
			if ptr >= off {
				return "", 0, ErrFormat
			}
			if end < 0 {
				end = off + 2
			}
			off = ptr
		case l&0xc0 != 0:
			return "", 0, ErrFormat
		default:
			if off+1+l > len(m) {
				return "", 0, ErrFormat
			}
			total += l + 1
			if total > maxName {
				return "", 0, ErrFormat
			}
			if sb.Len() > 0 {
				sb.WriteByte('.')
			}
			for _, c := range m[off+1 : off+1+l] {
				if c >= 'A' && c <= 'Z' {
					c += 'a' - 'A'
				}
				if c <= 0x20 || c >= 0x7f || c == '.' {
					sb.WriteString("\\")
					sb.WriteByte("0123456789"[c/100])
					sb.WriteByte("0123456789"[c/10%10])
					sb.WriteByte("0123456789"[c%10])
					continue
				}
				sb.WriteByte(c)
			}
			off += 1 + l
		}
	}
}

func parseRR(m []byte, off int) (RR, int, error) {
	name, off, err := readName(m, off)
	if err != nil {
		return RR{}, 0, err
	}
	if off+10 > len(m) {
		return RR{}, 0, ErrFormat
	}
	rr := RR{Name: name, Type: binary.BigEndian.Uint16(m[off:]), Class: binary.BigEndian.Uint16(m[off+2:]), TTL: binary.BigEndian.Uint32(m[off+4:])}
	rdlen := int(binary.BigEndian.Uint16(m[off+8:]))
	off += 10
	if off+rdlen > len(m) {
		return RR{}, 0, ErrFormat
	}
	rd := m[off : off+rdlen]
	end := off + rdlen
	if rr.TTL > 0x7fffffff {
		rr.TTL = 0
	}
	switch rr.Type {
	case TypeA:
		if rdlen != 4 {
			return RR{}, 0, ErrFormat
		}
		rr.IP = net.IP(append([]byte(nil), rd...))
	case TypeAAAA:
		if rdlen != 16 {
			return RR{}, 0, ErrFormat
		}
		rr.IP = net.IP(append([]byte(nil), rd...))
	case TypeNS, TypeCNAME:
		t, n, err := readName(m, off)
		if err != nil || n != end {
			return RR{}, 0, ErrFormat
		}
		rr.Target = t
	case TypeSOA:
		_, n, err := readName(m, off)
		if err != nil {
			return RR{}, 0, ErrFormat
		}
		_, n, err = readName(m, n)
		if err != nil || n+20 != end {
			return RR{}, 0, ErrFormat
		}
		rr.MinTTL = binary.BigEndian.Uint32(m[n+16:])
	case TypeTXT:
		if rdlen == 0 {
			return RR{}, 0, ErrFormat
		}
		for i := 0; i < rdlen; {
			l := int(rd[i])
			if i+1+l > rdlen {
				return RR{}, 0, ErrFormat
			}
			rr.TXT = append(rr.TXT, string(rd[i+1:i+1+l]))
			i += 1 + l
		}
	case TypeCAA:
		if rdlen < 2 {
			return RR{}, 0, ErrFormat
		}
		tl := int(rd[1])
		if tl == 0 || tl > 15 || 2+tl > rdlen {
			return RR{}, 0, ErrFormat
		}
		tag := strings.ToLower(string(rd[2 : 2+tl]))
		for i := 0; i < len(tag); i++ {
			if !(tag[i] >= 'a' && tag[i] <= 'z' || tag[i] >= '0' && tag[i] <= '9') {
				return RR{}, 0, ErrFormat
			}
		}
		rr.CAA = &CAA{Flags: rd[0], Tag: tag, Value: string(rd[2+tl:])}
	}
	return rr, end, nil
}

func Parse(m []byte) (*Msg, error) {
	if len(m) < 12 || len(m) > maxMsg {
		return nil, ErrFormat
	}
	flags := binary.BigEndian.Uint16(m[2:])
	msg := &Msg{
		ID:        binary.BigEndian.Uint16(m[0:]),
		Response:  flags&0x8000 != 0,
		Authority: flags&0x0400 != 0,
		Truncated: flags&0x0200 != 0,
		Rcode:     int(flags & 0x000f),
	}
	if flags&0x7800 != 0 {
		return nil, ErrFormat
	}
	qd := int(binary.BigEndian.Uint16(m[4:]))
	an := int(binary.BigEndian.Uint16(m[6:]))
	ns := int(binary.BigEndian.Uint16(m[8:]))
	ar := int(binary.BigEndian.Uint16(m[10:]))
	if qd > 1 || an+ns+ar > maxRecords {
		return nil, ErrFormat
	}
	off := 12
	for i := 0; i < qd; i++ {
		name, n, err := readName(m, off)
		if err != nil || n+4 > len(m) {
			return nil, ErrFormat
		}
		msg.Question = append(msg.Question, Question{Name: name, Type: binary.BigEndian.Uint16(m[n:]), Class: binary.BigEndian.Uint16(m[n+2:])})
		off = n + 4
	}
	sections := []*[]RR{&msg.Answer, &msg.NS, &msg.Additional}
	for si, count := range []int{an, ns, ar} {
		for i := 0; i < count; i++ {
			rr, n, err := parseRR(m, off)
			if err != nil {
				if msg.Truncated {
					return msg, nil
				}
				return nil, err
			}
			off = n
			*sections[si] = append(*sections[si], rr)
		}
	}
	if off != len(m) && !msg.Truncated {
		return nil, ErrFormat
	}
	return msg, nil
}
