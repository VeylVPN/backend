package recordstest

import (
	"encoding/binary"
	"io"
	"net"
	"strings"
	"sync"
	"testing"

	"github.com/veylvpn/backend/internal/records"
)

type Zone struct {
	mu   sync.Mutex
	recs map[string][]records.RR
	AA   bool
	TC   bool
	Down bool
}

func key(name string, t uint16) string {
	return name + "/" + string(rune(t))
}

func (z *Zone) Set(name string, t uint16, rrs ...records.RR) {
	z.mu.Lock()
	defer z.mu.Unlock()
	if z.recs == nil {
		z.recs = map[string][]records.RR{}
	}
	for i := range rrs {
		rrs[i].Name = name
		rrs[i].Type = t
		rrs[i].Class = 1
		if rrs[i].TTL == 0 {
			rrs[i].TTL = 300
		}
	}
	z.recs[key(name, t)] = rrs
}

func (z *Zone) SetDown(down bool) {
	z.mu.Lock()
	z.Down = down
	z.mu.Unlock()
}

func putName(b []byte, name string) []byte {
	if name != "." && name != "" {
		for _, l := range strings.Split(name, ".") {
			b = append(b, byte(len(l)))
			b = append(b, l...)
		}
	}
	return append(b, 0)
}

func EncodeRR(b []byte, rr records.RR) []byte {
	b = putName(b, rr.Name)
	var rd []byte
	switch rr.Type {
	case records.TypeA:
		rd = rr.IP.To4()
	case records.TypeAAAA:
		rd = rr.IP.To16()
	case records.TypeNS, records.TypeCNAME:
		rd = putName(nil, rr.Target)
	case records.TypeTXT:
		for _, s := range rr.TXT {
			rd = append(rd, byte(len(s)))
			rd = append(rd, s...)
		}
	case records.TypeCAA:
		rd = append([]byte{rr.CAA.Flags, byte(len(rr.CAA.Tag))}, rr.CAA.Tag...)
		rd = append(rd, rr.CAA.Value...)
	}
	h := make([]byte, 10)
	binary.BigEndian.PutUint16(h[0:], rr.Type)
	binary.BigEndian.PutUint16(h[2:], rr.Class)
	binary.BigEndian.PutUint32(h[4:], rr.TTL)
	binary.BigEndian.PutUint16(h[8:], uint16(len(rd)))
	return append(append(b, h...), rd...)
}

func (z *Zone) Answer(q []byte, tcp bool) []byte {
	z.mu.Lock()
	defer z.mu.Unlock()
	if z.Down {
		return nil
	}
	msg, err := records.Parse(q)
	if err != nil || len(msg.Question) != 1 {
		return nil
	}
	name, qt := msg.Question[0].Name, msg.Question[0].Type
	qlen := 12 + len(putName(nil, name)) + 4
	if qlen > len(q) {
		return nil
	}
	var ans []records.RR
	cur := name
	for i := 0; i < 4; i++ {
		if c := z.recs[key(cur, records.TypeCNAME)]; len(c) > 0 && qt != records.TypeCNAME {
			ans = append(ans, c[0])
			cur = c[0].Target
			continue
		}
		ans = append(ans, z.recs[key(cur, qt)]...)
		break
	}
	rcode := 0
	if len(ans) == 0 {
		known := false
		for k := range z.recs {
			owner := strings.SplitN(k, "/", 2)[0]
			if owner == name || strings.HasSuffix(owner, "."+name) {
				known = true
			}
		}
		if !known {
			rcode = records.RcodeNXDomain
		}
	}
	flags := uint16(0x8000 | rcode)
	if z.AA {
		flags |= 0x0400
	}
	if q[2]&0x01 != 0 {
		flags |= 0x0100
	}
	if z.TC && !tcp {
		flags |= 0x0200
		ans = nil
	}
	b := make([]byte, 12)
	copy(b, q[:2])
	binary.BigEndian.PutUint16(b[2:], flags)
	binary.BigEndian.PutUint16(b[4:], 1)
	binary.BigEndian.PutUint16(b[6:], uint16(len(ans)))
	b = append(b, q[12:qlen]...)
	for _, rr := range ans {
		b = EncodeRR(b, rr)
	}
	return b
}

func Serve(t testing.TB, addr string, z *Zone) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		t.Skipf("cannot listen on %s: %v", addr, err)
	}
	real := pc.LocalAddr().String()
	ln, err := net.Listen("tcp", real)
	if err != nil {
		pc.Close()
		t.Skipf("cannot listen tcp on %s: %v", real, err)
	}
	t.Cleanup(func() { pc.Close(); ln.Close() })
	go func() {
		buf := make([]byte, 4096)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if out := z.Answer(append([]byte(nil), buf[:n]...), false); out != nil {
				_, _ = pc.WriteTo(out, from)
			}
		}
	}()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				var lb [2]byte
				if _, err := io.ReadFull(c, lb[:]); err != nil {
					return
				}
				q := make([]byte, binary.BigEndian.Uint16(lb[:]))
				if _, err := io.ReadFull(c, q); err != nil {
					return
				}
				out := z.Answer(q, true)
				if out == nil {
					return
				}
				binary.BigEndian.PutUint16(lb[:], uint16(len(out)))
				_, _ = c.Write(append(lb[:], out...))
			}(c)
		}
	}()
	return real
}

func FreePort(t testing.TB, ips ...string) string {
	t.Helper()
	for i := 0; i < 20; i++ {
		pc, err := net.ListenPacket("udp", ips[0]+":0")
		if err != nil {
			t.Skipf("%s not available", ips[0])
		}
		_, port, _ := net.SplitHostPort(pc.LocalAddr().String())
		pc.Close()
		ok := true
		for _, ip := range ips {
			p, err := net.ListenPacket("udp", ip+":"+port)
			if err != nil {
				ok = false
				break
			}
			p.Close()
		}
		if ok {
			return port
		}
	}
	t.Skip("no free port")
	return ""
}

type World struct {
	Public  *Zone
	NS1     *Zone
	NS2     *Zone
	Checker *records.Checker
}

func NewWorld(t testing.TB, zone string, timeout func() *records.Client) *World {
	w := &World{Public: &Zone{}, NS1: &Zone{AA: true}, NS2: &Zone{AA: true}}
	port := FreePort(t, "127.0.0.2", "127.0.0.3")
	Serve(t, "127.0.0.2:"+port, w.NS1)
	Serve(t, "127.0.0.3:"+port, w.NS2)
	r1 := Serve(t, "127.0.0.1:0", w.Public)
	r2 := Serve(t, "127.0.0.1:0", w.Public)
	w.Checker = &records.Checker{Client: timeout(), Resolvers: []string{r1, r2}, AuthPort: port}
	w.Public.Set(zone, records.TypeNS, records.RR{Target: "ns1." + zone}, records.RR{Target: "ns2." + zone})
	w.Public.Set("ns1."+zone, records.TypeA, records.RR{IP: net.ParseIP("127.0.0.2")})
	w.Public.Set("ns2."+zone, records.TypeA, records.RR{IP: net.ParseIP("127.0.0.3")})
	return w
}

func (w *World) Both(name string, t uint16, rrs ...records.RR) {
	w.NS1.Set(name, t, append([]records.RR(nil), rrs...)...)
	w.NS2.Set(name, t, append([]records.RR(nil), rrs...)...)
}
