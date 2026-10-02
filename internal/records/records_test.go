package records

import (
	"context"
	"encoding/binary"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

type zoneData struct {
	mu   sync.Mutex
	recs map[string][]RR
	aa   bool
	tc   bool
	down bool
}

func key(name string, t uint16) string {
	return name + "/" + string(rune(t))
}

func (z *zoneData) set(name string, t uint16, rrs ...RR) {
	z.mu.Lock()
	defer z.mu.Unlock()
	if z.recs == nil {
		z.recs = map[string][]RR{}
	}
	for i := range rrs {
		rrs[i].Name = name
		rrs[i].Type = t
		rrs[i].Class = classIN
		if rrs[i].TTL == 0 {
			rrs[i].TTL = 300
		}
	}
	z.recs[key(name, t)] = rrs
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

func encodeRR(b []byte, rr RR) []byte {
	b = putName(b, rr.Name)
	var rd []byte
	switch rr.Type {
	case TypeA:
		rd = rr.IP.To4()
	case TypeAAAA:
		rd = rr.IP.To16()
	case TypeNS, TypeCNAME:
		rd = putName(nil, rr.Target)
	case TypeTXT:
		for _, s := range rr.TXT {
			rd = append(rd, byte(len(s)))
			rd = append(rd, s...)
		}
	case TypeCAA:
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

func (z *zoneData) answer(q []byte, tcp bool) []byte {
	z.mu.Lock()
	defer z.mu.Unlock()
	if z.down {
		return nil
	}
	if len(q) < 12 {
		return nil
	}
	name, off, err := readName(q, 12)
	if err != nil || off+4 > len(q) {
		return nil
	}
	qt := binary.BigEndian.Uint16(q[off:])
	var ans []RR
	cur := name
	for i := 0; i < 4; i++ {
		if c := z.recs[key(cur, TypeCNAME)]; len(c) > 0 && qt != TypeCNAME {
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
			if strings.HasPrefix(k, name+"/") || strings.HasSuffix(strings.SplitN(k, "/", 2)[0], "."+name) {
				known = true
			}
		}
		if !known {
			rcode = RcodeNXDomain
		}
	}
	flags := uint16(0x8000 | rcode)
	if z.aa {
		flags |= 0x0400
	}
	if q[2]&0x01 != 0 {
		flags |= 0x0100
	}
	trunc := z.tc && !tcp
	if trunc {
		flags |= 0x0200
		ans = nil
	}
	b := make([]byte, 12)
	copy(b, q[:2])
	binary.BigEndian.PutUint16(b[2:], flags)
	binary.BigEndian.PutUint16(b[4:], 1)
	binary.BigEndian.PutUint16(b[6:], uint16(len(ans)))
	b = append(b, q[12:off+4]...)
	for _, rr := range ans {
		b = encodeRR(b, rr)
	}
	return b
}

func serveZone(t *testing.T, addr string, z *zoneData) string {
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
			if out := z.answer(append([]byte(nil), buf[:n]...), false); out != nil {
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
				if _, err := c.Read(lb[:]); err != nil {
					return
				}
				q := make([]byte, binary.BigEndian.Uint16(lb[:]))
				if _, err := c.Read(q); err != nil {
					return
				}
				out := z.answer(q, true)
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

type world struct {
	pub  *zoneData
	ns1  *zoneData
	ns2  *zoneData
	chk  *Checker
	port string
}

func freePort(t *testing.T) string {
	for i := 0; i < 20; i++ {
		pc, err := net.ListenPacket("udp", "127.0.0.2:0")
		if err != nil {
			t.Skip("127.0.0.2 not available")
		}
		_, port, _ := net.SplitHostPort(pc.LocalAddr().String())
		pc.Close()
		ok := true
		for _, ip := range []string{"127.0.0.2", "127.0.0.3"} {
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

func newWorld(t *testing.T) *world {
	w := &world{pub: &zoneData{}, ns1: &zoneData{aa: true}, ns2: &zoneData{aa: true}}
	w.port = freePort(t)
	serveZone(t, "127.0.0.2:"+w.port, w.ns1)
	serveZone(t, "127.0.0.3:"+w.port, w.ns2)
	r1 := serveZone(t, "127.0.0.1:0", w.pub)
	r2 := serveZone(t, "127.0.0.1:0", w.pub)
	w.chk = &Checker{Client: &Client{Timeout: 700 * time.Millisecond}, Resolvers: []string{r1, r2}, AuthPort: w.port}
	w.pub.set("example.test", TypeNS, RR{Target: "ns1.example.test"}, RR{Target: "ns2.example.test"})
	w.pub.set("ns1.example.test", TypeA, RR{IP: net.ParseIP("127.0.0.2")})
	w.pub.set("ns2.example.test", TypeA, RR{IP: net.ParseIP("127.0.0.3")})
	return w
}

func (w *world) both(name string, t uint16, rrs ...RR) {
	w.ns1.set(name, t, append([]RR(nil), rrs...)...)
	w.ns2.set(name, t, append([]RR(nil), rrs...)...)
}

func target() Target {
	return Target{Host: "panel.example.test", Role: RolePanel, IPv4: []string{"203.0.113.10"}}
}

func TestCheckOK(t *testing.T) {
	w := newWorld(t)
	w.pub.set("panel.example.test", TypeA, RR{IP: net.ParseIP("203.0.113.10")})
	w.both("panel.example.test", TypeA, RR{IP: net.ParseIP("203.0.113.10")})
	r := w.chk.Check(context.Background(), target())
	if r.Status != StatusOK || r.Zone != "example.test" || len(r.Auth) != 2 || len(r.Public) != 2 {
		t.Fatalf("%+v", r)
	}
	if len(r.Records) != 0 || !r.CAA.AllowsLE {
		t.Fatalf("records %+v caa %+v", r.Records, r.CAA)
	}
}

func TestCheckPropagating(t *testing.T) {
	w := newWorld(t)
	w.pub.set("panel.example.test", TypeA, RR{IP: net.ParseIP("198.51.100.7"), TTL: 7200})
	w.both("panel.example.test", TypeA, RR{IP: net.ParseIP("203.0.113.10")})
	r := w.chk.Check(context.Background(), target())
	if r.Status != StatusPropagating {
		t.Fatalf("%s %+v", r.Status, r.Public)
	}
	found := false
	for _, f := range r.Findings {
		if strings.Contains(f.Text, "TTL is 2 hours") {
			found = true
		}
	}
	if !found {
		t.Fatalf("no ttl advice: %+v", r.Findings)
	}
}

func TestCheckMissingGivesRecords(t *testing.T) {
	w := newWorld(t)
	tg := target()
	tg.IPv6 = []string{"2001:db8::10"}
	r := w.chk.Check(context.Background(), tg)
	if r.Status != StatusMissing {
		t.Fatalf("%s", r.Status)
	}
	if len(r.Records) != 2 || r.Records[0].Line != "panel.example.test. 300 IN A 203.0.113.10" || r.Records[0].Host != "panel" || r.Records[1].Type != "AAAA" {
		t.Fatalf("%+v", r.Records)
	}
}

func TestCheckWrongAndPartial(t *testing.T) {
	w := newWorld(t)
	w.ns1.set("panel.example.test", TypeA, RR{IP: net.ParseIP("198.51.100.7")})
	w.ns2.set("panel.example.test", TypeA, RR{IP: net.ParseIP("203.0.113.10")})
	r := w.chk.Check(context.Background(), target())
	if r.Status != StatusWrong {
		t.Fatalf("%s", r.Status)
	}
	var remove, add bool
	for _, rec := range r.Records {
		remove = remove || rec.Action == "remove" && rec.Value == "198.51.100.7"
		add = add || rec.Action == "add" && rec.Value == "203.0.113.10"
	}
	if !remove || !add {
		t.Fatalf("%+v", r.Records)
	}
}

func TestCheckCloudflareNode(t *testing.T) {
	w := newWorld(t)
	w.pub.set("vpn.example.test", TypeA, RR{IP: net.ParseIP("104.16.1.1")})
	w.both("vpn.example.test", TypeA, RR{IP: net.ParseIP("104.16.1.1")})
	r := w.chk.Check(context.Background(), Target{Host: "vpn.example.test", Role: RoleNode, IPv4: []string{"203.0.113.10"}})
	if r.Status != StatusProxied || !r.Cloudflare || r.Findings[0].Level != "error" || !strings.Contains(r.Summary, "UDP") {
		t.Fatalf("%+v", r)
	}
}

func TestCheckCNAME(t *testing.T) {
	w := newWorld(t)
	w.pub.set("panel.example.test", TypeCNAME, RR{Target: "host.example.test"})
	w.pub.set("host.example.test", TypeA, RR{IP: net.ParseIP("203.0.113.10")})
	w.both("panel.example.test", TypeCNAME, RR{Target: "host.example.test"})
	w.both("host.example.test", TypeA, RR{IP: net.ParseIP("203.0.113.10")})
	r := w.chk.Check(context.Background(), target())
	if r.Status != StatusOK || len(r.Public[0].CNAME) != 1 {
		t.Fatalf("%s %+v", r.Status, r.Public)
	}
}

func TestCheckNameserverDown(t *testing.T) {
	w := newWorld(t)
	w.pub.set("panel.example.test", TypeA, RR{IP: net.ParseIP("203.0.113.10")})
	w.ns1.set("panel.example.test", TypeA, RR{IP: net.ParseIP("203.0.113.10")})
	w.ns2.down = true
	r := w.chk.Check(context.Background(), target())
	if r.Status == StatusOK {
		t.Fatalf("should not be fully ok with a dead nameserver")
	}
	warn := false
	for _, f := range r.Findings {
		warn = warn || strings.Contains(f.Text, "ns2.example.test did not answer")
	}
	if !warn {
		t.Fatalf("%+v", r.Findings)
	}
}

func TestCAA(t *testing.T) {
	w := newWorld(t)
	w.pub.set("example.test", TypeCAA, RR{CAA: &CAA{Tag: "issue", Value: "digicert.com"}}, RR{CAA: &CAA{Tag: "iodef", Value: "mailto:a@example.test"}})
	w.pub.set("panel.example.test", TypeA, RR{IP: net.ParseIP("203.0.113.10")})
	w.both("panel.example.test", TypeA, RR{IP: net.ParseIP("203.0.113.10")})
	r := w.chk.Check(context.Background(), target())
	if r.CAA.AllowsLE || r.CAA.Domain != "example.test" || len(r.CAA.Records) != 2 {
		t.Fatalf("%+v", r.CAA)
	}
	last := r.Records[len(r.Records)-1]
	if last.Line != `example.test. 300 IN CAA 0 issue "letsencrypt.org"` || last.Host != "@" {
		t.Fatalf("%+v", last)
	}
	w.pub.set("example.test", TypeCAA, RR{CAA: &CAA{Tag: "issue", Value: "letsencrypt.org; validationmethods=http-01"}})
	if c := w.chk.CAA(context.Background(), "panel.example.test"); !c.AllowsLE {
		t.Fatalf("%+v", c)
	}
	w.pub.set("panel.example.test", TypeCAA, RR{CAA: &CAA{Flags: 128, Tag: "future", Value: "x"}})
	if c := w.chk.CAA(context.Background(), "panel.example.test"); c.AllowsLE || c.Domain != "panel.example.test" {
		t.Fatalf("critical unknown tag must block: %+v", c)
	}
}

func TestCaaAllows(t *testing.T) {
	cases := []struct {
		rrs  []RR
		want bool
	}{
		{nil, true},
		{[]RR{{CAA: &CAA{Tag: "iodef", Value: "mailto:x@y"}}}, true},
		{[]RR{{CAA: &CAA{Tag: "issue", Value: ";"}}}, false},
		{[]RR{{CAA: &CAA{Tag: "issue", Value: "LetsEncrypt.org"}}}, true},
		{[]RR{{CAA: &CAA{Tag: "issuewild", Value: "letsencrypt.org"}}, {CAA: &CAA{Tag: "issue", Value: "sectigo.com"}}}, false},
	}
	for i, c := range cases {
		if got := caaAllows(c.rrs, LetsEncrypt); got != c.want {
			t.Errorf("case %d: %v", i, got)
		}
	}
}

func TestTXTWait(t *testing.T) {
	w := newWorld(t)
	name := "_acme-challenge.panel.example.test"
	w.ns1.set(name, TypeTXT, RR{TXT: []string{"token-value"}})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var reports []TXTReport
	go func() {
		time.Sleep(300 * time.Millisecond)
		w.ns2.set(name, TypeTXT, RR{TXT: []string{"token-", "value"}})
	}()
	err := w.chk.WaitTXT(ctx, name, "token-value", 100*time.Millisecond, func(r TXTReport) { reports = append(reports, r) })
	if err != nil {
		t.Fatal(err)
	}
	if len(reports) < 2 || reports[0].Visible || !reports[len(reports)-1].Visible {
		t.Fatalf("%+v", reports)
	}
	if reports[0].Record.Line != `_acme-challenge.panel.example.test. 300 IN TXT "token-value"` || reports[0].Record.Host != "_acme-challenge.panel" {
		t.Fatalf("%+v", reports[0].Record)
	}
	short, c2 := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer c2()
	if err := w.chk.WaitTXT(short, name, "other", 50*time.Millisecond, nil); err == nil {
		t.Fatal("expected timeout")
	}
}

func TestTruncatedFallsBackToTCP(t *testing.T) {
	z := &zoneData{tc: true}
	z.set("big.example.test", TypeTXT, RR{TXT: []string{strings.Repeat("x", 200)}})
	addr := serveZone(t, "127.0.0.1:0", z)
	c := &Client{Timeout: time.Second}
	a, err := c.Lookup(context.Background(), addr, "big.example.test", TypeTXT, true)
	if err != nil || len(a.Records) != 1 || len(a.Records[0].TXT[0]) != 200 {
		t.Fatalf("%v %+v", err, a)
	}
}

func TestNXDomain(t *testing.T) {
	z := &zoneData{}
	z.set("a.example.test", TypeA, RR{IP: net.ParseIP("192.0.2.1")})
	addr := serveZone(t, "127.0.0.1:0", z)
	c := &Client{Timeout: time.Second}
	if _, err := c.Lookup(context.Background(), addr, "nope.invalid", TypeA, true); err != ErrNXDomain {
		t.Fatalf("%v", err)
	}
}

func TestParseRejects(t *testing.T) {
	q, _ := BuildQuery(7, "a.example.test", TypeA, true)
	resp := append([]byte(nil), q[:len(q)-11]...)
	resp[2] = 0x81
	binary.BigEndian.PutUint16(resp[10:], 0)
	binary.BigEndian.PutUint16(resp[6:], 1)
	loop := append(append([]byte(nil), resp...), 0xc0, byte(len(resp)), 0, 1, 0, 1, 0, 0, 0, 1, 0, 4, 1, 2, 3, 4)
	if _, err := Parse(loop); err == nil {
		t.Fatal("forward pointer accepted")
	}
	short := append(append([]byte(nil), resp...), 0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 1, 0, 5, 1, 2, 3, 4)
	if _, err := Parse(short); err == nil {
		t.Fatal("overlong rdata accepted")
	}
	bad := append(append([]byte(nil), resp...), 0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 1, 0, 3, 1, 2, 3)
	if _, err := Parse(bad); err == nil {
		t.Fatal("short A accepted")
	}
	good := append(append([]byte(nil), resp...), 0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 1, 0, 4, 1, 2, 3, 4)
	m, err := Parse(good)
	if err != nil || len(m.Answer) != 1 || m.Answer[0].IP.String() != "1.2.3.4" || m.Answer[0].Name != "a.example.test" {
		t.Fatalf("%v %+v", err, m)
	}
	if _, err := Parse(append(good, 0)); err == nil {
		t.Fatal("trailing garbage accepted")
	}
	if _, err := CanonicalName("bad name.example"); err == nil {
		t.Fatal("space accepted")
	}
	if _, err := BuildQuery(1, strings.Repeat("a", 64)+".com", TypeA, true); err == nil {
		t.Fatal("long label accepted")
	}
}

func FuzzParse(f *testing.F) {
	q, _ := BuildQuery(7, "panel.example.test", TypeCAA, true)
	f.Add(q)
	z := &zoneData{}
	z.set("x.test", TypeCAA, RR{CAA: &CAA{Tag: "issue", Value: "letsencrypt.org"}})
	z.set("x.test", TypeTXT, RR{TXT: []string{"a", "b"}})
	qq, _ := BuildQuery(1, "x.test", TypeCAA, true)
	f.Add(z.answer(qq, true))
	qt, _ := BuildQuery(1, "x.test", TypeTXT, true)
	f.Add(z.answer(qt, true))
	f.Add([]byte{0, 0, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0, 0xc0, 0x0c})
	f.Fuzz(func(t *testing.T, b []byte) {
		m, err := Parse(b)
		if err != nil {
			return
		}
		for _, rr := range append(append(m.Answer, m.NS...), m.Additional...) {
			if len(rr.Name) > 4*maxName {
				t.Fatalf("name too long: %d", len(rr.Name))
			}
			if rr.Type == TypeA && len(rr.IP) != 4 {
				t.Fatal("bad A")
			}
		}
	})
}
