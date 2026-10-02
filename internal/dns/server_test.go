package dns

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/veylvpn/backend/internal/config"
)

type testServer struct {
	srv   *Server
	addrs []string
	up    *fakeUpstream
}

func startServer(t *testing.T, o Options, masks ...int) *testServer {
	t.Helper()
	up := newFakeUpstream(t)
	if o.Upstream == "" {
		o.Upstream = up.addr
	}
	if o.Lists == nil {
		l := NewLists(map[string]Set{
			config.CatAds:     setOf("ads.example.com"),
			config.CatMalware: setOf("evil.example.net"),
		})
		o.Lists = func() *Lists { return l }
	}
	for _, m := range masks {
		o.Listeners = append(o.Listeners, Listener{Addr: "127.0.0.1:0", Mask: m})
	}
	s := NewServer(o)
	if err := s.Listen(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		s.Serve(ctx)
		close(done)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("server did not stop")
		}
	})
	return &testServer{srv: s, addrs: s.Addrs(), up: up}
}

func mustParse(t *testing.T, b []byte) msg {
	t.Helper()
	m, err := parseMsg(b)
	if err != nil {
		t.Fatalf("invalid dns message: %v", err)
	}
	return m
}

func isBlockedA(m msg) bool {
	return m.rcode() == 0 && len(m.answer) == 1 && bytes.Equal(m.answer[0].data, []byte{0, 0, 0, 0})
}

func isForwardedA(m msg) bool {
	return m.rcode() == 0 && len(m.answer) >= 1 && bytes.Equal(m.answer[0].data, []byte{192, 0, 2, 1})
}

func TestEndToEndUDPAndTCP(t *testing.T) {
	ads := config.Mask([]string{config.CatAds})
	mal := config.Mask([]string{config.CatMalware})
	ts := startServer(t, Options{}, ads, mal, 0)
	adsAddr, malAddr, noneAddr := ts.addrs[0], ts.addrs[1], ts.addrs[2]

	r, err := udpExchange(t, adsAddr, buildQuery(100, "x.ads.example.com", typeA, false), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if m := mustParse(t, r); m.id != 100 || !isBlockedA(m) {
		t.Fatalf("udp blocked A %+v", m)
	}
	r, _ = udpExchange(t, adsAddr, buildQuery(101, "ads.example.com", typeAAAA, true), 2*time.Second)
	if m := mustParse(t, r); m.id != 101 || len(m.answer) != 1 || !bytes.Equal(m.answer[0].data, make([]byte, 16)) || len(m.extra) != 1 {
		t.Fatalf("udp blocked AAAA %+v", m)
	}
	r, _ = udpExchange(t, adsAddr, buildQuery(102, "ads.example.com", 16, false), 2*time.Second)
	if m := mustParse(t, r); m.rcode() != rcodeNX || len(m.answer) != 0 {
		t.Fatalf("udp blocked TXT %+v", m)
	}
	r, _ = udpExchange(t, malAddr, buildQuery(103, "ads.example.com", typeA, false), 2*time.Second)
	if m := mustParse(t, r); m.id != 103 || !isForwardedA(m) {
		t.Fatalf("mask isolation %+v", m)
	}
	r, _ = udpExchange(t, malAddr, buildQuery(104, "evil.example.net", typeA, false), 2*time.Second)
	if m := mustParse(t, r); !isBlockedA(m) {
		t.Fatalf("malware %+v", m)
	}
	r, _ = udpExchange(t, noneAddr, buildQuery(105, "evil.example.net", typeA, false), 2*time.Second)
	if m := mustParse(t, r); !isForwardedA(m) {
		t.Fatalf("mask 0 %+v", m)
	}

	udpBefore := ts.up.udpHits.Load()
	rs := tcpExchange(t, adsAddr,
		buildQuery(200, "deep.ads.example.com", typeA, false),
		buildQuery(201, "www.example.org", typeA, true),
		buildQuery(202, "ads.example.com", 15, false),
	)
	if m := mustParse(t, rs[0]); m.id != 200 || !isBlockedA(m) {
		t.Fatalf("tcp blocked %+v", m)
	}
	if m := mustParse(t, rs[1]); m.id != 201 || !isForwardedA(m) || m.qname != "www.example.org" {
		t.Fatalf("tcp forwarded %+v", m)
	}
	if m := mustParse(t, rs[2]); m.rcode() != rcodeNX {
		t.Fatalf("tcp nx %+v", m)
	}
	if ts.up.udpHits.Load() != udpBefore || ts.up.tcpHits.Load() != 1 {
		t.Fatalf("tcp client must be forwarded over tcp: udp %d tcp %d", ts.up.udpHits.Load()-udpBefore, ts.up.tcpHits.Load())
	}
}

func TestForwardRelaysUnchanged(t *testing.T) {
	ts := startServer(t, Options{}, 0)
	q := buildQuery(4242, "relay.example.org", typeA, true)
	r, err := udpExchange(t, ts.addrs[0], q, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	want := ts.up.answer(q, false, 0)
	if !bytes.Equal(r, want) {
		t.Fatalf("response altered")
	}
}

func TestUpstreamRetry(t *testing.T) {
	ts := startServer(t, Options{UDPTimeout: 200 * time.Millisecond}, 0)
	ts.up.dropUDP.Store(1)
	r, err := udpExchange(t, ts.addrs[0], buildQuery(7, "retry.example.org", typeA, false), 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if m := mustParse(t, r); m.id != 7 || !isForwardedA(m) {
		t.Fatalf("%+v", m)
	}
	if ts.up.udpHits.Load() != 2 {
		t.Fatalf("hits %d", ts.up.udpHits.Load())
	}
	ts.up.dropUDP.Store(2)
	if _, err := udpExchange(t, ts.addrs[0], buildQuery(8, "gone.example.org", typeA, false), 800*time.Millisecond); err == nil {
		t.Fatal("expected no answer after two lost attempts")
	}
}

func TestTruncatedUpstreamUsesTCP(t *testing.T) {
	ts := startServer(t, Options{}, 0)
	ts.up.truncUDP.Store(true)
	r, err := udpExchange(t, ts.addrs[0], buildQuery(9, "big.example.org", typeA, false), 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	m := mustParse(t, r)
	if m.flags&flagTC != 0 || !isForwardedA(m) || ts.up.tcpHits.Load() != 1 {
		t.Fatalf("expected full answer via tcp %+v", m)
	}
	ts.up.tcpPad.Store(40)
	r, err = udpExchange(t, ts.addrs[0], buildQuery(10, "huge.example.org", typeA, false), 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	m = mustParse(t, r)
	if m.flags&flagTC == 0 || len(r) > 512 || m.id != 10 {
		t.Fatalf("expected truncated reply %+v len %d", m, len(r))
	}
	r, err = udpExchange(t, ts.addrs[0], buildQuery(11, "huge.example.org", typeA, true), 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	m = mustParse(t, r)
	if m.flags&flagTC != 0 || len(m.answer) != 41 {
		t.Fatalf("edns client should get full answer %d", len(m.answer))
	}
}

func TestMalformedDropped(t *testing.T) {
	ts := startServer(t, Options{}, 0)
	bad := [][]byte{
		{1, 2, 3},
		bytes.Repeat([]byte{0xff}, 40),
		append(buildQuery(1, "example.com", typeA, false), 9, 9),
	}
	for _, b := range bad {
		if _, err := udpExchange(t, ts.addrs[0], b, 300*time.Millisecond); err == nil {
			t.Fatalf("answered malformed %x", b)
		}
	}
	c, err := net.Dial("tcp", ts.addrs[0])
	if err != nil {
		t.Fatal(err)
	}
	c.SetDeadline(time.Now().Add(2 * time.Second))
	c.Write([]byte{0, 3, 1, 2, 3})
	if n, err := c.Read(make([]byte, 10)); err == nil || n != 0 {
		t.Fatal("tcp malformed not closed")
	}
	c.Close()
	if ts.up.udpHits.Load() != 0 || ts.up.tcpHits.Load() != 0 {
		t.Fatal("malformed forwarded")
	}
	r, err := udpExchange(t, ts.addrs[0], buildQuery(2, "ok.example.com", typeA, false), 2*time.Second)
	if err != nil || !isForwardedA(mustParse(t, r)) {
		t.Fatal("server unhealthy after malformed input")
	}
}

func TestRateLimitPerSource(t *testing.T) {
	ts := startServer(t, Options{Rate: 0.001, Burst: 3}, 0)
	for i := 0; i < 3; i++ {
		if _, err := udpExchange(t, ts.addrs[0], buildQuery(uint16(i), "ads.example.com", typeA, false), time.Second); err != nil {
			t.Fatalf("query %d: %v", i, err)
		}
	}
	if _, err := udpExchange(t, ts.addrs[0], buildQuery(9, "ads.example.com", typeA, false), 300*time.Millisecond); err == nil {
		t.Fatal("rate limit not applied on udp")
	}
	rs := tcpExchange(t, ts.addrs[0], buildQuery(10, "ads.example.com", typeA, false))
	if m := mustParse(t, rs[0]); m.rcode() != rcodeRefused || m.id != 10 {
		t.Fatalf("tcp over limit %+v", m)
	}
}

func TestLimiterBuckets(t *testing.T) {
	now := time.Unix(1000, 0)
	l := newLimiter(10, 20)
	l.now = func() time.Time { return now }
	a := netip.MustParseAddr("10.8.0.2")
	b := netip.MustParseAddr("::ffff:10.8.0.3")
	for i := 0; i < 20; i++ {
		if !l.allow(a) {
			t.Fatalf("burst %d", i)
		}
	}
	if l.allow(a) {
		t.Fatal("over burst")
	}
	if !l.allow(b) {
		t.Fatal("other source affected")
	}
	now = now.Add(500 * time.Millisecond)
	for i := 0; i < 5; i++ {
		if !l.allow(a) {
			t.Fatalf("refill %d", i)
		}
	}
	if l.allow(a) {
		t.Fatal("refill too generous")
	}
	if !l.allow(netip.MustParseAddr("10.8.0.3")) || l.size() != 2 {
		t.Fatalf("unmap failed size %d", l.size())
	}
	now = now.Add(10 * time.Second)
	l.prune()
	if l.size() != 0 {
		t.Fatalf("prune left %d", l.size())
	}
	var nl *limiter
	if !nl.allow(a) {
		t.Fatal("nil limiter")
	}
}

func TestListenersMaskMapping(t *testing.T) {
	ls, err := Listeners(config.DNSPrefix, 64, 53)
	if err != nil {
		t.Fatal(err)
	}
	if len(ls) != 64 {
		t.Fatal(len(ls))
	}
	for i, l := range ls {
		host, _, _ := net.SplitHostPort(l.Addr)
		if l.Mask != i {
			t.Fatalf("%s mask %d", l.Addr, l.Mask)
		}
		if config.DNSAddrForMask(l.Mask) != host {
			t.Fatalf("%s does not match DNSAddr", l.Addr)
		}
	}
	if ls[0].Addr != "10.64.0.1:53" || ls[63].Addr != "10.64.0.64:53" {
		t.Fatal(ls[0].Addr, ls[63].Addr)
	}
	want := config.DNSAddr([]string{config.CatAds, config.CatTrackers, config.CatMalware}) + ":53"
	if ls[config.Mask([]string{config.CatAds, config.CatTrackers, config.CatMalware})].Addr != want {
		t.Fatal("default categories address")
	}
	if _, err := Listeners(config.DNSPrefix, 65, 53); err == nil {
		t.Fatal("count 65 accepted")
	}
	if _, err := Listeners("10.64", 4, 53); err == nil {
		t.Fatal("bad prefix accepted")
	}
	if _, err := Listeners("10.64.0", 0, 53); err == nil {
		t.Fatal("count 0 accepted")
	}
}

func TestServerAnswersPerListenerAddress(t *testing.T) {
	var masks []int
	for m := 0; m <= config.MaxMask(); m += 9 {
		masks = append(masks, m)
	}
	ts := startServer(t, Options{}, masks...)
	for i, m := range masks {
		r, err := udpExchange(t, ts.addrs[i], buildQuery(uint16(i), "ads.example.com", typeA, false), 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		blocked := isBlockedA(mustParse(t, r))
		if blocked != (m&1 != 0) {
			t.Fatalf("mask %d blocked=%v", m, blocked)
		}
	}
}

func TestTCPLengthLimits(t *testing.T) {
	ts := startServer(t, Options{}, 0)
	c, err := net.Dial("tcp", ts.addrs[0])
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(2 * time.Second))
	hdr := binary.BigEndian.AppendUint16(nil, 5000)
	c.Write(hdr)
	if n, err := c.Read(make([]byte, 4)); err == nil || n != 0 {
		t.Fatal("oversized tcp query not rejected")
	}
}
