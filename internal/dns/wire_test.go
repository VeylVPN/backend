package dns

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestParseQueryValid(t *testing.T) {
	q, err := ParseQuery(buildQuery(0x1234, "WWW.Example.COM", typeA, false))
	if err != nil {
		t.Fatal(err)
	}
	if q.ID != 0x1234 || q.Name != "www.example.com" || q.Type != typeA || q.Class != classIN || !q.Plain || q.EDNS {
		t.Fatalf("%+v", q)
	}
	if q.ClientUDPSize() != 512 {
		t.Fatal(q.ClientUDPSize())
	}
	q, err = ParseQuery(buildQuery(1, "example.com", typeAAAA, true))
	if err != nil {
		t.Fatal(err)
	}
	if !q.EDNS || q.UDPSize != 4096 || q.ClientUDPSize() != 4096 {
		t.Fatalf("%+v", q)
	}
	q, err = ParseQuery(buildQuery(1, "", 2, false))
	if err != nil || q.Name != "" {
		t.Fatalf("root %+v %v", q, err)
	}
	b := buildQuery(1, "a.b", typeA, false)
	b[13] = '.'
	q, err = ParseQuery(b)
	if err != nil || q.Plain {
		t.Fatalf("dot label %+v %v", q, err)
	}
}

func TestParseQueryInvalid(t *testing.T) {
	good := buildQuery(7, "example.com", typeA, true)
	mut := func(f func(b []byte) []byte) []byte {
		c := append([]byte(nil), good...)
		return f(c)
	}
	cases := map[string][]byte{
		"short":      good[:11],
		"truncq":     good[:20],
		"response":   mut(func(b []byte) []byte { b[2] |= 0x80; return b }),
		"opcode":     mut(func(b []byte) []byte { b[2] |= 0x08; return b }),
		"qd0":        mut(func(b []byte) []byte { b[5] = 0; return b }),
		"qd2":        mut(func(b []byte) []byte { b[5] = 2; return b }),
		"an":         mut(func(b []byte) []byte { b[7] = 1; return b }),
		"ns":         mut(func(b []byte) []byte { b[9] = 1; return b }),
		"ar2":        mut(func(b []byte) []byte { b[11] = 2; return b }),
		"ar0trail":   mut(func(b []byte) []byte { b[11] = 0; return b }),
		"trailing":   append(append([]byte(nil), good...), 0),
		"label64":    mut(func(b []byte) []byte { b[12] = 64; return b }),
		"pointer":    mut(func(b []byte) []byte { b[12] = 0xc0; return b }),
		"labeltrunc": mut(func(b []byte) []byte { b[12] = 60; return b }),
		"rdlen":      mut(func(b []byte) []byte { b[len(b)-1] = 5; return b }),
	}
	long := []byte{0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0}
	for i := 0; i < 5; i++ {
		long = append(long, 63)
		long = append(long, bytes.Repeat([]byte{'a'}, 63)...)
	}
	long = append(long, 0, 0, 1, 0, 1)
	cases["namelong"] = long
	dbl := append([]byte(nil), good...)
	dbl[11] = 2
	dbl = append(dbl, 0, 0, typeOPT, 0x10, 0, 0, 0, 0, 0, 0, 0)
	cases["twoopt"] = dbl
	for name, b := range cases {
		if _, err := ParseQuery(b); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestParseQuerySkipsCompressedAdditional(t *testing.T) {
	b := buildQuery(9, "example.com", typeA, false)
	b[11] = 1
	b = append(b, 0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 1, 0, 4, 1, 2, 3, 4)
	if _, err := ParseQuery(b); err != nil {
		t.Fatal(err)
	}
	b[len(b)-15] = 0xff
	if _, err := ParseQuery(b); err == nil {
		t.Fatal("forward pointer accepted")
	}
}

func TestBlockedReplies(t *testing.T) {
	for _, edns := range []bool{false, true} {
		for _, tc := range []struct {
			qtype uint16
			rcode int
			data  []byte
		}{
			{typeA, 0, make([]byte, 4)},
			{typeAAAA, 0, make([]byte, 16)},
			{15, rcodeNX, nil},
			{65, rcodeNX, nil},
		} {
			qb := buildQuery(0xbeef, "Ads.Example.com", tc.qtype, edns)
			q, err := ParseQuery(qb)
			if err != nil {
				t.Fatal(err)
			}
			r := BlockedReply(qb, q)
			m, err := parseMsg(r)
			if err != nil {
				t.Fatalf("type %d: %v", tc.qtype, err)
			}
			if m.id != 0xbeef || m.flags&flagQR == 0 || m.flags&flagRD == 0 || m.flags&flagRA == 0 || m.flags&flagTC != 0 {
				t.Fatalf("flags %x", m.flags)
			}
			if m.rcode() != tc.rcode || m.qname != "Ads.Example.com" || m.qtype != tc.qtype || m.qclass != classIN {
				t.Fatalf("%+v", m)
			}
			if tc.data == nil {
				if len(m.answer) != 0 || binary.BigEndian.Uint16(r[8:]) != 0 {
					t.Fatal("unexpected records")
				}
			} else {
				if len(m.answer) != 1 {
					t.Fatal("answer count")
				}
				a := m.answer[0]
				if a.name != "Ads.Example.com" || a.typ != tc.qtype || a.class != classIN || a.ttl != 300 || !bytes.Equal(a.data, tc.data) {
					t.Fatalf("%+v", a)
				}
			}
			if edns != (len(m.extra) == 1 && m.extra[0].typ == typeOPT) {
				t.Fatalf("edns echo %v %+v", edns, m.extra)
			}
		}
	}
}

func TestTruncatedAndRefusedReplies(t *testing.T) {
	qb := buildQuery(5, "example.com", typeA, false)
	q, _ := ParseQuery(qb)
	m, err := parseMsg(truncatedReply(qb, q))
	if err != nil || m.flags&flagTC == 0 || m.rcode() != 0 || len(m.answer) != 0 {
		t.Fatalf("%+v %v", m, err)
	}
	m, err = parseMsg(refusedReply(qb, q))
	if err != nil || m.rcode() != rcodeRefused {
		t.Fatalf("%+v %v", m, err)
	}
}

func FuzzParseQuery(f *testing.F) {
	f.Add(buildQuery(1, "example.com", typeA, false))
	f.Add(buildQuery(2, "a.b.c.example.org", typeAAAA, true))
	f.Add(buildQuery(3, "", 2, false))
	f.Add([]byte{0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 1, 0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		q, err := ParseQuery(b)
		if err != nil {
			return
		}
		if q.End < headerLen || q.End > len(b) {
			t.Fatalf("bad end %d", q.End)
		}
		if len(q.Name) > 254 {
			t.Fatalf("name too long %d", len(q.Name))
		}
		if s := q.ClientUDPSize(); s < minUDP || s > maxUDP {
			t.Fatalf("udp size %d", s)
		}
		for _, r := range [][]byte{BlockedReply(b, q), truncatedReply(b, q), refusedReply(b, q)} {
			m, err := parseMsg(r)
			if err != nil {
				t.Fatalf("reply does not parse: %v", err)
			}
			if m.id != q.ID || m.flags&flagQR == 0 || m.qtype != q.Type || m.qclass != q.Class {
				t.Fatalf("reply mismatch %+v", m)
			}
		}
	})
}
