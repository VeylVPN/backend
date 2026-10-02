package ratelimit

import (
	"fmt"
	"net/http/httptest"
	"testing"
	"time"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func newTest(p Policy) (*Limiter, *clock) {
	c := &clock{t: time.Unix(1_800_000_000, 0)}
	l := New(p)
	l.Now = c.now
	return l, c
}

func TestPerKeyBurstAndRefill(t *testing.T) {
	l, c := newTest(Auth)
	for i := 0; i < 20; i++ {
		if ok, _ := l.Allow("198.51.100.1"); !ok {
			t.Fatalf("request %d denied", i)
		}
	}
	ok, wait := l.Allow("198.51.100.1")
	if ok || wait < time.Second {
		t.Fatalf("burst not enforced %v %v", ok, wait)
	}
	if ok, _ := l.Allow("198.51.100.2"); !ok {
		t.Fatal("other key affected")
	}
	c.t = c.t.Add(6 * time.Second)
	if ok, _ := l.Allow("198.51.100.1"); !ok {
		t.Fatal("no refill after 6s at 10/min")
	}
	if ok, _ := l.Allow("198.51.100.1"); ok {
		t.Fatal("refilled too much")
	}
}

func TestGlobalCeiling(t *testing.T) {
	l, c := newTest(Policy{PerKey: Rate{PerMinute: 60, Burst: 5}, Global: Rate{PerMinute: 60, Burst: 8}})
	allowed := 0
	for i := 0; i < 20; i++ {
		if ok, _ := l.Allow(fmt.Sprintf("203.0.113.%d", i)); ok {
			allowed++
		}
	}
	if allowed != 8 {
		t.Fatalf("global ceiling allowed %d", allowed)
	}
	if ok, _ := l.Allow(""); ok {
		t.Fatal("shared key bypassed global ceiling")
	}
	c.t = c.t.Add(2 * time.Second)
	if ok, _ := l.Allow(""); !ok {
		t.Fatal("global did not refill")
	}
}

func TestSharedKeyOnlyGlobal(t *testing.T) {
	l, _ := newTest(Policy{PerKey: Rate{PerMinute: 1, Burst: 1}, Global: Rate{PerMinute: 60, Burst: 50}})
	for i := 0; i < 50; i++ {
		if ok, _ := l.Allow(""); !ok {
			t.Fatalf("shared request %d denied by per-key policy", i)
		}
	}
	if ok, _ := l.Allow(""); ok {
		t.Fatal("global not enforced for shared key")
	}
}

func TestPruneAndMaxKeys(t *testing.T) {
	l, c := newTest(Policy{PerKey: Rate{PerMinute: 60, Burst: 2}, Global: Rate{PerMinute: 1e6, Burst: 1e6}, MaxKeys: 3})
	for i := 0; i < 3; i++ {
		l.Allow(fmt.Sprintf("192.0.2.%d", i))
	}
	if ok, _ := l.Allow("192.0.2.9"); ok {
		t.Fatal("key table ceiling not enforced")
	}
	c.t = c.t.Add(10 * time.Second)
	if ok, _ := l.Allow("192.0.2.9"); !ok {
		t.Fatal("idle keys not pruned")
	}
	if n := l.Len(); n != 1 {
		t.Fatalf("len %d", n)
	}
}

func TestKeysAreHashed(t *testing.T) {
	l, _ := newTest(Auth)
	l.Allow("198.51.100.7")
	for k := range l.m {
		if k == "198.51.100.7" || len(k) != 16 {
			t.Fatalf("raw key stored: %q", k)
		}
	}
}

func TestClientIP(t *testing.T) {
	cases := []struct {
		remote string
		xff    []string
		want   string
	}{
		{"198.51.100.1:5000", nil, "198.51.100.1"},
		{"198.51.100.1:5000", []string{"203.0.113.9"}, "198.51.100.1"},
		{"127.0.0.1:5000", []string{"203.0.113.9"}, "203.0.113.9"},
		{"127.0.0.1:5000", []string{"10.1.1.1, 203.0.113.9"}, "203.0.113.9"},
		{"127.0.0.1:5000", []string{"1.1.1.1", "203.0.113.5, 203.0.113.9"}, "203.0.113.9"},
		{"[::1]:5000", []string{"2001:db8:1:2:3:4:5:6"}, "2001:db8:1:2::"},
		{"127.0.0.1:5000", nil, ""},
		{"127.0.0.1:5000", []string{"127.0.0.1"}, ""},
		{"127.0.0.1:5000", []string{"garbage"}, ""},
		{"[2001:db8:aa:bb:1:2:3:4]:5000", nil, "2001:db8:aa:bb::"},
	}
	for _, c := range cases {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = c.remote
		for _, v := range c.xff {
			r.Header.Add("X-Forwarded-For", v)
		}
		if got := ClientIP(r); got != c.want {
			t.Errorf("%s %v: got %q want %q", c.remote, c.xff, got, c.want)
		}
	}
}
