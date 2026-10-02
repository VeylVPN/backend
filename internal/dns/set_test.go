package dns

import (
	"fmt"
	"runtime"
	"testing"

	"github.com/veylvpn/backend/internal/config"
)

func setOf(names ...string) Set {
	h := make([]uint64, 0, len(names))
	for _, n := range names {
		h = append(h, Hash(n))
	}
	return NewSet(h)
}

func TestSetDedupAndExactCapacity(t *testing.T) {
	s := setOf("a.com", "b.com", "a.com", "c.com", "b.com")
	if s.Len() != 3 || cap(s) != 3 {
		t.Fatalf("len %d cap %d", s.Len(), cap(s))
	}
	for i := 1; i < len(s); i++ {
		if s[i-1] >= s[i] {
			t.Fatal("not sorted")
		}
	}
}

func TestSuffixMatching(t *testing.T) {
	l := NewLists(map[string]Set{
		config.CatAds:     setOf("ads.example.com", "doubleclick.net"),
		config.CatMalware: setOf("evil.org"),
		config.CatSocial:  setOf("social.example"),
	})
	ads := config.Mask([]string{config.CatAds})
	mal := config.Mask([]string{config.CatMalware})
	all := config.MaxMask()
	cases := []struct {
		name string
		mask int
		want bool
	}{
		{"ads.example.com", ads, true},
		{"x.y.ads.example.com", ads, true},
		{"ADS.Example.Com", ads, true},
		{"example.com", ads, false},
		{"notads.example.com", ads, false},
		{"bads.example.com", ads, false},
		{"stats.g.doubleclick.net", ads, true},
		{"doubleclick.net.evil", ads, false},
		{"evil.org", ads, false},
		{"evil.org", mal, true},
		{"a.evil.org", ads | mal, true},
		{"social.example", all, true},
		{"social.example", all &^ config.Mask([]string{config.CatSocial}), false},
		{"ads.example.com", 0, false},
		{"", all, false},
		{"com", all, false},
	}
	for _, c := range cases {
		if got := l.Blocked(c.name, c.mask); got != c.want {
			t.Errorf("Blocked(%q, %d) = %v want %v", c.name, c.mask, got, c.want)
		}
	}
	if l.Count(config.CatAds) != 2 || l.Count(config.CatTrackers) != 0 || l.Count("nope") != 0 {
		t.Fatal("counts")
	}
	var nilLists *Lists
	if nilLists.Blocked("ads.example.com", all) || nilLists.Count(config.CatAds) != 0 {
		t.Fatal("nil lists")
	}
}

func TestBytesPerEntry(t *testing.T) {
	const n = 200000
	before := heapAlloc()
	s := buildSynthetic(n)
	after := heapAlloc()
	per := float64(int64(after)-int64(before)) / float64(s.Len())
	if s.Len() != n {
		t.Fatalf("len %d", s.Len())
	}
	if cap(s)*8/s.Len() > 8 {
		t.Fatalf("structural %d bytes per entry", cap(s)*8/s.Len())
	}
	t.Logf("%.2f bytes per entry (structural %d)", per, cap(s)*8/s.Len())
	runtime.KeepAlive(s)
}

func heapAlloc() uint64 {
	runtime.GC()
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.HeapAlloc
}

func buildSynthetic(n int) Set {
	h := make([]uint64, 0, n)
	for i := 0; i < n; i++ {
		h = append(h, Hash(fmt.Sprintf("host%d.tracker%d.example", i, i%977)))
	}
	return NewSet(h)
}

func BenchmarkBuildSet(b *testing.B) {
	const n = 200000
	b.ReportAllocs()
	var per float64
	for i := 0; i < b.N; i++ {
		before := heapAlloc()
		s := buildSynthetic(n)
		after := heapAlloc()
		per = float64(int64(after)-int64(before)) / float64(s.Len())
		runtime.KeepAlive(s)
	}
	b.ReportMetric(per, "bytes/entry")
}

func BenchmarkBlocked(b *testing.B) {
	s := buildSynthetic(200000)
	l := NewLists(map[string]Set{config.CatAds: s, config.CatTrackers: s, config.CatMalware: s})
	names := []string{"a.b.c.host77.tracker77.example", "www.notblocked.example.org", "cdn.static.site.example.net"}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		l.Blocked(names[i%len(names)], 7)
	}
}
