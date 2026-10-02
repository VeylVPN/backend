package config

import (
	"fmt"
	"sort"
)

const (
	CatAds      = "ads"
	CatTrackers = "trackers"
	CatMalware  = "malware"
	CatAdult    = "adult"
	CatGambling = "gambling"
	CatSocial   = "social"
)

var Categories = []string{CatAds, CatTrackers, CatMalware, CatAdult, CatGambling, CatSocial}

func bit(cat string) (int, bool) {
	for i, c := range Categories {
		if c == cat {
			return 1 << i, true
		}
	}
	return 0, false
}

func ValidCategories(cats []string) bool {
	seen := map[string]bool{}
	for _, c := range cats {
		if _, ok := bit(c); !ok || seen[c] {
			return false
		}
		seen[c] = true
	}
	return true
}

func Mask(cats []string) int {
	m := 0
	for _, c := range cats {
		if b, ok := bit(c); ok {
			m |= b
		}
	}
	return m
}

func FromMask(m int) []string {
	out := []string{}
	for i, c := range Categories {
		if m&(1<<i) != 0 {
			out = append(out, c)
		}
	}
	return out
}

func MaxMask() int {
	return 1<<len(Categories) - 1
}

func DNSAddr(cats []string) string {
	return DNSAddrForMask(Mask(cats))
}

func DNSAddrForMask(m int) string {
	return fmt.Sprintf("%s.%d", DNSPrefix, m+1)
}

func MaskForAddr(addr string) (int, bool) {
	var a, b, c, d int
	if n, err := fmt.Sscanf(addr, "%d.%d.%d.%d", &a, &b, &c, &d); err != nil || n != 4 {
		return 0, false
	}
	if fmt.Sprintf("%d.%d.%d", a, b, c) != DNSPrefix || d < 1 || d > MaxMask()+1 {
		return 0, false
	}
	return d - 1, true
}

func SortedCategories(cats []string) []string {
	out := append([]string(nil), cats...)
	order := map[string]int{}
	for i, c := range Categories {
		order[c] = i
	}
	sort.Slice(out, func(i, j int) bool { return order[out[i]] < order[out[j]] })
	return out
}
