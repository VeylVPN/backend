package dns

import (
	"slices"
	"strings"

	"github.com/veylvpn/backend/internal/config"
)

const (
	fnvOffset64 = 14695981039346656037
	fnvPrime64  = 1099511628211
)

func Hash(name string) uint64 {
	h := uint64(fnvOffset64)
	for i := 0; i < len(name); i++ {
		c := name[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		h ^= uint64(c)
		h *= fnvPrime64
	}
	return h
}

type Set []uint64

func NewSet(hashes []uint64) Set {
	slices.Sort(hashes)
	hashes = slices.Compact(hashes)
	out := make(Set, len(hashes))
	copy(out, hashes)
	return out
}

func (s Set) Has(h uint64) bool {
	_, ok := slices.BinarySearch(s, h)
	return ok
}

func (s Set) Len() int { return len(s) }

type Lists struct {
	sets []Set
}

func NewLists(sets map[string]Set) *Lists {
	l := &Lists{sets: make([]Set, len(config.Categories))}
	for i, c := range config.Categories {
		l.sets[i] = sets[c]
	}
	return l
}

func (l *Lists) Count(cat string) int {
	if l == nil {
		return 0
	}
	for i, c := range config.Categories {
		if c == cat {
			return len(l.sets[i])
		}
	}
	return 0
}

func (l *Lists) Blocked(name string, mask int) bool {
	if l == nil || mask <= 0 || name == "" {
		return false
	}
	for {
		h := Hash(name)
		for i := range l.sets {
			if mask&(1<<i) != 0 && l.sets[i].Has(h) {
				return true
			}
		}
		j := strings.IndexByte(name, '.')
		if j < 0 {
			return false
		}
		name = name[j+1:]
	}
}
