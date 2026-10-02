package dns

import (
	"net/netip"
	"sync"
	"time"
)

const maxSources = 65536

type bucket struct {
	tokens float64
	last   time.Time
}

type limiter struct {
	mu      sync.Mutex
	rate    float64
	burst   float64
	buckets map[netip.Addr]*bucket
	now     func() time.Time
}

func newLimiter(rate, burst float64) *limiter {
	return &limiter{rate: rate, burst: burst, buckets: map[netip.Addr]*bucket{}, now: time.Now}
}

func (l *limiter) allow(a netip.Addr) bool {
	if l == nil || l.rate <= 0 {
		return true
	}
	a = a.Unmap()
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.buckets[a]
	if b == nil {
		if len(l.buckets) >= maxSources {
			l.pruneLocked(now)
			if len(l.buckets) >= maxSources {
				return false
			}
		}
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[a] = b
	}
	if el := now.Sub(b.last).Seconds(); el > 0 {
		b.tokens += el * l.rate
		if b.tokens > l.burst {
			b.tokens = l.burst
		}
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

func (l *limiter) prune() {
	if l == nil {
		return
	}
	now := l.now()
	l.mu.Lock()
	l.pruneLocked(now)
	l.mu.Unlock()
}

func (l *limiter) pruneLocked(now time.Time) {
	full := time.Duration(l.burst / l.rate * float64(time.Second))
	for a, b := range l.buckets {
		if now.Sub(b.last) >= full {
			delete(l.buckets, a)
		}
	}
}

func (l *limiter) size() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.buckets)
}
