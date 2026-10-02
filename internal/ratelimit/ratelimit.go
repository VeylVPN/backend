package ratelimit

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"math"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

type Rate struct {
	PerMinute float64
	Burst     float64
}

type Policy struct {
	PerKey  Rate
	Global  Rate
	MaxKeys int
}

var (
	Auth    = Policy{PerKey: Rate{PerMinute: 10, Burst: 20}, Global: Rate{PerMinute: 300, Burst: 60}, MaxKeys: 65536}
	General = Policy{PerKey: Rate{PerMinute: 120, Burst: 120}, Global: Rate{PerMinute: 6000, Burst: 1000}, MaxKeys: 65536}
)

type bucket struct {
	tokens float64
	last   time.Time
}

func (b *bucket) refill(r Rate, now time.Time) {
	if el := now.Sub(b.last).Seconds(); el > 0 {
		b.tokens = math.Min(r.Burst, b.tokens+el*r.PerMinute/60)
	}
	b.last = now
}

func (b *bucket) wait(r Rate) time.Duration {
	need := 1 - b.tokens
	if need <= 0 || r.PerMinute <= 0 {
		return time.Second
	}
	d := time.Duration(need / (r.PerMinute / 60) * float64(time.Second))
	if d < time.Second {
		d = time.Second
	}
	return d
}

type Limiter struct {
	mu        sync.Mutex
	p         Policy
	secret    []byte
	m         map[string]*bucket
	global    bucket
	lastPrune time.Time
	Now       func() time.Time
}

func New(p Policy) *Limiter {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		panic(err)
	}
	if p.MaxKeys <= 0 {
		p.MaxKeys = 65536
	}
	l := &Limiter{p: p, secret: secret, m: map[string]*bucket{}, Now: time.Now}
	l.global = bucket{tokens: p.Global.Burst, last: time.Now()}
	return l
}

func (l *Limiter) hash(ip string) string {
	mac := hmac.New(sha256.New, l.secret)
	mac.Write([]byte(ip))
	return string(mac.Sum(nil)[:16])
}

func (l *Limiter) idle() time.Duration {
	if l.p.PerKey.PerMinute <= 0 {
		return time.Hour
	}
	return time.Duration(l.p.PerKey.Burst/(l.p.PerKey.PerMinute/60)*float64(time.Second)) + time.Second
}

func (l *Limiter) prune(now time.Time) {
	idle := l.idle()
	for k, b := range l.m {
		if now.Sub(b.last) >= idle {
			delete(l.m, k)
		}
	}
	l.lastPrune = now
}

func (l *Limiter) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.m)
}

func (l *Limiter) Allow(ip string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.Now()
	if l.global.last.IsZero() || now.Before(l.global.last) {
		l.global.last = now
	}
	l.global.refill(l.p.Global, now)
	if l.global.tokens < 1 {
		return false, l.global.wait(l.p.Global)
	}
	if ip == "" {
		l.global.tokens--
		return true, 0
	}
	if now.Sub(l.lastPrune) > time.Minute {
		l.prune(now)
	}
	k := l.hash(ip)
	b := l.m[k]
	if b == nil {
		if len(l.m) >= l.p.MaxKeys {
			l.prune(now)
			if len(l.m) >= l.p.MaxKeys {
				return false, time.Minute
			}
		}
		b = &bucket{tokens: l.p.PerKey.Burst, last: now}
		l.m[k] = b
	}
	b.refill(l.p.PerKey, now)
	if b.tokens < 1 {
		return false, b.wait(l.p.PerKey)
	}
	b.tokens--
	l.global.tokens--
	return true, 0
}

func (l *Limiter) AllowRequest(r *http.Request) (bool, time.Duration) {
	return l.Allow(ClientIP(r))
}

func hostIP(addr string) net.IP {
	h, _, err := net.SplitHostPort(addr)
	if err != nil {
		h = addr
	}
	return net.ParseIP(strings.TrimSpace(h))
}

func normalize(ip net.IP) string {
	if ip == nil || ip.IsLoopback() || ip.IsUnspecified() {
		return ""
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.Mask(net.CIDRMask(64, 128)).String()
}

func ClientIP(r *http.Request) string {
	remote := hostIP(r.RemoteAddr)
	if remote == nil {
		return ""
	}
	if !remote.IsLoopback() {
		return normalize(remote)
	}
	xff := r.Header.Values("X-Forwarded-For")
	if len(xff) == 0 {
		return ""
	}
	parts := strings.Split(xff[len(xff)-1], ",")
	last := strings.TrimSpace(parts[len(parts)-1])
	if len(last) > 64 {
		return ""
	}
	return normalize(net.ParseIP(last))
}
