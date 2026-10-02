package store

import (
	"sync"
	"time"
)

const (
	throttleFree  = 5
	throttleBase  = 60 * time.Second
	throttleMax   = 15 * time.Minute
	throttleIdle  = time.Hour
	throttlePrune = 4096
)

type entry struct {
	fails int
	until time.Time
	last  time.Time
}

type Throttle struct {
	mu  sync.Mutex
	m   map[string]*entry
	now func() time.Time
}

func NewThrottle() *Throttle {
	return &Throttle{m: map[string]*entry{}, now: time.Now}
}

func (t *Throttle) Locked(key string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	e := t.m[key]
	return e != nil && t.now().Before(e.until)
}

func (t *Throttle) Fail(key string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	if len(t.m) >= throttlePrune {
		for k, v := range t.m {
			if now.Sub(v.last) > throttleIdle && now.After(v.until) {
				delete(t.m, k)
			}
		}
	}
	e := t.m[key]
	if e == nil {
		e = &entry{}
		t.m[key] = e
	}
	e.fails++
	e.last = now
	if e.fails >= throttleFree {
		d := throttleMax
		if shift := e.fails - throttleFree; shift < 5 {
			d = throttleBase << uint(shift)
			if d > throttleMax {
				d = throttleMax
			}
		}
		e.until = now.Add(d)
	}
}

func (t *Throttle) Reset(key string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.m, key)
}
