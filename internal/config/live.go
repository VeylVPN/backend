package config

import (
	"os"
	"sync"
	"time"
)

type Live struct {
	mu    sync.Mutex
	path  string
	cur   Settings
	mtime time.Time
	size  int64
}

func NewLive(path string) (*Live, error) {
	l := &Live{path: path}
	if err := l.reload(); err != nil {
		return nil, err
	}
	return l, nil
}

func (l *Live) reload() error {
	s, err := Load(l.path)
	if err != nil {
		return err
	}
	l.cur = s
	if fi, err := os.Stat(l.path); err == nil {
		l.mtime, l.size = fi.ModTime(), fi.Size()
	}
	return nil
}

func (l *Live) Get() Settings {
	l.mu.Lock()
	defer l.mu.Unlock()
	if fi, err := os.Stat(l.path); err == nil && (!fi.ModTime().Equal(l.mtime) || fi.Size() != l.size) {
		_ = l.reload()
	}
	c := l.cur
	c.DNS.Default = append([]string(nil), l.cur.DNS.Default...)
	return c
}

func (l *Live) Update(fn func(*Settings) error) (Settings, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.reload(); err != nil {
		return Settings{}, err
	}
	next := l.cur
	next.DNS.Default = append([]string(nil), l.cur.DNS.Default...)
	if err := fn(&next); err != nil {
		return Settings{}, err
	}
	if err := Save(l.path, next); err != nil {
		return Settings{}, err
	}
	if err := l.reload(); err != nil {
		return Settings{}, err
	}
	return l.cur, nil
}
