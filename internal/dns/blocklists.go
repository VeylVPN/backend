package dns

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/veylvpn/backend/internal/config"
)

const maxListFile = 256 << 20

type stamp struct {
	mod  time.Time
	size int64
	ok   bool
}

type Blocklists struct {
	dir    string
	mu     sync.Mutex
	stamps map[string]stamp
	sets   map[string]Set
	cur    atomic.Pointer[Lists]
}

func NewBlocklists(dir string) *Blocklists {
	b := &Blocklists{dir: dir, stamps: map[string]stamp{}, sets: map[string]Set{}}
	b.cur.Store(NewLists(nil))
	return b
}

func (b *Blocklists) Lists() *Lists {
	return b.cur.Load()
}

func ListPath(dir, cat string) string {
	return filepath.Join(dir, cat+".txt")
}

func (b *Blocklists) Reload(force bool) (bool, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	changed := false
	var errs []error
	for _, c := range config.Categories {
		p := ListPath(b.dir, c)
		fi, err := os.Stat(p)
		var st stamp
		if err == nil && fi.Mode().IsRegular() {
			st = stamp{mod: fi.ModTime(), size: fi.Size(), ok: true}
		} else if err != nil && !errors.Is(err, fs.ErrNotExist) {
			errs = append(errs, fmt.Errorf("%s: %w", c, err))
			continue
		}
		old, seen := b.stamps[c]
		if !force && seen && old == st {
			continue
		}
		if !st.ok {
			if len(b.sets[c]) > 0 || !seen {
				changed = true
			}
			b.sets[c] = nil
			b.stamps[c] = st
			continue
		}
		s, err := LoadFile(p)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", c, err))
			continue
		}
		b.sets[c] = s
		b.stamps[c] = st
		changed = true
	}
	if changed {
		b.cur.Store(NewLists(b.sets))
	}
	return changed, errors.Join(errs...)
}

func LoadFile(path string) (Set, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if fi.Size() > maxListFile {
		return nil, errors.New("blocklist file too large")
	}
	hashes := make([]uint64, 0, fi.Size()/20+16)
	err = Parse(io.LimitReader(f, maxListFile), func(d string) {
		hashes = append(hashes, Hash(d))
	})
	if err != nil {
		return nil, err
	}
	return NewSet(hashes), nil
}

func (b *Blocklists) Run(ctx context.Context, every time.Duration, hup <-chan os.Signal) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			b.Reload(false)
		case <-hup:
			b.Reload(true)
		}
	}
}
