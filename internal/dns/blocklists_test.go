package dns

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
	"time"

	"github.com/veylvpn/backend/internal/config"
)

func writeFile(t *testing.T, path, content string, mod time.Time) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, mod, mod); err != nil {
		t.Fatal(err)
	}
}

func TestReload(t *testing.T) {
	dir := t.TempDir()
	ads := config.Mask([]string{config.CatAds})
	soc := config.Mask([]string{config.CatSocial})
	t0 := time.Unix(1700000000, 0)
	writeFile(t, ListPath(dir, config.CatAds), "# ads\nads.example.com\r\n0.0.0.0 track.example.com\n", t0)
	b := NewBlocklists(dir)
	if b.Lists().Blocked("ads.example.com", ads) {
		t.Fatal("blocked before load")
	}
	changed, err := b.Reload(false)
	if err != nil || !changed {
		t.Fatal(changed, err)
	}
	l1 := b.Lists()
	if !l1.Blocked("x.ads.example.com", ads) || !l1.Blocked("track.example.com", ads) || l1.Count(config.CatAds) != 2 {
		t.Fatal("ads not loaded")
	}
	if l1.Count(config.CatSocial) != 0 {
		t.Fatal("missing file must be empty")
	}
	if changed, _ := b.Reload(false); changed || b.Lists() != l1 {
		t.Fatal("unchanged files must not swap")
	}
	writeFile(t, ListPath(dir, config.CatAds), "other.example.com\n", t0.Add(time.Second))
	writeFile(t, ListPath(dir, config.CatSocial), "social.example.com\n", t0)
	if changed, err := b.Reload(false); !changed || err != nil {
		t.Fatal(changed, err)
	}
	l2 := b.Lists()
	if l2.Blocked("ads.example.com", ads) || !l2.Blocked("other.example.com", ads) || !l2.Blocked("social.example.com", soc) {
		t.Fatal("reload content")
	}
	if !l1.Blocked("ads.example.com", ads) {
		t.Fatal("old snapshot mutated")
	}
	os.Remove(ListPath(dir, config.CatSocial))
	b.Reload(false)
	if b.Lists().Blocked("social.example.com", soc) || !b.Lists().Blocked("other.example.com", ads) {
		t.Fatal("removed file not emptied")
	}
	writeFile(t, ListPath(dir, config.CatAds), "sameq.example.com\n", t0.Add(time.Second))
	if changed, _ := b.Reload(false); changed {
		t.Fatal("same stamp should not reload")
	}
	if changed, _ := b.Reload(true); !changed || !b.Lists().Blocked("sameq.example.com", ads) {
		t.Fatal("forced reload")
	}
}

func TestReloadBadFileKeepsOld(t *testing.T) {
	dir := t.TempDir()
	p := ListPath(dir, config.CatAds)
	writeFile(t, p, "keep.example.com\n", time.Unix(1700000000, 0))
	b := NewBlocklists(dir)
	b.Reload(false)
	os.Remove(p)
	if err := os.Mkdir(p, 0o755); err != nil {
		t.Fatal(err)
	}
	b.Reload(false)
	if b.Lists().Blocked("keep.example.com", 1) {
		t.Fatal("directory in place of file should read as empty")
	}
	os.Remove(p)
	writeFile(t, p, "keep.example.com\n", time.Unix(1700000001, 0))
	os.Chmod(p, 0)
	if os.Geteuid() == 0 || runtime.GOOS == "windows" {
		t.Skip("root ignores permissions")
	}
	if _, err := b.Reload(true); err == nil {
		t.Fatal("expected error on unreadable file")
	}
}

func TestRunReloadsOnSignal(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, config.CatAds+".txt")
	t0 := time.Unix(1700000000, 0)
	writeFile(t, p, "one.example.com\n", t0)
	b := NewBlocklists(dir)
	b.Reload(false)
	hup := make(chan os.Signal, 1)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		b.Run(ctx, time.Hour, hup)
		close(done)
	}()
	writeFile(t, p, "two.example.com\n", t0)
	hup <- syscall.SIGHUP
	deadline := time.Now().Add(3 * time.Second)
	for !b.Lists().Blocked("two.example.com", 1) {
		if time.Now().After(deadline) {
			t.Fatal("sighup reload did not happen")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
}

func TestRunReloadsOnTimer(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, config.CatMalware+".txt")
	b := NewBlocklists(dir)
	b.Reload(false)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go b.Run(ctx, 20*time.Millisecond, nil)
	writeFile(t, p, "late.example.com\n", time.Unix(1700000000, 0))
	deadline := time.Now().Add(3 * time.Second)
	for !b.Lists().Blocked("late.example.com", config.Mask([]string{config.CatMalware})) {
		if time.Now().After(deadline) {
			t.Fatal("timer reload did not happen")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
