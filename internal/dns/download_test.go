package dns

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/veylvpn/backend/internal/config"
)

func domains(prefix string, n int) string {
	var b strings.Builder
	b.WriteString("# list\r\n")
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "%s%d.Example.com\r\n", prefix, i)
	}
	return b.String()
}

func withSources(t *testing.T, m map[string][]string) {
	t.Helper()
	old := BlocklistSources
	BlocklistSources = m
	t.Cleanup(func() { BlocklistSources = old })
}

func TestDownload(t *testing.T) {
	bodies := map[string]string{
		"/ads":     domains("ad", 150) + "ad1.example.com\n",
		"/mal1":    domains("m", 80),
		"/mal2":    "127.0.0.1\tm79.example.com\n127.0.0.1 x0.example.com\n" + domains("x", 30),
		"/small":   domains("s", 10),
		"/big":     strings.Repeat("a.example.com\n", 2000),
		"/missing": "",
	}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redir" {
			http.Redirect(w, r, "http://example.invalid/x", http.StatusFound)
			return
		}
		b, ok := bodies[r.URL.Path]
		if !ok || b == "" {
			http.NotFound(w, r)
			return
		}
		w.Write([]byte(b))
	}))
	defer srv.Close()
	dir := t.TempDir()
	prevSmall := "keep.example.com\n"
	os.WriteFile(ListPath(dir, config.CatAdult), []byte(prevSmall), 0o600)
	os.WriteFile(ListPath(dir, config.CatGambling), []byte(prevSmall), 0o600)
	os.WriteFile(ListPath(dir, config.CatSocial), []byte(prevSmall), 0o600)
	old := maxSourceBytes
	maxSourceBytes = 10000
	t.Cleanup(func() { maxSourceBytes = old })
	withSources(t, map[string][]string{
		config.CatAds:      {srv.URL + "/ads"},
		config.CatMalware:  {srv.URL + "/mal1", srv.URL + "/missing", srv.URL + "/mal2"},
		config.CatAdult:    {srv.URL + "/small"},
		config.CatGambling: {srv.URL + "/big", "http://" + strings.TrimPrefix(srv.URL, "https://") + "/ads"},
		config.CatSocial:   {srv.URL + "/redir"},
	})
	counts, err := Download(context.Background(), dir, srv.Client())
	if err == nil {
		t.Fatal("expected aggregated errors")
	}
	if counts[config.CatAds] != 150 || counts[config.CatMalware] != 110 {
		t.Fatalf("counts %v", counts)
	}
	if _, ok := counts[config.CatAdult]; ok {
		t.Fatal("small list must not be written")
	}
	ads, _ := os.ReadFile(ListPath(dir, config.CatAds))
	lines := strings.Split(strings.TrimSpace(string(ads)), "\n")
	if len(lines) != 150 || lines[0] != "ad0.example.com" || strings.Contains(string(ads), "\r") || strings.Contains(string(ads), "#") {
		t.Fatalf("ads file not normalized: %q", lines[:3])
	}
	for i := 1; i < len(lines); i++ {
		if lines[i-1] >= lines[i] {
			t.Fatal("not sorted unique")
		}
	}
	fi, _ := os.Stat(ListPath(dir, config.CatAds))
	if fi.Mode().Perm() != 0o644 {
		t.Fatalf("mode %v", fi.Mode().Perm())
	}
	for _, c := range []string{config.CatAdult, config.CatGambling, config.CatSocial} {
		b, _ := os.ReadFile(ListPath(dir, c))
		if string(b) != prevSmall {
			t.Fatalf("%s overwritten", c)
		}
	}
	if _, err := os.Stat(ListPath(dir, config.CatTrackers)); !os.IsNotExist(err) {
		t.Fatal("category without sources written")
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".") {
			t.Fatalf("temp file left: %s", e.Name())
		}
	}
	bl := NewBlocklists(dir)
	bl.Reload(true)
	if !bl.Lists().Blocked("sub.x29.example.com", config.Mask([]string{config.CatMalware})) {
		t.Fatal("downloaded list not loadable")
	}
}

func TestDownloadSizeCap(t *testing.T) {
	body := domains("big", 500)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(body))
	}))
	defer srv.Close()
	withSources(t, map[string][]string{config.CatAds: {srv.URL + "/x"}})
	old := maxSourceBytes
	t.Cleanup(func() { maxSourceBytes = old })
	dir := t.TempDir()
	maxSourceBytes = int64(len(body) - 1)
	counts, err := Download(context.Background(), dir, srv.Client())
	if err == nil || !strings.Contains(err.Error(), "larger") || len(counts) != 0 {
		t.Fatalf("cap not enforced: %v %v", counts, err)
	}
	maxSourceBytes = int64(len(body))
	counts, err = Download(context.Background(), dir, srv.Client())
	if err != nil || counts[config.CatAds] != 500 {
		t.Fatalf("exact size rejected: %v %v", counts, err)
	}
}

func TestDownloadCanceled(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(bytes.Repeat([]byte("a.example.com\n"), 200))
	}))
	defer srv.Close()
	withSources(t, map[string][]string{config.CatAds: {srv.URL}})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	dir := t.TempDir()
	counts, err := Download(ctx, dir, srv.Client())
	if err == nil || len(counts) != 0 {
		t.Fatal("canceled download succeeded")
	}
}

func TestBlocklistSourcesTable(t *testing.T) {
	for _, c := range config.Categories {
		if len(BlocklistSources[c]) == 0 {
			t.Fatalf("no sources for %s", c)
		}
		for _, u := range BlocklistSources[c] {
			if !strings.HasPrefix(u, "https://") {
				t.Fatalf("non-https source %s", u)
			}
		}
	}
	if len(BlocklistSources[config.CatMalware]) != 2 {
		t.Fatal("malware sources")
	}
}
