package web

import (
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
)

func TestBrandExposesOnlyBrandFiles(t *testing.T) {
	b := Brand()
	for _, name := range BrandFiles {
		if _, err := fs.ReadFile(b, name); err != nil {
			t.Fatal(name, err)
		}
	}
	for _, name := range []string{"setup.js", "admin.js", "setup.html", "admin.html"} {
		if _, err := fs.ReadFile(b, name); !errors.Is(err, fs.ErrNotExist) {
			t.Fatal(name, err)
		}
	}
	entries, err := fs.ReadDir(b, ".")
	if err != nil || len(entries) != len(BrandFiles) {
		t.Fatal(len(entries), err)
	}
}

func TestOverlayPagesServeBrandAndOwnFiles(t *testing.T) {
	own := fstest.MapFS{
		"panel.html": {Data: []byte("<!doctype html><title>Panel</title>")},
		"panel.js":   {Data: []byte("\"use strict\";")},
	}
	p := NewPagesFS("/panel", "panel.html", Overlay(own, Brand()))
	for path, ct := range map[string]string{"/panel": "text/html", "/panel/panel.js": "text/javascript", "/panel/brand.css": "text/css", "/panel/brand.js": "text/javascript", "/panel/mark.svg": "image/svg+xml"} {
		rec := httptest.NewRecorder()
		p.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
		if rec.Code != 200 || !strings.HasPrefix(rec.Header().Get("Content-Type"), ct) || rec.Header().Get("Content-Security-Policy") != CSP {
			t.Fatal(path, rec.Code, rec.Header().Get("Content-Type"))
		}
	}
	for _, path := range []string{"/panel/setup.js", "/panel/admin.js"} {
		rec := httptest.NewRecorder()
		p.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
		if rec.Code != 404 {
			t.Fatal(path, rec.Code)
		}
	}
}

func TestBrandCopyRules(t *testing.T) {
	err := fs.WalkDir(Assets(), ".", func(name string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, _ := fs.ReadFile(Assets(), name)
		for _, bad := range []string{"—", "–", "eyebrow", "…"} {
			if bytes.Contains(b, []byte(bad)) {
				t.Errorf("%s contains %q", name, bad)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	css, _ := fs.ReadFile(Assets(), "brand.css")
	for _, token := range []string{"--ink-950: #05050a", "--violet-500: #715cff", "--ok: #54e870", "--radius-3xl: 52px", "--ease-veil: cubic-bezier(0.22, 1, 0.36, 1)", "url(\"" + FontRoute + "\")", "prefers-reduced-motion"} {
		if !bytes.Contains(css, []byte(token)) {
			t.Errorf("brand.css is missing %q", token)
		}
	}
}

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func fakeClient(code int, body []byte, seen *string) *http.Client {
	return &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
		if seen != nil {
			*seen = r.URL.String()
		}
		return &http.Response{StatusCode: code, Body: io.NopCloser(bytes.NewReader(body)), Header: http.Header{}, Request: r}, nil
	})}
}

func TestFetchFontVerifiesChecksumAndSize(t *testing.T) {
	var seen string
	if _, err := FetchFont(context.Background(), fakeClient(200, []byte("not the font"), &seen)); !errors.Is(err, ErrFontChecksum) {
		t.Fatal(err)
	}
	if seen != FontURL || !strings.HasPrefix(FontURL, "https://cdn.fontshare.com/") || len(FontSHA256) != 64 {
		t.Fatal(seen)
	}
	if _, err := FetchFont(context.Background(), fakeClient(200, make([]byte, FontMax+10), nil)); !errors.Is(err, ErrFontSize) {
		t.Fatal(err)
	}
	if _, err := FetchFont(context.Background(), fakeClient(404, nil, nil)); err == nil {
		t.Fatal("404 accepted")
	}
	if FontOK(nil) || FontOK([]byte("x")) {
		t.Fatal("bad font accepted")
	}
}

func TestFontsHandler(t *testing.T) {
	dir := t.TempDir()
	h := Fonts(dir)
	get := func(path string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
		return rec
	}
	if rec := get(FontRoute); rec.Code != 404 || rec.Header().Get("Content-Security-Policy") != CSP {
		t.Fatal("missing font", rec.Code)
	}
	if err := os.MkdirAll(FontDir(dir), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(FontPath(dir), []byte("tampered"), 0o644); err != nil {
		t.Fatal(err)
	}
	if rec := get(FontRoute); rec.Code != 404 {
		t.Fatal("tampered font served", rec.Code)
	}
	if rec := get("/assets/fonts/../settings.json"); rec.Code != 404 {
		t.Fatal(rec.Code)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("POST", FontRoute, nil))
	if rec.Code != 405 {
		t.Fatal(rec.Code)
	}
	real := os.Getenv("VEYL_FONT_FILE")
	if real == "" {
		t.Skip("set VEYL_FONT_FILE to the pinned Satoshi file to check serving")
	}
	b, err := os.ReadFile(real)
	if err != nil || !FontOK(b) {
		t.Fatal("VEYL_FONT_FILE does not match the pinned checksum")
	}
	if err := os.WriteFile(filepath.Join(FontDir(dir), FontFile), b, 0o644); err != nil {
		t.Fatal(err)
	}
	if rec := get(FontRoute); rec.Code != 200 || rec.Header().Get("Content-Type") != "font/woff2" || rec.Body.Len() != len(b) {
		t.Fatal("font not served", rec.Code, rec.Header())
	}
}
