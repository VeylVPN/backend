package web

import (
	"bufio"
	"context"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/veylvpn/backend/internal/agentapi"
)

func TestQRMatchesReference(t *testing.T) {
	cases := map[string]struct {
		file string
		mask int
	}{
		"otpauth://totp/Veyl:admin?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&issuer=Veyl&algorithm=SHA1&digits=6&period=30": {"testdata/qr_v7_mask5.txt", 5},
		"hello veyl": {"testdata/qr_v1_mask3.txt", 3},
	}
	for text, c := range cases {
		raw, err := os.ReadFile(c.file)
		if err != nil {
			t.Fatal(err)
		}
		lines := strings.Fields(string(raw))
		q, err := EncodeQR([]byte(text), c.mask)
		if err != nil {
			t.Fatal(err)
		}
		if lines[0] != strconv.Itoa(q.Version) || len(lines)-1 != q.Size {
			t.Fatal("version or size", lines[0], q.Version)
		}
		for y := 0; y < q.Size; y++ {
			for x := 0; x < q.Size; x++ {
				if (lines[y+1][x] == '1') != q.Dark(x, y) {
					t.Fatalf("%s: module %d,%d differs", c.file, x, y)
				}
			}
		}
	}
	if _, err := EncodeQR(make([]byte, 600), -1); err != ErrQRTooLong {
		t.Fatal("too long accepted")
	}
	uri, err := QRDataURI("otpauth://totp/x?secret=ABC")
	if err != nil || !strings.HasPrefix(uri, "data:image/svg+xml;base64,") {
		t.Fatal(uri, err)
	}
}

var commentRE = []*regexp.Regexp{
	regexp.MustCompile(`(?m)^\s*//`),
	regexp.MustCompile(`/\*`),
	regexp.MustCompile("<!" + "--"),
	regexp.MustCompile(`\son[a-z]+\s*=\s*["']`),
	regexp.MustCompile(`\sstyle\s*=`),
	regexp.MustCompile(`innerHTML|outerHTML|insertAdjacentHTML|document\.write|eval\(|new Function`),
	regexp.MustCompile(`<script>|<style`),
	regexp.MustCompile(`https?://(?:[a-z0-9-]+\.)+[a-z]{2,}/[^"\s]*\.(?:js|css|woff2?)`),
}

func TestAssetsHaveNoCommentsOrInlineCode(t *testing.T) {
	err := fs.WalkDir(Assets(), ".", func(name string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, _ := fs.ReadFile(Assets(), name)
		for _, re := range commentRE {
			if loc := re.FindIndex(b); loc != nil {
				t.Errorf("%s: forbidden pattern %q near %q", name, re.String(), string(b[loc[0]:min(len(b), loc[1]+30)]))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestPagesServeTypesAndCSP(t *testing.T) {
	p := NewPages("/setup", "setup.html")
	cases := map[string]string{"/setup": "text/html", "/setup/": "text/html", "/setup/setup.js": "text/javascript", "/setup/ui.js": "text/javascript", "/setup/app.css": "text/css", "/setup/favicon.svg": "image/svg+xml"}
	for path, ct := range cases {
		rec := httptest.NewRecorder()
		p.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
		if rec.Code != 200 || !strings.HasPrefix(rec.Header().Get("Content-Type"), ct) {
			t.Fatal(path, rec.Code, rec.Header().Get("Content-Type"))
		}
		if rec.Header().Get("Content-Security-Policy") != CSP || rec.Header().Get("X-Content-Type-Options") != "nosniff" || rec.Header().Get("X-Frame-Options") != "DENY" {
			t.Fatal("headers", path)
		}
	}
	for _, path := range []string{"/setup/admin.html", "/setup/../go.mod", "/setup/x/ui.js", "/setup/.hidden", "/setup/missing.js", "/elsewhere"} {
		rec := httptest.NewRecorder()
		p.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
		if rec.Code != 404 {
			t.Fatal(path, rec.Code)
		}
	}
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, httptest.NewRequest("POST", "/setup", nil))
	if rec.Code != 405 {
		t.Fatal(rec.Code)
	}
	rec = httptest.NewRecorder()
	p.ServeHTTP(rec, httptest.NewRequest("GET", "/setup/app.css", nil))
	tag := rec.Header().Get("ETag")
	req := httptest.NewRequest("GET", "/setup/app.css", nil)
	req.Header.Set("If-None-Match", tag)
	rec = httptest.NewRecorder()
	p.ServeHTTP(rec, req)
	if tag == "" || rec.Code != 304 {
		t.Fatal("etag", rec.Code)
	}
	if !strings.Contains(CSP, "default-src 'none'") || strings.Contains(CSP, "unsafe") {
		t.Fatal(CSP)
	}
}

func TestPagesReferenceOnlyLocalAssets(t *testing.T) {
	for _, page := range []string{"setup.html", "admin.html"} {
		b, _ := fs.ReadFile(Assets(), page)
		for _, m := range regexp.MustCompile(`(?:src|href)="([^"]+)"`).FindAllSubmatch(b, -1) {
			ref := string(m[1])
			if !strings.HasPrefix(ref, "/setup/") && !strings.HasPrefix(ref, "/admin/") {
				t.Fatal(page, ref)
			}
			name := ref[strings.LastIndex(ref, "/")+1:]
			if _, err := fs.Stat(Assets(), name); err != nil {
				t.Fatal(page, "missing asset", name)
			}
		}
	}
}

func TestClientIPAndSecure(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "127.0.0.1:5000"
	r.Header.Set("X-Forwarded-For", "1.2.3.4, 10.8.0.5")
	r.Header.Set("X-Forwarded-Proto", "https")
	if ClientIP(r).String() != "10.8.0.5" || !Secure(r) {
		t.Fatal(ClientIP(r))
	}
	r.RemoteAddr = "198.51.100.1:5000"
	if ClientIP(r).String() != "198.51.100.1" || Secure(r) {
		t.Fatal("trusted forwarded headers from non-proxy")
	}
}

func TestJobSSEResume(t *testing.T) {
	j := NewJob("apply")
	j.Event(agentapi.Event{Step: "a", Status: "run"})
	j.Event(agentapi.Event{Step: "a", Status: "ok", Detail: "line\nbreak"})
	srv := httptest.NewServer(http.HandlerFunc(j.ServeSSE))
	defer srv.Close()
	read := func(last string) []string {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		req, _ := http.NewRequestWithContext(ctx, "GET", srv.URL, nil)
		if last != "" {
			req.Header.Set("Last-Event-ID", last)
		}
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		var ids []string
		sc := bufio.NewScanner(res.Body)
		for sc.Scan() {
			if v, ok := strings.CutPrefix(sc.Text(), "id: "); ok {
				ids = append(ids, v)
			}
			if strings.HasPrefix(sc.Text(), "event: done") {
				return ids
			}
		}
		return ids
	}
	go func() {
		time.Sleep(100 * time.Millisecond)
		j.Event(agentapi.Event{Step: "b", Status: "ok"})
		j.Event(agentapi.Event{Done: true})
		j.Finish(map[string]string{"x": "y"}, nil)
	}()
	all := read("")
	if len(all) != 4 || all[0] != j.ID+".1" || all[3] != j.ID+".3" {
		t.Fatal(all)
	}
	resumed := read(j.ID + ".2")
	if len(resumed) != 2 || resumed[0] != j.ID+".3" {
		t.Fatal(resumed)
	}
	other := read("deadbeef.2")
	if len(other) != 4 {
		t.Fatal("foreign id should replay all", other)
	}
	steps, done, out := j.State()
	if !done || !out.OK || len(steps) != 3 || strings.Contains(steps[1].Detail, "\n") {
		t.Fatal(steps, out)
	}
}

func TestDecodeRejects(t *testing.T) {
	var v struct {
		A int `json:"a"`
	}
	cases := []struct {
		ct, body string
		code     int
	}{
		{"text/plain", `{"a":1}`, 415},
		{"application/json", `{"a":1,"b":2}`, 400},
		{"application/json", `{"a":1}{"a":2}`, 400},
		{"application/json", `{"a":"` + strings.Repeat("x", 100) + `"}`, 413},
	}
	for _, c := range cases {
		rec := httptest.NewRecorder()
		r := httptest.NewRequest("POST", "/", strings.NewReader(c.body))
		r.Header.Set("Content-Type", c.ct)
		if Decode(rec, r, &v, 64) || rec.Code != c.code {
			t.Fatal(c, rec.Code)
		}
	}
}
