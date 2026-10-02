package panel

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/veylvpn/backend/internal/backup"
	"github.com/veylvpn/backend/internal/web"
)

func TestSealer(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret.key")
	k, err := LoadOrCreateKey(path)
	if err != nil || len(k) != 32 {
		t.Fatal(err)
	}
	fi, _ := os.Stat(path)
	if fi.Mode().Perm() != 0o600 {
		t.Fatal(fi.Mode())
	}
	k2, _ := LoadOrCreateKey(path)
	if string(k) != string(k2) {
		t.Fatal("key not stable")
	}
	s, _ := NewSealer(k)
	sealed, _ := s.Seal("vpk_secret", "node-key:a")
	if strings.Contains(sealed, "vpk_secret") {
		t.Fatal("not sealed")
	}
	if v, err := s.Open(sealed, "node-key:a"); err != nil || v != "vpk_secret" {
		t.Fatal(v, err)
	}
	if _, err := s.Open(sealed, "node-key:b"); err == nil {
		t.Fatal("sealed value moved between records")
	}
	other, _ := NewSealer(make([]byte, 32))
	if _, err := other.Open(sealed, "node-key:a"); err == nil {
		t.Fatal("wrong key opened value")
	}
}

func TestBackupRoundTrip(t *testing.T) {
	h := newHarness(t, nil)
	configure(h)
	o := h.owner()
	if code, _ := o.do("POST", "/api/system/backup", map[string]string{"passphrase": "short"}); code != 400 {
		t.Fatal(code)
	}
	res, data := o.raw("POST", "/api/system/backup", map[string]string{"passphrase": "a long backup passphrase"}, nil)
	if res.StatusCode != 200 || !strings.HasPrefix(string(data), backup.Magic) {
		t.Fatal(res.StatusCode)
	}
	if _, err := RestoreBackup(h.paths, data, "a long backup passphrase", false); err != ErrPanelExists {
		t.Fatal(err)
	}
	if _, err := RestoreBackup(h.paths, data, "the wrong passphrase", true); err != backup.ErrPassphrase {
		t.Fatal(err)
	}
	dir := t.TempDir()
	h2 := newHarness(t, nil)
	h2.paths.Data = dir
	written, err := RestoreBackup(h2.paths, data, "a long backup passphrase", false)
	if err != nil || len(written) != 3 {
		t.Fatal(err, written)
	}
	k1, _ := os.ReadFile(h.paths.Secret())
	k2, _ := os.ReadFile(filepath.Join(dir, "secret.key"))
	if string(k1) != string(k2) {
		t.Fatal("secret key not restored")
	}
	if _, err := backup.Open(data, "a long backup passphrase"); err == nil {
		t.Fatal("panel backup accepted as node backup")
	}
}

func TestStaticAndHeaders(t *testing.T) {
	h := newHarness(t, nil)
	c := h.client()
	for path, ct := range map[string]string{"/": "text/html", "/setup": "text/html", "/join": "text/html", "/app.js": "text/javascript", "/control.css": "text/css", "/favicon.svg": "image/svg+xml"} {
		res, _ := c.raw("GET", path, nil, nil)
		if res.StatusCode != 200 || !strings.HasPrefix(res.Header.Get("Content-Type"), ct) || res.Header.Get("Content-Security-Policy") != web.CSP {
			t.Errorf("%s: %d %s", path, res.StatusCode, res.Header.Get("Content-Type"))
		}
		if res.Header.Get("X-Frame-Options") != "DENY" {
			t.Error("no frame header")
		}
	}
	for _, path := range []string{"/app.html", "/../go.mod", "/.env", "/x.go"} {
		if res, _ := c.raw("GET", path, nil, nil); res.StatusCode == 200 {
			t.Errorf("%s served", path)
		}
	}
	if res, b := c.raw("GET", "/v1/health", nil, nil); res.StatusCode != 200 || !strings.Contains(string(b), "ok") {
		t.Fatal(res.StatusCode)
	}
}

func TestNotify(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "notify")
	ln, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: sock, Net: "unixgram"})
	if err != nil {
		t.Skip(err)
	}
	defer ln.Close()
	t.Setenv("NOTIFY_SOCKET", sock)
	if err := Notify("READY=1"); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	_ = ln.SetReadDeadline(time.Now().Add(time.Second))
	n, _, err := ln.ReadFrom(buf)
	if err != nil || string(buf[:n]) != "READY=1" {
		t.Fatal(err, string(buf[:n]))
	}
	t.Setenv("WATCHDOG_USEC", "30000000")
	t.Setenv("WATCHDOG_PID", "")
	if WatchdogInterval() != 15*time.Second {
		t.Fatal(WatchdogInterval())
	}
	t.Setenv("WATCHDOG_PID", "1")
	if WatchdogInterval() != 0 {
		t.Fatal("watchdog for another pid")
	}
}

func TestSetupLink(t *testing.T) {
	if SetupLink("203.0.113.5", "tok", false) != "http://203.0.113.5/control/setup#tok" || SetupLink("2001:db8::1", "t", false) != "http://[2001:db8::1]/control/setup#t" || SetupLink("control.example.com", "t", true) != "https://control.example.com/setup#t" {
		t.Fatal("links")
	}
}

func TestPanelCopyRules(t *testing.T) {
	for _, name := range []string{"app.html", "setup.html", "app.js", "setup.js", "control.css"} {
		b, err := webFS.ReadFile("web/" + name)
		if err != nil {
			t.Fatal(err)
		}
		for _, bad := range []string{"—", "–", "…", "eyebrow", "style=", "<script>", "/*", "<!--"} {
			if strings.Contains(string(b), bad) {
				t.Errorf("%s contains %q", name, bad)
			}
		}
	}
}
