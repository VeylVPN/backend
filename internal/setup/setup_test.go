package setup

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/veylvpn/backend/internal/admin"
	"github.com/veylvpn/backend/internal/agentapi"
	"github.com/veylvpn/backend/internal/app"
	"github.com/veylvpn/backend/internal/backup"
	"github.com/veylvpn/backend/internal/config"
	"github.com/veylvpn/backend/internal/pki"
	"github.com/veylvpn/backend/internal/store"
)

type fakeAgent struct {
	mu   sync.Mutex
	ops  []string
	fail map[string]string
}

func (f *fakeAgent) Do(ctx context.Context, req agentapi.Request, fn func(agentapi.Event)) error {
	f.mu.Lock()
	f.ops = append(f.ops, req.Op)
	msg := f.fail[req.Op]
	f.mu.Unlock()
	if req.Op == agentapi.OpStatus {
		fn(agentapi.Event{Data: map[string]string{"public_ip": "203.0.113.5", "openssl": "3.0.13", "os": "Debian 12"}})
		fn(agentapi.Event{Done: true})
		return nil
	}
	fn(agentapi.Event{Step: req.Op + "-1", Status: agentapi.StatusRun})
	fn(agentapi.Event{Step: req.Op + "-1", Status: agentapi.StatusOK})
	if msg != "" {
		fn(agentapi.Event{Done: true, Error: msg})
		return agentapi.ErrAgent
	}
	fn(agentapi.Event{Done: true})
	return nil
}

const tok = "test-token-abcdefghijklmnopqrstuvwxyz0123456"

type env struct {
	t     *testing.T
	w     *Wizard
	d     app.Deps
	agent *fakeAgent
	srv   *httptest.Server
	c     *http.Client
	csrf  string
	https bool
}

func newEnv(t *testing.T) *env {
	t.Helper()
	dir := t.TempDir()
	p := config.Paths{Data: dir, Run: dir}
	live, err := config.NewLive(p.Settings())
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(p.State())
	if err != nil {
		t.Fatal(err)
	}
	ca, err := pki.Init(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.SetupToken(), []byte(tok+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ag := &fakeAgent{fail: map[string]string{}}
	d := app.Deps{Paths: p, Settings: live, Store: st, CA: ca, Agent: ag}
	w := New(d)
	srv := httptest.NewServer(w.Handler())
	t.Cleanup(srv.Close)
	return &env{t: t, w: w, d: d, agent: ag, srv: srv, c: client()}
}

func client() *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{Jar: jar}
}

func (e *env) do(method, path string, body any, hdr map[string]string) (*http.Response, map[string]any) {
	e.t.Helper()
	var r io.Reader
	ct := ""
	switch b := body.(type) {
	case nil:
	case []byte:
		r = bytes.NewReader(b)
		ct = "application/octet-stream"
	default:
		raw, _ := json.Marshal(b)
		r = bytes.NewReader(raw)
		ct = "application/json"
	}
	req, _ := http.NewRequest(method, e.srv.URL+path, r)
	if ct != "" {
		req.Header.Set("Content-Type", ct)
	}
	if e.csrf != "" {
		req.Header.Set(CSRFHeader, e.csrf)
	}
	if e.https {
		req.Header.Set("X-Forwarded-Proto", "https")
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	res, err := e.c.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	return res, out
}

func (e *env) open() {
	e.t.Helper()
	res, out := e.do("POST", "/v1/setup/session", nil, map[string]string{TokenHeader: tok})
	if res.StatusCode != 200 {
		e.t.Fatal(res.StatusCode, out)
	}
	e.csrf = out["csrf"].(string)
}

func (e *env) sse() (int, map[string]any) {
	e.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", e.srv.URL+"/v1/setup/progress", nil)
	res, err := e.c.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		e.t.Fatal("progress", res.StatusCode)
	}
	steps := 0
	ev := ""
	sc := bufio.NewScanner(res.Body)
	for sc.Scan() {
		if v, ok := strings.CutPrefix(sc.Text(), "event: "); ok {
			ev = v
		}
		if v, ok := strings.CutPrefix(sc.Text(), "data: "); ok {
			if ev == "step" {
				steps++
			}
			if ev == "done" {
				var out map[string]any
				_ = json.Unmarshal([]byte(v), &out)
				return steps, out
			}
		}
	}
	e.t.Fatal("stream ended without done")
	return 0, nil
}

func TestTokenAuth(t *testing.T) {
	e := newEnv(t)
	if res, _ := e.do("GET", "/v1/setup/state", nil, nil); res.StatusCode != 401 {
		t.Fatal("state without session", res.StatusCode)
	}
	if res, _ := e.do("POST", "/v1/setup/session", nil, map[string]string{TokenHeader: "wrong"}); res.StatusCode != 403 {
		t.Fatal(res.StatusCode)
	}
	if res, _ := e.do("POST", "/v1/setup/session", nil, nil); res.StatusCode != 403 {
		t.Fatal("empty token accepted")
	}
	res, out := e.do("POST", "/v1/setup/session", nil, map[string]string{TokenHeader: tok, "X-Forwarded-Proto": "https"})
	if res.StatusCode != 200 || out["csrf"] == "" {
		t.Fatal(res.StatusCode)
	}
	var ck *http.Cookie
	for _, c := range res.Cookies() {
		if c.Name == SessionCookie {
			ck = c
		}
	}
	if ck == nil || !ck.HttpOnly || !ck.Secure || ck.SameSite != http.SameSiteStrictMode {
		t.Fatalf("%+v", ck)
	}
	e.open()
	res, out = e.do("GET", "/v1/setup/state", nil, nil)
	if res.StatusCode != 200 || out["configured"] != false {
		t.Fatal(res.StatusCode)
	}
	if out["facts"].(map[string]any)["pq_available"] != false {
		t.Fatal("pq should be unavailable on openssl 3.0")
	}
}

func TestTokenThrottle(t *testing.T) {
	e := newEnv(t)
	for i := 0; i < 5; i++ {
		e.do("POST", "/v1/setup/session", nil, map[string]string{TokenHeader: "bad"})
	}
	if res, _ := e.do("POST", "/v1/setup/session", nil, map[string]string{TokenHeader: tok}); res.StatusCode != 429 {
		t.Fatal("not throttled", res.StatusCode)
	}
	now := time.Now().Add(2 * time.Minute)
	e.w.now = func() time.Time { return now }
	if res, _ := e.do("POST", "/v1/setup/session", nil, map[string]string{TokenHeader: tok}); res.StatusCode != 200 {
		t.Fatal("throttle did not expire", res.StatusCode)
	}
}

func TestMissingTokenFile(t *testing.T) {
	e := newEnv(t)
	_ = os.Remove(e.d.Paths.SetupToken())
	if res, _ := e.do("POST", "/v1/setup/session", nil, map[string]string{TokenHeader: ""}); res.StatusCode != 403 {
		t.Fatal(res.StatusCode)
	}
}

func TestCSRFAndSessionExpiry(t *testing.T) {
	e := newEnv(t)
	e.open()
	good := e.csrf
	e.csrf = ""
	if res, _ := e.do("POST", "/v1/setup/address", map[string]string{"mode": "free"}, nil); res.StatusCode != 403 {
		t.Fatal("csrf missing accepted")
	}
	e.csrf = good
	now := time.Now().Add(SessionTTL + time.Minute)
	e.w.now = func() time.Time { return now }
	if res, _ := e.do("GET", "/v1/setup/state", nil, nil); res.StatusCode != 401 {
		t.Fatal("expired session accepted")
	}
}

func TestAddressStep(t *testing.T) {
	e := newEnv(t)
	e.open()
	res, out := e.do("POST", "/v1/setup/address", map[string]string{"mode": "domain", "host": "bad host"}, nil)
	if res.StatusCode != 400 {
		t.Fatal(out)
	}
	res, _ = e.do("POST", "/v1/setup/address", map[string]string{"mode": "domain", "host": "1.2.3.4"}, nil)
	if res.StatusCode != 400 {
		t.Fatal("ip accepted as domain")
	}
	res, _ = e.do("POST", "/v1/setup/address", map[string]string{"mode": "domain", "host": "vpn.example.com", "email": "a b@example.com"}, nil)
	if res.StatusCode != 400 {
		t.Fatal("bad email accepted")
	}
	res, out = e.do("POST", "/v1/setup/address", map[string]string{"mode": "domain", "host": "VPN.Example.com.", "email": "me@example.com"}, nil)
	if res.StatusCode != 200 || out["host"] != "vpn.example.com" || out["tls"] != "acme" {
		t.Fatal(out)
	}
	s := e.d.Settings.Get()
	if s.Host != "vpn.example.com" || s.ACMEEmail != "me@example.com" || s.Configured {
		t.Fatal(s)
	}
	res, out = e.do("POST", "/v1/setup/address", map[string]string{"mode": "free"}, nil)
	if out["host"] != "203-0-113-5.sslip.io" || out["tls"] != "acme" {
		t.Fatal(out)
	}
	res, out = e.do("POST", "/v1/setup/address", map[string]any{"mode": "free", "self_signed": true}, nil)
	if out["tls"] != "internal" {
		t.Fatal(out)
	}
	res, out = e.do("POST", "/v1/setup/address", map[string]string{"mode": "ip"}, nil)
	if out["host"] != "203.0.113.5" || out["tls"] != "internal" {
		t.Fatal(out)
	}
	if res, _ = e.do("POST", "/v1/setup/address", map[string]string{"mode": "other"}, nil); res.StatusCode != 400 {
		t.Fatal(res.StatusCode)
	}
	if SSLIPHost("2001:db8::1") != "" || SSLIPHost("198.51.100.20") != "198-51-100-20.sslip.io" {
		t.Fatal("sslip")
	}
}

func TestSecureStreamsRedirect(t *testing.T) {
	e := newEnv(t)
	e.open()
	if res, _ := e.do("POST", "/v1/setup/secure", map[string]string{}, nil); res.StatusCode != 400 {
		t.Fatal("secure without host")
	}
	e.do("POST", "/v1/setup/address", map[string]string{"mode": "free"}, nil)
	if res, _ := e.do("POST", "/v1/setup/secure", map[string]string{}, nil); res.StatusCode != 202 {
		t.Fatal(res.StatusCode)
	}
	steps, done := e.sse()
	if steps != 2 || done["ok"] != true || done["result"].(map[string]any)["redirect"] != "https://203-0-113-5.sslip.io/setup" {
		t.Fatal(steps, done)
	}
	e.agent.fail[agentapi.OpTLS] = "acme: rate limited"
	e.do("POST", "/v1/setup/secure", map[string]string{}, nil)
	_, done = e.sse()
	if done["ok"] != false || done["error"] != "acme: rate limited" {
		t.Fatal(done)
	}
}

func TestSetupWorksOverPlainHTTP(t *testing.T) {
	e := newEnv(t)
	e.open()
	e.https = false
	if res, out := e.do("POST", "/v1/setup/admin", map[string]string{"password": "a-long-enough-password"}, nil); res.StatusCode != 200 {
		t.Fatal("plain http rejected", res.StatusCode, out)
	}
	if !admin.Exists(e.d.Paths) {
		t.Fatal("admin not saved")
	}
}

func TestSettingsStepValidation(t *testing.T) {
	e := newEnv(t)
	e.open()
	cases := []any{
		map[string]any{"device_limit": 0},
		map[string]any{"dns_default": []string{"ads", "nope"}},
		map[string]any{"dns_upstream": "8.8.8.8"},
		map[string]any{"registration": "maybe"},
		map[string]any{"name": ""},
		map[string]any{"configured": true},
		map[string]any{"app_url": "javascript:alert(1)"},
	}
	for i, c := range cases {
		if res, _ := e.do("PUT", "/v1/setup/settings", c, nil); res.StatusCode != 400 {
			t.Fatal(i, res.StatusCode)
		}
	}
	res, out := e.do("PUT", "/v1/setup/settings", map[string]any{"name": "Home", "stealth": false, "device_limit": 3, "dns_default": []string{"malware", "ads"}, "dns_upstream": "quad9", "registration": "open", "admin_vpn_only": true}, nil)
	if res.StatusCode != 200 {
		t.Fatal(out)
	}
	s := e.d.Settings.Get()
	if s.Name != "Home" || s.Stealth || s.DeviceLimit != 3 || s.DNS.Default[0] != "ads" || s.DNS.Upstream != "quad9" || s.Registration != "open" || !s.AdminVPNOnly || s.Configured {
		t.Fatalf("%+v", s)
	}
	if e.d.Store.DefaultLimit() != 3 {
		t.Fatal("store limit not updated")
	}
}

func fullSetup(t *testing.T, e *env) map[string]any {
	t.Helper()
	e.open()
	e.https = true
	e.do("POST", "/v1/setup/address", map[string]string{"mode": "domain", "host": "vpn.example.com"}, nil)
	if res, _ := e.do("POST", "/v1/setup/apply", map[string]string{}, nil); res.StatusCode != 400 {
		t.Fatal("apply without admin")
	}
	if res, _ := e.do("POST", "/v1/setup/admin", map[string]string{"password": "short"}, nil); res.StatusCode != 400 {
		t.Fatal("weak admin password")
	}
	e.do("POST", "/v1/setup/admin", map[string]string{"password": "admin-password-long"}, nil)
	if res, _ := e.do("POST", "/v1/setup/account", map[string]string{"password": "short"}, nil); res.StatusCode != 400 {
		t.Fatal("weak account password")
	}
	e.do("POST", "/v1/setup/account", map[string]string{"password": "first-account-pw"}, nil)
	e.do("POST", "/v1/setup/account", map[string]string{"password": "second-account-pw"}, nil)
	if n, _, _ := e.d.Store.Counts(); n != 1 {
		t.Fatal("re-creating the first account left", n)
	}
	e.agent.fail[agentapi.OpApply] = "openvpn did not start"
	if res, _ := e.do("POST", "/v1/setup/apply", map[string]string{}, nil); res.StatusCode != 202 {
		t.Fatal(res.StatusCode)
	}
	_, done := e.sse()
	if done["ok"] != false || e.d.Settings.Get().Configured {
		t.Fatal("failed apply marked configured", done)
	}
	delete(e.agent.fail, agentapi.OpApply)
	e.do("POST", "/v1/setup/apply", map[string]string{}, nil)
	steps, done := e.sse()
	if steps != 2 || done["ok"] != true {
		t.Fatal(done)
	}
	return done["result"].(map[string]any)
}

func TestApplyCompletesAndLocks(t *testing.T) {
	e := newEnv(t)
	res := fullSetup(t, e)
	number := res["account"].(string)
	if _, err := e.d.Store.Auth(number, "second-account-pw"); err != nil {
		t.Fatal("first account unusable", err)
	}
	if res["host"] != "vpn.example.com" || res["admin_url"] != "https://vpn.example.com/admin" {
		t.Fatal(res)
	}
	if !e.d.Settings.Get().Configured {
		t.Fatal("not configured")
	}
	if _, err := os.Stat(e.d.Paths.SetupToken()); !os.IsNotExist(err) {
		t.Fatal("token not deleted")
	}
	stranger := &env{t: t, w: e.w, d: e.d, srv: e.srv, c: client()}
	for _, path := range []string{"/setup", "/setup/setup.js", "/v1/setup/state"} {
		if r, _ := stranger.do("GET", path, nil, nil); r.StatusCode != 404 {
			t.Fatal("not locked", path, r.StatusCode)
		}
	}
	if r, _ := stranger.do("POST", "/v1/setup/session", nil, map[string]string{TokenHeader: tok}); r.StatusCode != 404 {
		t.Fatal("session after lock", r.StatusCode)
	}
	if r, _ := e.do("GET", "/v1/setup/state", nil, nil); r.StatusCode != 200 {
		t.Fatal("grace session lost state", r.StatusCode)
	}
	if r, _ := e.do("POST", "/v1/setup/address", map[string]string{"mode": "free"}, nil); r.StatusCode != 404 {
		t.Fatal("grace session can still change things", r.StatusCode)
	}
	if _, done := e.sse(); done["result"].(map[string]any)["account"] != number {
		t.Fatal("result not replayed")
	}
	b, _ := json.Marshal(map[string]string{"passphrase": "backup-passphrase"})
	req, _ := http.NewRequest("POST", e.srv.URL+"/v1/setup/backup", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(CSRFHeader, e.csrf)
	r, err := e.c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := io.ReadAll(r.Body)
	r.Body.Close()
	if r.StatusCode != 200 || !bytes.HasPrefix(data, []byte(backup.Magic)) {
		t.Fatal("backup download", r.StatusCode)
	}
	later := time.Now().Add(Grace + time.Minute)
	e.w.now = func() time.Time { return later }
	if r, _ := e.do("GET", "/v1/setup/state", nil, nil); r.StatusCode != 404 {
		t.Fatal("grace never ends", r.StatusCode)
	}
}

func TestRestorePath(t *testing.T) {
	old := newEnv(t)
	fullSetup(t, old)
	data, err := backup.Create(old.d.Paths, "backup-passphrase")
	if err != nil {
		t.Fatal(err)
	}
	e := newEnv(t)
	e.open()
	e.do("POST", "/v1/setup/address", map[string]any{"mode": "free", "restore": true}, nil)
	if r, _ := e.do("POST", "/v1/setup/restore", data, map[string]string{PassHeader: base64.RawURLEncoding.EncodeToString([]byte("wrong-passphrase"))}); r.StatusCode != 400 {
		t.Fatal("wrong passphrase", r.StatusCode)
	}
	if r, _ := e.do("POST", "/v1/setup/restore", []byte("junk"), map[string]string{PassHeader: base64.RawURLEncoding.EncodeToString([]byte("backup-passphrase"))}); r.StatusCode != 400 {
		t.Fatal("junk", r.StatusCode)
	}
	r, out := e.do("POST", "/v1/setup/restore", data, map[string]string{PassHeader: base64.RawURLEncoding.EncodeToString([]byte("backup-passphrase"))})
	if r.StatusCode != 200 {
		t.Fatal(r.StatusCode, out)
	}
	s := e.d.Settings.Get()
	if s.Configured || s.Host != "203-0-113-5.sslip.io" {
		t.Fatalf("%+v", s)
	}
	if n, _, _ := e.d.Store.Counts(); n != 1 {
		t.Fatal("accounts not restored")
	}
	if !bytes.Equal(e.d.CA.CertPEM(), old.d.CA.CertPEM()) {
		t.Fatal("ca not reloaded")
	}
	_, st := e.do("GET", "/v1/setup/state", nil, nil)
	if st["restored"] != true || st["restore"] != true || st["admin_set"] != true {
		t.Fatal(st)
	}
	e.do("POST", "/v1/setup/apply", map[string]string{}, nil)
	_, done := e.sse()
	if done["ok"] != true || done["result"].(map[string]any)["restored"] != true {
		t.Fatal(done)
	}
}

func fakeResolver(t *testing.T, answers map[string][]net.IP, nx bool) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 512)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			q := append([]byte(nil), buf[:n]...)
			off := 12
			var labels []string
			for q[off] != 0 {
				l := int(q[off])
				labels = append(labels, string(q[off+1:off+1+l]))
				off += 1 + l
			}
			qtype := binary.BigEndian.Uint16(q[off+1:])
			resp := append([]byte(nil), q[:off+5]...)
			resp[2], resp[3] = 0x81, 0x80
			if nx {
				resp[3] = 0x83
			}
			resp = append(resp, 0xc0, 12, 0, 5, 0, 1, 0, 0, 0, 60, 0, 2, 0xc0, 12)
			cnt := 1
			for _, ip := range answers[strings.Join(labels, ".")] {
				v4 := ip.To4()
				if v4 != nil && qtype == typeA {
					resp = append(resp, 0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4)
					resp = append(resp, v4...)
					cnt++
				}
				if v4 == nil && qtype == typeAAAA {
					resp = append(resp, 0xc0, 12, 0, 28, 0, 1, 0, 0, 0, 60, 0, 16)
					resp = append(resp, ip.To16()...)
					cnt++
				}
			}
			binary.BigEndian.PutUint16(resp[6:], uint16(cnt))
			_, _ = pc.WriteTo(resp, from)
		}
	}()
	return pc.LocalAddr().String()
}

func TestDNSCheck(t *testing.T) {
	e := newEnv(t)
	e.open()
	ans := map[string][]net.IP{
		"ok.example.com":    {net.ParseIP("203.0.113.5"), net.ParseIP("2001:db8::1")},
		"wrong.example.com": {net.ParseIP("198.51.100.7")},
		"mixed.example.com": {net.ParseIP("203.0.113.5"), net.ParseIP("198.51.100.7")},
		"cf.example.com":    {net.ParseIP("104.16.1.1")},
	}
	e.w.Resolvers = []string{fakeResolver(t, ans, false), fakeResolver(t, ans, false)}
	e.w.DNSTimeout = time.Second
	for host, want := range map[string]string{"ok.example.com": "ok", "wrong.example.com": "wrong", "mixed.example.com": "mixed", "cf.example.com": "proxied", "none.example.com": "missing"} {
		r, out := e.do("GET", "/v1/setup/dns-check?host="+host, nil, nil)
		if r.StatusCode != 200 || out["status"] != want {
			t.Fatal(host, out)
		}
		if host == "ok.example.com" && out["note"] == nil {
			t.Fatal("aaaa mismatch not noted")
		}
	}
	if r, _ := e.do("GET", "/v1/setup/dns-check?host=bad%0Ahost", nil, nil); r.StatusCode != 400 {
		t.Fatal(r.StatusCode)
	}
	e.w.Resolvers = []string{fakeResolver(t, nil, true)}
	if _, out := e.do("GET", "/v1/setup/dns-check?host=gone.example.com", nil, nil); out["status"] != "missing" {
		t.Fatal(out)
	}
	pc, _ := net.ListenPacket("udp", "127.0.0.1:0")
	dead := pc.LocalAddr().String()
	pc.Close()
	e.w.Resolvers = []string{dead}
	e.w.DNSTimeout = 200 * time.Millisecond
	if _, out := e.do("GET", "/v1/setup/dns-check?host=ok.example.com", nil, nil); out["status"] != "error" {
		t.Fatal(out)
	}
}

func TestBuildQueryRejectsBadNames(t *testing.T) {
	if _, err := buildQuery(1, strings.Repeat("a", 64)+".com", typeA); err == nil {
		t.Fatal("long label")
	}
	if _, err := buildQuery(1, "a..com", typeA); err == nil {
		t.Fatal("empty label")
	}
	q, err := buildQuery(0x1234, "vpn.example.com.", typeAAAA)
	if err != nil || len(q) != 12+17+4 || q[0] != 0x12 || q[len(q)-3] != typeAAAA {
		t.Fatal(q, err)
	}
}

func FuzzParseAnswer(f *testing.F) {
	q, _ := buildQuery(7, "a.example.com", typeA)
	resp := append([]byte(nil), q...)
	resp[2] = 0x81
	resp[7] = 1
	resp = append(resp, 0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 1, 0, 4, 1, 2, 3, 4)
	f.Add(resp)
	f.Add([]byte{0, 7, 0x81, 0x80, 0, 1, 0, 1, 0xc0})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		ips, _ := parseAnswer(b, 7, typeA)
		for _, ip := range ips {
			if len(ip) != 4 {
				t.Fatal("bad ip length")
			}
		}
	})
}

func TestLinkAndNewToken(t *testing.T) {
	p := config.Paths{Data: t.TempDir()}
	a, err := NewToken(p)
	if err != nil || len(a) != 43 {
		t.Fatal(a, err)
	}
	b, _ := NewToken(p)
	raw, _ := os.ReadFile(p.SetupToken())
	if a == b || strings.TrimSpace(string(raw)) != b {
		t.Fatal("token not rotated")
	}
	fi, _ := os.Stat(p.SetupToken())
	if runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
		t.Fatal(fi.Mode())
	}
	if Link("203.0.113.5", "t", false) != "http://203.0.113.5/setup#t" || Link("2001:db8::1", "t", true) != "https://[2001:db8::1]/setup#t" {
		t.Fatal("link")
	}
}

func TestSetupPageServedAndOtherPaths404(t *testing.T) {
	e := newEnv(t)
	r, _ := e.do("GET", "/setup", nil, nil)
	if r.StatusCode != 200 || !strings.HasPrefix(r.Header.Get("Content-Type"), "text/html") || !strings.Contains(r.Header.Get("Content-Security-Policy"), "default-src 'none'") {
		t.Fatal(r.StatusCode, r.Header)
	}
	for _, p := range []string{"/v1/info", "/admin", "/setupx/../x"} {
		if r, _ := e.do("GET", p, nil, nil); r.StatusCode != 404 {
			t.Fatal(p, r.StatusCode)
		}
	}
}
