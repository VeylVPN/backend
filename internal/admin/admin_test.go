package admin

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base32"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

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
	fail string
	data map[string]string
}

func (f *fakeAgent) Do(ctx context.Context, req agentapi.Request, fn func(agentapi.Event)) error {
	f.mu.Lock()
	f.ops = append(f.ops, req.Op)
	f.mu.Unlock()
	if req.Op == agentapi.OpStatus {
		fn(agentapi.Event{Data: f.data})
		fn(agentapi.Event{Done: true})
		return nil
	}
	fn(agentapi.Event{Step: "nftables", Status: agentapi.StatusRun})
	fn(agentapi.Event{Step: "nftables", Status: agentapi.StatusOK})
	if f.fail != "" {
		fn(agentapi.Event{Done: true, Error: f.fail})
		return agentapi.ErrAgent
	}
	fn(agentapi.Event{Done: true})
	return nil
}

func (f *fakeAgent) count(op string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, o := range f.ops {
		if o == op {
			n++
		}
	}
	return n
}

type fakeMgmt struct {
	mu     sync.Mutex
	on     map[string]bool
	killed []string
}

func (m *fakeMgmt) Online() (map[string]bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := map[string]bool{}
	for k, v := range m.on {
		out[k] = v
	}
	return out, nil
}

func (m *fakeMgmt) Kill(cn string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.killed = append(m.killed, cn)
	delete(m.on, cn)
	return nil
}

const adminPW = "correct-horse-battery"

type env struct {
	t     *testing.T
	a     *Admin
	d     app.Deps
	agent *fakeAgent
	mgmt  *fakeMgmt
	srv   *httptest.Server
	c     *http.Client
	csrf  string
}

func setup(t *testing.T) *env {
	t.Helper()
	dir := t.TempDir()
	p := config.Paths{Data: dir, Run: dir}
	live, err := config.NewLive(p.Settings())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := live.Update(func(s *config.Settings) error { s.Host = "vpn.example.com"; s.Configured = true; return nil }); err != nil {
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
	if err := SetPassword(p, adminPW); err != nil {
		t.Fatal(err)
	}
	ag := &fakeAgent{data: map[string]string{"openssl": "3.5.1", "svc.caddy": "active", "public_ip": "203.0.113.5", "cert_expiry": "2026-12-30"}}
	mg := &fakeMgmt{on: map[string]bool{}}
	d := app.Deps{Paths: p, Settings: live, Store: st, CA: ca, Mgmt: mg, Agent: ag}
	a := New(d)
	srv := httptest.NewServer(a.Handler())
	t.Cleanup(srv.Close)
	jar, _ := cookiejar.New(nil)
	e := &env{t: t, a: a, d: d, agent: ag, mgmt: mg, srv: srv, c: &http.Client{Jar: jar}}
	return e
}

func (e *env) do(method, path string, body any, hdr map[string]string) (*http.Response, map[string]any) {
	e.t.Helper()
	var r io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		r = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, e.srv.URL+path, r)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if e.csrf != "" {
		req.Header.Set(CSRFHeader, e.csrf)
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

func (e *env) session() {
	e.t.Helper()
	res, out := e.do("GET", "/v1/admin/session", nil, nil)
	if res.StatusCode != 200 {
		e.t.Fatal(res.StatusCode)
	}
	e.csrf, _ = out["csrf"].(string)
}

func (e *env) login() {
	e.t.Helper()
	e.session()
	res, out := e.do("POST", "/v1/admin/login", map[string]string{"password": adminPW}, nil)
	if res.StatusCode != 200 {
		e.t.Fatal(res.StatusCode, out)
	}
	e.csrf = out["csrf"].(string)
}

func TestTOTPRFC6238Vectors(t *testing.T) {
	secret := []byte("12345678901234567890")
	cases := map[int64]string{59: "94287082", 1111111109: "07081804", 1111111111: "14050471", 1234567890: "89005924", 2000000000: "69279037", 20000000000: "65353130"}
	for ts, want := range cases {
		if got := TOTPCode(secret, ts/30, 8); got != want {
			t.Errorf("t=%d got %s want %s", ts, got, want)
		}
	}
	if got := TOTPCode(secret, 59/30, 6); got != "287082" {
		t.Fatal(got)
	}
}

func TestCheckTOTPWindowAndReplay(t *testing.T) {
	key := []byte("12345678901234567890")
	sec := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(key)
	now := time.Unix(1111111111, 0)
	step := now.Unix() / 30
	code := TOTPCode(key, step, 6)
	got, ok := CheckTOTP(sec, code, now, 0)
	if !ok || got != step {
		t.Fatal("current step rejected")
	}
	if _, ok := CheckTOTP(sec, code, now, step); ok {
		t.Fatal("replay accepted")
	}
	if _, ok := CheckTOTP(sec, TOTPCode(key, step-1, 6), now, 0); !ok {
		t.Fatal("previous step rejected")
	}
	if _, ok := CheckTOTP(sec, TOTPCode(key, step+1, 6), now, 0); !ok {
		t.Fatal("next step rejected")
	}
	if _, ok := CheckTOTP(sec, TOTPCode(key, step-2, 6), now, 0); ok {
		t.Fatal("old step accepted")
	}
	if _, ok := CheckTOTP(sec, "12345a", now, 0); ok {
		t.Fatal("garbage accepted")
	}
	if _, ok := CheckTOTP(sec, code[:3]+" "+code[3:], now, 0); !ok {
		t.Fatal("spaced code rejected")
	}
}

func TestPasswordFileAndReset(t *testing.T) {
	p := config.Paths{Data: t.TempDir()}
	if Exists(p) {
		t.Fatal("exists before set")
	}
	if SetPassword(p, "short") == nil {
		t.Fatal("weak password accepted")
	}
	if err := SetPassword(p, adminPW); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(p.Admin())
	if err != nil || (runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600) {
		t.Fatal("bad perms", err)
	}
	if err := updateCreds(p, func(c *Creds) error { c.TOTPSecret = NewTOTPSecret(); return nil }); err != nil {
		t.Fatal(err)
	}
	c1, _ := LoadCreds(p)
	if err := ResetPassword(p, "another-long-password"); err != nil {
		t.Fatal(err)
	}
	c2, _ := LoadCreds(p)
	if c2.TOTPSecret != "" || c2.Epoch == c1.Epoch || !verifyPassword(c2.Password, "another-long-password") {
		t.Fatal("reset did not clear totp or rotate epoch")
	}
	raw, _ := os.ReadFile(p.Admin())
	if strings.Contains(string(raw), "another-long-password") {
		t.Fatal("plaintext password stored")
	}
}

func TestLoginLogoutAndSession(t *testing.T) {
	e := setup(t)
	res, _ := e.do("GET", "/v1/admin/overview", nil, nil)
	if res.StatusCode != 401 {
		t.Fatal("unauthenticated overview", res.StatusCode)
	}
	e.session()
	res, _ = e.do("POST", "/v1/admin/login", map[string]string{"password": "wrong-password!"}, nil)
	if res.StatusCode != 401 {
		t.Fatal(res.StatusCode)
	}
	e.login()
	var sc *http.Cookie
	res, out := e.do("GET", "/v1/admin/session", nil, nil)
	if res.StatusCode != 200 || out["authenticated"] != true {
		t.Fatal(out)
	}
	for _, c := range e.c.Jar.Cookies(mustURL(e.srv.URL)) {
		if c.Name == SessionCookie {
			sc = c
		}
	}
	if sc == nil || len(sc.Value) < 40 {
		t.Fatal("no session cookie")
	}
	res, _ = e.do("POST", "/v1/admin/logout", map[string]string{}, nil)
	if res.StatusCode != 200 {
		t.Fatal(res.StatusCode)
	}
	res, _ = e.do("GET", "/v1/admin/overview", nil, nil)
	if res.StatusCode != 401 {
		t.Fatal("session survived logout")
	}
}

func TestSessionCookieFlags(t *testing.T) {
	e := setup(t)
	e.session()
	res, _ := e.do("POST", "/v1/admin/login", map[string]string{"password": adminPW}, map[string]string{"X-Forwarded-Proto": "https"})
	found := false
	for _, c := range res.Cookies() {
		if c.Name == SessionCookie {
			found = true
			if !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteStrictMode || c.Path != "/" {
				t.Fatalf("bad cookie %+v", c)
			}
		}
	}
	if !found {
		t.Fatal("no cookie")
	}
	if res.Header.Get("Strict-Transport-Security") == "" {
		t.Fatal("no hsts over https")
	}
}

func TestCSRFRequired(t *testing.T) {
	e := setup(t)
	e.login()
	good := e.csrf
	e.csrf = ""
	res, _ := e.do("POST", "/v1/admin/invites", map[string]int{"uses": 1}, nil)
	if res.StatusCode != 403 {
		t.Fatal("missing csrf accepted", res.StatusCode)
	}
	e.csrf = "x" + good[1:]
	res, _ = e.do("POST", "/v1/admin/invites", map[string]int{"uses": 1}, nil)
	if res.StatusCode != 403 {
		t.Fatal("wrong csrf accepted")
	}
	e.csrf = good
	res, _ = e.do("POST", "/v1/admin/invites", map[string]int{"uses": 1}, nil)
	if res.StatusCode != 201 {
		t.Fatal("good csrf rejected", res.StatusCode)
	}
	e2 := setup(t)
	res, _ = e2.do("POST", "/v1/admin/login", map[string]string{"password": adminPW}, nil)
	if res.StatusCode != 403 {
		t.Fatal("login without csrf accepted")
	}
}

func TestLoginThrottle(t *testing.T) {
	e := setup(t)
	e.session()
	for i := 0; i < 5; i++ {
		res, _ := e.do("POST", "/v1/admin/login", map[string]string{"password": "nope-nope-nope"}, nil)
		if res.StatusCode != 401 {
			t.Fatal(i, res.StatusCode)
		}
	}
	res, _ := e.do("POST", "/v1/admin/login", map[string]string{"password": adminPW}, nil)
	if res.StatusCode != 429 {
		t.Fatal("not locked", res.StatusCode)
	}
}

func TestSessionExpiry(t *testing.T) {
	e := setup(t)
	now := time.Now()
	e.a.now = func() time.Time { return now }
	e.login()
	now = now.Add(IdleTimeout - time.Minute)
	if res, _ := e.do("GET", "/v1/admin/session", nil, nil); res.StatusCode != 200 {
		t.Fatal(res.StatusCode)
	}
	if res, _ := e.do("GET", "/v1/admin/overview", nil, nil); res.StatusCode != 200 {
		t.Fatal("active session rejected")
	}
	now = now.Add(IdleTimeout + time.Second)
	if res, _ := e.do("GET", "/v1/admin/overview", nil, nil); res.StatusCode != 401 {
		t.Fatal("idle session accepted")
	}
	e.login()
	start := now
	for i := 0; i < 40; i++ {
		now = now.Add(25 * time.Minute)
		res, _ := e.do("GET", "/v1/admin/overview", nil, nil)
		if res.StatusCode == 401 {
			if now.Sub(start) <= MaxLifetime {
				t.Fatal("expired early", now.Sub(start))
			}
			return
		}
	}
	t.Fatal("never expired")
}

func TestPasswordChangeInvalidatesOtherSessions(t *testing.T) {
	e := setup(t)
	e.login()
	other := &env{t: t, a: e.a, d: e.d, srv: e.srv}
	jar, _ := cookiejar.New(nil)
	other.c = &http.Client{Jar: jar}
	other.login()
	res, out := e.do("POST", "/v1/admin/password", map[string]string{"password": adminPW, "new_password": "a-brand-new-password"}, nil)
	if res.StatusCode != 200 {
		t.Fatal(res.StatusCode, out)
	}
	e.csrf = out["csrf"].(string)
	if res, _ := other.do("GET", "/v1/admin/overview", nil, nil); res.StatusCode != 401 {
		t.Fatal("other session survived password change")
	}
	if res, _ := e.do("GET", "/v1/admin/overview", nil, nil); res.StatusCode != 200 {
		t.Fatal("own session dropped")
	}
	if err := ResetPassword(e.d.Paths, "reset-from-the-cli"); err != nil {
		t.Fatal(err)
	}
	if res, _ := e.do("GET", "/v1/admin/overview", nil, nil); res.StatusCode != 401 {
		t.Fatal("session survived cli reset")
	}
}

func TestTOTPEnableLoginReplayDisable(t *testing.T) {
	e := setup(t)
	now := time.Unix(1700000000, 0)
	e.a.now = func() time.Time { return now }
	e.login()
	res, out := e.do("POST", "/v1/admin/totp/setup", map[string]string{}, nil)
	if res.StatusCode != 200 || !strings.HasPrefix(out["qr"].(string), "data:image/svg+xml;base64,") || !strings.HasPrefix(out["uri"].(string), "otpauth://totp/") {
		t.Fatal(out)
	}
	sec := out["secret"].(string)
	key, _ := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(sec)
	res, _ = e.do("POST", "/v1/admin/totp/enable", map[string]string{"code": "000000"}, nil)
	if res.StatusCode != 400 {
		t.Fatal("bad code enabled totp")
	}
	res, _ = e.do("POST", "/v1/admin/totp/enable", map[string]string{"code": TOTPCode(key, now.Unix()/30, 6)}, nil)
	if res.StatusCode != 200 {
		t.Fatal(res.StatusCode)
	}
	e.do("POST", "/v1/admin/logout", map[string]string{}, nil)
	e.session()
	res, out = e.do("GET", "/v1/admin/session", nil, nil)
	if out["totp_required"] != true {
		t.Fatal("totp not required")
	}
	res, _ = e.do("POST", "/v1/admin/login", map[string]string{"password": adminPW}, nil)
	if res.StatusCode != 401 {
		t.Fatal("login without code")
	}
	res, _ = e.do("POST", "/v1/admin/login", map[string]string{"password": adminPW, "totp": TOTPCode(key, now.Unix()/30, 6)}, nil)
	if res.StatusCode != 401 {
		t.Fatal("code used for enabling accepted again")
	}
	now = now.Add(30 * time.Second)
	code := TOTPCode(key, now.Unix()/30, 6)
	res, out = e.do("POST", "/v1/admin/login", map[string]string{"password": adminPW, "totp": code}, nil)
	if res.StatusCode != 200 {
		t.Fatal("valid code rejected", res.StatusCode)
	}
	e.csrf = out["csrf"].(string)
	jar, _ := cookiejar.New(nil)
	other := &env{t: t, a: e.a, d: e.d, srv: e.srv, c: &http.Client{Jar: jar}}
	other.session()
	res, _ = other.do("POST", "/v1/admin/login", map[string]string{"password": adminPW, "totp": code}, nil)
	if res.StatusCode != 401 {
		t.Fatal("replayed code accepted")
	}
	res, _ = e.do("POST", "/v1/admin/totp/disable", map[string]string{"password": "wrong-password!!"}, nil)
	if res.StatusCode != 401 {
		t.Fatal("disable with wrong password")
	}
	res, _ = e.do("POST", "/v1/admin/totp/disable", map[string]string{"password": adminPW}, nil)
	if res.StatusCode != 200 {
		t.Fatal(res.StatusCode)
	}
	if c, _ := LoadCreds(e.d.Paths); c.TOTPSecret != "" {
		t.Fatal("not disabled")
	}
}

func TestAccountsEndpoints(t *testing.T) {
	e := setup(t)
	e.login()
	res, out := e.do("POST", "/v1/admin/accounts", map[string]any{"label": "Sam", "expires_days": 30, "limit": 3}, nil)
	if res.StatusCode != 201 {
		t.Fatal(res.StatusCode, out)
	}
	number := out["number"].(string)
	if !store.ValidNumber(number) {
		t.Fatal(number)
	}
	id := out["account"].(map[string]any)["id"].(string)
	if err := e.d.Store.AddDevice(number, store.Device{ID: "dev1", Name: "Phone", Serial: "abc1"}); err != nil {
		t.Fatal(err)
	}
	if err := e.d.Store.AddDevice(number, store.Device{ID: "dev2", Name: "Laptop", Serial: "abc2"}); err != nil {
		t.Fatal(err)
	}
	e.mgmt.on["dev1"] = true
	res, out = e.do("GET", "/v1/admin/accounts", nil, nil)
	accs := out["accounts"].([]any)
	if len(accs) != 1 {
		t.Fatal(out)
	}
	a0 := accs[0].(map[string]any)
	if a0["online"].(float64) != 1 || a0["devices"].(float64) != 2 || a0["max_devices"].(float64) != 3 || a0["status"] != "active" {
		t.Fatal(a0)
	}
	raw, _ := json.Marshal(out)
	if strings.Contains(string(raw), number) || strings.Contains(string(raw), "hash") {
		t.Fatal("account number or hash leaked in listing")
	}
	res, out = e.do("GET", "/v1/admin/accounts/"+id+"/devices", nil, nil)
	if res.StatusCode != 200 || len(out["devices"].([]any)) != 2 {
		t.Fatal(out)
	}
	res, _ = e.do("DELETE", "/v1/admin/accounts/"+id+"/devices/dev1", nil, nil)
	if res.StatusCode != 200 {
		t.Fatal(res.StatusCode)
	}
	if !contains(e.mgmt.killed, "dev1") {
		t.Fatal("device not killed")
	}
	crl, _ := os.ReadFile(e.d.Paths.CRL())
	if !bytes.Contains(crl, []byte("X509 CRL")) {
		t.Fatal("crl missing")
	}
	if rev, _ := e.d.Store.Revoked(); !contains(rev, "abc1") {
		t.Fatal("serial not revoked")
	}
	res, _ = e.do("DELETE", "/v1/admin/accounts/"+id+"/devices/nope", nil, nil)
	if res.StatusCode != 404 {
		t.Fatal(res.StatusCode)
	}
	off := true
	res, out = e.do("PATCH", "/v1/admin/accounts/"+id, map[string]any{"disabled": off, "label": "Samuel", "dns": []string{"ads"}}, nil)
	if res.StatusCode != 200 || out["account"].(map[string]any)["status"] != "disabled" || out["account"].(map[string]any)["label"] != "Samuel" {
		t.Fatal(out)
	}
	if !contains(e.mgmt.killed, "dev2") {
		t.Fatal("disabled account devices not killed")
	}
	res, out = e.do("PATCH", "/v1/admin/accounts/"+id, map[string]any{"disabled": false, "expires_days": 0, "dns_default": true}, nil)
	acc := out["account"].(map[string]any)
	if res.StatusCode != 200 || acc["expires"].(float64) != 0 || acc["dns_custom"] != false {
		t.Fatal(out)
	}
	res, _ = e.do("PATCH", "/v1/admin/accounts/"+id, map[string]any{"expires_days": 99999}, nil)
	if res.StatusCode != 400 {
		t.Fatal("bad expiry accepted")
	}
	res, _ = e.do("PATCH", "/v1/admin/accounts/"+id, map[string]any{"bogus": 1}, nil)
	if res.StatusCode != 400 {
		t.Fatal("unknown field accepted")
	}
	res, _ = e.do("DELETE", "/v1/admin/accounts/"+id, nil, nil)
	if res.StatusCode != 200 {
		t.Fatal(res.StatusCode)
	}
	if rev, _ := e.d.Store.Revoked(); !contains(rev, "abc2") {
		t.Fatal("deleted account serial not revoked")
	}
	res, _ = e.do("DELETE", "/v1/admin/accounts/"+id, nil, nil)
	if res.StatusCode != 404 {
		t.Fatal(res.StatusCode)
	}
	res, _ = e.do("POST", "/v1/admin/accounts", map[string]any{"password": "short"}, nil)
	if res.StatusCode != 400 {
		t.Fatal("weak password accepted")
	}
}

func TestInvitesEndpoints(t *testing.T) {
	e := setup(t)
	e.login()
	res, out := e.do("POST", "/v1/admin/invites", map[string]any{"uses": 3, "expires_days": 7}, nil)
	if res.StatusCode != 201 || !strings.HasPrefix(out["code"].(string), "VEYL-") {
		t.Fatal(out)
	}
	id := out["invite"].(map[string]any)["id"].(string)
	res, out = e.do("GET", "/v1/admin/invites", nil, nil)
	if len(out["invites"].([]any)) != 1 {
		t.Fatal(out)
	}
	res, _ = e.do("POST", "/v1/admin/invites", map[string]any{"uses": 5000}, nil)
	if res.StatusCode != 400 {
		t.Fatal(res.StatusCode)
	}
	res, _ = e.do("DELETE", "/v1/admin/invites/"+id, nil, nil)
	if res.StatusCode != 200 {
		t.Fatal(res.StatusCode)
	}
	res, _ = e.do("DELETE", "/v1/admin/invites/"+id, nil, nil)
	if res.StatusCode != 404 {
		t.Fatal(res.StatusCode)
	}
}

func readSSE(t *testing.T, e *env, path string) (steps int, done map[string]any) {
	t.Helper()
	req, _ := http.NewRequest("GET", e.srv.URL+path, nil)
	res, err := e.c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.Header.Get("Content-Type") != "text/event-stream" {
		t.Fatal(res.Header.Get("Content-Type"), res.StatusCode)
	}
	sc := bufio.NewScanner(res.Body)
	ev := ""
	for sc.Scan() {
		l := sc.Text()
		if v, ok := strings.CutPrefix(l, "event: "); ok {
			ev = v
		}
		if v, ok := strings.CutPrefix(l, "data: "); ok {
			if ev == "step" {
				steps++
			}
			if ev == "done" {
				_ = json.Unmarshal([]byte(v), &done)
				return
			}
		}
	}
	return
}

func TestSettingsPutAppliesAndStreams(t *testing.T) {
	e := setup(t)
	e.login()
	res, out := e.do("GET", "/v1/admin/settings", nil, nil)
	if res.StatusCode != 200 || out["pq_available"] != true {
		t.Fatal(out)
	}
	s := out["settings"].(map[string]any)
	s["name"] = "Family VPN"
	res, out = e.do("PUT", "/v1/admin/settings", s, nil)
	if res.StatusCode != 200 || out["applying"] != false {
		t.Fatal("name change should not apply", out)
	}
	if e.d.Settings.Get().Name != "Family VPN" {
		t.Fatal("not saved")
	}
	s["stealth"] = false
	res, out = e.do("PUT", "/v1/admin/settings", s, nil)
	if res.StatusCode != 200 || out["applying"] != true {
		t.Fatal(out)
	}
	steps, done := readSSE(t, e, "/v1/admin/apply-progress")
	if steps != 2 || done["ok"] != true {
		t.Fatal(steps, done)
	}
	if e.agent.count(agentapi.OpApply) != 1 {
		t.Fatal("apply not called once")
	}
	s["udp_port"] = 80
	res, out = e.do("PUT", "/v1/admin/settings", s, nil)
	if res.StatusCode != 400 || !strings.Contains(out["error"].(string), "port") {
		t.Fatal(out)
	}
	s["udp_port"] = 1194
	s["host"] = "evil.com\nup /bin/sh"
	res, _ = e.do("PUT", "/v1/admin/settings", s, nil)
	if res.StatusCode != 400 {
		t.Fatal("injection accepted")
	}
	e.agent.fail = "caddy validate failed"
	s["host"] = "vpn2.example.com"
	res, out = e.do("PUT", "/v1/admin/settings", s, nil)
	if out["applying"] != true {
		t.Fatal(out)
	}
	_, done = readSSE(t, e, "/v1/admin/apply-progress")
	if done["ok"] != false || done["error"] != "caddy validate failed" {
		t.Fatal(done)
	}
}

func TestOverviewAndDNSUpdate(t *testing.T) {
	e := setup(t)
	e.login()
	if err := os.MkdirAll(e.d.Paths.Blocklists(), 0o755); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(e.d.Paths.Blocklists(), "ads.txt"), []byte("a.com\nb.com\n# c\n\nd.com\n"), 0o644)
	e.mgmt.on["x"] = true
	res, out := e.do("GET", "/v1/admin/overview", nil, nil)
	if res.StatusCode != 200 || out["connected"].(float64) != 1 || out["cert_expiry"] != "2026-12-30" {
		t.Fatal(out)
	}
	bl := out["blocklists"].([]any)[0].(map[string]any)
	if bl["category"] != "ads" || bl["entries"].(float64) != 3 || len(bl["updated"].(string)) != 10 {
		t.Fatal(bl)
	}
	svcs := out["services"].([]any)
	if len(svcs) != 1 || svcs[0].(map[string]any)["name"] != "caddy" {
		t.Fatal(svcs)
	}
	res, _ = e.do("POST", "/v1/admin/dns/update", map[string]string{}, nil)
	if res.StatusCode != 202 {
		t.Fatal(res.StatusCode)
	}
	_, done := readSSE(t, e, "/v1/admin/apply-progress")
	if done["ok"] != true || e.agent.count(agentapi.OpDNSUpdate) != 1 {
		t.Fatal(done)
	}
}

func TestBackupDownload(t *testing.T) {
	e := setup(t)
	e.login()
	res, _ := e.do("POST", "/v1/admin/backup", map[string]string{"passphrase": "short"}, nil)
	if res.StatusCode != 400 {
		t.Fatal(res.StatusCode)
	}
	b, _ := json.Marshal(map[string]string{"passphrase": "a-long-backup-phrase"})
	req, _ := http.NewRequest("POST", e.srv.URL+"/v1/admin/backup", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(CSRFHeader, e.csrf)
	r, err := e.c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := io.ReadAll(r.Body)
	r.Body.Close()
	if r.StatusCode != 200 || !strings.Contains(r.Header.Get("Content-Disposition"), ".vbk") || !bytes.HasPrefix(data, []byte(backup.Magic)) {
		t.Fatal(r.StatusCode, r.Header)
	}
	files, err := backup.Open(data, "a-long-backup-phrase")
	if err != nil || files["ca.key"] == nil || files["admin.json"] == nil {
		t.Fatal(err)
	}
}

func TestVPNOnly(t *testing.T) {
	e := setup(t)
	if _, err := e.d.Settings.Update(func(s *config.Settings) error { s.AdminVPNOnly = true; return nil }); err != nil {
		t.Fatal(err)
	}
	res, _ := e.do("GET", "/v1/admin/session", nil, map[string]string{"X-Forwarded-For": "198.51.100.9"})
	if res.StatusCode != 404 {
		t.Fatal("public ip allowed", res.StatusCode)
	}
	res, _ = e.do("GET", "/admin", nil, map[string]string{"X-Forwarded-For": "198.51.100.9"})
	if res.StatusCode != 404 {
		t.Fatal("page shown to public ip")
	}
	res, _ = e.do("GET", "/v1/admin/session", nil, map[string]string{"X-Forwarded-For": "198.51.100.9, 10.8.0.7"})
	if res.StatusCode != 200 {
		t.Fatal("tunnel ip rejected", res.StatusCode)
	}
	res, _ = e.do("GET", "/v1/admin/session", nil, map[string]string{"X-Forwarded-For": "10.9.0.3"})
	if res.StatusCode != 200 {
		t.Fatal("tcp tunnel ip rejected")
	}
	res, _ = e.do("GET", "/v1/admin/session", nil, map[string]string{"X-Forwarded-For": "10.8.1.3"})
	if res.StatusCode != 404 {
		t.Fatal("non tunnel 10.x allowed")
	}
}

func TestPanelServedWithCSP(t *testing.T) {
	e := setup(t)
	for path, ct := range map[string]string{"/admin": "text/html", "/admin/admin.js": "text/javascript", "/admin/app.css": "text/css", "/admin/favicon.svg": "image/svg+xml"} {
		res, _ := e.do("GET", path, nil, nil)
		if res.StatusCode != 200 || !strings.HasPrefix(res.Header.Get("Content-Type"), ct) {
			t.Fatal(path, res.StatusCode, res.Header.Get("Content-Type"))
		}
		csp := res.Header.Get("Content-Security-Policy")
		if !strings.Contains(csp, "script-src 'self'") || strings.Contains(csp, "unsafe") {
			t.Fatal(csp)
		}
	}
	for _, path := range []string{"/admin/setup.html", "/admin/../web.go", "/admin/nope.js", "/adminx"} {
		res, _ := e.do("GET", path, nil, nil)
		if res.StatusCode != 404 {
			t.Fatal(path, res.StatusCode)
		}
	}
}

func TestPQAvailable(t *testing.T) {
	for v, want := range map[string]bool{"3.5.0": true, "OpenSSL 3.5.1 1 Jul 2025": true, "3.0.13": false, "3.4.9": false, "4.0.0": true, "": false, "3.10.0": true, "garbage": false} {
		if PQAvailable(v) != want {
			t.Error(v)
		}
	}
}

func mustURL(s string) *url.URL {
	u, err := url.Parse(s)
	if err != nil {
		panic(err)
	}
	return u
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}
