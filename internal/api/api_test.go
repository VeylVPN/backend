package api

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/veylvpn/backend/internal/app"
	"github.com/veylvpn/backend/internal/config"
	"github.com/veylvpn/backend/internal/pki"
	"github.com/veylvpn/backend/internal/pki/pkitest"
	"github.com/veylvpn/backend/internal/store"
)

func TestMain(m *testing.M) {
	os.Exit(pkitest.Main(m))
}

type fakeMgmt struct {
	mu     sync.Mutex
	online []string
	killed []string
	down   bool
}

func (f *fakeMgmt) Online() (map[string]bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.down {
		return nil, errors.New("down")
	}
	out := map[string]bool{}
	for _, cn := range f.online {
		out[cn] = true
	}
	return out, nil
}

func (f *fakeMgmt) Kill(cn string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.killed = append(f.killed, cn)
	return nil
}

func (f *fakeMgmt) setOnline(cns ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.online = cns
}

func (f *fakeMgmt) kills() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.killed...)
}

type env struct {
	srv  *httptest.Server
	s    *Server
	d    app.Deps
	st   *store.Store
	ca   *pki.CA
	live *config.Live
	mgmt *fakeMgmt
	dir  string
}

const pw = "correct horse"

func setup(t *testing.T, mutate func(*config.Settings)) *env {
	t.Helper()
	e := &env{dir: t.TempDir(), mgmt: &fakeMgmt{}}
	paths := config.Paths{Data: e.dir, Run: e.dir}
	var err error
	if e.ca, err = pki.Init(paths.PKI()); err != nil {
		t.Fatal(err)
	}
	if e.st, err = store.Open(paths.State()); err != nil {
		t.Fatal(err)
	}
	set := config.Defaults()
	set.Host = "vpn.example.com"
	set.Stealth = false
	set.Registration = config.RegClosed
	if mutate != nil {
		mutate(&set)
	}
	if err := config.Save(paths.Settings(), set); err != nil {
		t.Fatal(err)
	}
	if e.live, err = config.NewLive(paths.Settings()); err != nil {
		t.Fatal(err)
	}
	e.d = app.Deps{Paths: paths, Settings: e.live, Store: e.st, CA: e.ca, Mgmt: e.mgmt}
	e.s = New(e.d)
	e.srv = httptest.NewServer(e.s.Handler())
	t.Cleanup(e.srv.Close)
	return e
}

type m = map[string]any

type resp struct {
	code int
	body m
	raw  []byte
	h    http.Header
}

func (e *env) req(t *testing.T, method, path string, body any, hdr ...string) resp {
	t.Helper()
	var rd io.Reader
	switch b := body.(type) {
	case nil:
	case string:
		rd = strings.NewReader(b)
	default:
		j, _ := json.Marshal(b)
		rd = bytes.NewReader(j)
	}
	r, _ := http.NewRequest(method, e.srv.URL+path, rd)
	if body != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		if hdr[i+1] == "" {
			r.Header.Del(hdr[i])
			continue
		}
		r.Header.Set(hdr[i], hdr[i+1])
	}
	res, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	var out m
	_ = json.Unmarshal(raw, &out)
	return resp{code: res.StatusCode, body: out, raw: raw, h: res.Header}
}

func (e *env) do(t *testing.T, method, path string, body any) (int, m, http.Header) {
	t.Helper()
	r := e.req(t, method, path, body)
	return r.code, r.body, r.h
}

func (e *env) bearer(t *testing.T, tok, method, path string, body any) resp {
	t.Helper()
	return e.req(t, method, path, body, "Authorization", "Bearer "+tok)
}

func csr(t *testing.T, key any) string {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

func ecCSR(t *testing.T) string {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	return csr(t, k)
}

func claimed(t *testing.T, e *env) string {
	t.Helper()
	n, err := e.st.NewAccount()
	if err != nil {
		t.Fatal(err)
	}
	code, out, _ := e.do(t, "POST", "/v1/register", m{"account": n, "password": pw})
	if code != 200 || out["account"] != n {
		t.Fatalf("claim %d %v", code, out)
	}
	return n
}

func login(t *testing.T, e *env, n string) string {
	t.Helper()
	r := e.req(t, "POST", "/v1/auth/token", m{"account": n, "password": pw})
	tok, _ := r.body["access_token"].(string)
	if r.code != 200 || tok == "" {
		t.Fatalf("login %d %s", r.code, r.raw)
	}
	return tok
}

func expectErr(t *testing.T, name string, r resp, code int, machine string) {
	t.Helper()
	if r.code != code || r.body["code"] != machine || r.body["error"] == nil || r.body["error"] == "" {
		t.Errorf("%s: got %d %s, want %d %s", name, r.code, r.raw, code, machine)
	}
}

var tokenRE = regexp.MustCompile(`^vey_[A-Za-z0-9_-]{43}$`)

func TestInfoAndHeaders(t *testing.T) {
	e := setup(t, func(s *config.Settings) { s.Stealth = true; s.Registration = config.RegInvite; s.Name = "Home VPN" })
	r := e.req(t, "GET", "/v1/info", nil)
	b := r.body
	if r.code != 200 || b["endpoint"] != "vpn.example.com" || b["port"] != float64(1194) || b["proto"] != "udp" {
		t.Fatalf("%d %s", r.code, r.raw)
	}
	if b["name"] != "Home VPN" || b["version"] != app.Version || b["registration"] != "invite" || b["device_limit"] != float64(5) || b["stealth"] != true || b["post_quantum"] != true || b["stealth_port"] != float64(443) {
		t.Fatalf("%s", r.raw)
	}
	if b["app_url"] == "" || len(b["dns_categories"].([]any)) != len(config.Categories) || len(b["dns_default"].([]any)) != 3 {
		t.Fatalf("%s", r.raw)
	}
	for _, k := range []string{"X-Content-Type-Options", "Referrer-Policy", "Content-Security-Policy", "Cache-Control", "X-Frame-Options", "Cross-Origin-Opener-Policy", "Permissions-Policy"} {
		if r.h.Get(k) == "" {
			t.Errorf("missing header %s", k)
		}
	}
	if r.h.Get("Cross-Origin-Opener-Policy") != "same-origin" {
		t.Error("coop")
	}
	if r.h.Get("Strict-Transport-Security") != "" {
		t.Error("hsts without https proxy header")
	}
	r = e.req(t, "GET", "/v1/info", nil, "X-Forwarded-Proto", "https")
	if !strings.HasPrefix(r.h.Get("Strict-Transport-Security"), "max-age=") {
		t.Error("missing hsts behind https proxy")
	}
}

func TestHealthAndOpenAPI(t *testing.T) {
	e := setup(t, nil)
	r := e.req(t, "GET", "/v1/health", nil)
	if r.code != 200 || strings.TrimSpace(string(r.raw)) != `{"status":"ok"}` {
		t.Fatalf("%d %s", r.code, r.raw)
	}
	r = e.req(t, "GET", "/v1/openapi.yaml", nil)
	if r.code != 200 || !strings.HasPrefix(r.h.Get("Content-Type"), "application/yaml") || !strings.HasPrefix(string(r.raw), "openapi: 3.1") {
		t.Fatalf("%d %s", r.code, r.h.Get("Content-Type"))
	}
	doc := string(r.raw)
	for _, p := range []string{"/v1/info", "/v1/health", "/v1/openapi.yaml", "/v1/register", "/v1/devices", "/v1/enroll", "/v1/revoke", "/v1/password", "/v1/auth/token", "/v1/auth/logout", "/v1/me", "/v1/me/devices", "/v1/me/devices/{id}", "/v1/me/dns", "/v1/me/password"} {
		if !strings.Contains(doc, "\n  "+p+":\n") {
			t.Errorf("openapi missing path %s", p)
		}
	}
	for _, c := range []string{CodeInvalidCredentials, CodeInvalidToken, CodeMaxDevices, CodeDeviceNotFound, CodeExpired, CodeDisabled, CodeTooMany, CodeInvalidInvite, CodeRegClosed, CodeBadRequest, CodeTooLarge} {
		if !strings.Contains(doc, c) {
			t.Errorf("openapi missing code %s", c)
		}
	}
	for _, line := range strings.Split(doc, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			t.Fatalf("comment in openapi: %q", line)
		}
	}
}

func TestNotFoundAndMethod(t *testing.T) {
	e := setup(t, nil)
	expectErr(t, "404", e.req(t, "GET", "/v1/nope", nil), 404, CodeNotFound)
	expectErr(t, "root", e.req(t, "GET", "/", nil), 404, CodeNotFound)
	expectErr(t, "admin", e.req(t, "GET", "/v1/admin/overview", nil), 404, CodeNotFound)
	r := e.req(t, "DELETE", "/v1/info", nil)
	expectErr(t, "405", r, 405, CodeMethod)
	if !strings.Contains(r.h.Get("Allow"), "GET") {
		t.Errorf("allow %q", r.h.Get("Allow"))
	}
}

func TestRegisterClosed(t *testing.T) {
	e := setup(t, nil)
	n, _ := e.st.NewAccount()
	inv, _, _ := e.st.NewInvite(1, 0)
	cases := []struct {
		name string
		body m
		code int
		err  string
	}{
		{"closed registration", m{"password": pw}, 400, "account required"},
		{"closed invite", m{"invite": inv, "password": pw}, 403, "registration is closed"},
		{"short password", m{"account": n, "password": "short"}, 400, "password must be at least 10 characters"},
		{"unknown account", m{"account": "9999999999999999", "password": pw}, 401, "invalid credentials"},
		{"both", m{"account": n, "invite": inv, "password": pw}, 400, ""},
		{"claim", m{"account": n, "password": pw}, 200, ""},
		{"claim twice", m{"account": n, "password": "other password"}, 409, "account already claimed"},
	}
	for _, c := range cases {
		code, out, _ := e.do(t, "POST", "/v1/register", c.body)
		if code != c.code || (c.err != "" && out["error"] != c.err) {
			t.Errorf("%s: %d %v", c.name, code, out)
		}
	}
}

func TestRegistrationModes(t *testing.T) {
	for _, mode := range []string{config.RegClosed, config.RegInvite, config.RegOpen} {
		e := setup(t, func(s *config.Settings) { s.Registration = mode })
		n, _ := e.st.NewAccount()
		if code, out, _ := e.do(t, "POST", "/v1/register", m{"account": n, "password": pw}); code != 200 || out["account"] != n {
			t.Errorf("%s claim: %d %v", mode, code, out)
		}
		inv, _, _ := e.st.NewInvite(1, 0)
		r := e.req(t, "POST", "/v1/register", m{"invite": strings.ToLower(inv), "password": pw})
		if mode == config.RegClosed {
			expectErr(t, mode+" invite", r, 403, CodeRegClosed)
		} else {
			acct, _ := r.body["account"].(string)
			if r.code != 200 || !store.ValidNumber(acct) {
				t.Errorf("%s invite: %d %s", mode, r.code, r.raw)
			}
			expectErr(t, mode+" invite reuse", e.req(t, "POST", "/v1/register", m{"invite": inv, "password": pw}), 403, CodeInvalidInvite)
			expectErr(t, mode+" bad invite", e.req(t, "POST", "/v1/register", m{"invite": "VEYL-AAAA-BBBB-CCCC-DDDD", "password": pw}), 403, CodeInvalidInvite)
			expectErr(t, mode+" long invite", e.req(t, "POST", "/v1/register", m{"invite": strings.Repeat("A", 65), "password": pw}), 403, CodeInvalidInvite)
		}
		r = e.req(t, "POST", "/v1/register", m{"password": pw})
		switch mode {
		case config.RegOpen:
			acct, _ := r.body["account"].(string)
			if r.code != 200 || !store.ValidNumber(acct) {
				t.Errorf("open create: %d %s", r.code, r.raw)
			}
			expectErr(t, "open weak", e.req(t, "POST", "/v1/register", m{"password": "x"}), 400, CodeWeakPassword)
		case config.RegInvite:
			expectErr(t, "invite create", r, 400, CodeInviteRequired)
		default:
			expectErr(t, "closed create", r, 400, CodeRegClosed)
		}
	}
}

func certFromProfile(t *testing.T, profile string) *x509.Certificate {
	t.Helper()
	start := strings.Index(profile, "<cert>\n") + len("<cert>\n")
	end := strings.Index(profile, "</cert>")
	blk, _ := pem.Decode([]byte(profile[start:end]))
	cert, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func tlsCryptV2(profile string) string {
	start := strings.Index(profile, "<tls-crypt-v2>\n")
	end := strings.Index(profile, "</tls-crypt-v2>")
	if start < 0 || end < 0 {
		return ""
	}
	return profile[start+len("<tls-crypt-v2>\n") : end]
}

func readCRL(t *testing.T, e *env) *x509.RevocationList {
	t.Helper()
	b, _ := os.ReadFile(e.d.Paths.CRL())
	cb, _ := pem.Decode(b)
	rl, err := x509.ParseRevocationList(cb.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return rl
}

func TestEnrollDevicesRevoke(t *testing.T) {
	e := setup(t, nil)
	n := claimed(t, e)

	code, out, _ := e.do(t, "POST", "/v1/enroll", m{"account": n, "password": pw, "name": "  laptop ", "csr": ecCSR(t)})
	if code != 200 {
		t.Fatalf("enroll %d %v", code, out)
	}
	id := out["id"].(string)
	profile := out["profile"].(string)
	if len(id) != 16 {
		t.Fatalf("id %q", id)
	}
	for _, want := range []string{"<ca>", "<cert>", "__PRIVATE_KEY__", "<tls-crypt-v2>", "remote vpn.example.com 1194 udp"} {
		if !strings.Contains(profile, want) {
			t.Errorf("profile missing %q", want)
		}
	}
	for _, bad := range []string{"<tls-crypt>", "data-ciphers-fallback", "tcp-client"} {
		if strings.Contains(profile, bad) {
			t.Errorf("profile contains %q", bad)
		}
	}
	if md, ok := pkitest.Metadata(tlsCryptV2(profile)); !ok || md != id {
		t.Fatalf("tls-crypt-v2 metadata %q %v", md, ok)
	}
	cert := certFromProfile(t, profile)
	if cert.Subject.CommonName != id {
		t.Fatalf("cn %q != %q", cert.Subject.CommonName, id)
	}
	pool := x509.NewCertPool()
	pool.AddCert(e.ca.Cert())
	if _, err := cert.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Fatal(err)
	}

	e.mgmt.setOnline(id)
	code, out, _ = e.do(t, "POST", "/v1/devices", m{"account": n, "password": pw})
	devs := out["devices"].([]any)
	if code != 200 || out["limit"] != float64(5) || len(devs) != 1 {
		t.Fatalf("devices %d %v", code, out)
	}
	d := devs[0].(map[string]any)
	if d["id"] != id || d["name"] != "laptop" || d["online"] != true || d["created"] == nil {
		t.Fatalf("device %v", d)
	}
	if _, leaked := d["serial"]; leaked {
		t.Fatal("serial exposed")
	}
	e.mgmt.setOnline()
	_, out, _ = e.do(t, "POST", "/v1/devices", m{"account": n, "password": pw})
	if out["devices"].([]any)[0].(map[string]any)["online"] != false {
		t.Fatal("expected offline")
	}

	code, out, _ = e.do(t, "POST", "/v1/revoke", m{"account": n, "password": pw, "id": "nope"})
	if code != 404 || out["error"] != "unknown device" {
		t.Fatalf("revoke unknown %d %v", code, out)
	}
	code, out, _ = e.do(t, "POST", "/v1/revoke", m{"account": n, "password": pw, "id": id})
	if code != 200 || out["status"] != "revoked" {
		t.Fatalf("revoke %d %v", code, out)
	}
	if k := e.mgmt.kills(); len(k) != 1 || k[0] != id {
		t.Fatalf("killed %v", k)
	}
	rl := readCRL(t, e)
	if len(rl.RevokedCertificateEntries) != 1 || rl.RevokedCertificateEntries[0].SerialNumber.Cmp(cert.SerialNumber) != 0 {
		t.Fatalf("crl %v", rl.RevokedCertificateEntries)
	}
	_, out, _ = e.do(t, "POST", "/v1/devices", m{"account": n, "password": pw})
	if len(out["devices"].([]any)) != 0 {
		t.Fatal("device not removed")
	}
}

func TestStealthProfile(t *testing.T) {
	e := setup(t, func(s *config.Settings) { s.Stealth = true; s.UDPPort = 51820 })
	n := claimed(t, e)
	_, out, _ := e.do(t, "POST", "/v1/enroll", m{"account": n, "password": pw, "name": "a", "csr": ecCSR(t)})
	p, _ := out["profile"].(string)
	if !strings.Contains(p, "remote vpn.example.com 51820 udp\nremote vpn.example.com 443 tcp-client\n") {
		t.Fatalf("%s", p)
	}
}

func TestEnrollErrors(t *testing.T) {
	e := setup(t, nil)
	n := claimed(t, e)
	rk, _ := rsa.GenerateKey(rand.Reader, 2048)
	cases := []struct {
		name string
		body m
		code int
		err  string
	}{
		{"bad password", m{"account": n, "password": "wrong password", "name": "a", "csr": ecCSR(t)}, 401, "invalid credentials"},
		{"empty name", m{"account": n, "password": pw, "name": "  ", "csr": ecCSR(t)}, 400, "invalid device name"},
		{"long name", m{"account": n, "password": pw, "name": strings.Repeat("a", 33), "csr": ecCSR(t)}, 400, "invalid device name"},
		{"rsa csr", m{"account": n, "password": pw, "name": "a", "csr": csr(t, rk)}, 400, "invalid csr"},
		{"garbage csr", m{"account": n, "password": pw, "name": "a", "csr": "x"}, 400, "invalid csr"},
	}
	for _, c := range cases {
		code, out, _ := e.do(t, "POST", "/v1/enroll", c.body)
		if code != c.code || out["error"] != c.err {
			t.Errorf("%s: %d %v", c.name, code, out)
		}
	}
	if a, _ := e.st.AccountKey(store.HashAccount(n)); len(a.Devices) != 0 {
		t.Fatal("failed enrollments stored devices")
	}
}

func TestEnrollAccountState(t *testing.T) {
	e := setup(t, nil)
	n := claimed(t, e)
	key := store.HashAccount(n)
	past := time.Now().Add(-time.Hour).Unix()
	if _, err := e.st.UpdateKey(key, store.Patch{Expires: &past}); err != nil {
		t.Fatal(err)
	}
	expectErr(t, "expired", e.req(t, "POST", "/v1/enroll", m{"account": n, "password": pw, "name": "a", "csr": ecCSR(t)}), 403, CodeExpired)
	var zero int64
	yes := true
	if _, err := e.st.UpdateKey(key, store.Patch{Expires: &zero, Disabled: &yes}); err != nil {
		t.Fatal(err)
	}
	expectErr(t, "disabled", e.req(t, "POST", "/v1/enroll", m{"account": n, "password": pw, "name": "a", "csr": ecCSR(t)}), 403, CodeDisabled)
}

func TestNotConfigured(t *testing.T) {
	e := setup(t, func(s *config.Settings) { s.Host = "" })
	n := claimed(t, e)
	expectErr(t, "no host", e.req(t, "POST", "/v1/enroll", m{"account": n, "password": pw, "name": "a", "csr": ecCSR(t)}), 503, CodeNotConfigured)
}

func TestDeviceLimitFromSettings(t *testing.T) {
	e := setup(t, func(s *config.Settings) { s.DeviceLimit = 2 })
	n := claimed(t, e)
	for i := 0; i < 2; i++ {
		code, out, _ := e.do(t, "POST", "/v1/enroll", m{"account": n, "password": pw, "name": "d", "csr": ecCSR(t)})
		if code != 200 {
			t.Fatalf("enroll %d: %d %v", i, code, out)
		}
	}
	code, out, _ := e.do(t, "POST", "/v1/enroll", m{"account": n, "password": pw, "name": "d", "csr": ecCSR(t)})
	if code != 409 || out["error"] != "device limit reached" || out["code"] != CodeMaxDevices {
		t.Fatalf("%d %v", code, out)
	}
	if _, err := e.live.Update(func(s *config.Settings) error { s.DeviceLimit = 3; return nil }); err != nil {
		t.Fatal(err)
	}
	if code, out, _ := e.do(t, "POST", "/v1/devices", m{"account": n, "password": pw}); code != 200 || out["limit"] != float64(3) {
		t.Fatalf("%d %v", code, out)
	}
	if code, out, _ := e.do(t, "POST", "/v1/enroll", m{"account": n, "password": pw, "name": "d", "csr": ecCSR(t)}); code != 200 {
		t.Fatalf("raised limit not applied: %d %v", code, out)
	}
	lim := 4
	if _, err := e.st.UpdateKey(store.HashAccount(n), store.Patch{Limit: &lim}); err != nil {
		t.Fatal(err)
	}
	tok := login(t, e, n)
	if r := e.bearer(t, tok, "GET", "/v1/me", nil); r.body["device_limit"] != float64(4) || r.body["devices"] != float64(3) {
		t.Fatalf("%s", r.raw)
	}
}

func TestIdentical401(t *testing.T) {
	e := setup(t, nil)
	n := claimed(t, e)
	a := e.req(t, "POST", "/v1/devices", m{"account": n, "password": "wrong password"})
	b := e.req(t, "POST", "/v1/devices", m{"account": "1234123412341234", "password": "wrong password"})
	c := e.req(t, "POST", "/v1/devices", m{"account": "12", "password": "wrong password"})
	want := `{"error":"invalid credentials","code":"INVALID_CREDENTIALS"}`
	for _, r := range []resp{a, b, c} {
		if r.code != 401 || strings.TrimSpace(string(r.raw)) != want {
			t.Fatalf("%d %s", r.code, r.raw)
		}
	}
	t1 := e.req(t, "POST", "/v1/auth/token", m{"account": n, "password": "wrong password"})
	t2 := e.req(t, "POST", "/v1/auth/token", m{"account": "1234123412341234", "password": "wrong password"})
	if string(t1.raw) != string(t2.raw) || t1.code != 401 {
		t.Fatalf("%s vs %s", t1.raw, t2.raw)
	}
}

func TestAccountThrottle429(t *testing.T) {
	e := setup(t, nil)
	n := claimed(t, e)
	for i := 0; i < 5; i++ {
		code, _, _ := e.do(t, "POST", "/v1/devices", m{"account": n, "password": "wrong password"})
		if code != 401 {
			t.Fatalf("attempt %d: %d", i, code)
		}
	}
	for _, path := range []string{"/v1/devices", "/v1/enroll", "/v1/revoke", "/v1/password", "/v1/auth/token"} {
		r := e.req(t, "POST", path, m{"account": n, "password": pw})
		if r.code != 429 || r.body["code"] != CodeTooMany {
			t.Fatalf("%s: %d %s", path, r.code, r.raw)
		}
	}
	other := claimed(t, e)
	if code, _, _ := e.do(t, "POST", "/v1/devices", m{"account": other, "password": pw}); code != 200 {
		t.Fatalf("other account affected: %d", code)
	}
}

func TestIPRateLimitSharedAcrossAuthPaths(t *testing.T) {
	e := setup(t, nil)
	ip := "X-Forwarded-For"
	paths := []string{"/v1/auth/token", "/v1/register", "/v1/devices", "/v1/enroll", "/v1/revoke", "/v1/password"}
	for i := 0; i < 20; i++ {
		r := e.req(t, "POST", paths[i%len(paths)], "{", ip, "203.0.113.10")
		if r.code != 400 {
			t.Fatalf("request %d: %d %s", i, r.code, r.raw)
		}
	}
	for _, p := range paths {
		r := e.req(t, "POST", p, "{", ip, "203.0.113.10")
		expectErr(t, p, r, 429, CodeTooMany)
		if r.h.Get("Retry-After") == "" {
			t.Errorf("%s: no Retry-After", p)
		}
	}
	tok := "vey_" + strings.Repeat("A", 43)
	expectErr(t, "me password", e.req(t, "PUT", "/v1/me/password", m{}, ip, "203.0.113.10", "Authorization", "Bearer "+tok), 429, CodeTooMany)
	expectErr(t, "delete me", e.req(t, "DELETE", "/v1/me", m{}, ip, "203.0.113.10", "Authorization", "Bearer "+tok), 429, CodeTooMany)
	if r := e.req(t, "POST", "/v1/auth/token", "{", ip, "203.0.113.11"); r.code != 400 {
		t.Fatalf("other ip limited: %d", r.code)
	}
	if r := e.req(t, "GET", "/v1/info", nil, ip, "203.0.113.10"); r.code != 200 {
		t.Fatalf("general endpoints limited by auth policy: %d", r.code)
	}
}

func TestGeneralRateLimit(t *testing.T) {
	e := setup(t, nil)
	for i := 0; i < 120; i++ {
		if r := e.req(t, "GET", "/v1/health", nil, "X-Forwarded-For", "198.51.100.20"); r.code != 200 {
			t.Fatalf("request %d: %d", i, r.code)
		}
	}
	expectErr(t, "general", e.req(t, "GET", "/v1/health", nil, "X-Forwarded-For", "198.51.100.20"), 429, CodeTooMany)
}

func TestPassword(t *testing.T) {
	e := setup(t, nil)
	n := claimed(t, e)
	tok := login(t, e, n)
	code, _, _ := e.do(t, "POST", "/v1/password", m{"account": n, "password": pw, "new_password": "short"})
	if code != 400 {
		t.Fatalf("weak %d", code)
	}
	code, out, _ := e.do(t, "POST", "/v1/password", m{"account": n, "password": pw, "new_password": "brand new password"})
	if code != 200 || out["status"] != "changed" {
		t.Fatalf("%d %v", code, out)
	}
	if code, _, _ = e.do(t, "POST", "/v1/devices", m{"account": n, "password": pw}); code != 401 {
		t.Fatalf("old password %d", code)
	}
	if code, _, _ = e.do(t, "POST", "/v1/devices", m{"account": n, "password": "brand new password"}); code != 200 {
		t.Fatalf("new password %d", code)
	}
	expectErr(t, "token after legacy password change", e.bearer(t, tok, "GET", "/v1/me", nil), 401, CodeInvalidToken)
}

func TestBodyLimitAndBadJSON(t *testing.T) {
	e := setup(t, nil)
	big := `{"account":"1","password":"` + strings.Repeat("a", 9000) + `"}`
	r := e.req(t, "POST", "/v1/devices", big)
	if r.code != 400 || r.body["error"] != "bad request" || r.body["code"] != CodeTooLarge {
		t.Fatalf("big %d %s", r.code, r.raw)
	}
	if r := e.req(t, "POST", "/v1/devices", "{"); r.code != 400 || r.body["code"] != CodeBadRequest {
		t.Fatalf("bad json %d", r.code)
	}
	expectErr(t, "new big", e.req(t, "POST", "/v1/auth/token", big), 413, CodeTooLarge)
	expectErr(t, "unknown field", e.req(t, "POST", "/v1/auth/token", m{"account": "1", "password": "x", "extra": 1}), 400, CodeBadRequest)
	expectErr(t, "trailing", e.req(t, "POST", "/v1/auth/token", `{"account":"1","password":"x"} {}`), 400, CodeBadRequest)
	expectErr(t, "wrong type", e.req(t, "POST", "/v1/auth/token", `{"account":1}`), 400, CodeBadRequest)
}

func TestContentType(t *testing.T) {
	e := setup(t, nil)
	for _, ct := range []string{"", "text/plain", "application/x-www-form-urlencoded", "multipart/form-data; boundary=x"} {
		h := []string{"Content-Type", ct}
		expectErr(t, "legacy "+ct, e.req(t, "POST", "/v1/devices", `{}`, h...), 415, CodeMediaType)
		expectErr(t, "token "+ct, e.req(t, "POST", "/v1/auth/token", `{}`, h...), 415, CodeMediaType)
	}
	if r := e.req(t, "POST", "/v1/auth/token", `{"account":"1","password":"wrong password"}`, "Content-Type", "application/json; charset=utf-8"); r.code != 401 {
		t.Fatalf("charset param rejected: %d", r.code)
	}
}

func TestMgmtDown(t *testing.T) {
	e := setup(t, nil)
	e.mgmt.down = true
	n := claimed(t, e)
	e.do(t, "POST", "/v1/enroll", m{"account": n, "password": pw, "name": "a", "csr": ecCSR(t)})
	code, out, _ := e.do(t, "POST", "/v1/devices", m{"account": n, "password": pw})
	if code != 200 || out["devices"].([]any)[0].(map[string]any)["online"] != false {
		t.Fatalf("%d %v", code, out)
	}
}

func TestTokenLifecycle(t *testing.T) {
	e := setup(t, nil)
	n := claimed(t, e)
	clock := time.Now()
	e.s.tokens.now = func() time.Time { return clock }
	r := e.req(t, "POST", "/v1/auth/token", m{"account": n, "password": pw})
	tok, _ := r.body["access_token"].(string)
	if r.code != 200 || !tokenRE.MatchString(tok) {
		t.Fatalf("%d %s", r.code, r.raw)
	}
	exp, err := time.Parse(time.RFC3339, r.body["expires_at"].(string))
	if err != nil || exp.Sub(clock) < 59*time.Minute || exp.Sub(clock) > time.Hour {
		t.Fatalf("expires_at %v %v", exp, err)
	}
	for k := range e.s.tokens.m {
		if string(k[:]) == tok || strings.Contains(string(k[:]), tok[4:]) {
			t.Fatal("token stored in plain text")
		}
	}
	me := e.bearer(t, tok, "GET", "/v1/me", nil)
	if me.code != 200 || me.body["status"] != "active" || me.body["dns_custom"] != false || me.body["expires"] != nil || len(me.body["id"].(string)) != 12 {
		t.Fatalf("%d %s", me.code, me.raw)
	}
	if strings.Contains(string(me.raw), n) {
		t.Fatal("account number leaked in /v1/me")
	}
	if _, err := time.Parse(time.RFC3339, me.body["created"].(string)); err != nil {
		t.Fatal(err)
	}
	for _, h := range []string{"", "Bearer", "Bearer x", "Basic " + tok, "Bearer vey_" + strings.Repeat("A", 43), "Bearer " + tok + "x"} {
		r := e.req(t, "GET", "/v1/me", nil, "Authorization", h)
		expectErr(t, "auth header "+h, r, 401, CodeInvalidToken)
		if r.h.Get("WWW-Authenticate") == "" {
			t.Error("missing WWW-Authenticate")
		}
	}
	if r := e.req(t, "GET", "/v1/me", nil, "Authorization", "bearer "+tok); r.code != 200 {
		t.Fatalf("case-insensitive scheme %d", r.code)
	}
	clock = clock.Add(time.Hour)
	expectErr(t, "expired token", e.bearer(t, tok, "GET", "/v1/me", nil), 401, CodeInvalidToken)
	tok = login(t, e, n)
	if r := e.bearer(t, tok, "POST", "/v1/auth/logout", nil); r.code != 204 {
		t.Fatalf("logout %d", r.code)
	}
	expectErr(t, "after logout", e.bearer(t, tok, "GET", "/v1/me", nil), 401, CodeInvalidToken)
}

func TestTokenLimitPerAccount(t *testing.T) {
	e := setup(t, nil)
	n := claimed(t, e)
	clock := time.Now()
	e.s.tokens.now = func() time.Time { return clock }
	var toks []string
	for i := 0; i < 11; i++ {
		clock = clock.Add(time.Second)
		toks = append(toks, login(t, e, n))
	}
	if c := e.s.tokens.count(store.HashAccount(n)); c != 10 {
		t.Fatalf("live tokens %d", c)
	}
	expectErr(t, "oldest evicted", e.bearer(t, toks[0], "GET", "/v1/me", nil), 401, CodeInvalidToken)
	for _, tk := range toks[1:] {
		if r := e.bearer(t, tk, "GET", "/v1/me", nil); r.code != 200 {
			t.Fatalf("token evicted early: %d", r.code)
		}
	}
}

func TestTokenInvalidation(t *testing.T) {
	e := setup(t, nil)
	n := claimed(t, e)
	key := store.HashAccount(n)
	tok := login(t, e, n)
	other := login(t, e, n)

	expectErr(t, "wrong old pw", e.bearer(t, tok, "PUT", "/v1/me/password", m{"password": "wrong password", "new_password": "another password"}), 401, CodeInvalidCredentials)
	expectErr(t, "weak new pw", e.bearer(t, tok, "PUT", "/v1/me/password", m{"password": pw, "new_password": "x"}), 400, CodeWeakPassword)
	r := e.bearer(t, tok, "PUT", "/v1/me/password", m{"password": pw, "new_password": "another password"})
	fresh, _ := r.body["access_token"].(string)
	if r.code != 200 || !tokenRE.MatchString(fresh) {
		t.Fatalf("%d %s", r.code, r.raw)
	}
	expectErr(t, "old token after change", e.bearer(t, tok, "GET", "/v1/me", nil), 401, CodeInvalidToken)
	expectErr(t, "other token after change", e.bearer(t, other, "GET", "/v1/me", nil), 401, CodeInvalidToken)
	if r := e.bearer(t, fresh, "GET", "/v1/me", nil); r.code != 200 {
		t.Fatalf("fresh token %d", r.code)
	}

	yes := true
	if _, err := e.st.UpdateKey(key, store.Patch{Disabled: &yes}); err != nil {
		t.Fatal(err)
	}
	expectErr(t, "disabled", e.bearer(t, fresh, "GET", "/v1/me", nil), 403, CodeDisabled)
	expectErr(t, "disabled again", e.bearer(t, fresh, "GET", "/v1/me", nil), 401, CodeInvalidToken)
	r = e.req(t, "POST", "/v1/auth/token", m{"account": n, "password": "another password"})
	expectErr(t, "disabled login", r, 403, CodeDisabled)

	no := false
	if _, err := e.st.UpdateKey(key, store.Patch{Disabled: &no}); err != nil {
		t.Fatal(err)
	}
	r = e.req(t, "POST", "/v1/auth/token", m{"account": n, "password": "another password"})
	tok = r.body["access_token"].(string)
	if _, err := e.st.DeleteKey(key); err != nil {
		t.Fatal(err)
	}
	expectErr(t, "deleted", e.bearer(t, tok, "GET", "/v1/me", nil), 401, CodeInvalidToken)
}

func TestExpiredAccountToken(t *testing.T) {
	e := setup(t, nil)
	n := claimed(t, e)
	past := time.Now().Add(-48 * time.Hour).Unix()
	if _, err := e.st.UpdateKey(store.HashAccount(n), store.Patch{Expires: &past}); err != nil {
		t.Fatal(err)
	}
	tok := login(t, e, n)
	r := e.bearer(t, tok, "GET", "/v1/me", nil)
	if r.code != 200 || r.body["status"] != "expired" || r.body["expires"] == nil {
		t.Fatalf("%d %s", r.code, r.raw)
	}
	expectErr(t, "expired enroll", e.bearer(t, tok, "POST", "/v1/me/devices", m{"csr": ecCSR(t)}), 403, CodeExpired)
}

var friendlyRE = regexp.MustCompile(`^[A-Z][a-z]+ [A-Z][a-z]+$`)

func TestMeDevices(t *testing.T) {
	e := setup(t, func(s *config.Settings) { s.DeviceLimit = 3; s.Stealth = true })
	n := claimed(t, e)
	tok := login(t, e, n)

	r := e.bearer(t, tok, "POST", "/v1/me/devices", m{"csr": ecCSR(t)})
	if r.code != 200 {
		t.Fatalf("%d %s", r.code, r.raw)
	}
	id1 := r.body["id"].(string)
	name1 := r.body["name"].(string)
	if !friendlyRE.MatchString(name1) {
		t.Fatalf("friendly name %q", name1)
	}
	p := r.body["profile"].(string)
	if !strings.Contains(p, "remote vpn.example.com 443 tcp-client") || !strings.Contains(p, "<tls-crypt-v2>") {
		t.Fatalf("%s", p)
	}
	r = e.bearer(t, tok, "POST", "/v1/me/devices", m{"name": "  Phone ", "csr": ecCSR(t)})
	if r.code != 200 || r.body["name"] != "Phone" {
		t.Fatalf("%d %s", r.code, r.raw)
	}
	id2 := r.body["id"].(string)
	r = e.bearer(t, tok, "POST", "/v1/me/devices", m{"name": "", "csr": ecCSR(t)})
	if r.code != 200 || r.body["name"] == name1 || !friendlyRE.MatchString(r.body["name"].(string)) {
		t.Fatalf("%d %s", r.code, r.raw)
	}
	expectErr(t, "limit", e.bearer(t, tok, "POST", "/v1/me/devices", m{"csr": ecCSR(t)}), 409, CodeMaxDevices)
	expectErr(t, "bad csr", e.bearer(t, tok, "POST", "/v1/me/devices", m{"csr": "nope"}), 409, CodeMaxDevices)
	expectErr(t, "unknown field", e.bearer(t, tok, "POST", "/v1/me/devices", m{"csr": "x", "account": n}), 400, CodeBadRequest)

	e.mgmt.setOnline(id2)
	r = e.bearer(t, tok, "GET", "/v1/me/devices", nil)
	devs := r.body["devices"].([]any)
	if r.code != 200 || r.body["limit"] != float64(3) || len(devs) != 3 {
		t.Fatalf("%d %s", r.code, r.raw)
	}
	for _, d := range devs {
		dm := d.(map[string]any)
		if _, err := time.Parse(time.RFC3339, dm["created"].(string)); err != nil {
			t.Fatal(err)
		}
		if dm["online"] != (dm["id"] == id2) {
			t.Fatalf("online %v", dm)
		}
		if _, ok := dm["serial"]; ok {
			t.Fatal("serial exposed")
		}
	}

	r = e.bearer(t, tok, "PATCH", "/v1/me/devices/"+id1, m{"name": "Desk"})
	if r.code != 200 || r.body["name"] != "Desk" || r.body["id"] != id1 {
		t.Fatalf("%d %s", r.code, r.raw)
	}
	expectErr(t, "rename bad", e.bearer(t, tok, "PATCH", "/v1/me/devices/"+id1, m{"name": "\x00"}), 400, CodeDeviceName)
	expectErr(t, "rename unknown", e.bearer(t, tok, "PATCH", "/v1/me/devices/ffffffffffffffff", m{"name": "x"}), 404, CodeDeviceNotFound)
	expectErr(t, "rename long id", e.bearer(t, tok, "PATCH", "/v1/me/devices/"+strings.Repeat("a", 65), m{"name": "x"}), 404, CodeDeviceNotFound)

	other := claimed(t, e)
	otok := login(t, e, other)
	expectErr(t, "cross-account delete", e.bearer(t, otok, "DELETE", "/v1/me/devices/"+id1, nil), 404, CodeDeviceNotFound)
	expectErr(t, "cross-account rename", e.bearer(t, otok, "PATCH", "/v1/me/devices/"+id1, m{"name": "x"}), 404, CodeDeviceNotFound)

	if r := e.bearer(t, tok, "DELETE", "/v1/me/devices/"+id1, nil); r.code != 204 {
		t.Fatalf("delete %d %s", r.code, r.raw)
	}
	if k := e.mgmt.kills(); len(k) != 1 || k[0] != id1 {
		t.Fatalf("kills %v", k)
	}
	if n := len(readCRL(t, e).RevokedCertificateEntries); n != 1 {
		t.Fatalf("crl entries %d", n)
	}
	expectErr(t, "delete again", e.bearer(t, tok, "DELETE", "/v1/me/devices/"+id1, nil), 404, CodeDeviceNotFound)
	if _, _, ok := e.st.LookupDevice(id1); ok {
		t.Fatal("device still present")
	}
}

func TestMeDNS(t *testing.T) {
	e := setup(t, nil)
	n := claimed(t, e)
	tok := login(t, e, n)
	r := e.bearer(t, tok, "PUT", "/v1/me/dns", m{"blocking": []string{"social", "ads"}})
	if r.code != 200 || strings.TrimSpace(string(r.raw)) != `{"dns_blocking":["ads","social"],"dns_custom":true}` {
		t.Fatalf("%d %s", r.code, r.raw)
	}
	me := e.bearer(t, tok, "GET", "/v1/me", nil)
	if me.body["dns_custom"] != true || len(me.body["dns_blocking"].([]any)) != 2 {
		t.Fatalf("%s", me.raw)
	}
	r = e.bearer(t, tok, "PUT", "/v1/me/dns", m{"blocking": []string{}})
	if r.code != 200 || strings.TrimSpace(string(r.raw)) != `{"dns_blocking":[],"dns_custom":true}` {
		t.Fatalf("%d %s", r.code, r.raw)
	}
	expectErr(t, "unknown cat", e.bearer(t, tok, "PUT", "/v1/me/dns", m{"blocking": []string{"evil"}}), 400, CodeDNSCategory)
	expectErr(t, "dup cat", e.bearer(t, tok, "PUT", "/v1/me/dns", m{"blocking": []string{"ads", "ads"}}), 400, CodeDNSCategory)
	expectErr(t, "missing", e.bearer(t, tok, "PUT", "/v1/me/dns", m{}), 400, CodeBadRequest)
	r = e.bearer(t, tok, "DELETE", "/v1/me/dns", nil)
	if r.code != 200 || strings.TrimSpace(string(r.raw)) != `{"dns_blocking":["ads","trackers","malware"],"dns_custom":false}` {
		t.Fatalf("%d %s", r.code, r.raw)
	}
	a, _ := e.st.AccountKey(store.HashAccount(n))
	if a.DNSCustom {
		t.Fatal("dns not reset")
	}
}

func TestDeleteMe(t *testing.T) {
	e := setup(t, nil)
	n := claimed(t, e)
	tok := login(t, e, n)
	r := e.bearer(t, tok, "POST", "/v1/me/devices", m{"csr": ecCSR(t)})
	id := r.body["id"].(string)
	expectErr(t, "wrong pw", e.bearer(t, tok, "DELETE", "/v1/me", m{"password": "wrong password"}), 401, CodeInvalidCredentials)
	if r := e.bearer(t, tok, "DELETE", "/v1/me", m{"password": pw}); r.code != 204 {
		t.Fatalf("%d %s", r.code, r.raw)
	}
	expectErr(t, "token after delete", e.bearer(t, tok, "GET", "/v1/me", nil), 401, CodeInvalidToken)
	if k := e.mgmt.kills(); len(k) != 1 || k[0] != id {
		t.Fatalf("kills %v", k)
	}
	if n := len(readCRL(t, e).RevokedCertificateEntries); n != 1 {
		t.Fatalf("crl %d", n)
	}
	expectErr(t, "login after delete", e.req(t, "POST", "/v1/auth/token", m{"account": n, "password": pw}), 401, CodeInvalidCredentials)
}

func TestRevokeEffects(t *testing.T) {
	e := setup(t, nil)
	n := claimed(t, e)
	_, out, _ := e.do(t, "POST", "/v1/enroll", m{"account": n, "password": pw, "name": "a", "csr": ecCSR(t)})
	id := out["id"].(string)
	acc, _ := e.st.AccountKey(store.HashAccount(n))
	d, err := e.st.RevokeID(acc.ID, id)
	if err != nil {
		t.Fatal(err)
	}
	if err := RevokeEffects(e.d, []store.Device{d}); err != nil {
		t.Fatal(err)
	}
	if k := e.mgmt.kills(); len(k) != 1 || k[0] != id {
		t.Fatalf("%v", k)
	}
	if len(readCRL(t, e).RevokedCertificateEntries) != 1 {
		t.Fatal("crl not rewritten")
	}
	nd := e.d
	nd.Mgmt = nil
	if err := RevokeEffects(nd, nil); err != nil {
		t.Fatal(err)
	}
}

func TestFriendlyNames(t *testing.T) {
	taken := map[string]bool{}
	for i := 0; i < 200; i++ {
		n := friendlyName(taken)
		if taken[strings.ToLower(n)] {
			t.Fatalf("duplicate %q", n)
		}
		if _, err := store.CleanName(n); err != nil {
			t.Fatalf("invalid %q", n)
		}
		taken[strings.ToLower(n)] = true
	}
	for _, a := range adjectives {
		for _, b := range animals {
			taken[strings.ToLower(a+" "+b)] = true
		}
	}
	if n := friendlyName(taken); taken[strings.ToLower(n)] {
		t.Fatalf("fallback not unique %q", n)
	}
}

func TestHTTPServerTimeouts(t *testing.T) {
	s := HTTPServer("127.0.0.1:0", http.NotFoundHandler())
	if s.ReadHeaderTimeout == 0 || s.ReadTimeout == 0 || s.WriteTimeout == 0 || s.IdleTimeout == 0 || s.MaxHeaderBytes == 0 || s.ErrorLog == nil {
		t.Fatalf("%+v", s)
	}
}

func TestNoAccountNumberInURLs(t *testing.T) {
	e := setup(t, nil)
	n := claimed(t, e)
	tok := login(t, e, n)
	r := e.bearer(t, tok, "GET", "/v1/me/"+n, nil)
	if r.code != 404 {
		t.Fatalf("%d", r.code)
	}
}
