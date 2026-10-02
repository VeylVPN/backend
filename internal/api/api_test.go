package api

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/veylvpn/backend/internal/ovpn"
	"github.com/veylvpn/backend/internal/pki"
	"github.com/veylvpn/backend/internal/store"
)

type env struct {
	srv    *httptest.Server
	st     *store.Store
	ca     *pki.CA
	dir    string
	mu     sync.Mutex
	online []string
	killed []string
}

func setup(t *testing.T, open bool, static string) *env {
	t.Helper()
	e := &env{dir: t.TempDir()}
	var err error
	if e.ca, err = pki.Init(e.dir); err != nil {
		t.Fatal(err)
	}
	if e.st, err = store.Open(filepath.Join(e.dir, "state.json")); err != nil {
		t.Fatal(err)
	}
	sd, err := os.MkdirTemp("", "v")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(sd) })
	sock := filepath.Join(sd, "m")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				sc := bufio.NewScanner(c)
				for sc.Scan() {
					line := sc.Text()
					e.mu.Lock()
					switch {
					case line == "status 3":
						c.Write([]byte("HEADER\tCLIENT_LIST\tCommon Name\n"))
						for _, cn := range e.online {
							c.Write([]byte("CLIENT_LIST\t" + cn + "\t198.51.100.1:1000\t10.8.0.2\n"))
						}
						c.Write([]byte("END\n"))
					case strings.HasPrefix(line, "kill "):
						e.killed = append(e.killed, strings.TrimPrefix(line, "kill "))
						c.Write([]byte("SUCCESS: killed\n"))
					}
					e.mu.Unlock()
				}
			}()
		}
	}()
	cfg := Config{Endpoint: "vpn.example.com", CRLPath: filepath.Join(e.dir, pki.CRLFile), OpenRegistration: open, StaticDir: static}
	e.srv = httptest.NewServer(New(cfg, e.st, e.ca, &ovpn.Client{Socket: sock}).Handler())
	t.Cleanup(e.srv.Close)
	return e
}

func (e *env) do(t *testing.T, method, path string, body any) (int, map[string]any, http.Header) {
	t.Helper()
	var rd *bytes.Reader
	if s, ok := body.(string); ok {
		rd = bytes.NewReader([]byte(s))
	} else {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, e.srv.URL+path, rd)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out, resp.Header
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

type m = map[string]any

func claimed(t *testing.T, e *env) string {
	t.Helper()
	n, err := e.st.NewAccount()
	if err != nil {
		t.Fatal(err)
	}
	code, out, _ := e.do(t, "POST", "/v1/register", m{"account": n, "password": "correct horse"})
	if code != 200 || out["account"] != n {
		t.Fatalf("claim %d %v", code, out)
	}
	return n
}

func TestInfo(t *testing.T) {
	e := setup(t, false, "")
	code, out, h := e.do(t, "GET", "/v1/info", nil)
	if code != 200 || out["endpoint"] != "vpn.example.com" || out["port"] != float64(1194) || out["proto"] != "udp" {
		t.Fatalf("%d %v", code, out)
	}
	for _, k := range []string{"X-Content-Type-Options", "Referrer-Policy", "Content-Security-Policy", "Cache-Control"} {
		if h.Get(k) == "" {
			t.Errorf("missing header %s", k)
		}
	}
}

func TestRegister(t *testing.T) {
	e := setup(t, false, "")
	n, _ := e.st.NewAccount()
	cases := []struct {
		name string
		body m
		code int
		err  string
	}{
		{"closed registration", m{"password": "correct horse"}, 400, "account required"},
		{"short password", m{"account": n, "password": "short"}, 400, "password must be at least 10 characters"},
		{"unknown account", m{"account": "9999999999999999", "password": "correct horse"}, 401, "invalid credentials"},
		{"claim", m{"account": n, "password": "correct horse"}, 200, ""},
		{"claim twice", m{"account": n, "password": "other password"}, 409, "account already claimed"},
	}
	for _, c := range cases {
		code, out, _ := e.do(t, "POST", "/v1/register", c.body)
		if code != c.code || (c.err != "" && out["error"] != c.err) {
			t.Errorf("%s: %d %v", c.name, code, out)
		}
	}
}

func TestOpenRegistration(t *testing.T) {
	e := setup(t, true, "")
	code, out, _ := e.do(t, "POST", "/v1/register", m{"password": "correct horse"})
	n, _ := out["account"].(string)
	if code != 200 || len(n) != 16 {
		t.Fatalf("%d %v", code, out)
	}
	code, _, _ = e.do(t, "POST", "/v1/devices", m{"account": n, "password": "correct horse"})
	if code != 200 {
		t.Fatalf("devices %d", code)
	}
	code, _, _ = e.do(t, "POST", "/v1/register", m{"password": "x"})
	if code != 400 {
		t.Fatalf("weak %d", code)
	}
}

func TestEnrollDevicesRevoke(t *testing.T) {
	e := setup(t, false, "")
	n := claimed(t, e)
	pw := "correct horse"

	code, out, _ := e.do(t, "POST", "/v1/enroll", m{"account": n, "password": pw, "name": "  laptop ", "csr": ecCSR(t)})
	if code != 200 {
		t.Fatalf("enroll %d %v", code, out)
	}
	id := out["id"].(string)
	profile := out["profile"].(string)
	if len(id) != 16 {
		t.Fatalf("id %q", id)
	}
	for _, want := range []string{"<ca>", "<cert>", "__PRIVATE_KEY__", "<tls-crypt>", "remote vpn.example.com 1194"} {
		if !strings.Contains(profile, want) {
			t.Errorf("profile missing %q", want)
		}
	}
	start := strings.Index(profile, "<cert>\n") + len("<cert>\n")
	end := strings.Index(profile, "</cert>")
	blk, _ := pem.Decode([]byte(profile[start:end]))
	cert, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if cert.Subject.CommonName != id {
		t.Fatalf("cn %q != %q", cert.Subject.CommonName, id)
	}
	pool := x509.NewCertPool()
	pool.AddCert(e.ca.Cert())
	if _, err := cert.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Fatal(err)
	}

	e.mu.Lock()
	e.online = []string{id}
	e.mu.Unlock()
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

	e.mu.Lock()
	e.online = nil
	e.mu.Unlock()
	_, out, _ = e.do(t, "POST", "/v1/devices", m{"account": n, "password": pw})
	if out["devices"].([]any)[0].(map[string]any)["online"] != false {
		t.Fatal("expected offline")
	}

	code, out, _ = e.do(t, "POST", "/v1/revoke", m{"account": n, "password": pw, "id": "nope"})
	if code != 404 {
		t.Fatalf("revoke unknown %d %v", code, out)
	}
	code, out, _ = e.do(t, "POST", "/v1/revoke", m{"account": n, "password": pw, "id": id})
	if code != 200 || out["status"] != "revoked" {
		t.Fatalf("revoke %d %v", code, out)
	}
	e.mu.Lock()
	killed := append([]string(nil), e.killed...)
	e.mu.Unlock()
	if len(killed) != 1 || killed[0] != id {
		t.Fatalf("killed %v", killed)
	}
	b, _ := os.ReadFile(filepath.Join(e.dir, pki.CRLFile))
	cb, _ := pem.Decode(b)
	rl, err := x509.ParseRevocationList(cb.Bytes)
	if err != nil || len(rl.RevokedCertificateEntries) != 1 || rl.RevokedCertificateEntries[0].SerialNumber.Cmp(cert.SerialNumber) != 0 {
		t.Fatalf("crl %v %v", rl, err)
	}
	_, out, _ = e.do(t, "POST", "/v1/devices", m{"account": n, "password": pw})
	if len(out["devices"].([]any)) != 0 {
		t.Fatal("device not removed")
	}
}

func TestEnrollErrors(t *testing.T) {
	e := setup(t, false, "")
	n := claimed(t, e)
	pw := "correct horse"
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
}

func TestDeviceLimit(t *testing.T) {
	e := setup(t, false, "")
	n := claimed(t, e)
	for i := 0; i < 5; i++ {
		code, out, _ := e.do(t, "POST", "/v1/enroll", m{"account": n, "password": "correct horse", "name": "d", "csr": ecCSR(t)})
		if code != 200 {
			t.Fatalf("enroll %d: %d %v", i, code, out)
		}
	}
	code, out, _ := e.do(t, "POST", "/v1/enroll", m{"account": n, "password": "correct horse", "name": "d", "csr": ecCSR(t)})
	if code != 409 || out["error"] != "device limit reached" {
		t.Fatalf("%d %v", code, out)
	}
}

func TestIdentical401(t *testing.T) {
	e := setup(t, false, "")
	n := claimed(t, e)
	_, a, _ := e.do(t, "POST", "/v1/devices", m{"account": n, "password": "wrong password"})
	_, b, _ := e.do(t, "POST", "/v1/devices", m{"account": "1234123412341234", "password": "wrong password"})
	ab, _ := json.Marshal(a)
	bb, _ := json.Marshal(b)
	if string(ab) != string(bb) || string(ab) != `{"error":"invalid credentials"}` {
		t.Fatalf("%s vs %s", ab, bb)
	}
	code, _, _ := e.do(t, "POST", "/v1/devices", m{"account": n, "password": "wrong password"})
	if code != 401 {
		t.Fatalf("%d", code)
	}
}

func TestThrottle429(t *testing.T) {
	e := setup(t, false, "")
	n := claimed(t, e)
	for i := 0; i < 5; i++ {
		code, _, _ := e.do(t, "POST", "/v1/devices", m{"account": n, "password": "wrong password"})
		if code != 401 {
			t.Fatalf("attempt %d: %d", i, code)
		}
	}
	for _, path := range []string{"/v1/devices", "/v1/enroll", "/v1/revoke", "/v1/password"} {
		code, out, _ := e.do(t, "POST", path, m{"account": n, "password": "correct horse"})
		if code != 429 {
			t.Fatalf("%s: %d %v", path, code, out)
		}
	}
	other := claimed(t, e)
	code, _, _ := e.do(t, "POST", "/v1/devices", m{"account": other, "password": "correct horse"})
	if code != 200 {
		t.Fatalf("other account affected: %d", code)
	}
}

func TestPassword(t *testing.T) {
	e := setup(t, false, "")
	n := claimed(t, e)
	code, _, _ := e.do(t, "POST", "/v1/password", m{"account": n, "password": "correct horse", "new_password": "short"})
	if code != 400 {
		t.Fatalf("weak %d", code)
	}
	code, out, _ := e.do(t, "POST", "/v1/password", m{"account": n, "password": "correct horse", "new_password": "brand new password"})
	if code != 200 || out["status"] != "changed" {
		t.Fatalf("%d %v", code, out)
	}
	code, _, _ = e.do(t, "POST", "/v1/devices", m{"account": n, "password": "correct horse"})
	if code != 401 {
		t.Fatalf("old password %d", code)
	}
	code, _, _ = e.do(t, "POST", "/v1/devices", m{"account": n, "password": "brand new password"})
	if code != 200 {
		t.Fatalf("new password %d", code)
	}
}

func TestBodyLimitAndBadJSON(t *testing.T) {
	e := setup(t, false, "")
	big := `{"account":"1","password":"` + strings.Repeat("a", 9000) + `"}`
	if code, _, _ := e.do(t, "POST", "/v1/devices", big); code != 400 {
		t.Fatalf("big %d", code)
	}
	if code, _, _ := e.do(t, "POST", "/v1/devices", "{"); code != 400 {
		t.Fatalf("bad json %d", code)
	}
}

func TestMgmtDown(t *testing.T) {
	e := setup(t, false, "")
	e.srv.Close()
	cfg := Config{Endpoint: "h", CRLPath: filepath.Join(e.dir, pki.CRLFile)}
	e.srv = httptest.NewServer(New(cfg, e.st, e.ca, &ovpn.Client{Socket: "/nonexistent/m"}).Handler())
	defer e.srv.Close()
	n := claimed(t, e)
	e.do(t, "POST", "/v1/enroll", m{"account": n, "password": "correct horse", "name": "a", "csr": ecCSR(t)})
	code, out, _ := e.do(t, "POST", "/v1/devices", m{"account": n, "password": "correct horse"})
	if code != 200 || out["devices"].([]any)[0].(map[string]any)["online"] != false {
		t.Fatalf("%d %v", code, out)
	}
}

func TestStatic(t *testing.T) {
	d := t.TempDir()
	os.WriteFile(filepath.Join(d, "index.html"), []byte("hello"), 0o644)
	e := setup(t, false, d)
	resp, err := http.Get(e.srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 || resp.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("%d", resp.StatusCode)
	}
	e2 := setup(t, false, "")
	resp2, err := http.Get(e2.srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != 404 {
		t.Fatalf("no static: %d", resp2.StatusCode)
	}
}
