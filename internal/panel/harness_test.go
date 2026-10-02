package panel

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base32"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/veylvpn/backend/internal/admin"
	"github.com/veylvpn/backend/internal/agentapi"
	"github.com/veylvpn/backend/internal/app"
	"github.com/veylvpn/backend/internal/config"
	"github.com/veylvpn/backend/internal/panelcfg"
	"github.com/veylvpn/backend/internal/pki"
	"github.com/veylvpn/backend/internal/records"
	"github.com/veylvpn/backend/internal/store"
	"github.com/veylvpn/backend/internal/web"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) Add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type fakeAgent struct {
	mu     sync.Mutex
	ops    []string
	status map[string]string
	op     func(ctx context.Context, req agentapi.Request, fn func(agentapi.Event)) error
}

func (f *fakeAgent) Do(ctx context.Context, req agentapi.Request, fn func(agentapi.Event)) error {
	f.mu.Lock()
	f.ops = append(f.ops, req.Op)
	st := map[string]string{}
	for k, v := range f.status {
		st[k] = v
	}
	op := f.op
	f.mu.Unlock()
	if fn == nil {
		fn = func(agentapi.Event) {}
	}
	if req.Op == agentapi.OpStatus {
		fn(agentapi.Event{Done: true, Data: st})
		return nil
	}
	if op != nil {
		return op(ctx, req, fn)
	}
	fn(agentapi.Event{Step: req.Op, Status: agentapi.StatusRun})
	fn(agentapi.Event{Step: req.Op, Status: agentapi.StatusOK})
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

func (f *fakeAgent) set(k, v string) {
	f.mu.Lock()
	f.status[k] = v
	f.mu.Unlock()
}

type harness struct {
	t     *testing.T
	p     *Panel
	srv   *httptest.Server
	clk   *clock
	agent *fakeAgent
	paths panelcfg.Paths
}

type client struct {
	h    *harness
	c    *http.Client
	csrf string
}

func newHarness(t *testing.T, mod func(*Options)) *harness {
	t.Helper()
	dir := t.TempDir()
	paths := panelcfg.Paths{Data: dir, Run: dir}
	clk := &clock{t: time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)}
	ag := &fakeAgent{status: map[string]string{"public_ipv4": "203.0.113.10", "certbot": "2.11.0", "svc.caddy": "active"}}
	o := Options{Paths: paths, Agent: ag, Now: clk.Now, Insecure: true, Interval: 30 * time.Second, JobTime: 10 * time.Second,
		Checker: &records.Checker{Client: &records.Client{Timeout: 300 * time.Millisecond}, Resolvers: []string{"127.0.0.1:1"}}}
	if mod != nil {
		mod(&o)
	}
	p, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	p.alerts.Retry = []time.Duration{0}
	srv := httptest.NewServer(p.Handler())
	t.Cleanup(srv.Close)
	return &harness{t: t, p: p, srv: srv, clk: clk, agent: ag, paths: paths}
}

func (h *harness) client() *client {
	jar, _ := cookiejar.New(nil)
	return &client{h: h, c: &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

func (c *client) raw(method, path string, body any, hdr map[string]string) (*http.Response, []byte) {
	c.h.t.Helper()
	var r io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		r = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, c.h.srv.URL+path, r)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.csrf != "" {
		req.Header.Set(CSRFHeader, c.csrf)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	res, err := c.c.Do(req)
	if err != nil {
		c.h.t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res, b
}

func (c *client) do(method, path string, body any) (int, map[string]any) {
	c.h.t.Helper()
	res, b := c.raw(method, path, body, nil)
	var out map[string]any
	_ = json.Unmarshal(b, &out)
	return res.StatusCode, out
}

func totpNow(t *testing.T, secret string, at time.Time) string {
	t.Helper()
	k, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil {
		t.Fatal(err)
	}
	return admin.TOTPCode(k, at.Unix()/30, 6)
}

func (h *harness) addUser(name, role string) (User, string) {
	h.t.Helper()
	u, err := h.p.createUser(name, "correct-horse-battery", role, false)
	if err != nil {
		h.t.Fatal(err)
	}
	secret := admin.NewTOTPSecret()
	_, hashed := newRecoveryCodes()
	_ = h.p.db.Update(func(d *data) error {
		uu := d.user(u.ID)
		uu.TOTP, uu.Recovery = secret, hashed
		return nil
	})
	return u, secret
}

func (c *client) login(name, secret string) {
	c.h.t.Helper()
	code, out := c.do("GET", "/api/session", nil)
	if code != 200 {
		c.h.t.Fatal(code)
	}
	c.csrf = out["csrf"].(string)
	code, out = c.do("POST", "/api/login", map[string]string{"username": name, "password": "correct-horse-battery", "code": totpNow(c.h.t, secret, c.h.clk.Now())})
	if code != 200 {
		c.h.t.Fatal(code, out)
	}
	c.csrf = out["csrf"].(string)
	c.h.clk.Add(31 * time.Second)
}

func (h *harness) owner() *client {
	h.t.Helper()
	_, sec := h.addUser("owner", RoleOwner)
	c := h.client()
	c.login("owner", sec)
	return c
}

type fakeNode struct {
	t     *testing.T
	srv   *httptest.Server
	adm   *admin.Admin
	d     app.Deps
	agent *nodeAgent
	pool  *x509.CertPool
	down  bool
	mu    sync.Mutex
}

type nodeAgent struct {
	mu       sync.Mutex
	data     map[string]string
	restarts []string
}

func (a *nodeAgent) Do(ctx context.Context, req agentapi.Request, fn func(agentapi.Event)) error {
	a.mu.Lock()
	if req.Op == agentapi.OpRestart {
		a.restarts = append(a.restarts, req.Arg)
	}
	data := map[string]string{}
	for k, v := range a.data {
		data[k] = v
	}
	a.mu.Unlock()
	if req.Op == agentapi.OpStatus {
		fn(agentapi.Event{Data: data})
	}
	fn(agentapi.Event{Done: true})
	return nil
}

func (a *nodeAgent) set(k, v string) {
	a.mu.Lock()
	a.data[k] = v
	a.mu.Unlock()
}

func (a *nodeAgent) restarted() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string(nil), a.restarts...)
}

func newNode(t *testing.T, name string) *fakeNode {
	t.Helper()
	dir := t.TempDir()
	p := config.Paths{Data: dir, Run: dir}
	live, err := config.NewLive(p.Settings())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := live.Update(func(s *config.Settings) error {
		s.Name = name
		s.Host = "vpn.example.com"
		s.Configured = true
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(p.State())
	if err != nil {
		t.Fatal(err)
	}
	ca, err := pki.Init(filepath.Join(dir))
	if err != nil {
		t.Fatal(err)
	}
	ag := &nodeAgent{data: map[string]string{"svc.caddy": "active", "svc.veyl-dns": "active", "disk_total": "100", "disk_free": "50", "public_ip": "198.51.100.20", "cert_expiry": "2027-01-01T00:00:00Z"}}
	d := app.Deps{Paths: p, Settings: live, Store: st, CA: ca, Agent: ag}
	n := &fakeNode{t: t, d: d, agent: ag, adm: admin.New(d)}
	ah := n.adm.Handler()
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/health", func(w http.ResponseWriter, r *http.Request) {
		n.mu.Lock()
		down := n.down
		n.mu.Unlock()
		if down {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		web.JSON(w, 200, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("/v1/info", func(w http.ResponseWriter, r *http.Request) {
		web.JSON(w, 200, map[string]string{"platform": "linux", "name": name})
	})
	mux.Handle("/v1/admin/", ah)
	n.srv = httptest.NewTLSServer(mux)
	t.Cleanup(n.srv.Close)
	n.pool = x509.NewCertPool()
	n.pool.AddCert(n.srv.Certificate())
	return n
}

func (n *fakeNode) setDown(v bool) {
	n.mu.Lock()
	n.down = v
	n.mu.Unlock()
}

func (n *fakeNode) code(scope string) string {
	n.t.Helper()
	code, _, err := n.adm.NewPairingCode(n.srv.URL, scope)
	if err != nil {
		n.t.Fatal(err)
	}
	return code
}

func (n *fakeNode) host() string {
	u, _ := url.Parse(n.srv.URL)
	return u.Hostname()
}

func pools(nodes ...*fakeNode) *x509.CertPool {
	p := x509.NewCertPool()
	for _, n := range nodes {
		p.AddCert(n.srv.Certificate())
	}
	return p
}

func contains(s, sub string) bool { return strings.Contains(s, sub) }
