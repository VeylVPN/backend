package panel

import (
	"bufio"
	"context"
	"net"
	"net/http"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/veylvpn/backend/internal/agentapi"
	"github.com/veylvpn/backend/internal/panelcfg"
	"github.com/veylvpn/backend/internal/records"
	"github.com/veylvpn/backend/internal/records/recordstest"
)

func setupClient(t *testing.T, h *harness) *client {
	t.Helper()
	tok, err := NewSetupToken(h.paths)
	if err != nil {
		t.Fatal(err)
	}
	c := h.client()
	res, b := c.raw("POST", "/api/setup/session", nil, map[string]string{SetupHeader: tok})
	if res.StatusCode != 200 {
		t.Fatal(res.StatusCode, string(b))
	}
	_, out := c.do("GET", "/api/setup/state", nil)
	if out == nil {
		t.Fatal("no state")
	}
	c.csrf = strings.Split(strings.Split(string(b), `"csrf":"`)[1], `"`)[0]
	return c
}

func TestSetupTokenChecks(t *testing.T) {
	h := newHarness(t, nil)
	if _, err := NewSetupToken(h.paths); err != nil {
		t.Fatal(err)
	}
	c := h.client()
	for i := 0; i < 5; i++ {
		res, _ := c.raw("POST", "/api/setup/session", nil, map[string]string{SetupHeader: "wrong-token-value-wrong-token-value"})
		if res.StatusCode != 403 {
			t.Fatal(res.StatusCode)
		}
	}
	res, _ := c.raw("POST", "/api/setup/session", nil, map[string]string{SetupHeader: "x"})
	if res.StatusCode != 429 {
		t.Fatal("setup token not throttled", res.StatusCode)
	}
	if code, _ := c.do("GET", "/api/setup/state", nil); code != 401 {
		t.Fatal(code)
	}
	if code, out := c.do("GET", "/api/fleet", nil); code != 409 || out["code"] != "NOT_SET_UP" {
		t.Fatal("api reachable before setup", code)
	}
}

func TestSetupWizardFlow(t *testing.T) {
	w := recordstest.NewWorld(t, "example.com", func() *records.Client { return &records.Client{Timeout: 500 * time.Millisecond} })
	w.Public.Set("control.example.com", records.TypeA, records.RR{IP: net.ParseIP("203.0.113.10")})
	w.Both("control.example.com", records.TypeA, records.RR{IP: net.ParseIP("203.0.113.10")})
	h := newHarness(t, func(o *Options) { o.Checker = w.Checker })
	h.agent.set("node_host", "vpn.example.com")
	h.agent.op = func(ctx context.Context, req agentapi.Request, fn func(agentapi.Event)) error {
		if req.Op == panelcfg.OpCert {
			fn(agentapi.Event{Step: "issue", Status: agentapi.StatusOK, Detail: "certificate issued"})
			h.agent.set("cert_expiry", "2027-01-01T00:00:00Z")
		}
		fn(agentapi.Event{Done: true})
		return nil
	}
	c := setupClient(t, h)
	if code, out := c.do("POST", "/api/setup/domain", map[string]any{"domain": "vpn.example.com"}); code != 400 || out["code"] != "SAME_AS_NODE" {
		t.Fatal(code, out)
	}
	if code, _ := c.do("POST", "/api/setup/domain", map[string]any{"domain": "control.example.com\n}"}); code != 400 {
		t.Fatal(code)
	}
	if code, out := c.do("POST", "/api/setup/domain", map[string]any{"domain": "Control.Example.com."}); code != 200 || out["domain"] != "control.example.com" {
		t.Fatal(code, out)
	}
	s, _ := panelcfg.LoadSite(h.paths.Site())
	wantMode := panelcfg.ModeHTTP
	if h.p.opt.Platform == "windows" {
		wantMode = panelcfg.ModeCaddy
	}
	if s.Domain != "control.example.com" || s.Mode != wantMode || s.PublicIP != "203.0.113.10" {
		t.Fatal(s)
	}
	code, out := c.do("GET", "/api/setup/records?host=control.example.com", nil)
	if code != 200 || out["status"] != records.StatusOK || len(out["authoritative"].([]any)) != 2 {
		t.Fatal(code, out)
	}
	if code, _ := c.do("POST", "/api/setup/cert", map[string]any{"email": "ops@example.com", "agree": false, "mode": "http"}); code != 400 {
		t.Fatal("terms not required", code)
	}
	if code, out := c.do("POST", "/api/setup/cert", map[string]any{"email": "ops@example.com", "agree": true, "mode": "http"}); code != 202 || out["https"] != "https://control.example.com/setup" {
		t.Fatal(code, out)
	}
	if !h.p.job("cert").Wait(5 * time.Second) {
		t.Fatal("cert job did not finish")
	}
	_, st := c.do("GET", "/api/setup/state", nil)
	if st["cert"] != true {
		t.Fatal(st)
	}
	if code, out := c.do("POST", "/api/setup/finish", map[string]any{}); code != 409 || out["code"] != "NO_OWNER" {
		t.Fatal(code, out)
	}
	code, out = c.do("POST", "/api/setup/owner", map[string]string{"username": "root-owner", "password": "a-very-long-password"})
	if code != 200 {
		t.Fatal(code, out)
	}
	ticket := out["enroll"].(string)
	_, info := c.do("POST", "/api/enroll/info", map[string]string{"ticket": ticket})
	code, out = c.do("POST", "/api/enroll/finish", map[string]string{"ticket": ticket, "code": totpNow(t, info["secret"].(string), h.clk.Now())})
	if code != 200 || len(out["recovery"].([]any)) != 10 {
		t.Fatal(code, out)
	}
	if code, _ := c.do("POST", "/api/setup/owner", map[string]string{"username": "second", "password": "a-very-long-password"}); code != 409 {
		t.Fatal("second owner via setup", code)
	}
	code, out = c.do("POST", "/api/setup/finish", map[string]any{})
	if code != 200 || out["url"] != "https://control.example.com/" {
		t.Fatal(code, out)
	}
	if _, err := os.Stat(h.paths.SetupToken()); !os.IsNotExist(err) {
		t.Fatal("token not removed")
	}
	if code, _ := c.do("GET", "/api/setup/state", nil); code != 404 {
		t.Fatal("wizard still open", code)
	}
	time.Sleep(50 * time.Millisecond)
	if h.agent.count(panelcfg.OpSite) < 2 || h.agent.count(panelcfg.OpCert) != 1 {
		t.Fatal(h.agent.ops)
	}
}

func TestSetupOwnerNeedsHTTPS(t *testing.T) {
	h := newHarness(t, func(o *Options) { o.Insecure = false })
	c := setupClient(t, h)
	if code, out := c.do("POST", "/api/setup/owner", map[string]string{"username": "owner", "password": "a-very-long-password"}); code != 409 || out["code"] != "HTTPS_REQUIRED" {
		t.Fatal(code, out)
	}
	res, _ := c.raw("POST", "/api/setup/owner", map[string]string{"username": "owner", "password": "a-very-long-password"}, map[string]string{"X-Forwarded-Proto": "https"})
	if res.StatusCode != 200 {
		t.Fatal(res.StatusCode)
	}
}

func TestACMEDNSHandshake(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("certbot runs on linux only")
	}
	w := recordstest.NewWorld(t, "example.com", func() *records.Client { return &records.Client{Timeout: 500 * time.Millisecond} })
	h := newHarness(t, func(o *Options) { o.Checker = w.Checker })
	if err := panelcfg.SaveSite(h.paths.Site(), panelcfg.Site{Domain: "control.example.com", Email: "ops@example.com", Mode: panelcfg.ModeDNS}); err != nil {
		t.Fatal(err)
	}
	h.p.acme.Every = 50 * time.Millisecond
	allowHookUID = os.Getuid()
	defer func() { allowHookUID = -1 }()
	sock := h.paths.ACMESock()
	ln, err := h.p.acme.Listen(sock)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go h.p.acme.Serve(ctx, ln)
	value := "dGVzdC12YWxpZGF0aW9uLXRva2VuLTEyMzQ1Ng"
	if _, err := panelcfg.AskHook(ctx, sock, panelcfg.HookRequest{Op: panelcfg.HookAuth, Domain: "other.example.com", Validation: value}); err != nil {
		t.Fatal(err)
	}
	if rep, _ := panelcfg.AskHook(ctx, sock, panelcfg.HookRequest{Op: panelcfg.HookAuth, Domain: "other.example.com", Validation: value}); rep.OK {
		t.Fatal("foreign domain accepted")
	}
	done := make(chan panelcfg.HookReply, 1)
	go func() {
		rep, _ := panelcfg.AskHook(ctx, sock, panelcfg.HookRequest{Op: panelcfg.HookAuth, Domain: "control.example.com", Validation: value})
		done <- rep
	}()
	var ch *Challenge
	for i := 0; i < 100 && ch == nil; i++ {
		time.Sleep(20 * time.Millisecond)
		ch = h.p.acme.Current()
	}
	if ch == nil || ch.Name != "_acme-challenge.control.example.com" || ch.Value != value {
		t.Fatal(ch)
	}
	select {
	case <-done:
		t.Fatal("hook returned before the record was visible")
	case <-time.After(200 * time.Millisecond):
	}
	w.NS1.Set(ch.Name, records.TypeTXT, records.RR{TXT: []string{value}})
	w.NS2.Set(ch.Name, records.TypeTXT, records.RR{TXT: []string{value}})
	select {
	case rep := <-done:
		if !rep.OK {
			t.Fatal(rep)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("hook never released")
	}
	if c := h.p.acme.Current(); c == nil || c.Status != "visible" || !c.Report.Visible {
		t.Fatal(c)
	}
	if rep, err := panelcfg.AskHook(ctx, sock, panelcfg.HookRequest{Op: panelcfg.HookCleanup, Domain: "control.example.com", Validation: value}); err != nil || !rep.OK {
		t.Fatal(rep, err)
	}
	if h.p.acme.Current() != nil {
		t.Fatal("challenge not cleared")
	}
	go func() {
		rep, _ := panelcfg.AskHook(ctx, sock, panelcfg.HookRequest{Op: panelcfg.HookAuth, Domain: "control.example.com", Validation: value + "x2"})
		done <- rep
	}()
	for i := 0; i < 100 && h.p.acme.Current() == nil; i++ {
		time.Sleep(20 * time.Millisecond)
	}
	if !h.p.acme.Cancel() {
		t.Fatal("nothing to cancel")
	}
	if rep := <-done; rep.OK {
		t.Fatal("cancelled challenge reported ok")
	}
}

func TestACMEHookRejectsOtherUsers(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("peer credentials are unix only")
	}
	h := newHarness(t, nil)
	_ = panelcfg.SaveSite(h.paths.Site(), panelcfg.Site{Domain: "control.example.com", Mode: panelcfg.ModeDNS})
	ln, err := h.p.acme.Listen(h.paths.ACMESock())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go h.p.acme.Serve(ctx, ln)
	if os.Getuid() == 0 {
		t.Skip("running as root")
	}
	rep, err := panelcfg.AskHook(ctx, h.paths.ACMESock(), panelcfg.HookRequest{Op: panelcfg.HookAuth, Domain: "control.example.com", Validation: "dGVzdC12YWxpZGF0aW9uLXRva2Vu"})
	if err != nil || rep.OK || rep.Message != "forbidden" {
		t.Fatal(rep, err)
	}
}

func TestFakeCertbotDNSFlow(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("certbot runs on linux only")
	}
	if os.Getenv("VEYL_HOOK_HELPER") == "1" {
		return
	}
	w := recordstest.NewWorld(t, "example.com", func() *records.Client { return &records.Client{Timeout: 500 * time.Millisecond} })
	h := newHarness(t, func(o *Options) { o.Checker = w.Checker })
	_ = panelcfg.SaveSite(h.paths.Site(), panelcfg.Site{Domain: "control.example.com", Email: "ops@example.com", Mode: panelcfg.ModeDNS})
	h.p.acme.Every = 50 * time.Millisecond
	allowHookUID = os.Getuid()
	defer func() { allowHookUID = -1 }()
	ln, err := h.p.acme.Listen(h.paths.ACMESock())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go h.p.acme.Serve(ctx, ln)
	certbot := writeFakeCertbot(t, h.paths)
	go func() {
		for i := 0; i < 200; i++ {
			if c := h.p.acme.Current(); c != nil {
				w.Both(c.Name, records.TypeTXT, records.RR{TXT: []string{c.Value}})
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
	}()
	out, err := runScript(ctx, certbot, h.paths)
	if err != nil {
		t.Fatal(err, out)
	}
	if !strings.Contains(out, "auth-ok") || !strings.Contains(out, "cleanup-done") {
		t.Fatal(out)
	}
}

func readLines(s string) []string {
	var out []string
	sc := bufio.NewScanner(strings.NewReader(s))
	for sc.Scan() {
		out = append(out, sc.Text())
	}
	return out
}

var _ = http.StatusOK
