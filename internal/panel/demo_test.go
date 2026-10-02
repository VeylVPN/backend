package panel

import (
	"context"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/veylvpn/backend/internal/agentapi"
	"github.com/veylvpn/backend/internal/config"
	"github.com/veylvpn/backend/internal/panelcfg"
	"github.com/veylvpn/backend/internal/panelkey"
	"github.com/veylvpn/backend/internal/records"
	"github.com/veylvpn/backend/internal/records/recordstest"
	"github.com/veylvpn/backend/internal/store"
	"github.com/veylvpn/backend/internal/web"
)

const demoSecret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"

type demoSpec struct {
	host     string
	ip       string
	online   int
	name     string
	down     bool
	failed   string
	platform string
	accounts int
	disk     string
	cert     string
}

func demoWorld(t *testing.T) *recordstest.World {
	w := recordstest.NewWorld(t, "example.com", func() *records.Client { return &records.Client{Timeout: 400 * time.Millisecond} })
	ok := func(host, ip string) {
		w.Public.Set(host, records.TypeA, records.RR{IP: net.ParseIP(ip), TTL: 300})
		w.Both(host, records.TypeA, records.RR{IP: net.ParseIP(ip), TTL: 300})
	}
	ok("control.example.com", "203.0.113.10")
	ok("ams.example.com", "198.51.100.20")
	ok("fra.example.com", "198.51.100.21")
	ok("nyc.example.com", "198.51.100.22")
	ok("sgp.example.com", "198.51.100.24")
	w.Public.Set("lon.example.com", records.TypeA, records.RR{IP: net.ParseIP("104.16.4.4")})
	w.Both("lon.example.com", records.TypeA, records.RR{IP: net.ParseIP("104.16.4.4")})
	w.Public.Set("tyo.example.com", records.TypeA, records.RR{IP: net.ParseIP("192.0.2.99"), TTL: 14400})
	w.Both("tyo.example.com", records.TypeA, records.RR{IP: net.ParseIP("198.51.100.25"), TTL: 14400})
	return w
}

func demoPanel(t *testing.T, configured bool, w *recordstest.World) (*Panel, *fakeAgent, panelcfg.Paths) {
	dir := t.TempDir()
	paths := panelcfg.Paths{Data: dir, Run: dir}
	if f := os.Getenv("VEYL_PANEL_DEMO_FONT"); f != "" {
		if b, err := os.ReadFile(f); err == nil {
			_ = os.MkdirAll(web.FontDir(dir), 0o755)
			_ = os.WriteFile(web.FontPath(dir), b, 0o644)
		}
	}
	ag := &fakeAgent{status: map[string]string{"public_ipv4": "203.0.113.10", "certbot": "2.11.0", "svc.caddy": "active", "svc.veyl-panel": "active", "svc.veyl-panel-agent": "active", "svc.certbot.timer": "active", "uptime": "1209600", "load": "0.04 0.05 0.01", "platform": "linux"}}
	if configured {
		ag.status["cert_expiry"] = "2026-12-24T09:12:00Z"
	}
	ts := httptest.NewTLSServer(http.NotFoundHandler())
	pool := x509.NewCertPool()
	pool.AddCert(ts.Certificate())
	ts.Close()
	var p *Panel
	var err error
	p, err = New(Options{Paths: paths, Agent: ag, Checker: w.Checker, Insecure: true, RootCAs: pool, Interval: 30 * time.Second, Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, demoAddr(addr))
	}, Releases: func(ctx context.Context) (string, error) { return "v0.3.0", nil }})
	if err != nil {
		t.Fatal(err)
	}
	ag.op = func(ctx context.Context, req agentapi.Request, fn func(agentapi.Event)) error {
		step := func(name, detail string) {
			fn(agentapi.Event{Step: name, Status: agentapi.StatusRun})
			time.Sleep(500 * time.Millisecond)
			fn(agentapi.Event{Step: name, Status: agentapi.StatusOK, Detail: detail})
		}
		switch req.Op {
		case panelcfg.OpCert:
			s := p.site()
			step("certbot", "certbot 2.11.0")
			step("web", "updated")
			if s.Mode == panelcfg.ModeDNS {
				fn(agentapi.Event{Step: "issue", Status: agentapi.StatusRun, Detail: "waiting for the DNS TXT record"})
				go func() {
					time.Sleep(20 * time.Second)
					w.Both(panelcfg.ChallengeName(s.Domain), records.TypeTXT, records.RR{TXT: []string{"Xk4pR9vQe2LmW7sTz1YbN0cHgJuA5dFo3iKqE8rVw6M"}})
				}()
				p.acme.Every = time.Second
				if err := p.acme.Authorize(ctx, s.Domain, "Xk4pR9vQe2LmW7sTz1YbN0cHgJuA5dFo3iKqE8rVw6M"); err != nil {
					fn(agentapi.Event{Step: "issue", Status: agentapi.StatusFail, Detail: err.Error()})
					fn(agentapi.Event{Done: true, Error: err.Error()})
					return err
				}
			}
			step("issue", "certificate issued for "+s.Domain)
			step("install", "valid until 2026-12-31")
			step("https", "updated, https on")
			step("verify", "https://"+s.Domain+" is reachable")
			ag.set("cert_expiry", "2026-12-31T00:00:00Z")
		case panelcfg.OpRenew:
			step("renew", "renewed")
			step("install", "valid until 2027-01-01")
		default:
			step(req.Op, "done")
		}
		fn(agentapi.Event{Done: true})
		return nil
	}
	return p, ag, paths
}

var (
	demoMu    sync.Mutex
	demoPorts = map[string]string{}
)

func setDemoPort(host, addr string) {
	demoMu.Lock()
	demoPorts[host] = addr
	demoMu.Unlock()
}

func demoAddr(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	demoMu.Lock()
	real, ok := demoPorts[host]
	demoMu.Unlock()
	if ok {
		return real
	}
	return addr
}

func seedDemo(t *testing.T, p *Panel, ag *fakeAgent) {
	ctx := context.Background()
	_ = panelcfg.SaveSite(p.opt.Paths.Site(), panelcfg.Site{Domain: "control.example.com", Email: "ops@example.com", Mode: panelcfg.ModeHTTP, Configured: true})
	owner, err := p.createUser("maya", "correct-horse-battery", RoleOwner, false)
	if err != nil {
		t.Fatal(err)
	}
	_, hashed := newRecoveryCodes()
	_ = p.db.Update(func(d *data) error {
		u := d.user(owner.ID)
		u.TOTP, u.Recovery = demoSecret, hashed[:8]
		return nil
	})
	for _, u := range [][2]string{{"jonas", RoleAdmin}, {"priya", RoleAdmin}, {"support", RoleViewer}} {
		x, _ := p.createUser(u[0], "correct-horse-battery", u[1], u[0] == "support")
		_ = p.db.Update(func(d *data) error {
			if u[0] != "support" {
				d.user(x.ID).TOTP = demoSecret
			}
			d.user(x.ID).LastLogin = time.Now().Add(-time.Duration(len(u[0])) * 7 * time.Hour).Unix()
			return nil
		})
	}
	specs := []demoSpec{
		{host: "ams.example.com", ip: "198.51.100.20", online: 14, name: "Amsterdam", accounts: 6, disk: "61000000000", cert: "2026-12-20T00:00:00Z"},
		{host: "fra.example.com", ip: "198.51.100.21", online: 6, name: "Frankfurt", accounts: 4, failed: "veyl-dns", disk: "40000000000", cert: "2026-12-02T00:00:00Z"},
		{host: "lon.example.com", ip: "198.51.100.26", online: 9, name: "London", accounts: 3, disk: "70000000000", cert: "2026-10-11T00:00:00Z"},
		{host: "nyc.example.com", ip: "198.51.100.22", online: 21, name: "New York", accounts: 9, platform: "windows", disk: "8000000000", cert: "2026-12-28T00:00:00Z"},
		{host: "sgp.example.com", ip: "198.51.100.24", online: 0, name: "Singapore", accounts: 2, down: true, disk: "55000000000", cert: "2026-11-30T00:00:00Z"},
		{host: "tyo.example.com", ip: "198.51.100.25", online: 4, name: "Tokyo", accounts: 5, disk: "52000000000", cert: "2026-12-15T00:00:00Z"},
	}
	var nodes []*fakeNode
	for _, s := range specs {
		n := newNode(t, s.name)
		host := s.host
		_, _ = n.d.Settings.Update(func(c *config.Settings) error { c.Host = host; return nil })
		nodes = append(nodes, n)
		u := strings.TrimPrefix(n.srv.URL, "https://")
		setDemoPort(s.host, u)
		n.agent.set("public_ip", s.ip)
		n.setOnline(s.online)
		if s.platform != "" {
			n.setPlatform(s.platform)
		}
		if s.failed != "" {
			n.agent.set("svc."+s.failed, "failed")
		}
		n.agent.set("disk_total", "100000000000")
		n.agent.set("disk_free", s.disk)
		n.agent.set("mem", "412.0 MB used of 2.0 GB")
		n.agent.set("load", "0.12 0.09 0.05")
		n.agent.set("cert_expiry", s.cert)
		n.agent.set("svc.openvpn-server@veyl-udp", "active")
		n.agent.set("svc.unbound", "active")
		n.agent.set("svc.veyl", "active")
		for i := 0; i < s.accounts; i++ {
			_, _, _ = n.d.Store.CreateAccount(store.CreateOpts{Label: []string{"Family", "Laptop", "Office", "Travel", "Phone", "Studio", "Garage", "Parents", "Guest"}[i%9]})
		}
		_, _, _ = n.d.Store.NewInvite(3, time.Now().Add(7*24*time.Hour).Unix())
		code, _, _ := n.adm.NewPairingCode("https://"+s.host+":"+portOf(u), panelkey.ScopeManage)
		node, err := p.pairNode(ctx, code, s.name, "", false)
		if err != nil {
			t.Fatal(s.name, err)
		}
		if s.platform != "" {
			_ = p.db.Update(func(d *data) error { d.node(node.ID).Platform = s.platform; return nil })
		}
	}
	time.Sleep(300 * time.Millisecond)
	now := time.Now()
	_ = p.db.Update(func(d *data) error {
		for i, n := range d.Nodes {
			var hours []Hour
			for hh := 90 * 24; hh > 0; hh-- {
				start := hourStart(now.Add(-time.Duration(hh) * time.Hour))
				up := int64(3600)
				if (hh+i*37)%211 == 0 {
					up = 1800
				}
				if i == 4 && hh < 3 {
					up = 0
				}
				if i == 1 && hh%173 == 0 {
					up = 3000
				}
				hours = append(hours, Hour{Start: start, Up: up, Total: 3600})
			}
			d.Uptime[n.ID] = hours
			if i%2 == 0 {
				st := now.Add(-time.Duration(100+i*80) * time.Hour).Unix()
				d.Incidents = append(d.Incidents, Incident{ID: randID(), NodeID: n.ID, Kind: "down", Start: st, End: st + 540, Notes: []Note{{Time: st, Text: "Node stopped answering: timed out"}, {Time: st + 540, Text: "Node is answering again"}}})
			}
			if i == 3 {
				st := now.Add(-50 * time.Hour).Unix()
				d.Incidents = append(d.Incidents, Incident{ID: randID(), NodeID: n.ID, Kind: "service", Subject: "unbound", Start: st, End: st + 95, Notes: []Note{{Time: st, Text: "unbound failed"}, {Time: st + 1, Text: "Automatic restart requested (attempt 1 of 3)"}, {Time: st + 2, Text: "Restart accepted by the node"}, {Time: st + 95, Text: "Healed by automatic restart"}}})
			}
		}
		d.sortIncidents()
		d.Alerts.Webhooks = []WebhookConfig{{ID: randID(), Enabled: true, Name: "Ops on Discord", URL: "https://discord.com/api/webhooks/1234/abcd", Format: "discord"}}
		d.Alerts.Ntfy = NtfyConfig{Enabled: true, Server: "https://ntfy.sh", Topic: "veyl-ops-x9k2"}
		d.Alerts.SMTP = SMTPConfig{Enabled: true, Host: "smtp.fastmail.com", Port: 465, Security: "tls", Username: "alerts@example.com", From: "alerts@example.com", To: []string{"maya@example.com", "oncall@example.com"}}
		return nil
	})
	p.alerts.status["ntfy"] = Result{Time: now.Add(-3 * time.Hour).Unix(), OK: true}
	p.alerts.status["smtp"] = Result{Time: now.Add(-26 * time.Hour).Unix(), OK: true}
	actions := []AuditEntry{
		{User: "maya", Action: "login"},
		{User: "maya", Action: "node.pair", Target: "Tokyo", Detail: "tyo.example.com"},
		{User: "jonas", Action: "node.account.create", Target: "Amsterdam", Detail: "expires_days, label"},
		{User: "jonas", Action: "node.invite.create", Target: "Frankfurt", Detail: "bulk"},
		{User: "auto-heal", Action: "node.service.restart", Target: "New York", Detail: "unbound"},
		{User: "priya", Action: "node.settings.update", Target: "London", Detail: "device_limit, name, registration"},
		{User: "maya", Action: "team.invite", Target: "viewer", Detail: "Support desk"},
		{User: "maya", Action: "alerts.update"},
	}
	_ = p.db.Update(func(d *data) error {
		for i, a := range actions {
			a.Time = now.Add(-time.Duration(len(actions)-i) * 3 * time.Hour).Unix()
			d.Audit = append(d.Audit, a)
		}
		d.Invites = append(d.Invites, TeamInvite{ID: randID(), Hash: hashToken("demo-invite-token-0123456789abcdefghijk"), Role: RoleViewer, Note: "Support desk", By: "maya", Created: now.Unix(), Expires: now.Add(40 * time.Hour).Unix()})
		return nil
	})
	nodes[1].agent.set("svc.veyl-dns", "failed")
	nodes[4].setDown(true)
	p.mon.Tick(ctx)
	p.mon.Tick(ctx)
	time.Sleep(200 * time.Millisecond)
	nodes[1].agent.set("svc.veyl-dns", "failed")
}

func portOf(hostport string) string {
	_, p, _ := net.SplitHostPort(hostport)
	return p
}

func demoSession(t *testing.T, p *Panel) string {
	var u User
	p.db.View(func(d *data) { u = *d.userByName("maya") })
	rec := &cookieRecorder{h: http.Header{}}
	req, _ := http.NewRequest("GET", "http://127.0.0.1/", nil)
	if _, err := p.newSession(rec, req, u); err != nil {
		t.Fatal(err)
	}
	for _, c := range (&http.Response{Header: rec.h}).Cookies() {
		if c.Name == SessionCookie {
			return c.Value
		}
	}
	t.Fatal("no cookie")
	return ""
}

type cookieRecorder struct{ h http.Header }

func (c *cookieRecorder) Header() http.Header         { return c.h }
func (c *cookieRecorder) Write(b []byte) (int, error) { return len(b), nil }
func (c *cookieRecorder) WriteHeader(int)             {}

func TestPanelDemo(t *testing.T) {
	addr := os.Getenv("VEYL_PANEL_DEMO")
	if addr == "" {
		t.Skip("set VEYL_PANEL_DEMO=127.0.0.1:port to run the demo server")
	}
	w := demoWorld(t)
	p, ag, paths := demoPanel(t, true, w)
	seedDemo(t, p, ag)
	out := os.Getenv("VEYL_PANEL_DEMO_OUT")
	if out != "" {
		_ = os.WriteFile(out, []byte(demoSession(t, p)+"\n"), 0o600)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go p.alerts.Run(ctx)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = http.Serve(ln, p.Handler()) }()
	if sa := os.Getenv("VEYL_PANEL_DEMO_SETUP"); sa != "" {
		sw := demoWorld(t)
		sp, _, spaths := demoPanel(t, false, sw)
		_ = os.WriteFile(spaths.SetupToken(), []byte("demo-setup-token-0123456789abcdefghijklmnop\n"), 0o600)
		home := newNode(t, "Home")
		_, _ = home.d.Settings.Update(func(c *config.Settings) error { c.Host = "home.example.com"; return nil })
		hu := strings.TrimPrefix(home.srv.URL, "https://")
		setDemoPort("home.example.com", hu)
		lc, _, _ := home.adm.NewPairingCode("https://home.example.com:"+portOf(hu), panelkey.ScopeManage)
		_ = os.WriteFile(spaths.LocalPair(), []byte(lc+"\n"), 0o600)
		sp.agentStatus(ctx, true)
		sl, err := net.Listen("tcp", sa)
		if err != nil {
			t.Fatal(err)
		}
		go func() { _ = http.Serve(sl, sp.Handler()) }()
		_ = spaths
	}
	_ = paths
	stop := os.Getenv("VEYL_PANEL_DEMO_STOP")
	deadline := time.Now().Add(40 * time.Minute)
	for time.Now().Before(deadline) {
		time.Sleep(200 * time.Millisecond)
		if stop != "" {
			if _, err := os.Stat(stop); err == nil {
				return
			}
		}
	}
}
