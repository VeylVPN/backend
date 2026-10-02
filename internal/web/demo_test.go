package web_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/veylvpn/backend/internal/admin"
	"github.com/veylvpn/backend/internal/agentapi"
	"github.com/veylvpn/backend/internal/app"
	"github.com/veylvpn/backend/internal/config"
	"github.com/veylvpn/backend/internal/pki"
	"github.com/veylvpn/backend/internal/setup"
	"github.com/veylvpn/backend/internal/store"
	"github.com/veylvpn/backend/internal/web"
)

type demoAgent struct {
	fail  string
	delay time.Duration
}

func (a demoAgent) Do(ctx context.Context, req agentapi.Request, fn func(agentapi.Event)) error {
	step := func(name, detail string) bool {
		fn(agentapi.Event{Step: name, Status: agentapi.StatusRun})
		select {
		case <-time.After(a.delay):
		case <-ctx.Done():
			return false
		}
		if a.fail == req.Op+":"+name {
			fn(agentapi.Event{Step: name, Status: agentapi.StatusFail, Detail: detail})
			return false
		}
		fn(agentapi.Event{Step: name, Status: agentapi.StatusOK, Detail: detail})
		return true
	}
	done := func(ok bool, msg string) error {
		if ok {
			fn(agentapi.Event{Done: true})
			return nil
		}
		fn(agentapi.Event{Done: true, Error: msg})
		return agentapi.ErrAgent
	}
	switch req.Op {
	case agentapi.OpStatus:
		fn(agentapi.Event{Data: map[string]string{
			"public_ip": "203.0.113.5", "os": "Debian 12", "openvpn": "2.6.19", "openssl": "3.5.1", "ram_mb": "2048",
			"load": "0.04 0.03 0.01", "mem": "312 MB of 2 GB", "disk": "18% used", "uptime": "1209600", "cert_expiry": "2026-12-30",
			"svc.veyl": "active", "svc.veyl-dns": "active", "svc.openvpn-server@veyl-udp": "active", "svc.openvpn-server@veyl-tcp": "active",
			"svc.unbound": "active", "svc.caddy": "active", "svc.nftables": "active",
		}})
		if p := os.Getenv("VEYL_UI_DEMO_PLATFORM"); p != "" {
			fn(agentapi.Event{Data: map[string]string{"platform": p, "stealth_port": "993"}})
		}
		return done(true, "")
	case agentapi.OpTLS:
		for _, s := range []string{"caddy", "certificate", "health"} {
			if !step(s, "") {
				return done(false, "Let's Encrypt could not reach this server on port 80. Check that your firewall allows ports 80 and 443.")
			}
		}
		return done(true, "")
	case agentapi.OpApply:
		for _, s := range []string{"users", "privacy", "nftables", "unbound", "blocklists", "openvpn-udp", "openvpn-tcp", "caddy", "updates", "veyl-dns", "verify"} {
			if !step(s, "") {
				return done(false, "OpenVPN did not start. The previous configuration was restored.")
			}
		}
		return done(true, "")
	case agentapi.OpDNSUpdate:
		for _, s := range []string{"blocklists"} {
			if !step(s, "6 lists, 412,331 sites") {
				return done(false, "download failed")
			}
		}
		return done(true, "")
	}
	return done(true, "")
}

type demoMgmt struct {
	mu sync.Mutex
	on map[string]bool
}

func (m *demoMgmt) Online() (map[string]bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := map[string]bool{}
	for k, v := range m.on {
		out[k] = v
	}
	return out, nil
}

func (m *demoMgmt) Kill(cn string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.on, cn)
	return nil
}

func selfSigned(t *testing.T, host string) tls.Certificate {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: host}, DNSNames: []string{host}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}
}

func seed(t *testing.T, d app.Deps, m *demoMgmt) {
	if _, err := d.Settings.Update(func(s *config.Settings) error {
		s.Configured = true
		s.Host = "203-0-113-5.sslip.io"
		s.Name = "Home VPN"
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := admin.SetPassword(d.Paths, "correct-horse-battery"); err != nil {
		t.Fatal(err)
	}
	day := int64(86400)
	now := time.Now().Unix()
	people := []struct {
		label   string
		exp     int64
		devices []string
		off     bool
	}{
		{"Owner", 0, []string{"Pixel 9", "MacBook Air", "iPad"}, false},
		{"Mum's phone", now + 200*day, []string{"iPhone 15"}, false},
		{"Sam", now + 20*day, []string{"Galaxy S24", "Work laptop"}, false},
		{"Guest Wi-Fi test", now - 3*day, nil, false},
		{"Old tablet", 0, []string{"Fire HD"}, true},
	}
	m.on = map[string]bool{}
	for i, p := range people {
		n, acc, err := d.Store.CreateAccount(store.CreateOpts{Label: p.label, Expires: p.exp})
		if err != nil {
			t.Fatal(err)
		}
		for j, dn := range p.devices {
			id := strings.Repeat(string(rune('a'+i)), 8) + strings.Repeat(string(rune('0'+j)), 8)
			if err := d.Store.AddDevice(n, store.Device{ID: id, Name: dn, Serial: "1" + strings.Repeat("0", i+j+1)}); err != nil && p.exp > now {
				t.Fatal(err)
			}
			if j == 0 && i < 3 {
				m.on[id] = true
			}
		}
		if p.off {
			off := true
			_, _ = d.Store.UpdateID(acc.ID, store.Patch{Disabled: &off})
		}
	}
	_, _, _ = d.Store.NewInvite(1, now+7*day)
	_, _, _ = d.Store.NewInvite(5, 0)
	_ = os.MkdirAll(d.Paths.Blocklists(), 0o755)
	sizes := map[string]int{"ads": 2400, "trackers": 900, "malware": 1300, "adult": 0, "gambling": 300, "social": 120}
	for c, n := range sizes {
		if n == 0 {
			continue
		}
		var b strings.Builder
		for i := 0; i < n; i++ {
			b.WriteString("d")
			b.WriteString(big.NewInt(int64(i)).String())
			b.WriteString(".example\n")
		}
		_ = os.WriteFile(filepath.Join(d.Paths.Blocklists(), c+".txt"), []byte(b.String()), 0o644)
	}
}

func fakeDNS(t *testing.T) string {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	answers := map[string][]byte{"vpn.example.com": {203, 0, 113, 5}, "wrong.example.com": {198, 51, 100, 7}, "cf.example.com": {104, 16, 0, 1}}
	go func() {
		buf := make([]byte, 512)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			q := buf[:n]
			if n < 17 {
				continue
			}
			off := 12
			var labels []string
			for off < n && q[off] != 0 {
				l := int(q[off])
				if off+1+l > n {
					break
				}
				labels = append(labels, string(q[off+1:off+1+l]))
				off += 1 + l
			}
			end := off + 5
			if end > n {
				continue
			}
			qtype := int(q[off+1])<<8 | int(q[off+2])
			ip, ok := answers[strings.Join(labels, ".")]
			resp := append([]byte(nil), q[:end]...)
			resp[2], resp[3] = 0x81, 0x80
			resp[6], resp[7] = 0, 0
			if !ok {
				resp[3] = 0x83
			} else if qtype == 1 {
				resp[7] = 1
				resp = append(resp, 0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4)
				resp = append(resp, ip...)
			}
			_, _ = pc.WriteTo(resp, from)
		}
	}()
	return pc.LocalAddr().String()
}

func TestUIDemo(t *testing.T) {
	addr := os.Getenv("VEYL_UI_DEMO")
	if addr == "" {
		t.Skip("set VEYL_UI_DEMO=127.0.0.1:port to run the demo server")
	}
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
	if err := os.WriteFile(p.SetupToken(), []byte("demo-token-0123456789abcdefghijklmnopqrstuv\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	m := &demoMgmt{on: map[string]bool{}}
	d := app.Deps{Paths: p, Settings: live, Store: st, CA: ca, Mgmt: m, Agent: demoAgent{fail: os.Getenv("VEYL_UI_DEMO_FAIL"), delay: 450 * time.Millisecond}}
	if os.Getenv("VEYL_UI_DEMO_SEED") == "admin" {
		seed(t, d, m)
	}
	wz := setup.New(d)
	wz.Resolvers = []string{fakeDNS(t)}
	ad := admin.New(d)
	if f := os.Getenv("VEYL_UI_DEMO_FONT"); f != "" {
		if b, err := os.ReadFile(f); err == nil {
			_ = os.MkdirAll(web.FontDir(dir), 0o755)
			_ = os.WriteFile(web.FontPath(dir), b, 0o644)
		}
	}
	mux := http.NewServeMux()
	mux.Handle(web.FontRoute, web.Fonts(dir))
	sh, ah := wz.Handler(), ad.Handler()
	for _, pat := range []string{"/setup", "/setup/", "/v1/setup/"} {
		mux.Handle(pat, sh)
	}
	for _, pat := range []string{"/admin", "/admin/", "/v1/admin/"} {
		mux.Handle(pat, ah)
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = http.Serve(ln, mux) }()
	if tlsAddr := os.Getenv("VEYL_UI_DEMO_TLS"); tlsAddr != "" {
		cert := selfSigned(t, "203-0-113-5.sslip.io")
		tl, err := tls.Listen("tcp", tlsAddr, &tls.Config{Certificates: []tls.Certificate{cert}})
		if err != nil {
			t.Fatal(err)
		}
		go func() { _ = http.Serve(tl, mux) }()
	}
	stop := os.Getenv("VEYL_UI_DEMO_STOP")
	for {
		time.Sleep(200 * time.Millisecond)
		if stop != "" {
			if _, err := os.Stat(stop); err == nil {
				return
			}
		}
	}
}
