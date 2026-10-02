package agent

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/veylvpn/backend/internal/agentapi"
	"github.com/veylvpn/backend/internal/config"
	"github.com/veylvpn/backend/internal/panelcfg"
	"github.com/veylvpn/backend/internal/panelkey"
	"github.com/veylvpn/backend/internal/render"
)

func selfSigned(t *testing.T, domain string) (string, string) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: domain}, DNSNames: []string{domain}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Date(2027, 3, 1, 0, 0, 0, 0, time.UTC)}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	kb, _ := x509.MarshalECPrivateKey(k)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}))
}

type panelHarness struct {
	*harness
	p *PanelAgent
}

func newPanelHarness(t *testing.T, node bool, site panelcfg.Site) *panelHarness {
	t.Helper()
	h := newHarness(t, testSettings())
	if !node {
		_ = os.Remove(filepath.Join(h.root, h.a.Paths.Settings()))
	}
	pa := &PanelAgent{Agent: h.a, Panel: panelcfg.DefaultPaths(), Certbot: "certbot"}
	h.a.Ops = pa.Do
	if err := panelcfg.SaveSite(filepath.Join(h.root, pa.Panel.Site()), site); err != nil {
		t.Fatal(err)
	}
	return &panelHarness{harness: h, p: pa}
}

func (h *panelHarness) do(op string) (map[string]string, error) {
	return h.p.Do(context.Background(), op, "", h.emit)
}

func site() panelcfg.Site {
	return panelcfg.Site{Domain: "control.example.com", Email: "ops@example.com", Mode: panelcfg.ModeHTTP, PublicIP: "203.0.113.7"}
}

func TestPanelSiteStandalone(t *testing.T) {
	h := newPanelHarness(t, false, site())
	if _, err := h.do(PanelOpSite); err != nil {
		t.Fatal(err)
	}
	main := readFile(t, h.root, render.CaddyFile)
	if !strings.Contains(main, "import "+panelcfg.ImportGlob) || !strings.Contains(main, "email ops@example.com") {
		t.Fatal(main)
	}
	sf := readFile(t, h.root, panelcfg.SiteFile)
	if !strings.Contains(sf, "http://203.0.113.7 {") || !strings.Contains(sf, "redir /control/setup 302") || strings.Contains(sf, "tls /etc") {
		t.Fatal(sf)
	}
	if h.r.index(t, "caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile") < 0 || h.r.index(t, "systemctl restart caddy.service") < 0 {
		t.Fatal(h.r.list())
	}
}

func TestPanelSiteCombinedAddsImport(t *testing.T) {
	h := newPanelHarness(t, true, site())
	writeFile(t, h.root, render.CaddyFile, "vpn.example.com {\n}\n")
	if _, err := h.do(PanelOpSite); err != nil {
		t.Fatal(err)
	}
	main := readFile(t, h.root, render.CaddyFile)
	if !strings.Contains(main, "vpn.example.com {") || !strings.Contains(main, "reverse_proxy 127.0.0.1:8080") || !strings.Contains(main, "import "+panelcfg.ImportGlob) {
		t.Fatal(main)
	}
	sf := readFile(t, h.root, panelcfg.SiteFile)
	if !strings.Contains(sf, "http://control.example.com {") || !strings.Contains(sf, "\t\treverse_proxy 127.0.0.1:8080\n") {
		t.Fatal(sf)
	}
}

func TestPanelSiteRejectsTamperedConfig(t *testing.T) {
	h := newPanelHarness(t, false, site())
	writeFile(t, h.root, h.p.Panel.Site(), `{"domain":"x.example.com\n}\nevil {","mode":"http"}`)
	if _, err := h.do(PanelOpSite); err == nil {
		t.Fatal("accepted tampered site")
	}
	writeFile(t, h.root, h.p.Panel.Site(), `{"domain":"x.example.com","mode":"http","extra":1}`)
	if _, err := h.do(PanelOpSite); err == nil {
		t.Fatal("accepted unknown field")
	}
}

func TestPanelCertHTTP(t *testing.T) {
	h := newPanelHarness(t, false, site())
	crt, key := selfSigned(t, "control.example.com")
	writeFile(t, h.root, "/etc/letsencrypt/live/control.example.com/fullchain.pem", crt)
	writeFile(t, h.root, "/etc/letsencrypt/live/control.example.com/privkey.pem", key)
	data, err := h.do(PanelOpCert)
	if err != nil {
		t.Fatal(err, h.events)
	}
	want := "certbot certonly --non-interactive --agree-tos --no-eff-email -m ops@example.com --cert-name control.example.com -d control.example.com --keep-until-expiring --deploy-hook /usr/local/bin/veyl panel acme-deploy --webroot -w /var/www/veyl-panel-acme"
	if h.r.index(t, want) < 0 {
		t.Fatal(h.r.list())
	}
	if data["cert_expiry"] != "2027-03-01T00:00:00Z" {
		t.Fatal(data)
	}
	sf := readFile(t, h.root, panelcfg.SiteFile)
	if !strings.Contains(sf, "tls /etc/caddy/veyl-panel/control.example.com.crt /etc/caddy/veyl-panel/control.example.com.key") {
		t.Fatal(sf)
	}
	fi, err := os.Stat(filepath.Join(h.root, panelcfg.CertDir, "control.example.com.key"))
	if err != nil || fi.Mode().Perm() != 0o640 {
		t.Fatal(err, fi.Mode())
	}
	if h.status("verify") != agentapi.StatusOK {
		t.Fatal(h.events)
	}
}

func TestPanelCertDNSArgs(t *testing.T) {
	s := site()
	s.Mode = panelcfg.ModeDNS
	s.Staging = true
	args, err := CertbotArgs(s, "/usr/local/bin/veyl", "https://acme.test/dir")
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(args, " ")
	for _, want := range []string{"--manual --preferred-challenges dns", "--manual-auth-hook /usr/local/bin/veyl panel acme-auth", "--manual-cleanup-hook /usr/local/bin/veyl panel acme-cleanup", "--staging", "--server https://acme.test/dir"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in %s", want, got)
		}
	}
	s.Email = ""
	if _, err := CertbotArgs(s, "/usr/local/bin/veyl", ""); err == nil {
		t.Fatal("missing email accepted")
	}
}

func TestPanelCertFailureExplained(t *testing.T) {
	h := newPanelHarness(t, false, site())
	args, _ := CertbotArgs(site(), config.BinPath, "")
	cmd := "certbot " + strings.Join(args, " ")
	h.r.fail[cmd] = 1
	h.r.out[cmd] = "Certbot failed to authenticate some domains\n  Detail: 203.0.113.7: Timeout during connect (likely firewall problem)\n"
	_, err := h.do(PanelOpCert)
	if err == nil || !strings.Contains(err.Error(), "port 80") {
		t.Fatal(err)
	}
	cases := map[string]string{
		"Error creating new order :: too many certificates (5) already issued": "rate limit",
		"CAA record for control.example.com prevents issuance":                 "CAA",
		"DNS problem: NXDOMAIN looking up A for control.example.com":           "DNS",
		"Incorrect TXT record \"abc\" found at _acme-challenge":                "TXT",
	}
	for out, want := range cases {
		if got := ExplainCertbot(out); !strings.Contains(got, want) {
			t.Errorf("%q -> %q", out, got)
		}
	}
}

func TestPanelInstallCertbotWhenMissing(t *testing.T) {
	h := newPanelHarness(t, false, site())
	h.r.fail["certbot --version"] = 1
	if _, err := h.p.ensureCertbot(context.Background()); err != nil {
		t.Fatal(err)
	}
	if h.r.index(t, "apt-get -o DPkg::Lock::Timeout=120 -y install certbot") < 0 {
		t.Fatal(h.r.list())
	}
}

func TestPanelDeployHook(t *testing.T) {
	h := newPanelHarness(t, false, site())
	crt, key := selfSigned(t, "control.example.com")
	writeFile(t, h.root, "/etc/letsencrypt/live/control.example.com/fullchain.pem", crt)
	writeFile(t, h.root, "/etc/letsencrypt/live/control.example.com/privkey.pem", key)
	if err := h.p.DeployHook(context.Background(), "/etc/letsencrypt/live/other.example.com"); err == nil {
		t.Fatal("foreign lineage accepted")
	}
	if err := h.p.DeployHook(context.Background(), "/etc/letsencrypt/live/control.example.com/../other"); err == nil {
		t.Fatal("traversal accepted")
	}
	if err := h.p.DeployHook(context.Background(), "/etc/letsencrypt/live/control.example.com"); err != nil {
		t.Fatal(err)
	}
	if h.r.index(t, "systemctl restart caddy.service") < 0 {
		t.Fatal(h.r.list())
	}
	other, okey := selfSigned(t, "other.example.com")
	writeFile(t, h.root, "/etc/letsencrypt/live/control.example.com/fullchain.pem", other)
	writeFile(t, h.root, "/etc/letsencrypt/live/control.example.com/privkey.pem", okey)
	if err := h.p.DeployHook(context.Background(), "/etc/letsencrypt/live/control.example.com"); err == nil {
		t.Fatal("mismatched certificate accepted")
	}
}

func TestPanelInstallCombined(t *testing.T) {
	s := testSettings()
	s.Configured = true
	h := newPanelHarness(t, true, panelcfg.Site{})
	if err := config.Save(filepath.Join(h.root, h.a.Paths.Settings()), s); err != nil {
		t.Fatal(err)
	}
	token, err := h.p.Install(context.Background(), h.emit, PanelInstallOpts{Email: "ops@example.com", PublicIP: "203.0.113.7"})
	if err != nil {
		t.Fatal(err, h.events)
	}
	if len(token) != 43 || strings.TrimSpace(readFile(t, h.root, h.p.Panel.SetupToken())) != token {
		t.Fatal(token)
	}
	code := strings.TrimSpace(readFile(t, h.root, h.p.Panel.LocalPair()))
	u, err := panelkey.Decode(code)
	if err != nil || u != "https://vpn.example.com" {
		t.Fatal(u, err)
	}
	ks, err := panelkey.Open(filepath.Join(h.root, h.a.Paths.Data, panelkey.FileName))
	if err != nil || ks.Pending() != 1 {
		t.Fatal(err)
	}
	for _, f := range render.PanelUnits() {
		if readFile(t, h.root, f.Path) != f.Data {
			t.Fatal(f.Path)
		}
	}
	if h.r.index(t, "systemctl enable --now veyl-panel-agent.service veyl-panel.service") < 0 || h.r.index(t, "useradd --system --user-group --home-dir /var/lib/veyl-panel --no-create-home --shell /usr/sbin/nologin veyl-panel") >= 0 {
		t.Fatal(h.r.list())
	}
	sf := readFile(t, h.root, panelcfg.SiteFile)
	if !strings.Contains(sf, "http://203.0.113.7") || !strings.Contains(sf, "redir /control/setup 302") {
		t.Fatal(sf)
	}
}

func TestPanelOpsRejected(t *testing.T) {
	h := newPanelHarness(t, false, site())
	for _, op := range []string{agentapi.OpApply, agentapi.OpTLS, agentapi.OpDNSUpdate, "uninstall", ""} {
		if _, err := h.do(op); err != ErrUnknownOp {
			t.Errorf("%s: %v", op, err)
		}
	}
	if _, err := h.p.Do(context.Background(), agentapi.OpRestart, "caddy", h.emit); err != ErrUnknownOp {
		t.Fatal(err)
	}
	if _, err := h.do(agentapi.OpRestart); err != nil || h.r.index(t, "systemctl restart --no-block veyl-panel.service") < 0 {
		t.Fatal(err, h.r.list())
	}
	data, err := h.do(agentapi.OpStatus)
	if err != nil || data["svc.veyl-panel"] != "active" || data["public_ipv4"] != "203.0.113.7" {
		t.Fatal(err, data)
	}
}

func TestRestartService(t *testing.T) {
	h := newHarness(t, testSettings())
	if _, err := h.a.DoArg(context.Background(), agentapi.OpRestart, "veyl-dns", h.emit); err != nil {
		t.Fatal(err)
	}
	if h.r.index(t, "systemctl restart veyl-dns.service") < 0 || h.r.count("systemctl restart unbound.service") != 0 {
		t.Fatal(h.r.list())
	}
	if _, err := h.a.DoArg(context.Background(), agentapi.OpRestart, "sshd", h.emit); err != ErrService {
		t.Fatal(err)
	}
	if _, err := h.a.DoArg(context.Background(), agentapi.OpApply, "x", h.emit); err != ErrUnknownOp {
		t.Fatal(err)
	}
	h.r.inactive[render.UnitCaddy] = true
	h.r.fail["systemctl restart caddy.service"] = 1
	if _, err := h.a.DoArg(context.Background(), agentapi.OpRestart, "caddy", h.emit); err == nil {
		t.Fatal("failed restart hidden")
	}
}

func TestUpdateOp(t *testing.T) {
	h := newHarness(t, testSettings())
	if _, err := h.do(agentapi.OpUpdate); err == nil {
		t.Fatal("update without installer")
	}
	writeFile(t, h.root, InstallPath, "#!/bin/bash\n")
	if _, err := h.do(agentapi.OpUpdate); err != nil {
		t.Fatal(err)
	}
	if h.r.index(t, "systemd-run --unit veyl-update --collect --quiet --property=Type=exec --setenv=LC_ALL=C.UTF-8 /bin/bash /opt/veyl/src/install.sh --yes") < 0 {
		t.Fatal(h.r.list())
	}
}
