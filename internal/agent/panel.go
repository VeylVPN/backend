package agent

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/veylvpn/backend/internal/agentapi"
	"github.com/veylvpn/backend/internal/config"
	"github.com/veylvpn/backend/internal/panelcfg"
	"github.com/veylvpn/backend/internal/panelkey"
	"github.com/veylvpn/backend/internal/render"
)

const (
	PanelOpSite    = panelcfg.OpSite
	PanelOpCert    = panelcfg.OpCert
	PanelOpRenew   = panelcfg.OpRenew
	certbotTimeout = 50 * time.Minute
)

type PanelAgent struct {
	*Agent
	Panel      panelcfg.Paths
	Certbot    string
	ACMEServer string
}

func NewPanel() *PanelAgent {
	a := New()
	p := &PanelAgent{Agent: a, Panel: panelcfg.DefaultPaths(), Certbot: "certbot"}
	a.Group = panelcfg.User
	a.Ops = p.Do
	a.AllowUID = func(uid uint32) bool {
		if uid == 0 {
			return true
		}
		u, _, err := a.Lookup(panelcfg.User)
		return err == nil && uint32(u) == uid
	}
	return p
}

func (p *PanelAgent) init() {
	p.Agent.init()
	if p.Certbot == "" {
		p.Certbot = "certbot"
	}
	if p.Panel.Data == "" {
		p.Panel = panelcfg.DefaultPaths()
	}
}

func (p *PanelAgent) Do(ctx context.Context, op, arg string, emit Emit) (map[string]string, error) {
	p.init()
	if emit == nil {
		emit = func(agentapi.Event) {}
	}
	if arg != "" {
		return nil, ErrUnknownOp
	}
	switch op {
	case agentapi.OpPing:
		return map[string]string{"pong": "1"}, nil
	case agentapi.OpStatus:
		return p.Status(ctx)
	case PanelOpSite, PanelOpCert, PanelOpRenew, agentapi.OpRestart, agentapi.OpUpdate:
	default:
		return nil, ErrUnknownOp
	}
	if err := p.acquire(ctx, emit); err != nil {
		return nil, err
	}
	defer p.release()
	switch op {
	case PanelOpSite:
		return nil, step(emit, "web", func() (string, error) { return p.Site(ctx) })
	case PanelOpCert:
		return p.Cert(ctx, emit)
	case PanelOpRenew:
		return p.Renew(ctx, emit)
	case agentapi.OpRestart:
		return nil, step(emit, "panel", func() (string, error) {
			return "restart queued", p.systemctl(ctx, "restart", "--no-block", panelcfg.UnitPanel)
		})
	case agentapi.OpUpdate:
		return nil, p.runUpdate(ctx, emit, panelcfg.UpdateUnit)
	}
	return nil, ErrUnknownOp
}

func (p *PanelAgent) site() (panelcfg.Site, error) {
	return panelcfg.LoadSite(p.path(p.Panel.Site()))
}

func (p *PanelAgent) node() (config.Settings, bool) {
	s, err := config.Load(p.path(p.Paths.Settings()))
	if err != nil || !p.exists(p.Paths.Settings()) {
		return config.Settings{}, false
	}
	return s, true
}

func (p *PanelAgent) certIssued(domain string) (time.Time, bool) {
	if domain == "" {
		return time.Time{}, false
	}
	crt, key := panelcfg.CertPaths(domain)
	if !p.exists(key) {
		return time.Time{}, false
	}
	b, err := os.ReadFile(p.path(crt))
	if err != nil {
		return time.Time{}, false
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return time.Time{}, false
	}
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil || c.VerifyHostname(domain) != nil {
		return time.Time{}, false
	}
	return c.NotAfter, true
}

func (p *PanelAgent) Site(ctx context.Context) (string, error) {
	p.init()
	s, err := p.site()
	if err != nil {
		return "", err
	}
	ns, nodePresent := p.node()
	_, issued := p.certIssued(s.Domain)
	pc := render.PanelContext{NodePresent: nodePresent, NodeSetup: nodePresent && !ns.Configured, Stealth: nodePresent && ns.Configured && ns.Stealth, Issued: issued}
	if s.Mode == panelcfg.ModeCaddy {
		pc.Issued = false
	}
	data, err := render.PanelSite(s, pc)
	if err != nil {
		return "", err
	}
	if err := p.ensureDir(panelcfg.SiteDir, 0o755, 0, 0); err != nil {
		return "", err
	}
	if s.Mode == panelcfg.ModeHTTP {
		if err := p.ensureDir(panelcfg.Webroot, 0o755, 0, 0); err != nil {
			return "", err
		}
	}
	files := []fileOut{{panelcfg.SiteFile, data, 0o644}}
	if nodePresent {
		if b, err := os.ReadFile(p.path(render.CaddyFile)); err != nil || !strings.Contains(string(b), panelcfg.ImportGlob) {
			if _, err := p.stepCaddy(ctx, ns, pc.Stealth && p.active(ctx, render.UnitOpenVPNTCP)); err != nil {
				return "", err
			}
		}
	} else {
		main, err := render.PanelCaddyfile(s.Email)
		if err != nil {
			return "", err
		}
		if err := p.saveCaddyOrig(); err != nil {
			return "", err
		}
		files = append(files, fileOut{render.CaddyFile, main, 0o644})
	}
	detail, err := p.deploy(ctx, deployment{
		files: files,
		check: func() error {
			_, err := p.run(ctx, quick, "caddy", "validate", "--config", render.CaddyFile, "--adapter", "caddyfile")
			return err
		},
		unit:   render.UnitCaddy,
		enable: true,
	})
	if err != nil {
		return "", err
	}
	if issued {
		return detail + ", https on", nil
	}
	return detail, nil
}

func (p *PanelAgent) ensureCertbot(ctx context.Context) (string, error) {
	if out, err := p.run(ctx, quick, p.Certbot, "--version"); err == nil {
		return strings.TrimSpace(out), nil
	}
	if _, err := p.run(ctx, slow, "apt-get", "-o", "DPkg::Lock::Timeout=120", "-y", "install", "certbot"); err != nil {
		return "", fmt.Errorf("could not install certbot: %w", err)
	}
	out, err := p.run(ctx, quick, p.Certbot, "--version")
	if err != nil {
		return "", err
	}
	return "installed " + strings.TrimSpace(out), nil
}

func (p *PanelAgent) hook(name string) string {
	return config.BinPath + " panel " + name
}

func CertbotArgs(s panelcfg.Site, bin, server string) ([]string, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	if s.Domain == "" || s.Email == "" {
		return nil, errors.New("panel domain and email are required")
	}
	args := []string{"certonly", "--non-interactive", "--agree-tos", "--no-eff-email", "-m", s.Email, "--cert-name", s.Domain, "-d", s.Domain, "--keep-until-expiring", "--deploy-hook", bin + " panel acme-deploy"}
	switch s.Mode {
	case panelcfg.ModeHTTP:
		args = append(args, "--webroot", "-w", panelcfg.Webroot)
	case panelcfg.ModeDNS:
		args = append(args, "--manual", "--preferred-challenges", "dns", "--manual-auth-hook", bin+" panel acme-auth", "--manual-cleanup-hook", bin+" panel acme-cleanup")
	default:
		return nil, panelcfg.ErrMode
	}
	if s.Staging {
		args = append(args, "--staging")
	}
	if server != "" {
		args = append(args, "--server", server)
	}
	return args, nil
}

func ExplainCertbot(out string) string {
	l := strings.ToLower(out)
	switch {
	case strings.Contains(l, "too many certificates") || strings.Contains(l, "ratelimited") || strings.Contains(l, "rate limit"):
		return "Let's Encrypt rate limit reached for this domain. Wait before trying again, usually up to a week for duplicate certificates."
	case strings.Contains(l, "caa"):
		return "The CAA records on this domain do not allow Let's Encrypt. Add a CAA record: 0 issue \"letsencrypt.org\"."
	case strings.Contains(l, "nxdomain") || strings.Contains(l, "dns problem") || strings.Contains(l, "no valid ip addresses"):
		return "Let's Encrypt could not find this domain in DNS. Check the A record and try again in a few minutes."
	case strings.Contains(l, "incorrect txt record") || strings.Contains(l, "no txt record"):
		return "Let's Encrypt did not see the TXT record yet. Check the record and try again."
	case strings.Contains(l, "timeout during connect") || strings.Contains(l, "connection refused") || strings.Contains(l, "firewall"):
		return "Let's Encrypt could not reach port 80 on this server. Open port 80 or use the DNS TXT record method."
	case strings.Contains(l, "invalid response") || strings.Contains(l, "unauthorized"):
		return "Let's Encrypt reached a different server. Make sure the A record points here and is not proxied."
	case strings.Contains(l, "hook") && strings.Contains(l, "auth"):
		return "The DNS record step was cancelled or timed out."
	}
	return ""
}

func (p *PanelAgent) Cert(ctx context.Context, emit Emit) (map[string]string, error) {
	var s panelcfg.Site
	if err := step(emit, "settings", func() (string, error) {
		var err error
		s, err = p.site()
		if err != nil {
			return "", err
		}
		if s.Domain == "" || s.Email == "" {
			return "", errors.New("set the panel domain and email first")
		}
		return s.Domain, nil
	}); err != nil {
		return nil, err
	}
	if s.Mode == panelcfg.ModeCaddy {
		if err := step(emit, "web", func() (string, error) { return p.Site(ctx) }); err != nil {
			return nil, err
		}
		return nil, step(emit, "certificate", func() (string, error) {
			return p.waitPanelHealth(ctx, emit, s.Domain)
		})
	}
	steps := []struct {
		name string
		fn   func() (string, error)
	}{
		{"certbot", func() (string, error) { return p.ensureCertbot(ctx) }},
		{"web", func() (string, error) { return p.Site(ctx) }},
		{"issue", func() (string, error) {
			args, err := CertbotArgs(s, config.BinPath, p.ACMEServer)
			if err != nil {
				return "", err
			}
			if s.Mode == panelcfg.ModeDNS {
				emit(agentapi.Event{Step: "issue", Status: agentapi.StatusRun, Detail: "waiting for the DNS TXT record"})
			}
			out, err := p.run(ctx, certbotTimeout, p.Certbot, args...)
			if err != nil {
				if why := ExplainCertbot(out); why != "" {
					return "", errors.New(why)
				}
				return "", err
			}
			return "certificate issued for " + s.Domain, nil
		}},
		{"install", func() (string, error) { return p.installCert(ctx, s.Domain, false) }},
		{"https", func() (string, error) { return p.Site(ctx) }},
		{"verify", func() (string, error) { return p.waitPanelHealth(ctx, emit, s.Domain) }},
	}
	for _, st := range steps {
		if err := step(emit, st.name, st.fn); err != nil {
			return nil, err
		}
	}
	exp, _ := p.certIssued(s.Domain)
	return map[string]string{"cert_expiry": exp.UTC().Format(time.RFC3339)}, nil
}

func (p *PanelAgent) waitPanelHealth(ctx context.Context, emit Emit, domain string) (string, error) {
	timeout := p.HealthTimeout
	start := time.Now()
	for {
		err := p.Probe.Health(ctx, domain, false)
		if err == nil {
			return "https://" + domain + " is reachable", nil
		}
		if time.Since(start) > timeout {
			return "", fmt.Errorf("https not reachable yet: %w", err)
		}
		if serr := p.Sleep(ctx, 3*time.Second); serr != nil {
			return "", serr
		}
	}
}

func (p *PanelAgent) Renew(ctx context.Context, emit Emit) (map[string]string, error) {
	s, err := p.site()
	if err != nil {
		return nil, err
	}
	if s.Domain == "" || s.Mode == panelcfg.ModeCaddy {
		return nil, errors.New("certificates are renewed automatically by Caddy in this mode")
	}
	if err := step(emit, "renew", func() (string, error) {
		out, err := p.run(ctx, certbotTimeout, p.Certbot, "renew", "--non-interactive", "--cert-name", s.Domain, "--force-renewal")
		if err != nil {
			if why := ExplainCertbot(out); why != "" {
				return "", errors.New(why)
			}
			return "", err
		}
		return "renewed", nil
	}); err != nil {
		return nil, err
	}
	if err := step(emit, "install", func() (string, error) { return p.installCert(ctx, s.Domain, true) }); err != nil {
		return nil, err
	}
	exp, _ := p.certIssued(s.Domain)
	return map[string]string{"cert_expiry": exp.UTC().Format(time.RFC3339)}, nil
}

func (p *PanelAgent) installCert(ctx context.Context, domain string, restart bool) (string, error) {
	if !panelcfg.ValidDomain(domain) {
		return "", panelcfg.ErrDomain
	}
	live := filepath.Join(panelcfg.LetsEncryptDir, "live", domain)
	chain, err := os.ReadFile(p.path(filepath.Join(live, "fullchain.pem")))
	if err != nil {
		return "", fmt.Errorf("certificate not found: %w", err)
	}
	key, err := os.ReadFile(p.path(filepath.Join(live, "privkey.pem")))
	if err != nil {
		return "", fmt.Errorf("private key not found: %w", err)
	}
	blk, _ := pem.Decode(chain)
	if blk == nil {
		return "", errors.New("certificate is not PEM")
	}
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil || c.VerifyHostname(domain) != nil {
		return "", errors.New("certificate does not match the panel domain")
	}
	gid := 0
	if _, g, err := p.Lookup("caddy"); err == nil {
		gid = g
	}
	if err := p.ensureDir(panelcfg.CertDir, 0o750, 0, gid); err != nil {
		return "", err
	}
	crt, kp := panelcfg.CertPaths(domain)
	old, _ := os.ReadFile(p.path(crt))
	if err := writeAtomic(p.path(kp), key, 0o640); err != nil {
		return "", err
	}
	if err := writeAtomic(p.path(crt), chain, 0o644); err != nil {
		return "", err
	}
	for _, f := range []string{crt, kp} {
		if err := p.Chown(p.path(f), 0, gid); err != nil {
			return "", err
		}
	}
	if restart && string(old) != string(chain) {
		if err := p.systemctl(ctx, "restart", render.UnitCaddy); err != nil {
			return "", err
		}
	}
	return "valid until " + c.NotAfter.UTC().Format("2006-01-02"), nil
}

func (p *PanelAgent) DeployHook(ctx context.Context, lineage string) error {
	p.init()
	s, err := p.site()
	if err != nil {
		return err
	}
	want := filepath.Join(panelcfg.LetsEncryptDir, "live", s.Domain)
	if s.Domain == "" || filepath.Clean(lineage) != want {
		return errors.New("renewed certificate is not the panel certificate")
	}
	_, err = p.installCert(ctx, s.Domain, true)
	return err
}

func (p *PanelAgent) Status(ctx context.Context) (map[string]string, error) {
	p.init()
	data := map[string]string{"platform": "linux"}
	for _, u := range []string{panelcfg.UnitPanel, panelcfg.UnitPanelAgent, render.UnitCaddy, "certbot.timer"} {
		name := strings.TrimSuffix(u, ".service")
		data["svc."+name] = p.state(ctx, u)
	}
	if out, err := p.run(ctx, quick, p.Certbot, "--version"); err == nil {
		data["certbot"] = strings.TrimPrefix(strings.TrimSpace(out), "certbot ")
	}
	if b, err := os.ReadFile(p.path("/proc/uptime")); err == nil {
		if fs := strings.Fields(string(b)); len(fs) > 0 {
			if v, err := strconv.ParseFloat(fs[0], 64); err == nil {
				data["uptime"] = strconv.FormatInt(int64(v), 10)
			}
		}
	}
	if b, err := os.ReadFile(p.path("/proc/loadavg")); err == nil {
		if fs := strings.Fields(string(b)); len(fs) >= 3 {
			data["load"] = strings.Join(fs[:3], " ")
		}
	}
	if total, free, err := diskUsage(p.path("/")); err == nil {
		data["disk_total"] = strconv.FormatUint(total, 10)
		data["disk_free"] = strconv.FormatUint(free, 10)
	}
	pctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if ip, err := p.Probe.PublicIP(pctx, false); err == nil {
		data["public_ipv4"] = ip
	}
	if ip, err := p.Probe.PublicIP(pctx, true); err == nil {
		data["public_ipv6"] = ip
	}
	if ns, ok := p.node(); ok {
		data["node"] = "1"
		data["node_host"] = ns.Host
		data["node_configured"] = strconv.FormatBool(ns.Configured)
	}
	if s, err := p.site(); err == nil && s.Domain != "" {
		if exp, ok := p.certIssued(s.Domain); ok {
			data["cert_expiry"] = exp.UTC().Format(time.RFC3339)
		}
	}
	return data, nil
}

type PanelInstallOpts struct {
	Domain   string
	Email    string
	PublicIP string
}

func (p *PanelAgent) Install(ctx context.Context, emit Emit, o PanelInstallOpts) (string, error) {
	p.init()
	var uid, gid int
	token := ""
	steps := []struct {
		name string
		fn   func() (string, error)
	}{
		{"users", func() (string, error) {
			if _, err := p.run(ctx, quick, "getent", "passwd", panelcfg.User); err == nil {
				return "unchanged", nil
			}
			if _, err := p.run(ctx, quick, "useradd", "--system", "--user-group", "--home-dir", p.Panel.Data, "--no-create-home", "--shell", "/usr/sbin/nologin", panelcfg.User); err != nil {
				return "", err
			}
			return "created " + panelcfg.User, nil
		}},
		{"directories", func() (string, error) {
			var err error
			uid, gid, err = p.Lookup(panelcfg.User)
			if err != nil {
				return "", err
			}
			if err := p.ensureDir(p.Panel.Data, 0o750, uid, gid); err != nil {
				return "", err
			}
			if err := p.ensureDir(p.Panel.Run, 0o770, 0, gid); err != nil {
				return "", err
			}
			if err := p.ensureDir(panelcfg.Webroot, 0o755, 0, 0); err != nil {
				return "", err
			}
			return "ok", p.ensureDir(panelcfg.SiteDir, 0o755, 0, 0)
		}},
		{"units", func() (string, error) {
			t := p.txn()
			for _, f := range render.PanelUnits() {
				if _, err := t.put(f.Path, f.Data, os.FileMode(f.Mode)); err != nil {
					return "", err
				}
			}
			if err := p.systemctl(ctx, "daemon-reload"); err != nil {
				return "", err
			}
			_, _ = p.run(ctx, quick, "systemd-tmpfiles", "--create", panelcfg.TmpfilesFile)
			if t.changed() {
				return "updated", nil
			}
			return "unchanged", nil
		}},
		{"certbot", func() (string, error) { return p.ensureCertbot(ctx) }},
		{"fonts", func() (string, error) {
			node := p.Paths
			p.Paths.Data = p.Panel.Data
			defer func() { p.Paths = node }()
			return p.stepFonts(ctx)
		}},
		{"settings", func() (string, error) { return p.seedSite(o, uid, gid) }},
		{"web", func() (string, error) { return p.Site(ctx) }},
		{"services", func() (string, error) {
			return "enabled", p.systemctl(ctx, "enable", "--now", panelcfg.UnitPanelAgent, panelcfg.UnitPanel)
		}},
		{"local-node", func() (string, error) { return p.localPair(uid, gid) }},
		{"setup-link", func() (string, error) {
			s, err := p.site()
			if err != nil {
				return "", err
			}
			if s.Configured {
				return "", skip("panel already set up")
			}
			token, err = p.writeToken(uid, gid)
			return "ready", err
		}},
	}
	for _, st := range steps {
		if err := step(emit, st.name, st.fn); err != nil {
			return "", err
		}
	}
	return token, nil
}

func (p *PanelAgent) seedSite(o PanelInstallOpts, uid, gid int) (string, error) {
	path := p.path(p.Panel.Site())
	s, err := panelcfg.LoadSite(path)
	if err != nil {
		return "", err
	}
	if s.Configured {
		return "kept", nil
	}
	if o.Domain != "" {
		if !panelcfg.ValidDomain(o.Domain) {
			return "", panelcfg.ErrDomain
		}
		s.Domain = strings.ToLower(o.Domain)
		if s.Mode == "" {
			s.Mode = panelcfg.ModeHTTP
		}
	}
	if o.Email != "" {
		s.Email = o.Email
	}
	if o.PublicIP != "" && panelcfg.ValidPublicIP(o.PublicIP) {
		s.PublicIP = o.PublicIP
	}
	if err := panelcfg.SaveSite(path, s); err != nil {
		return "", err
	}
	return "saved", p.Chown(path, uid, gid)
}

func (p *PanelAgent) localPair(uid, gid int) (string, error) {
	ns, ok := p.node()
	if !ok || !ns.Configured || ns.Host == "" {
		return "", skip("no configured node on this server")
	}
	u, err := panelkey.NodeURL(ns.Host)
	if err != nil {
		return "", err
	}
	keys := p.path(filepath.Join(p.Paths.Data, panelkey.FileName))
	ks, err := panelkey.Open(keys)
	if err != nil {
		return "", err
	}
	code, _, err := ks.NewPairing(u, panelkey.ScopeManage)
	if err != nil {
		return "", err
	}
	if vu, vg, err := p.Lookup(config.ServiceUser); err == nil {
		_ = p.Chown(keys, vu, vg)
	}
	lp := p.path(p.Panel.LocalPair())
	if err := writeAtomic(lp, []byte(code+"\n"), 0o600); err != nil {
		return "", err
	}
	if err := p.Chown(lp, uid, gid); err != nil {
		return "", err
	}
	return "pairing code ready for " + ns.Host, nil
}

func (p *PanelAgent) writeToken(uid, gid int) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	t := base64.RawURLEncoding.EncodeToString(b)
	path := p.path(p.Panel.SetupToken())
	if err := writeAtomic(path, []byte(t+"\n"), 0o600); err != nil {
		return "", err
	}
	return t, p.Chown(path, uid, gid)
}

func (p *PanelAgent) Uninstall(ctx context.Context, emit Emit, purge bool) error {
	p.init()
	_ = step(emit, "services", func() (string, error) {
		_ = p.systemctl(ctx, "disable", "--now", panelcfg.UnitPanel)
		return "stopped", nil
	})
	_ = step(emit, "files", func() (string, error) {
		for _, f := range render.PanelUnits() {
			_, _ = p.remove(f.Path)
		}
		_, _ = p.remove(panelcfg.SiteFile)
		_ = os.RemoveAll(p.path(panelcfg.CertDir))
		_ = os.RemoveAll(p.path(panelcfg.Webroot))
		if _, ok := p.node(); !ok {
			orig := p.path(render.CaddyFile + ".veyl-orig")
			if _, err := os.Stat(orig); err == nil {
				_ = os.Rename(orig, p.path(render.CaddyFile))
			}
		}
		_ = p.systemctl(ctx, "daemon-reload")
		_ = p.systemctl(ctx, "try-restart", render.UnitCaddy)
		return "removed", nil
	})
	if purge {
		_ = step(emit, "data", func() (string, error) {
			return "removed " + p.Panel.Data, os.RemoveAll(p.path(p.Panel.Data))
		})
		_ = step(emit, "user", func() (string, error) {
			_, _ = p.run(ctx, quick, "userdel", panelcfg.User)
			return "removed", nil
		})
	} else {
		emit(agentapi.Event{Step: "data", Status: agentapi.StatusSkip, Detail: "kept " + p.Panel.Data})
	}
	_ = step(emit, "agent", func() (string, error) {
		_ = p.systemctl(ctx, "disable", panelcfg.UnitPanelAgent)
		_ = p.systemctl(ctx, "stop", "--no-block", panelcfg.UnitPanelAgent)
		return "removed", nil
	})
	return nil
}
