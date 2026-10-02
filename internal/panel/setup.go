package panel

import (
	"context"
	"crypto/subtle"
	"errors"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/veylvpn/backend/internal/agentapi"
	"github.com/veylvpn/backend/internal/config"
	"github.com/veylvpn/backend/internal/panelcfg"
	"github.com/veylvpn/backend/internal/records"
	"github.com/veylvpn/backend/internal/web"
)

const (
	SetupCookie    = "veyl_panel_setup"
	SetupHeader    = "X-Setup-Token"
	setupTTL       = 3 * time.Hour
	setupMaxFails  = 5
	setupFailEvery = time.Minute
)

type wsession struct {
	csrf    string
	expires time.Time
}

type wizardState struct {
	sessions map[string]*wsession
	fails    []time.Time
}

func (p *Panel) setupRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/setup/session", p.setupSession)
	mux.HandleFunc("GET /api/setup/state", p.wizard(p.setupState))
	mux.HandleFunc("POST /api/setup/domain", p.wizard(p.setupDomain))
	mux.HandleFunc("GET /api/setup/records", p.wizard(p.setupRecords))
	mux.HandleFunc("POST /api/setup/cert", p.wizard(p.setupCert))
	mux.HandleFunc("GET /api/setup/cert/progress", p.wizard(p.setupCertProgress))
	mux.HandleFunc("GET /api/setup/challenge", p.wizard(p.challengeState))
	mux.HandleFunc("POST /api/setup/challenge/cancel", p.wizard(p.challengeCancel))
	mux.HandleFunc("POST /api/setup/owner", p.wizard(p.setupOwner))
	mux.HandleFunc("POST /api/setup/pair", p.wizard(p.setupPair))
	mux.HandleFunc("POST /api/setup/finish", p.wizard(p.setupFinish))
}

func (p *Panel) readSetupToken() string {
	b, err := os.ReadFile(p.opt.Paths.SetupToken())
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func NewSetupToken(paths panelcfg.Paths) (string, error) {
	t := randToken(32)
	return t, panelcfg.WriteFile(paths.SetupToken(), []byte(t+"\n"), 0o600)
}

func (p *Panel) setupFailed() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	cut := p.now().Add(-setupFailEvery)
	keep := p.wiz.fails[:0]
	for _, t := range p.wiz.fails {
		if t.After(cut) {
			keep = append(keep, t)
		}
	}
	p.wiz.fails = keep
	return len(keep) >= setupMaxFails
}

func (p *Panel) setupSession(w http.ResponseWriter, r *http.Request) {
	if p.site().Configured {
		web.NotFound(w)
		return
	}
	if p.setupFailed() {
		web.Error(w, http.StatusTooManyRequests, "TOO_MANY_REQUESTS", "Too many tries. Wait a minute and open your setup link again.")
		return
	}
	got := r.Header.Get(SetupHeader)
	want := p.readSetupToken()
	if len(got) > 128 || want == "" || subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
		p.mu.Lock()
		p.wiz.fails = append(p.wiz.fails, p.now())
		p.mu.Unlock()
		web.Error(w, http.StatusForbidden, "INVALID_TOKEN", "This setup link is not valid. Run \"sudo veyl panel setup-link\" on the server for a fresh one.")
		return
	}
	t := randToken(32)
	csrf := randToken(24)
	p.mu.Lock()
	if p.wiz.sessions == nil {
		p.wiz.sessions = map[string]*wsession{}
	}
	for k, s := range p.wiz.sessions {
		if p.now().After(s.expires) {
			delete(p.wiz.sessions, k)
		}
	}
	if len(p.wiz.sessions) >= 16 {
		p.wiz.sessions = map[string]*wsession{}
	}
	p.wiz.sessions[hashToken(t)] = &wsession{csrf: csrf, expires: p.now().Add(setupTTL)}
	p.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: SetupCookie, Value: t, Path: "/", HttpOnly: true, Secure: web.Secure(r), SameSite: http.SameSiteStrictMode, MaxAge: int(setupTTL / time.Second)})
	web.JSON(w, http.StatusOK, map[string]any{"ok": true, "csrf": csrf})
}

func (p *Panel) wizard(fn http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if p.site().Configured {
			web.NotFound(w)
			return
		}
		c, err := r.Cookie(SetupCookie)
		var s *wsession
		if err == nil && len(c.Value) >= 20 && len(c.Value) <= 128 {
			p.mu.Lock()
			s = p.wiz.sessions[hashToken(c.Value)]
			if s != nil && p.now().After(s.expires) {
				s = nil
			}
			p.mu.Unlock()
		}
		if s == nil {
			web.Error(w, http.StatusUnauthorized, "UNAUTHORIZED", "Open your setup link again to continue.")
			return
		}
		if r.Method != http.MethodGet {
			h := r.Header.Get(CSRFHeader)
			if h == "" || subtle.ConstantTimeCompare([]byte(h), []byte(s.csrf)) != 1 {
				web.Error(w, http.StatusForbidden, "CSRF", "Your session expired. Reload the page.")
				return
			}
		}
		fn(w, r)
	}
}

func requestIP(r *http.Request) string {
	h := r.Host
	if hh, _, err := net.SplitHostPort(h); err == nil {
		h = hh
	}
	h = strings.Trim(h, "[]")
	if panelcfg.ValidPublicIP(h) {
		return h
	}
	return ""
}

func (p *Panel) publicIPs(r *http.Request) ([]string, []string) {
	st := p.agentStatus(r.Context(), false)
	var v4, v6 []string
	if ip := st["public_ipv4"]; panelcfg.ValidPublicIP(ip) {
		v4 = append(v4, ip)
	}
	if ip := st["public_ipv6"]; panelcfg.ValidPublicIP(ip) {
		v6 = append(v6, ip)
	}
	if len(v4) == 0 && r != nil {
		if ip := requestIP(r); ip != "" && net.ParseIP(ip).To4() != nil {
			v4 = append(v4, ip)
		}
	}
	return v4, v6
}

func (p *Panel) nodeHosts() []string {
	var out []string
	p.db.View(func(d *data) {
		for _, n := range d.Nodes {
			out = append(out, n.Host)
		}
	})
	if h := p.agentStatus(context.Background(), false)["node_host"]; h != "" {
		out = append(out, h)
	}
	return out
}

func (p *Panel) setupState(w http.ResponseWriter, r *http.Request) {
	s := p.site()
	st := p.agentStatus(r.Context(), false)
	v4, v6 := p.publicIPs(r)
	_, localErr := os.Stat(p.opt.Paths.LocalPair())
	nodes := []map[string]string{}
	p.db.View(func(d *data) {
		for _, n := range d.Nodes {
			nodes = append(nodes, map[string]string{"id": n.ID, "name": n.Name, "host": n.Host})
		}
	})
	_, certOK := certValid(st["cert_expiry"], p.now())
	if s.Mode == panelcfg.ModeCaddy {
		certOK = st["cert_expiry"] != "" || p.httpsReady(r)
	}
	job := map[string]any{"running": false}
	if j := p.job("cert"); j != nil {
		_, done, out := j.State()
		job = map[string]any{"running": !done, "done": done, "ok": out.OK, "error": out.Error}
	}
	web.JSON(w, http.StatusOK, map[string]any{
		"site":        map[string]any{"domain": s.Domain, "email": s.Email, "mode": s.Mode},
		"platform":    p.opt.Platform,
		"ipv4":        v4,
		"ipv6":        v6,
		"https":       web.Secure(r),
		"host":        r.Host,
		"cert":        certOK,
		"cert_expiry": st["cert_expiry"],
		"cert_job":    job,
		"owner":       p.ownerExists(),
		"local_node":  localErr == nil,
		"node_host":   st["node_host"],
		"nodes":       nodes,
		"certbot":     st["certbot"],
	})
}

func (p *Panel) httpsReady(r *http.Request) bool {
	return web.Secure(r)
}

type domainIn struct {
	Domain    string   `json:"domain"`
	NodeHosts []string `json:"node_hosts"`
}

func (p *Panel) setupDomain(w http.ResponseWriter, r *http.Request) {
	var in domainIn
	if !web.Decode(w, r, &in, bodyLimit) {
		return
	}
	d := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(in.Domain), "."))
	if !panelcfg.ValidDomain(d) {
		web.Error(w, http.StatusBadRequest, "BAD_DOMAIN", "Use a domain name like control.example.com.")
		return
	}
	if len(in.NodeHosts) > 32 {
		web.Error(w, http.StatusBadRequest, "BAD_REQUEST", "Check up to 32 node addresses at a time.")
		return
	}
	for _, h := range append(in.NodeHosts, p.nodeHosts()...) {
		if strings.EqualFold(strings.TrimSpace(h), d) {
			web.Error(w, http.StatusBadRequest, "SAME_AS_NODE", "The panel needs its own domain. Pick one that no VPN node uses, for example control."+parentOf(d)+".")
			return
		}
	}
	s := p.site()
	if s.Domain != d {
		s.Domain = d
		if p.opt.Platform == "windows" {
			s.Mode = panelcfg.ModeCaddy
		} else if s.Mode == "" || s.Mode == panelcfg.ModeCaddy {
			s.Mode = panelcfg.ModeHTTP
		}
	}
	if v4, _ := p.publicIPs(r); len(v4) > 0 {
		s.PublicIP = v4[0]
	}
	if err := p.saveSite(s); err != nil {
		web.Error(w, http.StatusInternalServerError, "INTERNAL", "Could not save the domain.")
		return
	}
	go p.runSiteOp()
	web.JSON(w, http.StatusOK, map[string]any{"ok": true, "domain": d})
}

func parentOf(d string) string {
	if p := records.Parent(d); strings.Contains(p, ".") {
		return p
	}
	return d
}

func (p *Panel) runSiteOp() {
	if p.opt.Agent == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	_ = p.opt.Agent.Do(ctx, agentapi.Request{Op: panelcfg.OpSite}, nil)
}

func (p *Panel) setupRecords(w http.ResponseWriter, r *http.Request) {
	p.serveRecords(w, r)
}

type certIn struct {
	Email   string `json:"email"`
	Agree   bool   `json:"agree"`
	Mode    string `json:"mode"`
	Staging bool   `json:"staging"`
}

func (p *Panel) setupCert(w http.ResponseWriter, r *http.Request) {
	var in certIn
	if !web.Decode(w, r, &in, bodyLimit) {
		return
	}
	s := p.site()
	if s.Domain == "" {
		web.Error(w, http.StatusConflict, "NO_DOMAIN", "Choose the panel domain first.")
		return
	}
	in.Email = strings.TrimSpace(in.Email)
	if in.Email == "" || !config.ValidEmail(in.Email) {
		web.Error(w, http.StatusBadRequest, "BAD_EMAIL", "Enter the email Let's Encrypt should use for expiry notices.")
		return
	}
	if !in.Agree {
		web.Error(w, http.StatusBadRequest, "TERMS", "Agree to the Let's Encrypt terms to continue.")
		return
	}
	mode := in.Mode
	if p.opt.Platform == "windows" {
		mode = panelcfg.ModeCaddy
	}
	if mode != panelcfg.ModeHTTP && mode != panelcfg.ModeDNS && mode != panelcfg.ModeCaddy {
		web.Error(w, http.StatusBadRequest, "BAD_MODE", "Pick how to prove you own the domain.")
		return
	}
	s.Email, s.Mode, s.Staging = in.Email, mode, in.Staging
	if err := p.saveSite(s); err != nil {
		web.Error(w, http.StatusInternalServerError, "INTERNAL", "Could not save the certificate settings.")
		return
	}
	if _, err := p.startJob("cert", agentapi.Request{Op: panelcfg.OpCert}, nil); err != nil {
		web.Error(w, http.StatusConflict, "BUSY", "A certificate request is already running.")
		return
	}
	web.JSON(w, http.StatusAccepted, map[string]any{"ok": true, "https": "https://" + s.Domain + "/setup"})
}

func (p *Panel) setupCertProgress(w http.ResponseWriter, r *http.Request) {
	j := p.job("cert")
	if j == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	j.ServeSSE(w, r)
}

type ownerIn struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (p *Panel) setupOwner(w http.ResponseWriter, r *http.Request) {
	var in ownerIn
	if !web.Decode(w, r, &in, bodyLimit) {
		return
	}
	if !web.Secure(r) && !p.opt.Insecure {
		web.Error(w, http.StatusConflict, "HTTPS_REQUIRED", "Open the panel over https before creating the owner account.")
		return
	}
	if p.ownerExists() {
		web.Error(w, http.StatusConflict, "OWNER_EXISTS", "The owner account already exists. Sign in instead.")
		return
	}
	if !ValidUsername(strings.ToLower(strings.TrimSpace(in.Username))) {
		web.Error(w, http.StatusBadRequest, "BAD_USERNAME", "Usernames use 3 to 32 lowercase letters, digits, dots, dashes or underscores.")
		return
	}
	if !ValidPassword(in.Password) {
		web.Error(w, http.StatusBadRequest, "WEAK_PASSWORD", "Use at least 12 characters.")
		return
	}
	u, err := p.createUser(in.Username, in.Password, RoleOwner, true)
	if err != nil {
		p.teamErr(w, err)
		return
	}
	p.audit(u.Username, "setup.owner", "", "")
	web.JSON(w, http.StatusOK, map[string]any{"enroll": p.startEnroll(u.ID, "")})
}

type pairIn struct {
	Code  string `json:"code"`
	Name  string `json:"name"`
	Pin   string `json:"pin"`
	Local bool   `json:"local"`
}

func (p *Panel) setupPair(w http.ResponseWriter, r *http.Request) {
	if !p.ownerExists() {
		web.Error(w, http.StatusConflict, "NO_OWNER", "Create the owner account first.")
		return
	}
	var in pairIn
	if !web.Decode(w, r, &in, bodyLimit) {
		return
	}
	if in.Local {
		b, err := os.ReadFile(p.opt.Paths.LocalPair())
		if err != nil {
			web.Error(w, http.StatusNotFound, "NO_LOCAL", "There is no VPN node on this server.")
			return
		}
		in.Code = strings.TrimSpace(string(b))
	}
	n, err := p.pairNode(r.Context(), in.Code, in.Name, in.Pin, in.Local)
	if !p.pairErr(w, err) {
		return
	}
	if in.Local {
		_ = os.Remove(p.opt.Paths.LocalPair())
	}
	p.audit("setup", "node.pair", n.Name, n.Host)
	web.JSON(w, http.StatusCreated, map[string]any{"node": map[string]string{"id": n.ID, "name": n.Name, "host": n.Host}})
}

func (p *Panel) setupFinish(w http.ResponseWriter, r *http.Request) {
	if !p.ownerExists() {
		web.Error(w, http.StatusConflict, "NO_OWNER", "Create the owner account first.")
		return
	}
	s := p.site()
	if s.Domain == "" || s.Mode == "" {
		web.Error(w, http.StatusConflict, "NO_DOMAIN", "Finish the domain and certificate steps first.")
		return
	}
	s.Configured = true
	if err := p.saveSite(s); err != nil {
		web.Error(w, http.StatusInternalServerError, "INTERNAL", "Could not finish setup.")
		return
	}
	_ = os.Remove(p.opt.Paths.SetupToken())
	p.mu.Lock()
	p.wiz.sessions = map[string]*wsession{}
	p.mu.Unlock()
	go p.runSiteOp()
	p.audit("setup", "setup.finish", s.Domain, "")
	web.JSON(w, http.StatusOK, map[string]any{"ok": true, "url": "https://" + s.Domain + "/"})
}

func certValid(expiry string, now time.Time) (time.Time, bool) {
	t, err := time.Parse(time.RFC3339, expiry)
	if err != nil {
		return time.Time{}, false
	}
	return t, t.After(now)
}

var errNoNode = errors.New("no such node")
