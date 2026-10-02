package setup

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/veylvpn/backend/internal/admin"
	"github.com/veylvpn/backend/internal/agentapi"
	"github.com/veylvpn/backend/internal/app"
	"github.com/veylvpn/backend/internal/backup"
	"github.com/veylvpn/backend/internal/config"
	"github.com/veylvpn/backend/internal/pki"
	"github.com/veylvpn/backend/internal/store"
	"github.com/veylvpn/backend/internal/web"
)

const (
	SessionCookie = "veyl_setup"
	TokenHeader   = "X-Setup-Token"
	CSRFHeader    = "X-CSRF-Token"
	PassHeader    = "X-Backup-Passphrase"
	SessionTTL    = 2 * time.Hour
	Grace         = time.Hour
	maxFails      = 5
	failWindow    = time.Minute
	maxSessions   = 16
	bodyLimit     = 16 << 10
	statusTTL     = 30 * time.Second
)

type wsession struct {
	csrf    string
	expires time.Time
	done    time.Time
}

type Wizard struct {
	d     app.Deps
	now   func() time.Time
	pages *web.Pages

	Resolvers  []string
	DNSTimeout time.Duration
	JobTimeout time.Duration

	mu        sync.Mutex
	sessions  map[string]*wsession
	fails     []time.Time
	job       *web.Job
	number    string
	firstID   string
	restore   bool
	restored  bool
	completed time.Time

	statMu sync.Mutex
	stat   map[string]string
	statAt time.Time
}

func New(d app.Deps) *Wizard {
	return &Wizard{
		d:          d,
		now:        time.Now,
		pages:      web.NewPages("/setup", "setup.html"),
		Resolvers:  []string{"1.1.1.1:53", "9.9.9.9:53"},
		DNSTimeout: 3 * time.Second,
		JobTimeout: 20 * time.Minute,
		sessions:   map[string]*wsession{},
	}
}

func NewToken(p config.Paths) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	t := base64.RawURLEncoding.EncodeToString(b)
	if err := os.MkdirAll(p.Data, 0o755); err != nil {
		return "", err
	}
	tmp := p.SetupToken() + ".tmp"
	if err := os.WriteFile(tmp, []byte(t+"\n"), 0o600); err != nil {
		return "", err
	}
	if err := os.Chmod(tmp, 0o600); err != nil {
		return "", err
	}
	return t, os.Rename(tmp, p.SetupToken())
}

func Link(host, token string, https bool) string {
	scheme := "http"
	if https {
		scheme = "https"
	}
	if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
		host = "[" + host + "]"
	}
	return scheme + "://" + host + "/setup#" + token
}

func (w *Wizard) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /setup", w.pages)
	mux.Handle("GET /setup/", w.pages)
	mux.HandleFunc("POST /v1/setup/session", w.newSession)
	mux.HandleFunc("GET /v1/setup/state", w.auth(w.state))
	mux.HandleFunc("GET /v1/setup/dns-check", w.auth(w.dnsCheck))
	mux.HandleFunc("POST /v1/setup/address", w.auth(w.address))
	mux.HandleFunc("POST /v1/setup/secure", w.auth(w.secure))
	mux.HandleFunc("PUT /v1/setup/settings", w.auth(w.settings))
	mux.HandleFunc("POST /v1/setup/admin", w.auth(w.adminPassword))
	mux.HandleFunc("POST /v1/setup/account", w.auth(w.account))
	mux.HandleFunc("POST /v1/setup/restore", w.auth(w.restoreBackup))
	mux.HandleFunc("POST /v1/setup/apply", w.auth(w.apply))
	mux.HandleFunc("GET /v1/setup/progress", w.auth(w.progress))
	mux.HandleFunc("POST /v1/setup/backup", w.auth(w.backup))
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		web.Headers(rw, r)
		if !strings.HasPrefix(r.URL.Path, "/setup") && !strings.HasPrefix(r.URL.Path, "/v1/setup/") {
			web.NotFound(rw)
			return
		}
		if w.d.Settings.Get().Configured && !w.graceAllowed(r) {
			web.NotFound(rw)
			return
		}
		mux.ServeHTTP(rw, r)
	})
}

var graceRoutes = map[string]bool{
	"GET /setup":              true,
	"GET /v1/setup/state":     true,
	"GET /v1/setup/progress":  true,
	"POST /v1/setup/backup":   true,
	"HEAD /setup":             true,
	"GET /setup/":             true,
	"GET /setup/app.css":      true,
	"GET /setup/ui.js":        true,
	"GET /setup/setup.js":     true,
	"GET /setup/favicon.svg":  true,
	"HEAD /setup/favicon.svg": true,
}

func (w *Wizard) graceAllowed(r *http.Request) bool {
	if !graceRoutes[r.Method+" "+r.URL.Path] {
		return false
	}
	s, _ := w.lookup(r)
	if s == nil || s.done.IsZero() {
		return false
	}
	return w.now().Sub(s.done) < Grace
}

func tokenKey(t string) string {
	sum := sha256.Sum256([]byte(t))
	return hex.EncodeToString(sum[:])
}

func randToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func (w *Wizard) lookup(r *http.Request) (*wsession, string) {
	c, err := r.Cookie(SessionCookie)
	if err != nil || len(c.Value) < 20 || len(c.Value) > 128 {
		return nil, ""
	}
	k := tokenKey(c.Value)
	w.mu.Lock()
	defer w.mu.Unlock()
	s := w.sessions[k]
	if s == nil {
		return nil, ""
	}
	if w.now().After(s.expires) && (s.done.IsZero() || w.now().Sub(s.done) >= Grace) {
		delete(w.sessions, k)
		return nil, ""
	}
	return s, k
}

type ctxKey struct{}

func (w *Wizard) auth(fn http.HandlerFunc) http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		s, k := w.lookup(r)
		if s == nil {
			web.Error(rw, http.StatusUnauthorized, "UNAUTHORIZED", "Open your setup link again to continue.")
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			h := r.Header.Get(CSRFHeader)
			if h == "" || subtle.ConstantTimeCompare([]byte(h), []byte(s.csrf)) != 1 {
				web.Error(rw, http.StatusForbidden, "CSRF", "Your session expired. Reload the page.")
				return
			}
		}
		fn(rw, r.WithContext(context.WithValue(r.Context(), ctxKey{}, k)))
	}
}

func (w *Wizard) readToken() string {
	b, err := os.ReadFile(w.d.Paths.SetupToken())
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func (w *Wizard) tooManyFails() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	cut := w.now().Add(-failWindow)
	keep := w.fails[:0]
	for _, t := range w.fails {
		if t.After(cut) {
			keep = append(keep, t)
		}
	}
	w.fails = keep
	return len(w.fails) >= maxFails
}

func (w *Wizard) fail() {
	w.mu.Lock()
	w.fails = append(w.fails, w.now())
	w.mu.Unlock()
}

func (w *Wizard) newSession(rw http.ResponseWriter, r *http.Request) {
	if w.tooManyFails() {
		web.Error(rw, http.StatusTooManyRequests, "TOO_MANY_REQUESTS", "Too many tries. Wait a minute and open your setup link again.")
		return
	}
	got := r.Header.Get(TokenHeader)
	want := w.readToken()
	if len(got) > 128 || want == "" || subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
		w.fail()
		web.Error(rw, http.StatusForbidden, "INVALID_TOKEN", "This setup link is not valid. Run \"veyl setup-link\" on the server to get a fresh one.")
		return
	}
	t := randToken()
	csrf := randToken()
	now := w.now()
	w.mu.Lock()
	for k, s := range w.sessions {
		if now.After(s.expires) && s.done.IsZero() {
			delete(w.sessions, k)
		}
	}
	for len(w.sessions) >= maxSessions {
		oldest := ""
		var at time.Time
		for k, s := range w.sessions {
			if oldest == "" || s.expires.Before(at) {
				oldest, at = k, s.expires
			}
		}
		delete(w.sessions, oldest)
	}
	w.sessions[tokenKey(t)] = &wsession{csrf: csrf, expires: now.Add(SessionTTL)}
	w.mu.Unlock()
	http.SetCookie(rw, &http.Cookie{Name: SessionCookie, Value: t, Path: "/", HttpOnly: true, Secure: web.Secure(r), SameSite: http.SameSiteStrictMode, MaxAge: int((SessionTTL + Grace) / time.Second)})
	web.JSON(rw, http.StatusOK, map[string]any{"ok": true, "csrf": csrf})
}

func (w *Wizard) status() map[string]string {
	w.statMu.Lock()
	defer w.statMu.Unlock()
	if w.stat != nil && w.now().Sub(w.statAt) < statusTTL {
		return w.stat
	}
	out := map[string]string{}
	if w.d.Agent != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		_ = w.d.Agent.Do(ctx, agentapi.Request{Op: agentapi.OpStatus}, func(ev agentapi.Event) {
			for k, v := range ev.Data {
				if len(k) <= 64 && len(v) <= 256 {
					out[k] = v
				}
			}
		})
		cancel()
	}
	w.stat = out
	w.statAt = w.now()
	return out
}

func requestIP(r *http.Request) string {
	h := r.Host
	if hh, _, err := net.SplitHostPort(h); err == nil {
		h = hh
	}
	h = strings.Trim(h, "[]")
	if ip := net.ParseIP(h); ip != nil && ip.IsGlobalUnicast() && !ip.IsPrivate() {
		return ip.String()
	}
	return ""
}

func (w *Wizard) publicIP(r *http.Request) string {
	st := w.status()
	if ip := net.ParseIP(st["public_ip"]); ip != nil && ip.To4() != nil {
		return ip.String()
	}
	if ip := requestIP(r); ip != "" && net.ParseIP(ip).To4() != nil {
		return ip
	}
	return ""
}

type facts struct {
	PublicIP    string `json:"public_ip"`
	PublicIPv6  string `json:"public_ipv6"`
	OS          string `json:"os"`
	OpenVPN     string `json:"openvpn"`
	OpenSSL     string `json:"openssl"`
	RAM         string `json:"ram_mb"`
	PQAvailable bool   `json:"pq_available"`
	HasIPv6     bool   `json:"has_ipv6"`
}

func (w *Wizard) facts(r *http.Request) facts {
	st := w.status()
	f := facts{PublicIP: w.publicIP(r), PublicIPv6: st["public_ipv6"], OS: st["os"], OpenVPN: st["openvpn"], OpenSSL: st["openssl"], RAM: st["ram_mb"]}
	f.PQAvailable = admin.PQAvailable(f.OpenSSL)
	f.HasIPv6 = f.PublicIPv6 != ""
	return f
}

func (w *Wizard) currentSession(r *http.Request) (*wsession, string) {
	k, _ := r.Context().Value(ctxKey{}).(string)
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.sessions[k], k
}

func (w *Wizard) state(rw http.ResponseWriter, r *http.Request) {
	set := w.d.Settings.Get()
	s, _ := w.currentSession(r)
	reqHost := r.Host
	if h, _, err := net.SplitHostPort(reqHost); err == nil {
		reqHost = h
	}
	reqHost = strings.Trim(strings.ToLower(reqHost), "[]")
	w.mu.Lock()
	job := map[string]any{}
	if w.job != nil {
		_, done, out := w.job.State()
		job = map[string]any{"kind": w.job.Kind, "running": !done, "done": done, "ok": out.OK, "error": out.Error}
	}
	restore, restored, account := w.restore, w.restored, w.firstID != ""
	csrf := ""
	if s != nil {
		csrf = s.csrf
	}
	w.mu.Unlock()
	web.JSON(rw, http.StatusOK, map[string]any{
		"configured":      set.Configured,
		"secure":          web.Secure(r),
		"on_host":         set.Host != "" && reqHost == strings.ToLower(set.Host),
		"settings":        settingsView(set),
		"facts":           w.facts(r),
		"admin_set":       admin.Exists(w.d.Paths),
		"account_created": account,
		"restore":         restore,
		"restored":        restored,
		"job":             job,
		"csrf":            csrf,
		"categories":      config.Categories,
		"version":         app.Version,
		"platform":        config.Platform,
		"stealth_port":    set.StealthTCPPort(),
	})
}

type view struct {
	Name         string   `json:"name"`
	Host         string   `json:"host"`
	TLS          string   `json:"tls"`
	ACMEEmail    string   `json:"acme_email"`
	Stealth      bool     `json:"stealth"`
	IPv6         bool     `json:"ipv6"`
	PostQuantum  bool     `json:"post_quantum"`
	Registration string   `json:"registration"`
	DeviceLimit  int      `json:"device_limit"`
	DNSDefault   []string `json:"dns_default"`
	DNSUpstream  string   `json:"dns_upstream"`
	AdminVPNOnly bool     `json:"admin_vpn_only"`
	AutoUpdates  bool     `json:"auto_updates"`
	AppURL       string   `json:"app_url"`
	UDPPort      int      `json:"udp_port"`
}

func settingsView(s config.Settings) view {
	d := s.DNS.Default
	if d == nil {
		d = []string{}
	}
	return view{Name: s.Name, Host: s.Host, TLS: s.TLS, ACMEEmail: s.ACMEEmail, Stealth: s.Stealth, IPv6: s.IPv6, PostQuantum: s.PostQuantum, Registration: s.Registration, DeviceLimit: s.DeviceLimit, DNSDefault: d, DNSUpstream: s.DNS.Upstream, AdminVPNOnly: s.AdminVPNOnly, AutoUpdates: s.AutoUpdates, AppURL: s.AppURL, UDPPort: s.UDPPort}
}

func (w *Wizard) dnsCheck(rw http.ResponseWriter, r *http.Request) {
	host := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(r.URL.Query().Get("host")), "."))
	if len(host) > 253 || !config.ValidHost(host) || config.IsIP(host) {
		web.Error(rw, http.StatusBadRequest, "INVALID_HOST", "Enter a domain name like vpn.example.com.")
		return
	}
	ip := w.publicIP(r)
	ip6 := w.status()["public_ipv6"]
	ctx, cancel := context.WithTimeout(r.Context(), w.DNSTimeout+time.Second)
	defer cancel()
	res := resolve(ctx, w.Resolvers, host, w.DNSTimeout)
	web.JSON(rw, http.StatusOK, evaluate(host, ip, ip6, res))
}

func (w *Wizard) busy() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.job != nil && w.job.Running()
}

type addressIn struct {
	Mode       string `json:"mode"`
	Host       string `json:"host"`
	Email      string `json:"email"`
	SelfSigned bool   `json:"self_signed"`
	Restore    bool   `json:"restore"`
}

func SSLIPHost(ip string) string {
	p := net.ParseIP(ip)
	if p == nil || p.To4() == nil {
		return ""
	}
	return strings.ReplaceAll(p.To4().String(), ".", "-") + ".sslip.io"
}

func (w *Wizard) address(rw http.ResponseWriter, r *http.Request) {
	var in addressIn
	if !web.Decode(rw, r, &in, bodyLimit) {
		return
	}
	if w.busy() {
		web.Error(rw, http.StatusConflict, "BUSY", "Please wait for the current step to finish.")
		return
	}
	host, tls := "", config.TLSACME
	switch in.Mode {
	case "domain":
		host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(in.Host), "."))
		if !config.ValidHost(host) || config.IsIP(host) {
			web.Error(rw, http.StatusBadRequest, "INVALID_HOST", "Enter a domain name like vpn.example.com.")
			return
		}
	case "free":
		host = SSLIPHost(w.publicIP(r))
		if host == "" {
			web.Error(rw, http.StatusBadRequest, "NO_PUBLIC_IP", "We couldn't find this server's public IPv4 address, so a free address isn't available.")
			return
		}
	case "ip":
		host = w.publicIP(r)
		if host == "" {
			web.Error(rw, http.StatusBadRequest, "NO_PUBLIC_IP", "We couldn't find this server's public IP address.")
			return
		}
		tls = config.TLSInternal
	default:
		web.Error(rw, http.StatusBadRequest, "BAD_REQUEST", "Choose how people will reach your server.")
		return
	}
	if in.SelfSigned {
		tls = config.TLSInternal
	}
	email := strings.TrimSpace(in.Email)
	if !config.ValidEmail(email) {
		web.Error(rw, http.StatusBadRequest, "INVALID_EMAIL", "That email address doesn't look right.")
		return
	}
	if _, err := w.d.Settings.Update(func(s *config.Settings) error {
		s.Configured = false
		s.Host, s.TLS, s.ACMEEmail = host, tls, email
		return nil
	}); err != nil {
		web.Error(rw, http.StatusBadRequest, "INVALID_HOST", "That address can't be used.")
		return
	}
	w.mu.Lock()
	w.restore = in.Restore
	w.mu.Unlock()
	web.JSON(rw, http.StatusOK, map[string]string{"host": host, "tls": tls})
}

func (w *Wizard) startJob(kind, op string, done func() (any, error)) (*web.Job, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.job != nil && w.job.Running() {
		return nil, errBusy
	}
	j := web.NewJob(kind)
	w.job = j
	go func() {
		if w.d.Agent == nil {
			j.Finish(nil, errors.New("the system agent is not running. Run \"sudo systemctl start veyl-agent\" and try again"))
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), w.JobTimeout)
		defer cancel()
		last := ""
		err := w.d.Agent.Do(ctx, agentapi.Request{Op: op}, func(ev agentapi.Event) {
			if ev.Done && ev.Error != "" {
				last = ev.Error
			}
			j.Event(ev)
		})
		if err != nil && last != "" {
			err = errors.New(last)
		}
		if err != nil {
			j.Finish(nil, errors.New(strings.TrimPrefix(err.Error(), agentapi.ErrAgent.Error()+"\n")))
			return
		}
		res, err := done()
		j.Finish(res, err)
	}()
	return j, nil
}

var errBusy = errors.New("busy")

func (w *Wizard) secure(rw http.ResponseWriter, r *http.Request) {
	set := w.d.Settings.Get()
	if set.Host == "" {
		web.Error(rw, http.StatusBadRequest, "NO_HOST", "Choose an address first.")
		return
	}
	host := set.Host
	if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
		host = "[" + host + "]"
	}
	_, err := w.startJob("tls", agentapi.OpTLS, func() (any, error) {
		return map[string]string{"redirect": "https://" + host + "/setup"}, nil
	})
	if err != nil {
		web.Error(rw, http.StatusConflict, "BUSY", "Please wait for the current step to finish.")
		return
	}
	web.JSON(rw, http.StatusAccepted, map[string]bool{"ok": true})
}

func (w *Wizard) progress(rw http.ResponseWriter, r *http.Request) {
	w.mu.Lock()
	j := w.job
	w.mu.Unlock()
	if j == nil {
		rw.WriteHeader(http.StatusNoContent)
		return
	}
	j.ServeSSE(rw, r)
}

func needSecure(rw http.ResponseWriter, r *http.Request) bool {
	if web.Secure(r) {
		return true
	}
	web.Error(rw, http.StatusForbidden, "INSECURE", "For your safety this step only works over the secure https link.")
	return false
}

type settingsIn struct {
	Name         *string   `json:"name"`
	Stealth      *bool     `json:"stealth"`
	StealthPort  *int      `json:"stealth_port"`
	IPv6         *bool     `json:"ipv6"`
	PostQuantum  *bool     `json:"post_quantum"`
	DeviceLimit  *int      `json:"device_limit"`
	DNSDefault   *[]string `json:"dns_default"`
	DNSUpstream  *string   `json:"dns_upstream"`
	AutoUpdates  *bool     `json:"auto_updates"`
	AdminVPNOnly *bool     `json:"admin_vpn_only"`
	Registration *string   `json:"registration"`
	AppURL       *string   `json:"app_url"`
}

func (w *Wizard) settings(rw http.ResponseWriter, r *http.Request) {
	var in settingsIn
	if !web.Decode(rw, r, &in, bodyLimit) {
		return
	}
	if w.busy() {
		web.Error(rw, http.StatusConflict, "BUSY", "Please wait for the current step to finish.")
		return
	}
	set, err := w.d.Settings.Update(func(s *config.Settings) error {
		s.Configured = false
		if in.Name != nil {
			s.Name = strings.TrimSpace(*in.Name)
		}
		if in.Stealth != nil {
			s.Stealth = *in.Stealth
		}
		if in.StealthPort != nil {
			s.StealthPort = *in.StealthPort
			if s.StealthPort == config.DefaultStealthPort(config.Platform) {
				s.StealthPort = 0
			}
		}
		if in.IPv6 != nil {
			s.IPv6 = *in.IPv6
		}
		if in.PostQuantum != nil {
			s.PostQuantum = *in.PostQuantum
		}
		if in.DeviceLimit != nil {
			s.DeviceLimit = *in.DeviceLimit
		}
		if in.DNSDefault != nil {
			if !config.ValidCategories(*in.DNSDefault) {
				return config.ErrCategory
			}
			s.DNS.Default = config.SortedCategories(*in.DNSDefault)
		}
		if in.DNSUpstream != nil {
			s.DNS.Upstream = *in.DNSUpstream
		}
		if in.AutoUpdates != nil {
			s.AutoUpdates = *in.AutoUpdates
		}
		if in.AdminVPNOnly != nil {
			s.AdminVPNOnly = *in.AdminVPNOnly
		}
		if in.Registration != nil {
			s.Registration = *in.Registration
		}
		if in.AppURL != nil {
			s.AppURL = strings.TrimSpace(*in.AppURL)
		}
		return nil
	})
	if err != nil {
		web.Error(rw, http.StatusBadRequest, "INVALID_SETTINGS", message(err))
		return
	}
	w.d.Store.SetDefaultLimit(set.DeviceLimit)
	web.JSON(rw, http.StatusOK, map[string]any{"settings": settingsView(set)})
}

func message(err error) string {
	switch {
	case errors.Is(err, config.ErrName):
		return "Pick a name with 1 to 40 characters."
	case errors.Is(err, config.ErrLimit):
		return "Devices per account must be between 1 and 20."
	case errors.Is(err, config.ErrCategory):
		return "Unknown blocking category."
	case errors.Is(err, config.ErrUpstream):
		return "Unknown DNS resolver."
	case errors.Is(err, config.ErrReg):
		return "Choose who can join."
	case errors.Is(err, config.ErrAppURL):
		return "The app link must start with https://."
	case errors.Is(err, config.ErrHost):
		return "Choose an address first."
	case errors.Is(err, config.ErrStealthPort):
		return "Pick a different stealth port. On Windows any free TCP port works except 53, 80, 443, 5335, 7505, 7506, 8080, 8081 and 8443."
	}
	return "Those settings could not be saved."
}

type passwordIn struct {
	Password string `json:"password"`
}

func (w *Wizard) adminPassword(rw http.ResponseWriter, r *http.Request) {
	if !needSecure(rw, r) {
		return
	}
	var in passwordIn
	if !web.Decode(rw, r, &in, bodyLimit) {
		return
	}
	if err := admin.ValidPassword(in.Password); err != nil {
		web.Error(rw, http.StatusBadRequest, "WEAK_PASSWORD", "Use at least 12 characters.")
		return
	}
	if err := admin.SetPassword(w.d.Paths, in.Password); err != nil {
		web.Error(rw, http.StatusInternalServerError, "INTERNAL", "Could not save the password.")
		return
	}
	web.JSON(rw, http.StatusOK, map[string]bool{"ok": true})
}

type accountIn struct {
	Password string `json:"password"`
	Skip     bool   `json:"skip"`
}

func (w *Wizard) account(rw http.ResponseWriter, r *http.Request) {
	if !needSecure(rw, r) {
		return
	}
	var in accountIn
	if !web.Decode(rw, r, &in, bodyLimit) {
		return
	}
	if !in.Skip {
		if n := len([]rune(in.Password)); n < store.MinPassword || n > store.MaxPassword {
			web.Error(rw, http.StatusBadRequest, "WEAK_PASSWORD", "Use at least 10 characters.")
			return
		}
	}
	w.mu.Lock()
	prev := w.firstID
	w.mu.Unlock()
	if prev != "" {
		if devs, err := w.d.Store.DeleteID(prev); err == nil && len(devs) > 0 && w.d.CA != nil {
			if serials, err := w.d.Store.Revoked(); err == nil {
				_ = w.d.CA.WriteCRL(w.d.Paths.CRL(), serials)
			}
		}
		w.mu.Lock()
		w.firstID, w.number = "", ""
		w.mu.Unlock()
	}
	if in.Skip {
		web.JSON(rw, http.StatusOK, map[string]bool{"ok": true})
		return
	}
	number, err := w.d.Store.CreateClaimed(in.Password)
	if err != nil {
		web.Error(rw, http.StatusBadRequest, "WEAK_PASSWORD", "Use at least 10 characters.")
		return
	}
	acc, err := w.d.Store.AccountKey(store.HashAccount(number))
	if err != nil {
		web.Error(rw, http.StatusInternalServerError, "INTERNAL", "Could not create the account.")
		return
	}
	_, _ = w.d.Store.UpdateID(acc.ID, store.Patch{Label: ptr("Owner")})
	w.mu.Lock()
	w.firstID, w.number = acc.ID, number
	w.mu.Unlock()
	web.JSON(rw, http.StatusOK, map[string]bool{"ok": true})
}

func ptr[T any](v T) *T { return &v }

func (w *Wizard) restoreBackup(rw http.ResponseWriter, r *http.Request) {
	if !needSecure(rw, r) {
		return
	}
	if w.busy() {
		web.Error(rw, http.StatusConflict, "BUSY", "Please wait for the current step to finish.")
		return
	}
	ct, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if ct != "application/octet-stream" {
		web.Error(rw, http.StatusUnsupportedMediaType, "BAD_REQUEST", "Upload the .vbk backup file.")
		return
	}
	pb, err := base64.RawURLEncoding.DecodeString(r.Header.Get(PassHeader))
	if err != nil || len(pb) == 0 || len(pb) > 1024 {
		web.Error(rw, http.StatusBadRequest, "BAD_PASSPHRASE", "Enter the backup passphrase.")
		return
	}
	data, err := io.ReadAll(http.MaxBytesReader(rw, r.Body, backup.MaxSize))
	if err != nil {
		web.Error(rw, http.StatusRequestEntityTooLarge, "PAYLOAD_TOO_LARGE", "That file is too large to be a Veyl backup.")
		return
	}
	cur := w.d.Settings.Get()
	err = backup.RestoreAdjust(w.d.Paths, data, string(pb), func(s *config.Settings) {
		s.Configured = false
		if cur.Host != "" {
			s.Host, s.TLS, s.ACMEEmail = cur.Host, cur.TLS, cur.ACMEEmail
		}
	})
	switch {
	case errors.Is(err, backup.ErrPassphrase):
		web.Error(rw, http.StatusBadRequest, "BAD_PASSPHRASE", "That passphrase didn't unlock the backup.")
		return
	case errors.Is(err, backup.ErrFormat), errors.Is(err, backup.ErrIncomplete):
		web.Error(rw, http.StatusBadRequest, "BAD_BACKUP", "This file isn't a complete Veyl backup.")
		return
	case errors.Is(err, backup.ErrConfigured):
		web.Error(rw, http.StatusConflict, "CONFIGURED", "This server is already set up.")
		return
	case err != nil:
		web.Error(rw, http.StatusInternalServerError, "INTERNAL", "Could not restore the backup.")
		return
	}
	if w.d.CA != nil {
		if ca, err := pki.Load(w.d.Paths.PKI()); err == nil {
			*w.d.CA = *ca
		}
	}
	if w.d.Store != nil {
		w.d.Store.SetDefaultLimit(w.d.Settings.Get().DeviceLimit)
	}
	w.mu.Lock()
	w.restored = true
	if w.firstID != "" {
		w.firstID, w.number = "", ""
	}
	w.mu.Unlock()
	web.JSON(rw, http.StatusOK, map[string]bool{"ok": true, "restored": true})
}

func (w *Wizard) apply(rw http.ResponseWriter, r *http.Request) {
	if !needSecure(rw, r) {
		return
	}
	set := w.d.Settings.Get()
	if set.Host == "" {
		web.Error(rw, http.StatusBadRequest, "NO_HOST", "Choose an address first.")
		return
	}
	if !admin.Exists(w.d.Paths) {
		web.Error(rw, http.StatusBadRequest, "NO_ADMIN", "Set an admin password first.")
		return
	}
	if _, err := w.d.Settings.Update(func(s *config.Settings) error { s.Configured = false; return nil }); err != nil {
		web.Error(rw, http.StatusBadRequest, "INVALID_SETTINGS", message(err))
		return
	}
	_, key := w.currentSession(r)
	_, err := w.startJob("apply", agentapi.OpApply, func() (any, error) { return w.finish(key) })
	if err != nil {
		web.Error(rw, http.StatusConflict, "BUSY", "Please wait for the current step to finish.")
		return
	}
	web.JSON(rw, http.StatusAccepted, map[string]bool{"ok": true})
}

func (w *Wizard) finish(key string) (any, error) {
	now := w.now()
	w.mu.Lock()
	if s := w.sessions[key]; s != nil {
		s.done = now
	}
	w.mu.Unlock()
	set, err := w.d.Settings.Update(func(s *config.Settings) error { s.Configured = true; return nil })
	if err != nil {
		w.mu.Lock()
		if s := w.sessions[key]; s != nil {
			s.done = time.Time{}
		}
		w.mu.Unlock()
		return nil, errors.New("could not save the final settings")
	}
	_ = os.Remove(w.d.Paths.SetupToken())
	w.mu.Lock()
	w.completed = now
	for k := range w.sessions {
		if k != key {
			delete(w.sessions, k)
		}
	}
	number, restored := w.number, w.restored
	w.mu.Unlock()
	host := set.Host
	if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
		host = "[" + host + "]"
	}
	return map[string]any{
		"name":      set.Name,
		"host":      set.Host,
		"account":   number,
		"restored":  restored,
		"app_url":   set.AppURL,
		"admin_url": "https://" + host + "/admin",
	}, nil
}

type backupIn struct {
	Passphrase string `json:"passphrase"`
}

func (w *Wizard) backup(rw http.ResponseWriter, r *http.Request) {
	s, _ := w.currentSession(r)
	if s == nil || s.done.IsZero() {
		web.Error(rw, http.StatusBadRequest, "NOT_READY", "Backups are available after setup finishes.")
		return
	}
	var in backupIn
	if !web.Decode(rw, r, &in, bodyLimit) {
		return
	}
	admin.WriteBackup(rw, w.d.Paths, in.Passphrase, w.now())
}
