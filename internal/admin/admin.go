package admin

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/veylvpn/backend/internal/agentapi"
	"github.com/veylvpn/backend/internal/app"
	"github.com/veylvpn/backend/internal/config"
	"github.com/veylvpn/backend/internal/panelkey"
	"github.com/veylvpn/backend/internal/store"
	"github.com/veylvpn/backend/internal/web"
)

const (
	SessionCookie = "veyl_admin"
	CSRFCookie    = "veyl_csrf"
	CSRFHeader    = "X-CSRF-Token"
	IdleTimeout   = 30 * time.Minute
	MaxLifetime   = 12 * time.Hour
	maxSessions   = 32
	bodyLimit     = 16 << 10
	throttleKey   = "admin-login"
)

type session struct {
	csrf    string
	created time.Time
	last    time.Time
	epoch   string
	pending string
}

type ctxKey struct{}

type Admin struct {
	d       app.Deps
	now     func() time.Time
	started time.Time
	pages   *web.Pages

	mu       sync.Mutex
	sessions map[string]*session
	throttle *store.Throttle

	jobMu sync.Mutex
	job   *web.Job

	statMu sync.Mutex
	stat   map[string]string
	statAt time.Time

	blMu sync.Mutex
	bl   map[string]blInfo

	keyMu sync.Mutex
	keys  *panelkey.Store

	JobTimeout time.Duration
}

func New(d app.Deps) *Admin {
	return &Admin{
		d:          d,
		now:        time.Now,
		started:    time.Now(),
		pages:      web.NewPages("/admin", "admin.html"),
		sessions:   map[string]*session{},
		throttle:   store.NewThrottle(),
		bl:         map[string]blInfo{},
		JobTimeout: 20 * time.Minute,
	}
}

func (a *Admin) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /admin", a.pages)
	mux.Handle("GET /admin/", a.pages)
	mux.HandleFunc("POST /v1/admin/login", a.login)
	mux.HandleFunc("GET /v1/admin/session", a.sessionInfo)
	mux.HandleFunc("POST /v1/admin/logout", a.session(a.logout))
	mux.HandleFunc("GET /v1/admin/overview", a.auth(a.overview))
	mux.HandleFunc("GET /v1/admin/accounts", a.auth(a.listAccounts))
	mux.HandleFunc("POST /v1/admin/accounts", a.auth(a.createAccount))
	mux.HandleFunc("PATCH /v1/admin/accounts/{id}", a.auth(a.patchAccount))
	mux.HandleFunc("DELETE /v1/admin/accounts/{id}", a.auth(a.deleteAccount))
	mux.HandleFunc("GET /v1/admin/accounts/{id}/devices", a.auth(a.listDevices))
	mux.HandleFunc("DELETE /v1/admin/accounts/{id}/devices/{device}", a.auth(a.deleteDevice))
	mux.HandleFunc("GET /v1/admin/invites", a.auth(a.listInvites))
	mux.HandleFunc("POST /v1/admin/invites", a.auth(a.createInvite))
	mux.HandleFunc("DELETE /v1/admin/invites/{id}", a.auth(a.deleteInvite))
	mux.HandleFunc("GET /v1/admin/settings", a.auth(a.getSettings))
	mux.HandleFunc("PUT /v1/admin/settings", a.auth(a.putSettings))
	mux.HandleFunc("GET /v1/admin/apply-progress", a.auth(a.progress))
	mux.HandleFunc("POST /v1/admin/password", a.session(a.changePassword))
	mux.HandleFunc("POST /v1/admin/totp/setup", a.session(a.totpSetup))
	mux.HandleFunc("POST /v1/admin/totp/enable", a.session(a.totpEnable))
	mux.HandleFunc("POST /v1/admin/totp/disable", a.session(a.totpDisable))
	mux.HandleFunc("POST /v1/admin/backup", a.session(a.backup))
	mux.HandleFunc("POST /v1/admin/dns/update", a.auth(a.dnsUpdate))
	a.panelRoutes(mux)
	return a.wrap(mux)
}

var tunnelNets = func() []*net.IPNet {
	var out []*net.IPNet
	for _, c := range []string{config.UDPNet4 + "/24", config.TCPNet4 + "/24", config.UDPNet6, config.TCPNet6} {
		_, n, err := net.ParseCIDR(c)
		if err == nil {
			out = append(out, n)
		}
	}
	return out
}()

func InTunnel(ip net.IP) bool {
	if ip == nil {
		return false
	}
	for _, n := range tunnelNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func (a *Admin) wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/admin") && !strings.HasPrefix(r.URL.Path, "/v1/admin/") {
			web.Headers(w, r)
			web.NotFound(w)
			return
		}
		machine := bearer(r) != "" || r.URL.Path == PairPath
		if !machine && a.d.Settings != nil && a.d.Settings.Get().AdminVPNOnly && !InTunnel(web.ClientIP(r)) {
			web.Headers(w, r)
			web.NotFound(w)
			return
		}
		web.Headers(w, r)
		if !machine && strings.HasPrefix(r.URL.Path, "/v1/admin/") && r.Method != http.MethodGet && r.Method != http.MethodHead {
			if !a.csrfOK(r) {
				web.Error(w, http.StatusForbidden, "CSRF", "Your session expired. Reload the page and try again.")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (a *Admin) csrfOK(r *http.Request) bool {
	h := r.Header.Get(CSRFHeader)
	c, err := r.Cookie(CSRFCookie)
	if h == "" || len(h) > 128 || err != nil || subtle.ConstantTimeCompare([]byte(h), []byte(c.Value)) != 1 {
		return false
	}
	if s, _ := a.lookup(r); s != nil {
		return subtle.ConstantTimeCompare([]byte(h), []byte(s.csrf)) == 1
	}
	return true
}

func token() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func tokenKey(t string) string {
	sum := sha256.Sum256([]byte(t))
	return hex.EncodeToString(sum[:])
}

func setCookie(w http.ResponseWriter, r *http.Request, name, value string, httpOnly bool, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		HttpOnly: httpOnly,
		Secure:   web.Secure(r),
		SameSite: http.SameSiteStrictMode,
		MaxAge:   maxAge,
	})
}

func (a *Admin) currentEpoch() string {
	c, err := LoadCreds(a.d.Paths)
	if err != nil {
		return ""
	}
	return c.Epoch
}

func (a *Admin) lookup(r *http.Request) (*session, string) {
	c, err := r.Cookie(SessionCookie)
	if err != nil || len(c.Value) < 20 || len(c.Value) > 128 {
		return nil, ""
	}
	k := tokenKey(c.Value)
	now := a.now()
	a.mu.Lock()
	s := a.sessions[k]
	if s != nil && (now.Sub(s.last) > IdleTimeout || now.Sub(s.created) > MaxLifetime) {
		delete(a.sessions, k)
		s = nil
	}
	a.mu.Unlock()
	if s == nil {
		return nil, ""
	}
	ep := a.currentEpoch()
	if ep == "" || subtle.ConstantTimeCompare([]byte(ep), []byte(s.epoch)) != 1 {
		a.mu.Lock()
		delete(a.sessions, k)
		a.mu.Unlock()
		return nil, ""
	}
	return s, k
}

func (a *Admin) auth(fn http.HandlerFunc) http.HandlerFunc {
	session := a.session(fn)
	return func(w http.ResponseWriter, r *http.Request) {
		if bearer(r) != "" {
			a.keyAuth(fn)(w, r)
			return
		}
		session(w, r)
	}
}

func (a *Admin) session(fn http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if bearer(r) != "" {
			web.Error(w, http.StatusForbidden, "FORBIDDEN", "Node keys cannot do this.")
			return
		}
		s, k := a.lookup(r)
		if s == nil {
			web.Error(w, http.StatusUnauthorized, "UNAUTHORIZED", "Please sign in again.")
			return
		}
		a.mu.Lock()
		s.last = a.now()
		a.mu.Unlock()
		fn(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, k)))
	}
}

func (a *Admin) current(r *http.Request) (*session, string) {
	k, _ := r.Context().Value(ctxKey{}).(string)
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.sessions[k], k
}

func (a *Admin) newSession(w http.ResponseWriter, r *http.Request, epoch string) string {
	now := a.now()
	t := token()
	csrf := token()
	a.mu.Lock()
	for k, s := range a.sessions {
		if now.Sub(s.last) > IdleTimeout || now.Sub(s.created) > MaxLifetime {
			delete(a.sessions, k)
		}
	}
	for len(a.sessions) >= maxSessions {
		oldest := ""
		var at time.Time
		for k, s := range a.sessions {
			if oldest == "" || s.created.Before(at) {
				oldest, at = k, s.created
			}
		}
		delete(a.sessions, oldest)
	}
	a.sessions[tokenKey(t)] = &session{csrf: csrf, created: now, last: now, epoch: epoch}
	a.mu.Unlock()
	setCookie(w, r, SessionCookie, t, true, int(MaxLifetime/time.Second))
	setCookie(w, r, CSRFCookie, csrf, false, int(MaxLifetime/time.Second))
	return csrf
}

func (a *Admin) dropAll() {
	a.mu.Lock()
	a.sessions = map[string]*session{}
	a.mu.Unlock()
}

type loginIn struct {
	Password string `json:"password"`
	TOTP     string `json:"totp"`
}

func (a *Admin) login(w http.ResponseWriter, r *http.Request) {
	var in loginIn
	if !web.Decode(w, r, &in, bodyLimit) {
		return
	}
	if a.throttle.Locked(throttleKey) {
		web.Error(w, http.StatusTooManyRequests, "TOO_MANY_REQUESTS", "Too many attempts. Wait a few minutes and try again.")
		return
	}
	if len(in.Password) > MaxPassword*4 {
		in.Password = ""
	}
	c, err := LoadCreds(a.d.Paths)
	stored := c.Password
	if err != nil {
		stored = dummy()
	}
	ok := verifyPassword(stored, in.Password) && err == nil
	step := int64(0)
	if ok && c.TOTPSecret != "" {
		var good bool
		step, good = CheckTOTP(c.TOTPSecret, in.TOTP, a.now(), c.TOTPLast)
		ok = good
	}
	if !ok {
		a.throttle.Fail(throttleKey)
		web.Error(w, http.StatusUnauthorized, "INVALID_CREDENTIALS", "That didn't work. Check your password and code.")
		return
	}
	if c.TOTPSecret != "" {
		replay := false
		if err := updateCreds(a.d.Paths, func(cc *Creds) error {
			if step <= cc.TOTPLast {
				replay = true
				return ErrBadCode
			}
			cc.TOTPLast = step
			return nil
		}); err != nil {
			if replay {
				a.throttle.Fail(throttleKey)
				web.Error(w, http.StatusUnauthorized, "INVALID_CREDENTIALS", "That code was already used. Wait for the next one.")
				return
			}
			web.Error(w, http.StatusInternalServerError, "INTERNAL", "Could not sign in.")
			return
		}
	}
	a.throttle.Reset(throttleKey)
	csrf := a.newSession(w, r, c.Epoch)
	web.JSON(w, http.StatusOK, map[string]any{"ok": true, "csrf": csrf})
}

func (a *Admin) logout(w http.ResponseWriter, r *http.Request) {
	_, k := a.current(r)
	a.mu.Lock()
	delete(a.sessions, k)
	a.mu.Unlock()
	setCookie(w, r, SessionCookie, "", true, -1)
	web.JSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (a *Admin) sessionInfo(w http.ResponseWriter, r *http.Request) {
	c, err := LoadCreds(a.d.Paths)
	set := a.d.Settings.Get()
	out := map[string]any{
		"authenticated": false,
		"admin_set":     err == nil,
		"totp_required": err == nil && c.TOTPSecret != "",
		"configured":    set.Configured,
		"name":          set.Name,
	}
	if s, _ := a.lookup(r); s != nil {
		out["authenticated"] = true
		out["csrf"] = s.csrf
		out["totp_enabled"] = c.TOTPSecret != ""
		out["host"] = set.Host
		out["version"] = app.Version
		web.JSON(w, http.StatusOK, out)
		return
	}
	csrf := ""
	if ck, err := r.Cookie(CSRFCookie); err == nil && len(ck.Value) >= 20 && len(ck.Value) <= 128 {
		csrf = ck.Value
	} else {
		csrf = token()
		setCookie(w, r, CSRFCookie, csrf, false, int(MaxLifetime/time.Second))
	}
	out["csrf"] = csrf
	web.JSON(w, http.StatusOK, out)
}

func (a *Admin) startJob(kind, op string) (*web.Job, error) {
	return a.startRequest(kind, agentapi.Request{Op: op})
}

func (a *Admin) startRequest(kind string, req agentapi.Request) (*web.Job, error) {
	a.jobMu.Lock()
	defer a.jobMu.Unlock()
	if a.job != nil && a.job.Running() {
		return nil, errBusy
	}
	j := web.NewJob(kind)
	a.job = j
	go func() {
		if a.d.Agent == nil {
			j.Finish(nil, errors.New("the system agent is not running"))
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), a.JobTimeout)
		defer cancel()
		last := ""
		err := a.d.Agent.Do(ctx, req, func(ev agentapi.Event) {
			if ev.Done && ev.Error != "" {
				last = ev.Error
			}
			j.Event(ev)
		})
		if err != nil && last != "" {
			err = errors.New(last)
		}
		if err != nil {
			err = errors.New(strings.TrimPrefix(err.Error(), agentapi.ErrAgent.Error()+"\n"))
		}
		a.statMu.Lock()
		a.statAt = time.Time{}
		a.statMu.Unlock()
		j.Finish(map[string]string{"kind": kind}, err)
	}()
	return j, nil
}

var errBusy = errors.New("busy")

func (a *Admin) currentJob() *web.Job {
	a.jobMu.Lock()
	defer a.jobMu.Unlock()
	return a.job
}

func (a *Admin) progress(w http.ResponseWriter, r *http.Request) {
	j := a.currentJob()
	if j == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	j.ServeSSE(w, r)
}
