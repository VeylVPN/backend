package panel

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/veylvpn/backend/internal/admin"
	"github.com/veylvpn/backend/internal/web"
)

const (
	SessionCookie = "veyl_panel"
	CSRFCookie    = "veyl_panel_csrf"
	CSRFHeader    = "X-CSRF-Token"
	IdleTimeout   = 30 * time.Minute
	MaxLifetime   = 12 * time.Hour
	InviteTTL     = 48 * time.Hour
	enrollTTL     = 15 * time.Minute
	recoveryCount = 10
	maxSessions   = 64
	bodyLimit     = 32 << 10
)

var roleLevel = map[string]int{RoleViewer: 1, RoleAdmin: 2, RoleOwner: 3}

type ctxKey struct{}

type actor struct {
	User    User
	Session string
	CSRF    string
}

func randToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func randID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

func hashToken(t string) string {
	s := sha256.Sum256([]byte(t))
	return hex.EncodeToString(s[:])
}

var recoveryEnc = base32.NewEncoding("abcdefghijkmnpqrstuvwxyz23456789").WithPadding(base32.NoPadding)

func newRecoveryCodes() ([]string, []string) {
	plain := make([]string, recoveryCount)
	hashed := make([]string, recoveryCount)
	for i := range plain {
		b := make([]byte, 8)
		if _, err := rand.Read(b); err != nil {
			panic(err)
		}
		s := recoveryEnc.EncodeToString(b)[:12]
		plain[i] = s[0:4] + "-" + s[4:8] + "-" + s[8:12]
		hashed[i] = hashToken(normRecovery(plain[i]))
	}
	return plain, hashed
}

func normRecovery(s string) string {
	return strings.ToLower(strings.NewReplacer("-", "", " ", "").Replace(strings.TrimSpace(s)))
}

func isRecovery(code string) bool {
	n := normRecovery(code)
	if len(n) != 12 {
		return false
	}
	for _, r := range n {
		if !strings.ContainsRune("abcdefghijkmnpqrstuvwxyz23456789", r) {
			return false
		}
	}
	return true
}

func ValidUsername(u string) bool {
	if len(u) < 3 || len(u) > 32 {
		return false
	}
	for _, r := range u {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '-') {
			return false
		}
	}
	return true
}

func agentSummary(ua string) string {
	l := strings.ToLower(ua)
	browser := "Browser"
	switch {
	case strings.Contains(l, "edg/"):
		browser = "Edge"
	case strings.Contains(l, "firefox/"):
		browser = "Firefox"
	case strings.Contains(l, "chrome/") || strings.Contains(l, "chromium/"):
		browser = "Chrome"
	case strings.Contains(l, "safari/"):
		browser = "Safari"
	}
	osName := ""
	switch {
	case strings.Contains(l, "iphone") || strings.Contains(l, "ipad"):
		osName = "iOS"
	case strings.Contains(l, "android"):
		osName = "Android"
	case strings.Contains(l, "windows"):
		osName = "Windows"
	case strings.Contains(l, "mac os"):
		osName = "macOS"
	case strings.Contains(l, "linux"):
		osName = "Linux"
	}
	if osName == "" {
		return browser
	}
	return browser + " on " + osName
}

func setCookie(w http.ResponseWriter, r *http.Request, name, value string, httpOnly bool, maxAge int) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: value, Path: "/", HttpOnly: httpOnly, Secure: web.Secure(r), SameSite: http.SameSiteStrictMode, MaxAge: maxAge})
}

func (p *Panel) throttleKey(r *http.Request) string {
	ip := web.ClientIP(r)
	m := hmac.New(sha256.New, p.ipKey)
	m.Write([]byte(ip.String()))
	return "ip:" + hex.EncodeToString(m.Sum(nil)[:12])
}

func (p *Panel) lookup(r *http.Request) (*actor, bool) {
	c, err := r.Cookie(SessionCookie)
	if err != nil || len(c.Value) < 20 || len(c.Value) > 128 {
		return nil, false
	}
	h := hashToken(c.Value)
	now := p.now().Unix()
	var a *actor
	touch := false
	p.db.View(func(d *data) {
		for i := range d.Sessions {
			s := &d.Sessions[i]
			if subtle.ConstantTimeCompare([]byte(s.Hash), []byte(h)) != 1 {
				continue
			}
			if now-s.Last > int64(IdleTimeout/time.Second) || now-s.Created > int64(MaxLifetime/time.Second) {
				return
			}
			u := d.user(s.UserID)
			if u == nil || u.Epoch != s.Epoch || u.MustEnroll || u.TOTP == "" {
				return
			}
			a = &actor{User: *u, Session: s.Hash, CSRF: s.CSRF}
			touch = now-s.Last >= 60
		}
	})
	if a != nil && touch {
		_ = p.db.Update(func(d *data) error {
			for i := range d.Sessions {
				if d.Sessions[i].Hash == a.Session {
					d.Sessions[i].Last = now
				}
			}
			return nil
		})
	}
	return a, a != nil
}

func current(r *http.Request) *actor {
	a, _ := r.Context().Value(ctxKey{}).(*actor)
	return a
}

func (p *Panel) authed(role string, fn http.HandlerFunc) http.HandlerFunc {
	need := roleLevel[role]
	return func(w http.ResponseWriter, r *http.Request) {
		a, ok := p.lookup(r)
		if !ok {
			web.Error(w, http.StatusUnauthorized, "UNAUTHORIZED", "Please sign in again.")
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			h := r.Header.Get(CSRFHeader)
			if h == "" || len(h) > 128 || subtle.ConstantTimeCompare([]byte(h), []byte(a.CSRF)) != 1 {
				web.Error(w, http.StatusForbidden, "CSRF", "Your session expired. Reload the page and try again.")
				return
			}
		}
		if roleLevel[a.User.Role] < need {
			web.Error(w, http.StatusForbidden, "FORBIDDEN", "Your role does not allow this.")
			return
		}
		fn(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, a)))
	}
}

func (p *Panel) newSession(w http.ResponseWriter, r *http.Request, u User) (string, error) {
	t := randToken(32)
	csrf := randToken(24)
	now := p.now().Unix()
	ua := r.UserAgent()
	if len(ua) > 512 {
		ua = ua[:512]
	}
	err := p.db.Update(func(d *data) error {
		d.Sessions = append(d.Sessions, Session{Hash: hashToken(t), UserID: u.ID, CSRF: csrf, Created: now, Last: now, Agent: agentSummary(ua), Epoch: u.Epoch})
		for len(d.Sessions) > maxSessions {
			d.Sessions = d.Sessions[1:]
		}
		if uu := d.user(u.ID); uu != nil {
			uu.LastLogin = now - now%60
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	setCookie(w, r, SessionCookie, t, true, int(MaxLifetime/time.Second))
	setCookie(w, r, CSRFCookie, csrf, false, int(MaxLifetime/time.Second))
	return csrf, nil
}

func (p *Panel) csrfCookieOK(r *http.Request) bool {
	h := r.Header.Get(CSRFHeader)
	c, err := r.Cookie(CSRFCookie)
	return err == nil && h != "" && len(h) <= 128 && subtle.ConstantTimeCompare([]byte(h), []byte(c.Value)) == 1
}

func (p *Panel) sessionInfo(w http.ResponseWriter, r *http.Request) {
	site := p.site()
	out := map[string]any{"authenticated": false, "configured": site.Configured, "name": p.settings().Name, "platform": p.opt.Platform}
	if a, ok := p.lookup(r); ok {
		out["authenticated"] = true
		out["csrf"] = a.CSRF
		out["user"] = map[string]string{"id": a.User.ID, "username": a.User.Username, "role": a.User.Role}
		web.JSON(w, http.StatusOK, out)
		return
	}
	csrf := ""
	if c, err := r.Cookie(CSRFCookie); err == nil && len(c.Value) >= 20 && len(c.Value) <= 128 {
		csrf = c.Value
	} else {
		csrf = randToken(24)
		setCookie(w, r, CSRFCookie, csrf, false, int(MaxLifetime/time.Second))
	}
	out["csrf"] = csrf
	web.JSON(w, http.StatusOK, out)
}

type loginIn struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Code     string `json:"code"`
}

var errBadLogin = errors.New("bad login")

func (p *Panel) checkSecondFactor(d *data, u *User, code string, now time.Time) (int64, int, bool) {
	if isRecovery(code) {
		h := hashToken(normRecovery(code))
		for i, rc := range u.Recovery {
			if subtle.ConstantTimeCompare([]byte(rc), []byte(h)) == 1 {
				return 0, i, true
			}
		}
		return 0, -1, false
	}
	step, ok := admin.CheckTOTP(u.TOTP, code, now, u.TOTPLast)
	return step, -1, ok
}

func (p *Panel) login(w http.ResponseWriter, r *http.Request) {
	var in loginIn
	if !web.Decode(w, r, &in, bodyLimit) {
		return
	}
	if !p.csrfCookieOK(r) {
		web.Error(w, http.StatusForbidden, "CSRF", "Reload the page and try again.")
		return
	}
	in.Username = strings.ToLower(strings.TrimSpace(in.Username))
	ukey := "u:" + in.Username
	ikey := p.throttleKey(r)
	if p.throttle.Locked(ukey) || p.throttle.Locked(ikey) {
		web.Error(w, http.StatusTooManyRequests, "TOO_MANY_REQUESTS", "Too many attempts. Wait a few minutes and try again.")
		return
	}
	if len(in.Password) > admin.MaxPassword*4 || !ValidUsername(in.Username) {
		in.Password = ""
	}
	var u User
	found := false
	p.db.View(func(d *data) {
		if uu := d.userByName(in.Username); uu != nil {
			u = *uu
			found = true
		}
	})
	stored := u.Password
	if !found {
		stored = admin.DummyHash()
	}
	if !admin.VerifyPassword(stored, in.Password) || !found {
		p.throttle.Fail(ukey)
		p.throttle.Fail(ikey)
		web.Error(w, http.StatusUnauthorized, "INVALID_CREDENTIALS", "That username and password did not match.")
		return
	}
	if u.MustEnroll || u.TOTP == "" {
		ticket := p.startEnroll(u.ID, "")
		web.JSON(w, http.StatusOK, map[string]any{"enroll": ticket})
		return
	}
	if strings.TrimSpace(in.Code) == "" {
		web.Error(w, http.StatusUnauthorized, "CODE_REQUIRED", "Enter the 6 digit code from your authenticator app.")
		return
	}
	now := p.now()
	usedRecovery := false
	err := p.db.Update(func(d *data) error {
		uu := d.user(u.ID)
		if uu == nil {
			return errBadLogin
		}
		step, idx, ok := p.checkSecondFactor(d, uu, in.Code, now)
		if !ok {
			return errBadLogin
		}
		if idx >= 0 {
			uu.Recovery = append(uu.Recovery[:idx], uu.Recovery[idx+1:]...)
			usedRecovery = true
		} else {
			uu.TOTPLast = step
		}
		u = *uu
		return nil
	})
	if err != nil {
		p.throttle.Fail(ukey)
		p.throttle.Fail(ikey)
		web.Error(w, http.StatusUnauthorized, "INVALID_CODE", "That code did not work. Codes can only be used once.")
		return
	}
	p.throttle.Reset(ukey)
	csrf, err := p.newSession(w, r, u)
	if err != nil {
		web.Error(w, http.StatusInternalServerError, "INTERNAL", "Could not sign in.")
		return
	}
	detail := ""
	if usedRecovery {
		detail = "recovery code used"
	}
	p.audit(u.Username, "login", "", detail)
	web.JSON(w, http.StatusOK, map[string]any{"ok": true, "csrf": csrf, "recovery_left": len(u.Recovery)})
}

func (p *Panel) logout(w http.ResponseWriter, r *http.Request) {
	a := current(r)
	_ = p.db.Update(func(d *data) error {
		keep := d.Sessions[:0]
		for _, s := range d.Sessions {
			if s.Hash != a.Session {
				keep = append(keep, s)
			}
		}
		d.Sessions = keep
		return nil
	})
	setCookie(w, r, SessionCookie, "", true, -1)
	web.JSON(w, http.StatusOK, map[string]bool{"ok": true})
}

type enrollment struct {
	userID  string
	secret  string
	expires time.Time
}

func (p *Panel) startEnroll(userID, secret string) string {
	if secret == "" {
		secret = admin.NewTOTPSecret()
	}
	t := randToken(24)
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.now()
	for k, e := range p.enrolls {
		if now.After(e.expires) {
			delete(p.enrolls, k)
		}
	}
	p.enrolls[hashToken(t)] = &enrollment{userID: userID, secret: secret, expires: now.Add(enrollTTL)}
	return t
}

func (p *Panel) enrollment(ticket string) (*enrollment, bool) {
	if len(ticket) < 20 || len(ticket) > 64 {
		return nil, false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	e := p.enrolls[hashToken(ticket)]
	if e == nil || p.now().After(e.expires) {
		return nil, false
	}
	return e, true
}

func (p *Panel) dropEnroll(ticket string) {
	p.mu.Lock()
	delete(p.enrolls, hashToken(ticket))
	p.mu.Unlock()
}

func (p *Panel) otpURI(username, secret string) (string, string, error) {
	issuer := p.settings().Name
	label := issuer + ":" + username
	if s := p.site(); s.Domain != "" {
		label += "@" + s.Domain
	}
	uri := "otpauth://totp/" + url.PathEscape(label) + "?secret=" + secret + "&issuer=" + url.PathEscape(issuer) + "&algorithm=SHA1&digits=6&period=30"
	qr, err := web.QRDataURI(uri)
	return uri, qr, err
}

type enrollIn struct {
	Ticket string `json:"ticket"`
	Code   string `json:"code"`
}

func (p *Panel) enrollInfo(w http.ResponseWriter, r *http.Request) {
	var in enrollIn
	if !web.Decode(w, r, &in, bodyLimit) {
		return
	}
	e, ok := p.enrollment(in.Ticket)
	if !ok {
		web.Error(w, http.StatusUnauthorized, "EXPIRED", "This step expired. Sign in again.")
		return
	}
	name := ""
	p.db.View(func(d *data) {
		if u := d.user(e.userID); u != nil {
			name = u.Username
		}
	})
	uri, qr, err := p.otpURI(name, e.secret)
	if err != nil {
		web.Error(w, http.StatusInternalServerError, "INTERNAL", "Could not make the QR code.")
		return
	}
	web.JSON(w, http.StatusOK, map[string]string{"secret": e.secret, "uri": uri, "qr": qr, "username": name})
}

func (p *Panel) enrollFinish(w http.ResponseWriter, r *http.Request) {
	var in enrollIn
	if !web.Decode(w, r, &in, bodyLimit) {
		return
	}
	e, ok := p.enrollment(in.Ticket)
	if !ok {
		web.Error(w, http.StatusUnauthorized, "EXPIRED", "This step expired. Sign in again.")
		return
	}
	step, ok := admin.CheckTOTP(e.secret, in.Code, p.now(), 0)
	if !ok {
		web.Error(w, http.StatusBadRequest, "INVALID_CODE", "That code did not match. Check the time on your phone and try again.")
		return
	}
	plain, hashed := newRecoveryCodes()
	var u User
	err := p.db.Update(func(d *data) error {
		uu := d.user(e.userID)
		if uu == nil {
			return errBadLogin
		}
		uu.TOTP, uu.TOTPLast, uu.Recovery, uu.MustEnroll = e.secret, step, hashed, false
		u = *uu
		return nil
	})
	if err != nil {
		web.Error(w, http.StatusInternalServerError, "INTERNAL", "Could not save two-step sign in.")
		return
	}
	p.dropEnroll(in.Ticket)
	csrf, err := p.newSession(w, r, u)
	if err != nil {
		web.Error(w, http.StatusInternalServerError, "INTERNAL", "Could not sign in.")
		return
	}
	p.audit(u.Username, "2fa.enrolled", "", "")
	web.JSON(w, http.StatusOK, map[string]any{"ok": true, "csrf": csrf, "recovery": plain})
}

func ValidPassword(pw string) bool {
	return admin.ValidPassword(pw) == nil && utf8.ValidString(pw)
}

type sessionOut struct {
	ID      string `json:"id"`
	Agent   string `json:"agent"`
	Created int64  `json:"created"`
	Last    int64  `json:"last"`
	Current bool   `json:"current"`
}

func (p *Panel) mySessions(w http.ResponseWriter, r *http.Request) {
	a := current(r)
	out := []sessionOut{}
	p.db.View(func(d *data) {
		for _, s := range d.Sessions {
			if s.UserID == a.User.ID {
				out = append(out, sessionOut{ID: s.Hash[:16], Agent: s.Agent, Created: s.Created, Last: s.Last, Current: s.Hash == a.Session})
			}
		}
	})
	web.JSON(w, http.StatusOK, map[string]any{"sessions": out})
}

func (p *Panel) revokeSession(w http.ResponseWriter, r *http.Request) {
	a := current(r)
	id := r.PathValue("id")
	others := id == "others"
	n := 0
	_ = p.db.Update(func(d *data) error {
		keep := d.Sessions[:0]
		for _, s := range d.Sessions {
			drop := s.UserID == a.User.ID && ((others && s.Hash != a.Session) || (!others && len(id) == 16 && strings.HasPrefix(s.Hash, id)))
			if drop {
				n++
				continue
			}
			keep = append(keep, s)
		}
		d.Sessions = keep
		return nil
	})
	p.audit(a.User.Username, "session.revoke", "", "")
	web.JSON(w, http.StatusOK, map[string]int{"revoked": n})
}

type passwordIn struct {
	Password    string `json:"password"`
	NewPassword string `json:"new_password"`
	Code        string `json:"code"`
}

func (p *Panel) reauth(w http.ResponseWriter, r *http.Request, a *actor, password, code string) bool {
	key := "u:" + a.User.Username
	if p.throttle.Locked(key) {
		web.Error(w, http.StatusTooManyRequests, "TOO_MANY_REQUESTS", "Too many attempts. Wait a few minutes and try again.")
		return false
	}
	ok := false
	_ = p.db.Update(func(d *data) error {
		u := d.user(a.User.ID)
		if u == nil || !admin.VerifyPassword(u.Password, password) {
			return errBadLogin
		}
		step, idx, good := p.checkSecondFactor(d, u, code, p.now())
		if !good || idx >= 0 {
			return errBadLogin
		}
		u.TOTPLast = step
		ok = true
		return nil
	})
	if !ok {
		p.throttle.Fail(key)
		web.Error(w, http.StatusUnauthorized, "INVALID_CREDENTIALS", "Your password or code is not right.")
	}
	return ok
}

func (p *Panel) changePassword(w http.ResponseWriter, r *http.Request) {
	var in passwordIn
	if !web.Decode(w, r, &in, bodyLimit) {
		return
	}
	a := current(r)
	if !ValidPassword(in.NewPassword) {
		web.Error(w, http.StatusBadRequest, "WEAK_PASSWORD", "Use at least 12 characters.")
		return
	}
	if !p.reauth(w, r, a, in.Password, in.Code) {
		return
	}
	h, err := admin.HashPassword(in.NewPassword)
	if err != nil {
		web.Error(w, http.StatusInternalServerError, "INTERNAL", "Could not save the password.")
		return
	}
	var u User
	_ = p.db.Update(func(d *data) error {
		uu := d.user(a.User.ID)
		uu.Password, uu.Epoch = h, randID()
		u = *uu
		keep := d.Sessions[:0]
		for _, s := range d.Sessions {
			if s.UserID != u.ID {
				keep = append(keep, s)
			}
		}
		d.Sessions = keep
		return nil
	})
	csrf, _ := p.newSession(w, r, u)
	p.audit(u.Username, "password.change", "", "")
	web.JSON(w, http.StatusOK, map[string]any{"ok": true, "csrf": csrf})
}

func (p *Panel) newRecovery(w http.ResponseWriter, r *http.Request) {
	var in passwordIn
	if !web.Decode(w, r, &in, bodyLimit) {
		return
	}
	a := current(r)
	if !p.reauth(w, r, a, in.Password, in.Code) {
		return
	}
	plain, hashed := newRecoveryCodes()
	_ = p.db.Update(func(d *data) error {
		d.user(a.User.ID).Recovery = hashed
		return nil
	})
	p.audit(a.User.Username, "2fa.recovery-codes", "", "")
	web.JSON(w, http.StatusOK, map[string]any{"recovery": plain})
}

func (p *Panel) me(w http.ResponseWriter, r *http.Request) {
	a := current(r)
	left := 0
	p.db.View(func(d *data) {
		if u := d.user(a.User.ID); u != nil {
			left = len(u.Recovery)
		}
	})
	web.JSON(w, http.StatusOK, map[string]any{"id": a.User.ID, "username": a.User.Username, "role": a.User.Role, "created": a.User.Created, "recovery_left": left})
}
