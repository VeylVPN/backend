package admin

import (
	"bufio"
	"context"
	"errors"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/veylvpn/backend/internal/agentapi"
	"github.com/veylvpn/backend/internal/app"
	"github.com/veylvpn/backend/internal/backup"
	"github.com/veylvpn/backend/internal/config"
	"github.com/veylvpn/backend/internal/store"
	"github.com/veylvpn/backend/internal/web"
)

const statusTTL = 15 * time.Second

func (a *Admin) status() map[string]string {
	a.statMu.Lock()
	defer a.statMu.Unlock()
	if a.stat != nil && a.now().Sub(a.statAt) < statusTTL {
		return a.stat
	}
	out := map[string]string{}
	if a.d.Agent != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		_ = a.d.Agent.Do(ctx, agentapi.Request{Op: agentapi.OpStatus}, func(ev agentapi.Event) {
			for k, v := range ev.Data {
				if len(k) <= 64 && len(v) <= 256 {
					out[k] = v
				}
			}
		})
		cancel()
	}
	a.stat = out
	a.statAt = a.now()
	return out
}

type blInfo struct {
	mtime   time.Time
	size    int64
	entries int
}

func countLines(path string) int {
	f, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer f.Close()
	n := 0
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		l := strings.TrimSpace(sc.Text())
		if l != "" && l[0] != '#' && l[0] != '!' {
			n++
		}
	}
	return n
}

type blOut struct {
	Category string `json:"category"`
	Entries  int    `json:"entries"`
	Updated  string `json:"updated,omitempty"`
}

func (a *Admin) blocklists() []blOut {
	a.blMu.Lock()
	defer a.blMu.Unlock()
	out := make([]blOut, 0, len(config.Categories))
	for _, c := range config.Categories {
		p := filepath.Join(a.d.Paths.Blocklists(), c+".txt")
		fi, err := os.Stat(p)
		if err != nil {
			out = append(out, blOut{Category: c})
			continue
		}
		info, ok := a.bl[c]
		if !ok || !info.mtime.Equal(fi.ModTime()) || info.size != fi.Size() {
			info = blInfo{mtime: fi.ModTime(), size: fi.Size(), entries: countLines(p)}
			a.bl[c] = info
		}
		out = append(out, blOut{Category: c, Entries: info.entries, Updated: fi.ModTime().UTC().Format("2006-01-02")})
	}
	return out
}

func (a *Admin) online() map[string]bool {
	if a.d.Mgmt == nil {
		return map[string]bool{}
	}
	m, err := a.d.Mgmt.Online()
	if err != nil || m == nil {
		return map[string]bool{}
	}
	return m
}

type service struct {
	Name  string `json:"name"`
	State string `json:"state"`
}

func (a *Admin) overview(w http.ResponseWriter, r *http.Request) {
	set := a.d.Settings.Get()
	accounts, devices, _ := a.d.Store.Counts()
	st := a.status()
	sys := map[string]string{}
	var svcs []service
	for k, v := range st {
		if name, ok := strings.CutPrefix(k, "svc."); ok {
			svcs = append(svcs, service{Name: name, State: v})
			continue
		}
		sys[k] = v
	}
	sort.Slice(svcs, func(i, j int) bool { return svcs[i].Name < svcs[j].Name })
	if svcs == nil {
		svcs = []service{}
	}
	job := map[string]any{"running": false}
	if j := a.currentJob(); j != nil {
		job = map[string]any{"running": j.Running(), "kind": j.Kind}
	}
	web.JSON(w, http.StatusOK, map[string]any{
		"version":     app.Version,
		"name":        set.Name,
		"host":        set.Host,
		"uptime":      int64(a.now().Sub(a.started) / time.Second),
		"connected":   len(a.online()),
		"accounts":    accounts,
		"devices":     devices,
		"system":      sys,
		"services":    svcs,
		"blocklists":  a.blocklists(),
		"cert_expiry": st["cert_expiry"],
		"job":         job,
		"stealth":     set.Stealth,
		"udp_port":    set.UDPPort,
	})
}

type accountOut struct {
	ID        string   `json:"id"`
	Label     string   `json:"label"`
	Created   int64    `json:"created"`
	Expires   int64    `json:"expires"`
	Disabled  bool     `json:"disabled"`
	Limit     int      `json:"limit"`
	MaxDev    int      `json:"max_devices"`
	Devices   int      `json:"devices"`
	Online    int      `json:"online"`
	DNSCustom bool     `json:"dns_custom"`
	DNS       []string `json:"dns"`
	Status    string   `json:"status"`
}

func (a *Admin) out(acc store.Account, on map[string]bool, set config.Settings) accountOut {
	o := accountOut{ID: acc.ID, Label: acc.Label, Created: acc.Created, Expires: acc.Expires, Disabled: acc.Disabled, Limit: acc.Limit, MaxDev: acc.EffectiveLimit(set.DeviceLimit), Devices: len(acc.Devices), DNSCustom: acc.DNSCustom, DNS: acc.DNSCategories(set.DNS.Default)}
	for _, d := range acc.Devices {
		if on[d.ID] {
			o.Online++
		}
	}
	switch {
	case acc.Disabled:
		o.Status = "disabled"
	case acc.Active(a.now().Unix()) != nil:
		o.Status = "expired"
	default:
		o.Status = "active"
	}
	if o.DNS == nil {
		o.DNS = []string{}
	}
	return o
}

func storeErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrNoAccount):
		web.Error(w, http.StatusNotFound, "ACCOUNT_NOT_FOUND", "That account no longer exists.")
	case errors.Is(err, store.ErrNoDevice):
		web.Error(w, http.StatusNotFound, "DEVICE_NOT_FOUND", "That device no longer exists.")
	case errors.Is(err, store.ErrNoInvite):
		web.Error(w, http.StatusNotFound, "INVITE_NOT_FOUND", "That invite no longer exists.")
	case errors.Is(err, store.ErrWeakPassword):
		web.Error(w, http.StatusBadRequest, "WEAK_PASSWORD", "Passwords need at least 10 characters.")
	case errors.Is(err, store.ErrBadLabel):
		web.Error(w, http.StatusBadRequest, "BAD_REQUEST", "Names can be up to 40 characters.")
	case errors.Is(err, store.ErrDeviceLimit):
		web.Error(w, http.StatusBadRequest, "BAD_REQUEST", "Device limit must be between 1 and 20.")
	case errors.Is(err, store.ErrBadInvite):
		web.Error(w, http.StatusBadRequest, "BAD_REQUEST", "Uses must be between 1 and 1000.")
	case errors.Is(err, config.ErrCategory):
		web.Error(w, http.StatusBadRequest, "BAD_REQUEST", "Unknown blocking category.")
	default:
		web.Error(w, http.StatusInternalServerError, "INTERNAL", "Something went wrong on the server.")
	}
}

func (a *Admin) listAccounts(w http.ResponseWriter, r *http.Request) {
	accs, err := a.d.Store.Accounts()
	if err != nil {
		storeErr(w, err)
		return
	}
	on := a.online()
	set := a.d.Settings.Get()
	out := make([]accountOut, 0, len(accs))
	for _, acc := range accs {
		out = append(out, a.out(acc, on, set))
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Created > out[j].Created })
	web.JSON(w, http.StatusOK, map[string]any{"accounts": out, "default_limit": set.DeviceLimit})
}

func (a *Admin) expiry(days int) (int64, bool) {
	if days < 0 || days > 3650 {
		return 0, false
	}
	if days == 0 {
		return 0, true
	}
	return store.Day(a.now().Unix()) + int64(days)*86400, true
}

type createIn struct {
	Label       string `json:"label"`
	ExpiresDays int    `json:"expires_days"`
	Password    string `json:"password"`
	Limit       int    `json:"limit"`
}

func (a *Admin) createAccount(w http.ResponseWriter, r *http.Request) {
	var in createIn
	if !web.Decode(w, r, &in, bodyLimit) {
		return
	}
	exp, ok := a.expiry(in.ExpiresDays)
	if !ok {
		web.Error(w, http.StatusBadRequest, "BAD_REQUEST", "Expiry must be between 0 and 3650 days.")
		return
	}
	if in.Limit < 0 || in.Limit > 20 {
		storeErr(w, store.ErrDeviceLimit)
		return
	}
	number, acc, err := a.d.Store.CreateAccount(store.CreateOpts{Label: in.Label, Expires: exp, Password: in.Password, Limit: in.Limit})
	if err != nil {
		storeErr(w, err)
		return
	}
	web.JSON(w, http.StatusCreated, map[string]any{"number": number, "account": a.out(acc, nil, a.d.Settings.Get())})
}

type patchIn struct {
	Label       *string   `json:"label"`
	ExpiresDays *int      `json:"expires_days"`
	Disabled    *bool     `json:"disabled"`
	Limit       *int      `json:"limit"`
	DNS         *[]string `json:"dns"`
	DNSDefault  bool      `json:"dns_default"`
}

func validID(id string) bool {
	if id == "" || len(id) > 64 {
		return false
	}
	for _, r := range id {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') {
			return false
		}
	}
	return true
}

func (a *Admin) patchAccount(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !validID(id) {
		storeErr(w, store.ErrNoAccount)
		return
	}
	var in patchIn
	if !web.Decode(w, r, &in, bodyLimit) {
		return
	}
	p := store.Patch{Label: in.Label, Disabled: in.Disabled, Limit: in.Limit, DNS: in.DNS}
	if in.ExpiresDays != nil {
		exp, ok := a.expiry(*in.ExpiresDays)
		if !ok {
			web.Error(w, http.StatusBadRequest, "BAD_REQUEST", "Expiry must be between 0 and 3650 days.")
			return
		}
		p.Expires = &exp
	}
	acc, err := a.d.Store.UpdateID(id, p)
	if err != nil {
		storeErr(w, err)
		return
	}
	if in.DNSDefault {
		if full, err := a.d.Store.AccountID(id); err == nil {
			if err := a.d.Store.ResetDNS(full.Hash); err != nil {
				storeErr(w, err)
				return
			}
			acc, _ = a.d.Store.AccountID(id)
		}
	}
	if acc.Active(a.now().Unix()) != nil && a.d.Mgmt != nil {
		for _, d := range acc.Devices {
			_ = a.d.Mgmt.Kill(d.ID)
		}
	}
	acc.Hash, acc.Password = "", ""
	web.JSON(w, http.StatusOK, map[string]any{"account": a.out(acc, a.online(), a.d.Settings.Get())})
}

func (a *Admin) revokeEffects(devs []store.Device) error {
	var err error
	if a.d.CA != nil {
		var serials []string
		serials, err = a.d.Store.Revoked()
		if err == nil {
			err = a.d.CA.WriteCRL(a.d.Paths.CRL(), serials)
		}
	}
	if a.d.Mgmt != nil {
		for _, d := range devs {
			_ = a.d.Mgmt.Kill(d.ID)
		}
	}
	return err
}

func (a *Admin) deleteAccount(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !validID(id) {
		storeErr(w, store.ErrNoAccount)
		return
	}
	devs, err := a.d.Store.DeleteID(id)
	if err != nil {
		storeErr(w, err)
		return
	}
	if err := a.revokeEffects(devs); err != nil {
		web.Error(w, http.StatusInternalServerError, "INTERNAL", "Account deleted, but the revocation list could not be updated.")
		return
	}
	web.JSON(w, http.StatusOK, map[string]bool{"ok": true})
}

type deviceOut struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Created int64  `json:"created"`
	Online  bool   `json:"online"`
}

func (a *Admin) listDevices(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !validID(id) {
		storeErr(w, store.ErrNoAccount)
		return
	}
	acc, err := a.d.Store.AccountID(id)
	if err != nil {
		storeErr(w, err)
		return
	}
	on := a.online()
	out := make([]deviceOut, 0, len(acc.Devices))
	for _, d := range acc.Devices {
		out = append(out, deviceOut{ID: d.ID, Name: d.Name, Created: d.Created, Online: on[d.ID]})
	}
	web.JSON(w, http.StatusOK, map[string]any{"devices": out, "limit": acc.EffectiveLimit(a.d.Settings.Get().DeviceLimit)})
}

func (a *Admin) deleteDevice(w http.ResponseWriter, r *http.Request) {
	id, dev := r.PathValue("id"), r.PathValue("device")
	if !validID(id) || len(dev) > 64 || dev == "" {
		storeErr(w, store.ErrNoDevice)
		return
	}
	d, err := a.d.Store.RevokeID(id, dev)
	if err != nil {
		storeErr(w, err)
		return
	}
	if err := a.revokeEffects([]store.Device{d}); err != nil {
		web.Error(w, http.StatusInternalServerError, "INTERNAL", "Device removed, but the revocation list could not be updated.")
		return
	}
	web.JSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (a *Admin) listInvites(w http.ResponseWriter, r *http.Request) {
	inv, err := a.d.Store.Invites()
	if err != nil {
		storeErr(w, err)
		return
	}
	sort.SliceStable(inv, func(i, j int) bool { return inv[i].Created > inv[j].Created })
	web.JSON(w, http.StatusOK, map[string]any{"invites": inv, "registration": a.d.Settings.Get().Registration})
}

type inviteIn struct {
	Uses        int `json:"uses"`
	ExpiresDays int `json:"expires_days"`
}

func (a *Admin) createInvite(w http.ResponseWriter, r *http.Request) {
	var in inviteIn
	if !web.Decode(w, r, &in, bodyLimit) {
		return
	}
	if in.Uses == 0 {
		in.Uses = 1
	}
	exp, ok := a.expiry(in.ExpiresDays)
	if !ok {
		web.Error(w, http.StatusBadRequest, "BAD_REQUEST", "Expiry must be between 0 and 3650 days.")
		return
	}
	code, inv, err := a.d.Store.NewInvite(in.Uses, exp)
	if err != nil {
		storeErr(w, err)
		return
	}
	web.JSON(w, http.StatusCreated, map[string]any{"code": code, "invite": inv})
}

func (a *Admin) deleteInvite(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !validID(id) {
		storeErr(w, store.ErrNoInvite)
		return
	}
	if err := a.d.Store.DeleteInvite(id); err != nil {
		storeErr(w, err)
		return
	}
	web.JSON(w, http.StatusOK, map[string]bool{"ok": true})
}

type SettingsIn struct {
	Name         string   `json:"name"`
	Host         string   `json:"host"`
	TLS          string   `json:"tls"`
	ACMEEmail    string   `json:"acme_email"`
	UDPPort      int      `json:"udp_port"`
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
}

func settingsOut(s config.Settings) SettingsIn {
	d := s.DNS.Default
	if d == nil {
		d = []string{}
	}
	return SettingsIn{Name: s.Name, Host: s.Host, TLS: s.TLS, ACMEEmail: s.ACMEEmail, UDPPort: s.UDPPort, Stealth: s.Stealth, IPv6: s.IPv6, PostQuantum: s.PostQuantum, Registration: s.Registration, DeviceLimit: s.DeviceLimit, DNSDefault: d, DNSUpstream: s.DNS.Upstream, AdminVPNOnly: s.AdminVPNOnly, AutoUpdates: s.AutoUpdates, AppURL: s.AppURL}
}

func SystemChanged(a, b config.Settings) bool {
	return a.Host != b.Host || a.TLS != b.TLS || a.ACMEEmail != b.ACMEEmail || a.UDPPort != b.UDPPort || a.Stealth != b.Stealth || a.IPv6 != b.IPv6 || a.PostQuantum != b.PostQuantum || a.DNS.Upstream != b.DNS.Upstream || a.AutoUpdates != b.AutoUpdates
}

func PQAvailable(opensslVersion string) bool {
	v := strings.TrimSpace(opensslVersion)
	if f := strings.Fields(v); len(f) > 1 && strings.EqualFold(f[0], "openssl") {
		v = f[1]
	}
	parts := strings.SplitN(v, ".", 3)
	if len(parts) < 2 {
		return false
	}
	maj, err1 := strconv.Atoi(parts[0])
	minStr := parts[1]
	for i, r := range minStr {
		if r < '0' || r > '9' {
			minStr = minStr[:i]
			break
		}
	}
	mn, err2 := strconv.Atoi(minStr)
	if err1 != nil || err2 != nil {
		return false
	}
	return maj > 3 || (maj == 3 && mn >= 5)
}

func (a *Admin) getSettings(w http.ResponseWriter, r *http.Request) {
	st := a.status()
	web.JSON(w, http.StatusOK, map[string]any{"settings": settingsOut(a.d.Settings.Get()), "categories": config.Categories, "pq_available": PQAvailable(st["openssl"])})
}

func (a *Admin) putSettings(w http.ResponseWriter, r *http.Request) {
	var in SettingsIn
	if !web.Decode(w, r, &in, bodyLimit) {
		return
	}
	if j := a.currentJob(); j != nil && j.Running() {
		web.Error(w, http.StatusConflict, "BUSY", "Changes are still being applied. Try again in a moment.")
		return
	}
	in.Name = strings.TrimSpace(in.Name)
	in.Host = strings.ToLower(strings.TrimSpace(in.Host))
	in.ACMEEmail = strings.TrimSpace(in.ACMEEmail)
	if in.TLS == "" {
		in.TLS = config.TLSACME
		if config.IsIP(in.Host) {
			in.TLS = config.TLSInternal
		}
	}
	before := a.d.Settings.Get()
	after, err := a.d.Settings.Update(func(s *config.Settings) error {
		s.Name, s.Host, s.TLS, s.ACMEEmail = in.Name, in.Host, in.TLS, in.ACMEEmail
		s.UDPPort, s.Stealth, s.IPv6, s.PostQuantum = in.UDPPort, in.Stealth, in.IPv6, in.PostQuantum
		s.Registration, s.DeviceLimit = in.Registration, in.DeviceLimit
		s.DNS.Default = config.SortedCategories(in.DNSDefault)
		s.DNS.Upstream = in.DNSUpstream
		s.AdminVPNOnly, s.AutoUpdates, s.AppURL = in.AdminVPNOnly, in.AutoUpdates, in.AppURL
		return nil
	})
	if err != nil {
		web.Error(w, http.StatusBadRequest, "INVALID_SETTINGS", settingsMessage(err))
		return
	}
	a.d.Store.SetDefaultLimit(after.DeviceLimit)
	applying := false
	if SystemChanged(before, after) {
		if _, err := a.startJob("apply", agentapi.OpApply); err == nil {
			applying = true
		}
	}
	web.JSON(w, http.StatusOK, map[string]any{"settings": settingsOut(after), "applying": applying})
}

func settingsMessage(err error) string {
	switch {
	case errors.Is(err, config.ErrHost):
		return "That address doesn't look right. Use a domain like vpn.example.com or a public IP."
	case errors.Is(err, config.ErrName):
		return "Pick a name with 1 to 40 characters."
	case errors.Is(err, config.ErrPort):
		return "The VPN port must be between 1024 and 65535 (not 8080 or 8443)."
	case errors.Is(err, config.ErrTLS):
		return "Automatic certificates need a domain name, not an IP address."
	case errors.Is(err, config.ErrEmail):
		return "That email address doesn't look right."
	case errors.Is(err, config.ErrReg):
		return "Choose who can join."
	case errors.Is(err, config.ErrLimit):
		return "Devices per account must be between 1 and 20."
	case errors.Is(err, config.ErrCategory):
		return "Unknown blocking category."
	case errors.Is(err, config.ErrUpstream):
		return "Unknown DNS resolver."
	case errors.Is(err, config.ErrAppURL):
		return "The app link must start with https://."
	}
	return "Those settings could not be saved."
}

type passwordIn struct {
	Password    string `json:"password"`
	NewPassword string `json:"new_password"`
}

func (a *Admin) changePassword(w http.ResponseWriter, r *http.Request) {
	var in passwordIn
	if !web.Decode(w, r, &in, bodyLimit) {
		return
	}
	if a.throttle.Locked(throttleKey) {
		web.Error(w, http.StatusTooManyRequests, "TOO_MANY_REQUESTS", "Too many attempts. Wait a few minutes and try again.")
		return
	}
	c, err := LoadCreds(a.d.Paths)
	if err != nil || !verifyPassword(c.Password, in.Password) {
		a.throttle.Fail(throttleKey)
		web.Error(w, http.StatusUnauthorized, "INVALID_CREDENTIALS", "Your current password is not right.")
		return
	}
	if err := ValidPassword(in.NewPassword); err != nil {
		web.Error(w, http.StatusBadRequest, "WEAK_PASSWORD", "Use at least 12 characters.")
		return
	}
	if err := SetPassword(a.d.Paths, in.NewPassword); err != nil {
		web.Error(w, http.StatusInternalServerError, "INTERNAL", "Could not save the new password.")
		return
	}
	a.dropAll()
	csrf := a.newSession(w, r, a.currentEpoch())
	web.JSON(w, http.StatusOK, map[string]any{"ok": true, "csrf": csrf})
}

func (a *Admin) totpSetup(w http.ResponseWriter, r *http.Request) {
	s, _ := a.current(r)
	if s == nil {
		web.Error(w, http.StatusUnauthorized, "UNAUTHORIZED", "Please sign in again.")
		return
	}
	secret := NewTOTPSecret()
	a.mu.Lock()
	s.pending = secret
	a.mu.Unlock()
	set := a.d.Settings.Get()
	issuer := set.Name
	label := issuer + ":admin"
	if set.Host != "" {
		label = issuer + ":admin@" + set.Host
	}
	uri := "otpauth://totp/" + url.PathEscape(label) + "?secret=" + secret + "&issuer=" + url.PathEscape(issuer) + "&algorithm=SHA1&digits=6&period=30"
	qr, err := web.QRDataURI(uri)
	if err != nil {
		web.Error(w, http.StatusInternalServerError, "INTERNAL", "Could not make the QR code.")
		return
	}
	web.JSON(w, http.StatusOK, map[string]string{"secret": secret, "uri": uri, "qr": qr})
}

type codeIn struct {
	Code     string `json:"code"`
	Password string `json:"password"`
}

func (a *Admin) totpEnable(w http.ResponseWriter, r *http.Request) {
	var in codeIn
	if !web.Decode(w, r, &in, bodyLimit) {
		return
	}
	s, _ := a.current(r)
	a.mu.Lock()
	pending := ""
	if s != nil {
		pending = s.pending
	}
	a.mu.Unlock()
	if pending == "" {
		web.Error(w, http.StatusBadRequest, "BAD_REQUEST", "Start two-step setup first.")
		return
	}
	step, ok := CheckTOTP(pending, in.Code, a.now(), 0)
	if !ok {
		web.Error(w, http.StatusBadRequest, "INVALID_CODE", "That code didn't match. Check the time on your phone and try again.")
		return
	}
	if err := updateCreds(a.d.Paths, func(c *Creds) error {
		c.TOTPSecret = pending
		c.TOTPLast = step
		return nil
	}); err != nil {
		web.Error(w, http.StatusInternalServerError, "INTERNAL", "Could not save two-step sign in.")
		return
	}
	a.mu.Lock()
	s.pending = ""
	a.mu.Unlock()
	web.JSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (a *Admin) totpDisable(w http.ResponseWriter, r *http.Request) {
	var in codeIn
	if !web.Decode(w, r, &in, bodyLimit) {
		return
	}
	if a.throttle.Locked(throttleKey) {
		web.Error(w, http.StatusTooManyRequests, "TOO_MANY_REQUESTS", "Too many attempts. Wait a few minutes and try again.")
		return
	}
	c, err := LoadCreds(a.d.Paths)
	if err != nil || !verifyPassword(c.Password, in.Password) {
		a.throttle.Fail(throttleKey)
		web.Error(w, http.StatusUnauthorized, "INVALID_CREDENTIALS", "Your password is not right.")
		return
	}
	if err := updateCreds(a.d.Paths, func(c *Creds) error {
		c.TOTPSecret = ""
		c.TOTPLast = 0
		return nil
	}); err != nil {
		web.Error(w, http.StatusInternalServerError, "INTERNAL", "Could not turn off two-step sign in.")
		return
	}
	web.JSON(w, http.StatusOK, map[string]bool{"ok": true})
}

type backupIn struct {
	Passphrase string `json:"passphrase"`
}

func (a *Admin) backup(w http.ResponseWriter, r *http.Request) {
	var in backupIn
	if !web.Decode(w, r, &in, bodyLimit) {
		return
	}
	WriteBackup(w, a.d.Paths, in.Passphrase, a.now())
}

func WriteBackup(w http.ResponseWriter, p config.Paths, pass string, now time.Time) {
	data, err := backup.Create(p, pass)
	if errors.Is(err, backup.ErrWeak) {
		web.Error(w, http.StatusBadRequest, "WEAK_PASSPHRASE", "Use a passphrase with at least 10 characters.")
		return
	}
	if err != nil {
		web.Error(w, http.StatusInternalServerError, "INTERNAL", "Could not create the backup.")
		return
	}
	h := w.Header()
	h.Set("Content-Type", "application/octet-stream")
	h.Set("Content-Disposition", `attachment; filename="veyl-backup-`+now.UTC().Format("2006-01-02")+`.vbk"`)
	h.Set("Content-Length", strconv.Itoa(len(data)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

func (a *Admin) dnsUpdate(w http.ResponseWriter, r *http.Request) {
	if _, err := a.startJob("dns-update", agentapi.OpDNSUpdate); err != nil {
		web.Error(w, http.StatusConflict, "BUSY", "Something else is running. Try again in a moment.")
		return
	}
	web.JSON(w, http.StatusAccepted, map[string]bool{"ok": true})
}
