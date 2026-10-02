package admin

import (
	"context"
	"errors"
	"net/http"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/veylvpn/backend/internal/agentapi"
	"github.com/veylvpn/backend/internal/app"
	"github.com/veylvpn/backend/internal/config"
	"github.com/veylvpn/backend/internal/panelkey"
	"github.com/veylvpn/backend/internal/web"
)

const (
	PairPath        = "/v1/admin/pair"
	SelfKeyPath     = "/v1/admin/panel/key"
	bearerThrottle  = "admin-bearer"
	pairThrottle    = "admin-pair"
	maxBearerHeader = 256
)

type keyCtx struct{}

var RestartableServices = []string{"veyl", "veyl-dns", "veyl-dnsif", "veyl-firewall", "openvpn-server@veyl-udp", "openvpn-server@veyl-tcp", "unbound", "caddy"}

func (a *Admin) panelRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST "+PairPath, a.pair)
	mux.HandleFunc("GET /v1/admin/panel/keys", a.session(a.listKeys))
	mux.HandleFunc("POST /v1/admin/panel/pairing", a.session(a.newPairing))
	mux.HandleFunc("DELETE /v1/admin/panel/keys/{id}", a.session(a.revokeKey))
	mux.HandleFunc("POST /v1/admin/services/restart", a.auth(a.restartServices))
	mux.HandleFunc("POST /v1/admin/update", a.auth(a.update))
	mux.HandleFunc("GET /v1/admin/job", a.auth(a.jobState))
	mux.HandleFunc("DELETE "+SelfKeyPath, a.keyAuth(a.revokeSelf))
}

func bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if h == "" || len(h) > maxBearerHeader {
		return ""
	}
	scheme, tok, ok := strings.Cut(h, " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return ""
	}
	return strings.TrimSpace(tok)
}

func KeyStorePath(p config.Paths) string {
	return filepath.Join(p.Data, panelkey.FileName)
}

func (a *Admin) keyStore() (*panelkey.Store, error) {
	a.keyMu.Lock()
	defer a.keyMu.Unlock()
	if a.keys != nil {
		return a.keys, nil
	}
	s, err := panelkey.Open(KeyStorePath(a.d.Paths))
	if err != nil {
		return nil, err
	}
	s.Now = a.now
	a.keys = s
	return s, nil
}

func (a *Admin) keyAuth(fn http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ks, err := a.keyStore()
		if err != nil {
			web.Error(w, http.StatusInternalServerError, "INTERNAL", "Node keys are unavailable.")
			return
		}
		k, ok := ks.Authenticate(bearer(r))
		if !ok {
			if a.throttle.Locked(bearerThrottle) {
				web.Error(w, http.StatusTooManyRequests, "TOO_MANY_REQUESTS", "Too many attempts. Wait a few minutes and try again.")
				return
			}
			a.throttle.Fail(bearerThrottle)
			web.Error(w, http.StatusUnauthorized, "INVALID_KEY", "That node key is not valid.")
			return
		}
		if k.Scope != panelkey.ScopeManage && r.Method != http.MethodGet && r.Method != http.MethodHead && r.URL.Path != SelfKeyPath {
			web.Error(w, http.StatusForbidden, "FORBIDDEN", "This node key can only read.")
			return
		}
		fn(w, r.WithContext(context.WithValue(r.Context(), keyCtx{}, k.ID)))
	}
}

type pairIn struct {
	Code string `json:"code"`
	Name string `json:"name"`
}

func (a *Admin) pair(w http.ResponseWriter, r *http.Request) {
	var in pairIn
	if !web.Decode(w, r, &in, bodyLimit) {
		return
	}
	if a.throttle.Locked(pairThrottle) {
		web.Error(w, http.StatusTooManyRequests, "TOO_MANY_REQUESTS", "Too many attempts. Wait a few minutes and try again.")
		return
	}
	ks, err := a.keyStore()
	if err != nil {
		web.Error(w, http.StatusInternalServerError, "INTERNAL", "Node keys are unavailable.")
		return
	}
	secret, k, err := ks.Redeem(in.Code, in.Name)
	if errors.Is(err, panelkey.ErrTooMany) {
		web.Error(w, http.StatusConflict, "TOO_MANY_KEYS", "This node already has the maximum number of panel keys. Remove one first.")
		return
	}
	if err != nil {
		a.throttle.Fail(pairThrottle)
		web.Error(w, http.StatusUnauthorized, "INVALID_CODE", "That pairing code is not valid or has expired. Create a new one on the node.")
		return
	}
	a.throttle.Reset(pairThrottle)
	set := a.d.Settings.Get()
	web.JSON(w, http.StatusCreated, map[string]any{
		"key":      secret,
		"id":       k.ID,
		"scope":    k.Scope,
		"name":     set.Name,
		"host":     set.Host,
		"version":  app.Version,
		"platform": platform(),
	})
}

type pairingIn struct {
	Scope string `json:"scope"`
}

func (a *Admin) newPairing(w http.ResponseWriter, r *http.Request) {
	var in pairingIn
	if !web.Decode(w, r, &in, bodyLimit) {
		return
	}
	if in.Scope == "" {
		in.Scope = panelkey.ScopeManage
	}
	if !panelkey.ValidScope(in.Scope) {
		web.Error(w, http.StatusBadRequest, "BAD_REQUEST", "Choose manage or monitor.")
		return
	}
	host := a.d.Settings.Get().Host
	u, err := panelkey.NodeURL(host)
	if err != nil {
		web.Error(w, http.StatusConflict, "NO_HOST", "Set a server address before pairing a control panel.")
		return
	}
	code, exp, err := a.NewPairingCode(u, in.Scope)
	if err != nil {
		web.Error(w, http.StatusInternalServerError, "INTERNAL", "Could not create a pairing code.")
		return
	}
	web.JSON(w, http.StatusCreated, map[string]any{"code": code, "expires": exp.UTC().Format(time.RFC3339), "scope": in.Scope})
}

func (a *Admin) NewPairingCode(nodeURL, scope string) (string, time.Time, error) {
	ks, err := a.keyStore()
	if err != nil {
		return "", time.Time{}, err
	}
	return ks.NewPairing(nodeURL, scope)
}

func (a *Admin) listKeys(w http.ResponseWriter, r *http.Request) {
	ks, err := a.keyStore()
	if err != nil {
		web.Error(w, http.StatusInternalServerError, "INTERNAL", "Node keys are unavailable.")
		return
	}
	type keyOut struct {
		ID       string `json:"id"`
		Name     string `json:"name"`
		Scope    string `json:"scope"`
		Created  string `json:"created"`
		LastUsed string `json:"last_used,omitempty"`
	}
	out := []keyOut{}
	for _, k := range ks.List() {
		o := keyOut{ID: k.ID, Name: k.Name, Scope: k.Scope, Created: time.Unix(k.Created, 0).UTC().Format("2006-01-02")}
		if k.LastUsed > 0 {
			o.LastUsed = time.Unix(k.LastUsed, 0).UTC().Format("2006-01-02")
		}
		out = append(out, o)
	}
	web.JSON(w, http.StatusOK, map[string]any{"keys": out, "pending": ks.Pending(), "host": a.d.Settings.Get().Host})
}

func (a *Admin) revokeKey(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !validID(id) {
		web.Error(w, http.StatusNotFound, "KEY_NOT_FOUND", "That key no longer exists.")
		return
	}
	ks, err := a.keyStore()
	if err == nil {
		err = ks.Revoke(id)
	}
	if errors.Is(err, panelkey.ErrNoKey) {
		web.Error(w, http.StatusNotFound, "KEY_NOT_FOUND", "That key no longer exists.")
		return
	}
	if err != nil {
		web.Error(w, http.StatusInternalServerError, "INTERNAL", "Could not remove the key.")
		return
	}
	web.JSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (a *Admin) revokeSelf(w http.ResponseWriter, r *http.Request) {
	id, _ := r.Context().Value(keyCtx{}).(string)
	ks, err := a.keyStore()
	if err == nil {
		err = ks.Revoke(id)
	}
	if err != nil {
		web.Error(w, http.StatusNotFound, "KEY_NOT_FOUND", "That key no longer exists.")
		return
	}
	web.JSON(w, http.StatusOK, map[string]bool{"ok": true})
}

type restartIn struct {
	Service string `json:"service"`
}

func validService(s string) bool {
	for _, v := range RestartableServices {
		if v == s {
			return true
		}
	}
	return false
}

func (a *Admin) restartServices(w http.ResponseWriter, r *http.Request) {
	var in restartIn
	if !web.Decode(w, r, &in, bodyLimit) {
		return
	}
	if in.Service != "" && !validService(in.Service) {
		web.Error(w, http.StatusBadRequest, "BAD_REQUEST", "Unknown service.")
		return
	}
	j, err := a.startRequest("restart", agentapi.Request{Op: agentapi.OpRestart, Arg: in.Service})
	if err != nil {
		web.Error(w, http.StatusConflict, "BUSY", "Something else is running. Try again in a moment.")
		return
	}
	web.JSON(w, http.StatusAccepted, map[string]any{"ok": true, "job": j.ID})
}

func (a *Admin) update(w http.ResponseWriter, r *http.Request) {
	j, err := a.startRequest("update", agentapi.Request{Op: agentapi.OpUpdate})
	if err != nil {
		web.Error(w, http.StatusConflict, "BUSY", "Something else is running. Try again in a moment.")
		return
	}
	web.JSON(w, http.StatusAccepted, map[string]any{"ok": true, "job": j.ID})
}

func (a *Admin) jobState(w http.ResponseWriter, r *http.Request) {
	j := a.currentJob()
	if j == nil {
		web.JSON(w, http.StatusOK, map[string]any{"running": false})
		return
	}
	steps, done, out := j.State()
	web.JSON(w, http.StatusOK, map[string]any{"id": j.ID, "kind": j.Kind, "running": !done, "steps": steps, "outcome": out})
}

func platform() string {
	return runtime.GOOS
}
