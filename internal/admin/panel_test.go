package admin

import (
	"net/http"
	"net/http/cookiejar"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/veylvpn/backend/internal/agentapi"
	"github.com/veylvpn/backend/internal/config"
	"github.com/veylvpn/backend/internal/panelkey"
)

func (e *env) pairKey(scope string) (string, map[string]any) {
	e.t.Helper()
	e.login()
	res, out := e.do("POST", "/v1/admin/panel/pairing", map[string]string{"scope": scope}, nil)
	if res.StatusCode != 201 {
		e.t.Fatal(res.StatusCode, out)
	}
	code := out["code"].(string)
	if !strings.HasPrefix(code, "vpp_") {
		e.t.Fatal(code)
	}
	if u, err := panelkey.Decode(code); err != nil || u != "https://vpn.example.com" {
		e.t.Fatal(u, err)
	}
	m := &env{t: e.t, a: e.a, d: e.d, srv: e.srv, c: &http.Client{}}
	res, out = m.do("POST", PairPath, map[string]string{"code": code, "name": "Control\n1"}, nil)
	if res.StatusCode != 201 {
		e.t.Fatal(res.StatusCode, out)
	}
	res2, _ := m.do("POST", PairPath, map[string]string{"code": code}, nil)
	if res2.StatusCode != 401 {
		e.t.Fatal("pairing code reused", res2.StatusCode)
	}
	return out["key"].(string), out
}

func bearerEnv(e *env) *env {
	return &env{t: e.t, a: e.a, d: e.d, srv: e.srv, c: &http.Client{}}
}

func TestPairAndBearer(t *testing.T) {
	e := setup(t)
	key, out := e.pairKey("manage")
	if !panelkey.ValidSecret(key) || out["host"] != "vpn.example.com" || out["scope"] != "manage" {
		t.Fatal(out)
	}
	raw, _ := os.ReadFile(KeyStorePath(e.d.Paths))
	if strings.Contains(string(raw), key) || strings.Contains(string(raw), strings.TrimPrefix(key, "vpk_")) {
		t.Fatal("key stored in clear")
	}
	b := bearerEnv(e)
	auth := map[string]string{"Authorization": "Bearer " + key}
	if res, o := b.do("GET", "/v1/admin/overview", nil, auth); res.StatusCode != 200 || o["host"] != "vpn.example.com" {
		t.Fatal(res.StatusCode, o)
	}
	if res, o := b.do("POST", "/v1/admin/invites", map[string]int{"uses": 1}, auth); res.StatusCode != 201 {
		t.Fatal("bearer post needs no csrf", res.StatusCode, o)
	}
	for _, p := range []string{"/v1/admin/password", "/v1/admin/totp/setup", "/v1/admin/backup", "/v1/admin/logout", "/v1/admin/panel/pairing"} {
		if res, _ := b.do("POST", p, map[string]string{}, auth); res.StatusCode != 403 {
			t.Errorf("%s allowed for bearer: %d", p, res.StatusCode)
		}
	}
	if res, _ := b.do("GET", "/v1/admin/panel/keys", nil, auth); res.StatusCode != 403 {
		t.Fatal("key listing allowed for bearer")
	}
	res, o := e.do("GET", "/v1/admin/panel/keys", nil, nil)
	keys := o["keys"].([]any)
	if res.StatusCode != 200 || len(keys) != 1 {
		t.Fatal(o)
	}
	k := keys[0].(map[string]any)
	if k["name"] != "Control1" || k["last_used"] != time.Now().UTC().Format("2006-01-02") || k["hash"] != nil {
		t.Fatal(k)
	}
	if res, _ := e.do("DELETE", "/v1/admin/panel/keys/"+k["id"].(string), nil, nil); res.StatusCode != 200 {
		t.Fatal(res.StatusCode)
	}
	if res, _ := b.do("GET", "/v1/admin/overview", nil, auth); res.StatusCode != 401 {
		t.Fatal("revoked key still works", res.StatusCode)
	}
}

func TestMonitorScopeReadOnly(t *testing.T) {
	e := setup(t)
	key, _ := e.pairKey("monitor")
	b := bearerEnv(e)
	auth := map[string]string{"Authorization": "Bearer " + key}
	if res, _ := b.do("GET", "/v1/admin/accounts", nil, auth); res.StatusCode != 200 {
		t.Fatal(res.StatusCode)
	}
	if res, _ := b.do("POST", "/v1/admin/accounts", map[string]string{"label": "x"}, auth); res.StatusCode != 403 {
		t.Fatal(res.StatusCode)
	}
}

func TestBearerThrottleAndJunk(t *testing.T) {
	e := setup(t)
	key, _ := e.pairKey("manage")
	b := bearerEnv(e)
	for i := 0; i < 12; i++ {
		b.do("GET", "/v1/admin/overview", nil, map[string]string{"Authorization": "Bearer vpk_" + strings.Repeat("A", 43)})
	}
	res, _ := b.do("GET", "/v1/admin/overview", nil, map[string]string{"Authorization": "Bearer vpk_" + strings.Repeat("B", 43)})
	if res.StatusCode != 429 {
		t.Fatal("bad keys not throttled", res.StatusCode)
	}
	if res, _ := b.do("GET", "/v1/admin/overview", nil, map[string]string{"Authorization": "Bearer " + key}); res.StatusCode != 200 {
		t.Fatal("valid key locked out by attacker", res.StatusCode)
	}
	if res, _ := b.do("GET", "/v1/admin/overview", nil, map[string]string{"Authorization": "Basic " + key}); res.StatusCode != 401 {
		t.Fatal(res.StatusCode)
	}
}

func TestPairingRequiresHostAndSession(t *testing.T) {
	e := setup(t)
	b := bearerEnv(e)
	if res, _ := b.do("POST", "/v1/admin/panel/pairing", map[string]string{}, nil); res.StatusCode != 403 {
		t.Fatal("pairing without csrf/session", res.StatusCode)
	}
	if res, _ := b.do("POST", PairPath, map[string]string{"code": "vpp_x.y"}, nil); res.StatusCode != 401 {
		t.Fatal(res.StatusCode)
	}
	e.login()
	if _, err := e.d.Settings.Update(func(s *config.Settings) error { s.Configured = false; s.Host = ""; return nil }); err != nil {
		t.Fatal(err)
	}
	if res, _ := e.do("POST", "/v1/admin/panel/pairing", map[string]string{"scope": "root"}, nil); res.StatusCode != 400 {
		t.Fatal(res.StatusCode)
	}
	if res, _ := e.do("POST", "/v1/admin/panel/pairing", map[string]string{}, nil); res.StatusCode != 409 {
		t.Fatal(res.StatusCode)
	}
}

func TestBearerBypassesVPNOnly(t *testing.T) {
	e := setup(t)
	key, _ := e.pairKey("manage")
	if _, err := e.d.Settings.Update(func(s *config.Settings) error { s.AdminVPNOnly = true; return nil }); err != nil {
		t.Fatal(err)
	}
	jar, _ := cookiejar.New(nil)
	e.c = &http.Client{Jar: jar}
	if res, _ := e.do("GET", "/v1/admin/session", nil, nil); res.StatusCode != 404 {
		t.Fatal("vpn-only not enforced for sessions", res.StatusCode)
	}
	b := bearerEnv(e)
	if res, _ := b.do("GET", "/v1/admin/overview", nil, map[string]string{"Authorization": "Bearer " + key}); res.StatusCode != 200 {
		t.Fatal(res.StatusCode)
	}
}

func TestRestartAndUpdateEndpoints(t *testing.T) {
	e := setup(t)
	key, _ := e.pairKey("manage")
	b := bearerEnv(e)
	auth := map[string]string{"Authorization": "Bearer " + key}
	if res, _ := b.do("POST", "/v1/admin/services/restart", map[string]string{"service": "sshd"}, auth); res.StatusCode != 400 {
		t.Fatal(res.StatusCode)
	}
	res, o := b.do("POST", "/v1/admin/services/restart", map[string]string{"service": "veyl-dns"}, auth)
	if res.StatusCode != 202 {
		t.Fatal(res.StatusCode, o)
	}
	j := e.a.currentJob()
	if j == nil || !j.Wait(2*time.Second) {
		t.Fatal("job not finished")
	}
	if res, o := b.do("GET", "/v1/admin/job", nil, auth); res.StatusCode != 200 || o["kind"] != "restart" || o["running"] != false {
		t.Fatal(o)
	}
	if res, _ := b.do("POST", "/v1/admin/update", map[string]string{}, auth); res.StatusCode != 202 {
		t.Fatal(res.StatusCode)
	}
	e.a.currentJob().Wait(2 * time.Second)
	if e.agent.count(agentapi.OpRestart) != 1 || e.agent.count(agentapi.OpUpdate) != 1 {
		t.Fatal(e.agent.ops)
	}
}
