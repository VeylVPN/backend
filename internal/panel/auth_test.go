package panel

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/veylvpn/backend/internal/panelcfg"
)

func configure(h *harness) {
	if err := panelcfg.SaveSite(h.paths.Site(), panelcfg.Site{Domain: "control.example.com", Email: "ops@example.com", Mode: panelcfg.ModeHTTP, Configured: true}); err != nil {
		h.t.Fatal(err)
	}
}

func TestLoginRequiresTOTPAndBlocksReplay(t *testing.T) {
	h := newHarness(t, nil)
	configure(h)
	_, sec := h.addUser("alice", RoleAdmin)
	c := h.client()
	_, out := c.do("GET", "/api/session", nil)
	c.csrf = out["csrf"].(string)
	if code, out := c.do("POST", "/api/login", map[string]string{"username": "alice", "password": "correct-horse-battery"}); code != 401 || out["code"] != "CODE_REQUIRED" {
		t.Fatal(code, out)
	}
	if code, _ := c.do("POST", "/api/login", map[string]string{"username": "alice", "password": "wrong-password-123", "code": totpNow(t, sec, h.clk.Now())}); code != 401 {
		t.Fatal(code)
	}
	good := totpNow(t, sec, h.clk.Now())
	if code, out := c.do("POST", "/api/login", map[string]string{"username": "alice", "password": "correct-horse-battery", "code": good}); code != 200 {
		t.Fatal(code, out)
	}
	c2 := h.client()
	_, out = c2.do("GET", "/api/session", nil)
	c2.csrf = out["csrf"].(string)
	if code, out := c2.do("POST", "/api/login", map[string]string{"username": "alice", "password": "correct-horse-battery", "code": good}); code != 401 || out["code"] != "INVALID_CODE" {
		t.Fatal("replayed code accepted", code, out)
	}
	if code, _ := c.do("GET", "/api/me", nil); code != 200 {
		t.Fatal(code)
	}
}

func TestLoginCSRFAndThrottle(t *testing.T) {
	h := newHarness(t, nil)
	configure(h)
	h.addUser("bob", RoleViewer)
	c := h.client()
	if code, _ := c.do("POST", "/api/login", map[string]string{"username": "bob", "password": "x"}); code != 403 {
		t.Fatal("login without csrf", code)
	}
	_, out := c.do("GET", "/api/session", nil)
	c.csrf = out["csrf"].(string)
	for i := 0; i < 6; i++ {
		c.do("POST", "/api/login", map[string]string{"username": "bob", "password": "wrong-password-123", "code": "000000"})
	}
	if code, _ := c.do("POST", "/api/login", map[string]string{"username": "bob", "password": "correct-horse-battery", "code": "000000"}); code != 429 {
		t.Fatal("not throttled", code)
	}
}

func TestRecoveryCodesAreSingleUse(t *testing.T) {
	h := newHarness(t, nil)
	configure(h)
	u, _ := h.addUser("carol", RoleOwner)
	plain, hashed := newRecoveryCodes()
	_ = h.p.db.Update(func(d *data) error { d.user(u.ID).Recovery = hashed; return nil })
	raw, _ := os.ReadFile(h.paths.DB())
	if strings.Contains(string(raw), plain[0]) || strings.Contains(string(raw), normRecovery(plain[0])) {
		t.Fatal("recovery code stored in clear")
	}
	c := h.client()
	_, out := c.do("GET", "/api/session", nil)
	c.csrf = out["csrf"].(string)
	code, out := c.do("POST", "/api/login", map[string]string{"username": "carol", "password": "correct-horse-battery", "code": strings.ToUpper(plain[3])})
	if code != 200 || out["recovery_left"].(float64) != 9 {
		t.Fatal(code, out)
	}
	c2 := h.client()
	_, out = c2.do("GET", "/api/session", nil)
	c2.csrf = out["csrf"].(string)
	if code, _ := c2.do("POST", "/api/login", map[string]string{"username": "carol", "password": "correct-horse-battery", "code": plain[3]}); code != 401 {
		t.Fatal("recovery code reused", code)
	}
}

func TestSessionTimeoutsAndCSRF(t *testing.T) {
	h := newHarness(t, nil)
	configure(h)
	c := h.owner()
	csrf := c.csrf
	c.csrf = ""
	if code, _ := c.do("POST", "/api/team/invites", map[string]string{"role": "viewer"}); code != 403 {
		t.Fatal("csrf not enforced", code)
	}
	c.csrf = csrf
	h.clk.Add(29 * time.Minute)
	if code, _ := c.do("GET", "/api/me", nil); code != 200 {
		t.Fatal(code)
	}
	h.clk.Add(31 * time.Minute)
	if code, _ := c.do("GET", "/api/me", nil); code != 401 {
		t.Fatal("idle timeout not enforced", code)
	}
	c = h.client()
	_, sec := h.addUser("dave", RoleOwner)
	c.login("dave", sec)
	for i := 0; i < 26; i++ {
		h.clk.Add(29 * time.Minute)
		if code, _ := c.do("GET", "/api/me", nil); code != 200 {
			if i < 24 {
				t.Fatal("expired early", i)
			}
			return
		}
	}
	t.Fatal("absolute lifetime not enforced")
}

func TestRoles(t *testing.T) {
	h := newHarness(t, nil)
	configure(h)
	_, vs := h.addUser("viewer1", RoleViewer)
	_, as := h.addUser("admin1", RoleAdmin)
	h.owner()
	v := h.client()
	v.login("viewer1", vs)
	a := h.client()
	a.login("admin1", as)
	if code, _ := v.do("GET", "/api/fleet", nil); code != 200 {
		t.Fatal(code)
	}
	if code, _ := v.do("POST", "/api/nodes", map[string]string{"code": "vpp_x"}); code != 403 {
		t.Fatal("viewer can pair", code)
	}
	if code, _ := v.do("GET", "/api/audit", nil); code != 403 {
		t.Fatal("viewer can read audit", code)
	}
	if code, _ := a.do("GET", "/api/audit", nil); code != 200 {
		t.Fatal(code)
	}
	if code, _ := a.do("GET", "/api/team", nil); code != 403 {
		t.Fatal("admin can manage team", code)
	}
	if code, _ := a.do("POST", "/api/system/backup", map[string]string{"passphrase": "long enough passphrase"}); code != 403 {
		t.Fatal("admin can download backup", code)
	}
}

func TestTeamInviteJoinAndLastOwner(t *testing.T) {
	h := newHarness(t, nil)
	configure(h)
	o := h.owner()
	code, out := o.do("POST", "/api/team/invites", map[string]string{"role": "admin", "note": "Ops\nteam"})
	if code != 201 {
		t.Fatal(code, out)
	}
	token := out["token"].(string)
	raw, _ := os.ReadFile(h.paths.DB())
	if strings.Contains(string(raw), token) {
		t.Fatal("invite token stored in clear")
	}
	j := h.client()
	if code, out := j.do("POST", "/api/join/info", map[string]string{"token": token}); code != 200 || out["role"] != "admin" {
		t.Fatal(code, out)
	}
	if code, _ := j.do("POST", "/api/join/start", map[string]string{"token": token, "username": "Erin", "password": "short"}); code != 400 {
		t.Fatal(code)
	}
	code, out = j.do("POST", "/api/join/start", map[string]string{"token": token, "username": "Erin", "password": "a-long-enough-password"})
	if code != 200 {
		t.Fatal(code, out)
	}
	ticket := out["enroll"].(string)
	if code, _ := h.client().do("POST", "/api/join/start", map[string]string{"token": token, "username": "frank", "password": "a-long-enough-password"}); code != 404 {
		t.Fatal("invite reused", code)
	}
	code, out = j.do("POST", "/api/enroll/info", map[string]string{"ticket": ticket})
	if code != 200 || !strings.HasPrefix(out["qr"].(string), "data:image/svg+xml") || out["username"] != "erin" {
		t.Fatal(code, out)
	}
	secret := out["secret"].(string)
	if code, _ := j.do("POST", "/api/enroll/finish", map[string]string{"ticket": ticket, "code": "123456"}); code != 400 {
		t.Fatal(code)
	}
	code, out = j.do("POST", "/api/enroll/finish", map[string]string{"ticket": ticket, "code": totpNow(t, secret, h.clk.Now())})
	if code != 200 || len(out["recovery"].([]any)) != 10 {
		t.Fatal(code, out)
	}
	j.csrf = out["csrf"].(string)
	if code, out := j.do("GET", "/api/me", nil); code != 200 || out["role"] != "admin" {
		t.Fatal(code, out)
	}
	_, out = o.do("GET", "/api/team", nil)
	var ownerID string
	for _, u := range out["users"].([]any) {
		m := u.(map[string]any)
		if m["username"] == "owner" {
			ownerID = m["id"].(string)
		}
	}
	if code, out := o.do("PATCH", "/api/team/users/"+ownerID, map[string]string{"role": "viewer"}); code != 409 || out["code"] != "LAST_OWNER" {
		t.Fatal(code, out)
	}
	if code, _ := o.do("DELETE", "/api/team/users/"+ownerID, nil); code != 409 {
		t.Fatal(code)
	}
}

func TestPasswordChangeDropsOtherSessions(t *testing.T) {
	h := newHarness(t, nil)
	configure(h)
	_, sec := h.addUser("gina", RoleOwner)
	a := h.client()
	a.login("gina", sec)
	b := h.client()
	b.login("gina", sec)
	code, out := a.do("POST", "/api/me/password", map[string]string{"password": "correct-horse-battery", "new_password": "another-long-password", "code": totpNow(t, sec, h.clk.Now())})
	if code != 200 {
		t.Fatal(code, out)
	}
	a.csrf = out["csrf"].(string)
	if code, _ := b.do("GET", "/api/me", nil); code != 401 {
		t.Fatal("old session survived password change", code)
	}
	if code, _ := a.do("GET", "/api/me", nil); code != 200 {
		t.Fatal(code)
	}
	_, out = a.do("GET", "/api/me/sessions", nil)
	if n := len(out["sessions"].([]any)); n != 1 {
		t.Fatal(n)
	}
}

func TestRecoverUserForcesEnrollment(t *testing.T) {
	h := newHarness(t, nil)
	configure(h)
	h.addUser("henry", RoleOwner)
	pw, err := RecoverUser(h.paths, "henry")
	if err != nil {
		t.Fatal(err)
	}
	h2 := newHarnessAt(t, h.paths, h.clk)
	c := h2.client()
	_, out := c.do("GET", "/api/session", nil)
	c.csrf = out["csrf"].(string)
	code, out := c.do("POST", "/api/login", map[string]string{"username": "henry", "password": pw})
	if code != 200 || out["enroll"] == nil {
		t.Fatal(code, out)
	}
}

func newHarnessAt(t *testing.T, paths panelcfg.Paths, clk *clock) *harness {
	h := newHarness(t, func(o *Options) { o.Paths = paths; o.Now = clk.Now })
	h.paths, h.clk = paths, clk
	return h
}
