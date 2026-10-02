package panel

import (
	"context"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/veylvpn/backend/internal/panelkey"
)

func pairedHarness(t *testing.T, nodes ...*fakeNode) (*harness, *client, []string) {
	t.Helper()
	h := newHarness(t, func(o *Options) { o.RootCAs = pools(nodes...) })
	configure(h)
	o := h.owner()
	var ids []string
	for i, n := range nodes {
		code, out := o.do("POST", "/api/nodes", map[string]string{"code": n.code(panelkey.ScopeManage), "name": "node-" + string(rune('a'+i))})
		if code != 201 {
			t.Fatal(code, out)
		}
		ids = append(ids, out["node"].(map[string]any)["id"].(string))
	}
	return h, o, ids
}

func TestPairNodeStoresKeyEncrypted(t *testing.T) {
	n := newNode(t, "Amsterdam")
	h, o, ids := pairedHarness(t, n)
	raw, _ := os.ReadFile(h.paths.DB())
	if strings.Contains(string(raw), "vpk_") {
		t.Fatal("node key stored in clear")
	}
	key, _ := os.ReadFile(h.paths.Secret())
	if len(key) != 32 {
		t.Fatal("secret key")
	}
	fi, _ := os.Stat(h.paths.Secret())
	if runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
		t.Fatal(fi.Mode())
	}
	if code, out := o.do("POST", "/api/nodes", map[string]string{"code": n.code(panelkey.ScopeManage)}); code != 409 || out["code"] != "DUPLICATE" {
		t.Fatal(code, out)
	}
	h.p.mon.Tick(context.Background())
	code, out := o.do("GET", "/api/fleet", nil)
	if code != 200 {
		t.Fatal(code)
	}
	nodes := out["nodes"].([]any)
	f := nodes[0].(map[string]any)
	if f["status"] != "up" || f["name"] != "node-a" || f["platform"] != "linux" || f["disk"].(float64) != 0.5 {
		t.Fatal(f)
	}
	if code, out := o.do("GET", "/api/nodes/"+ids[0], nil); code != 200 || len(out["days"].([]any)) != 90 {
		t.Fatal(code, out)
	}
	if code, out := o.do("DELETE", "/api/nodes/"+ids[0], nil); code != 200 || out["key_revoked"] != true {
		t.Fatal(code, out)
	}
	ks, _ := panelkey.Open(n.d.Paths.Data + "/panel-keys.json")
	if len(ks.List()) != 0 {
		t.Fatal("key not revoked on node")
	}
}

func TestPairUntrustedNeedsPin(t *testing.T) {
	n := newNode(t, "Self signed")
	h := newHarness(t, nil)
	configure(h)
	o := h.owner()
	code, out := o.do("POST", "/api/nodes", map[string]string{"code": n.code(panelkey.ScopeManage)})
	if code != 409 || out["code"] != "UNTRUSTED_CERT" || len(out["fingerprint"].(string)) != 64 {
		t.Fatal(code, out)
	}
	if code, _ := o.do("POST", "/api/nodes", map[string]string{"code": n.code(panelkey.ScopeManage), "pin": strings.Repeat("ab", 32)}); code != 409 {
		t.Fatal("wrong pin accepted", code)
	}
	code, out = o.do("POST", "/api/nodes", map[string]string{"code": n.code(panelkey.ScopeManage), "pin": strings.ToUpper(out["fingerprint"].(string))})
	if code != 201 {
		t.Fatal(code, out)
	}
	h.p.mon.Tick(context.Background())
	_, f := o.do("GET", "/api/fleet", nil)
	if f["nodes"].([]any)[0].(map[string]any)["status"] != "up" {
		t.Fatal(f)
	}
}

func TestProxyAndAudit(t *testing.T) {
	n := newNode(t, "Paris")
	h, o, ids := pairedHarness(t, n)
	base := "/api/nodes/" + ids[0] + "/admin/"
	code, out := o.do("POST", base+"accounts", map[string]any{"label": "Family", "expires_days": 30})
	if code != 201 {
		t.Fatal(code, out)
	}
	number := out["number"].(string)
	accID := out["account"].(map[string]any)["id"].(string)
	if code, out := o.do("GET", base+"accounts", nil); code != 200 || len(out["accounts"].([]any)) != 1 {
		t.Fatal(code, out)
	}
	if code, _ := o.do("PATCH", base+"accounts/"+accID, map[string]any{"disabled": true}); code != 200 {
		t.Fatal(code)
	}
	if code, _ := o.do("GET", base+"../../../v1/admin/backup", nil); code != 404 && code != 301 {
		t.Fatal(code)
	}
	for _, bad := range []string{"backup", "password", "panel/keys", "totp/setup", "accounts/XYZ"} {
		if code, _ := o.do("POST", base+bad, map[string]any{}); code != 404 {
			t.Errorf("%s proxied: %d", bad, code)
		}
	}
	_, vs := h.addUser("watcher", RoleViewer)
	v := h.client()
	v.login("watcher", vs)
	if code, _ := v.do("GET", base+"accounts", nil); code != 200 {
		t.Fatal(code)
	}
	if code, _ := v.do("DELETE", base+"accounts/"+accID, nil); code != 403 {
		t.Fatal("viewer changed node", code)
	}
	if code, _ := o.do("DELETE", base+"accounts/"+accID, nil); code != 200 {
		t.Fatal(code)
	}
	raw, _ := os.ReadFile(h.paths.DB())
	if strings.Contains(string(raw), number) || strings.Contains(string(raw), "Family") {
		t.Fatal("vpn user data stored in panel")
	}
	_, out = o.do("GET", "/api/audit?action=node.account", nil)
	entries := out["entries"].([]any)
	if len(entries) != 3 {
		t.Fatal(entries)
	}
	first := entries[2].(map[string]any)
	if first["action"] != "node.account.create" || first["detail"] != "expires_days, label" || first["user"] != "owner" {
		t.Fatal(first)
	}
	res, body := o.raw("GET", "/api/audit/export", nil, nil)
	if res.StatusCode != 200 || !strings.HasPrefix(string(body), "time,user,action,target,detail") || !strings.Contains(string(body), "node.account.delete") {
		t.Fatal(string(body))
	}
}

func TestBulkInvite(t *testing.T) {
	a, b := newNode(t, "A"), newNode(t, "B")
	_, o, ids := pairedHarness(t, a, b)
	code, out := o.do("POST", "/api/bulk", map[string]any{"action": "invite", "nodes": ids, "params": map[string]int{"uses": 3, "expires_days": 7}})
	if code != 200 {
		t.Fatal(code, out)
	}
	res := out["results"].([]any)
	if len(res) != 2 {
		t.Fatal(res)
	}
	for _, r := range res {
		m := r.(map[string]any)
		if m["ok"] != true || m["data"].(map[string]any)["code"] == "" {
			t.Fatal(m)
		}
	}
	if code, _ := o.do("POST", "/api/bulk", map[string]any{"action": "shell", "nodes": ids}); code != 400 {
		t.Fatal(code)
	}
}

func TestMonitorUptimeIncidentsAndAlerts(t *testing.T) {
	n := newNode(t, "Berlin")
	var got []string
	hook := newWebhook(t, func(body map[string]any) { got = append(got, body["event"].(string)) })
	h, o, ids := pairedHarness(t, n)
	h.p.opt.AlertHTTP = hook.client
	configureWebhook(t, o, hook.url, "")
	ctx := context.Background()
	h.clk.t = time.Date(2026, 10, 2, 10, 0, 0, 0, time.UTC)
	for i := 0; i < 4; i++ {
		h.p.mon.Tick(ctx)
		h.clk.Add(30 * time.Second)
	}
	n.setDown(true)
	h.p.mon.Tick(ctx)
	h.clk.Add(30 * time.Second)
	if _, out := o.do("GET", "/api/fleet", nil); out["nodes"].([]any)[0].(map[string]any)["status"] == "down" {
		t.Fatal("one failure must not mark the node down")
	}
	h.p.mon.Tick(ctx)
	h.clk.Add(30 * time.Second)
	_, out := o.do("GET", "/api/incidents?open=1", nil)
	inc := out["incidents"].([]any)
	if len(inc) != 1 || inc[0].(map[string]any)["kind"] != "down" {
		t.Fatal(inc)
	}
	n.setDown(false)
	h.p.mon.Tick(ctx)
	h.p.alerts.Drain(ctx)
	_, out = o.do("GET", "/api/incidents?open=1", nil)
	if len(out["incidents"].([]any)) != 0 {
		t.Fatal(out)
	}
	var hours []Hour
	h.p.db.View(func(d *data) { hours = d.Uptime[ids[0]] })
	if len(hours) != 1 || hours[0].Total != 7*30 || hours[0].Up != 5*30 || hours[0].Start%3600 != 0 {
		t.Fatal(hours)
	}
	if strings.Join(got, ",") != "node_down,node_up" {
		t.Fatal(got)
	}
	h.clk.Add(91 * 24 * time.Hour)
	h.p.mon.Tick(ctx)
	h.p.db.View(func(d *data) {
		hours = d.Uptime[ids[0]]
		if len(d.Incidents) != 0 {
			t.Error("incident older than 90 days kept")
		}
	})
	if len(hours) != 1 {
		t.Fatal("old uptime not pruned", hours)
	}
}

func TestAutoHealBackoff(t *testing.T) {
	n := newNode(t, "Oslo")
	h, o, ids := pairedHarness(t, n)
	ctx := context.Background()
	n.agent.set("svc.veyl-dns", "failed")
	for i := 0; i < 20; i++ {
		h.p.mon.Tick(ctx)
		h.clk.Add(30 * time.Second)
	}
	waitFor(t, func() bool { return len(n.agent.restarted()) >= 3 })
	r := n.agent.restarted()
	if len(r) != 3 || r[0] != "veyl-dns" {
		t.Fatal(r)
	}
	code, out := o.do("GET", "/api/incidents?node="+ids[0], nil)
	if code != 200 {
		t.Fatal(code, out)
	}
	inc := out["incidents"].([]any)[0].(map[string]any)
	notes := ""
	for _, nn := range inc["notes"].([]any) {
		notes += nn.(map[string]any)["text"].(string) + "|"
	}
	if !strings.Contains(notes, "attempt 3 of 3") || !strings.Contains(notes, "No more automatic restarts") {
		t.Fatal(notes)
	}
	h.clk.Add(61 * time.Minute)
	h.p.mon.Tick(ctx)
	waitFor(t, func() bool { return len(n.agent.restarted()) == 4 })
	n.agent.set("svc.veyl-dns", "active")
	h.p.mon.Tick(ctx)
	var in Incident
	h.p.db.View(func(d *data) { in = d.Incidents[len(d.Incidents)-1] })
	if in.End == 0 || in.Notes[len(in.Notes)-1].Text != "Healed by automatic restart" {
		t.Fatal(in)
	}
}

func TestAutoHealOffAndMonitorScope(t *testing.T) {
	n := newNode(t, "Rome")
	h := newHarness(t, func(o *Options) { o.RootCAs = pools(n) })
	configure(h)
	o := h.owner()
	if code, out := o.do("POST", "/api/nodes", map[string]string{"code": n.code(panelkey.ScopeMonitor)}); code != 201 {
		t.Fatal(code, out)
	}
	n.agent.set("svc.caddy", "failed")
	h.p.mon.Tick(context.Background())
	time.Sleep(50 * time.Millisecond)
	if len(n.agent.restarted()) != 0 {
		t.Fatal("monitor-only key tried to heal")
	}
	_, out := o.do("GET", "/api/fleet", nil)
	if out["nodes"].([]any)[0].(map[string]any)["status"] != "degraded" {
		t.Fatal(out)
	}
}

func waitFor(t *testing.T, fn func() bool) {
	t.Helper()
	for i := 0; i < 200; i++ {
		if fn() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition not met")
}

func TestNewer(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{{"v0.3.0", "0.2.9", true}, {"v0.3.0", "v0.3.0", false}, {"v0.3.0", "0.3.0-dev", true}, {"v0.2.0", "v0.10.0", false}, {"latest", "0.2.0", false}}
	for _, c := range cases {
		if Newer(c.a, c.b) != c.want {
			t.Errorf("%s vs %s", c.a, c.b)
		}
	}
}
