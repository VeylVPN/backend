package hook

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/veylvpn/backend/internal/app"
	"github.com/veylvpn/backend/internal/config"
	"github.com/veylvpn/backend/internal/hookapi"
	"github.com/veylvpn/backend/internal/store"
)

type fixture struct {
	d      app.Deps
	s      *Server
	key    string
	device string
	sock   string
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	dir := t.TempDir()
	paths := config.Paths{Data: dir, Run: dir}
	st, err := store.Open(paths.State())
	if err != nil {
		t.Fatal(err)
	}
	set := config.Defaults()
	if err := config.Save(paths.Settings(), set); err != nil {
		t.Fatal(err)
	}
	live, err := config.NewLive(paths.Settings())
	if err != nil {
		t.Fatal(err)
	}
	n, err := st.CreateClaimed("correct horse")
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{d: app.Deps{Paths: paths, Settings: live, Store: st}, key: store.HashAccount(n), device: "0123456789abcdef"}
	if err := st.AddDeviceKey(f.key, store.Device{ID: f.device, Name: "a", Serial: "abc"}); err != nil {
		t.Fatal(err)
	}
	f.s = NewServer(f.d)
	f.s.Group = ""
	return f
}

func (f *fixture) serve(t *testing.T) {
	t.Helper()
	sd, err := os.MkdirTemp("", "vh")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(sd) })
	f.sock = filepath.Join(sd, "hook.sock")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- f.s.Serve(ctx, f.sock) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	})
	for i := 0; i < 200; i++ {
		if _, err := os.Stat(f.sock); err == nil {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("socket not created")
}

func TestDecide(t *testing.T) {
	f := newFixture(t)
	def := config.DNSAddr(config.Defaults().DNS.Default)
	cases := []struct {
		name  string
		req   hookapi.Request
		allow bool
		push  []string
	}{
		{"verify known", hookapi.Request{Event: hookapi.EventVerify, CN: f.device}, true, nil},
		{"connect known", hookapi.Request{Event: hookapi.EventConnect, CN: f.device}, true, []string{"dhcp-option DNS " + def}},
		{"verify unknown", hookapi.Request{Event: hookapi.EventVerify, CN: "ffffffffffffffff"}, false, nil},
		{"connect unknown", hookapi.Request{Event: hookapi.EventConnect, CN: "ffffffffffffffff"}, false, nil},
		{"bad cn", hookapi.Request{Event: hookapi.EventConnect, CN: "a b"}, false, nil},
		{"empty cn", hookapi.Request{Event: hookapi.EventVerify}, false, nil},
		{"unknown event", hookapi.Request{Event: "learn-address", CN: f.device}, false, nil},
		{"disconnect", hookapi.Request{Event: hookapi.EventDisconnect, CN: "whatever"}, true, nil},
	}
	for _, c := range cases {
		got := f.s.Decide(c.req)
		if got.Allow != c.allow || strings.Join(got.Push, "|") != strings.Join(c.push, "|") {
			t.Errorf("%s: %+v", c.name, got)
		}
	}
	cats := []string{config.CatAds, config.CatSocial}
	if _, err := f.d.Store.UpdateKey(f.key, store.Patch{DNS: &cats}); err != nil {
		t.Fatal(err)
	}
	got := f.s.Decide(hookapi.Request{Event: hookapi.EventConnect, CN: f.device})
	if !got.Allow || len(got.Push) != 1 || got.Push[0] != "dhcp-option DNS "+config.DNSAddr(cats) {
		t.Fatalf("custom dns %+v", got)
	}
	empty := []string{}
	if _, err := f.d.Store.UpdateKey(f.key, store.Patch{DNS: &empty}); err != nil {
		t.Fatal(err)
	}
	if got := f.s.Decide(hookapi.Request{Event: hookapi.EventConnect, CN: f.device}); got.Push[0] != "dhcp-option DNS 10.64.0.1" {
		t.Fatalf("no blocking %+v", got)
	}
	past := time.Now().Add(-time.Minute).Unix()
	if _, err := f.d.Store.UpdateKey(f.key, store.Patch{Expires: &past}); err != nil {
		t.Fatal(err)
	}
	for _, ev := range []string{hookapi.EventVerify, hookapi.EventConnect} {
		if f.s.Decide(hookapi.Request{Event: ev, CN: f.device}).Allow {
			t.Fatalf("%s allowed for expired account", ev)
		}
	}
	var zero int64
	yes := true
	if _, err := f.d.Store.UpdateKey(f.key, store.Patch{Expires: &zero, Disabled: &yes}); err != nil {
		t.Fatal(err)
	}
	if f.s.Decide(hookapi.Request{Event: hookapi.EventVerify, CN: f.device}).Allow {
		t.Fatal("allowed for disabled account")
	}
	no := false
	f.d.Store.UpdateKey(f.key, store.Patch{Disabled: &no})
	if _, err := f.d.Store.RevokeKey(f.key, f.device); err != nil {
		t.Fatal(err)
	}
	if f.s.Decide(hookapi.Request{Event: hookapi.EventVerify, CN: f.device}).Allow {
		t.Fatal("allowed revoked device")
	}
}

func TestDecideFailsClosedOnBrokenState(t *testing.T) {
	f := newFixture(t)
	if err := os.WriteFile(f.d.Paths.State(), []byte("{broken"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, ev := range []string{hookapi.EventVerify, hookapi.EventConnect} {
		if f.s.Decide(hookapi.Request{Event: ev, CN: f.device}).Allow {
			t.Fatalf("%s allowed with unreadable state", ev)
		}
	}
}

func TestServeSocket(t *testing.T) {
	f := newFixture(t)
	f.serve(t)
	fi, err := os.Stat(f.sock)
	if err != nil || fi.Mode().Perm() != 0o660 {
		t.Fatalf("socket mode %v %v", fi, err)
	}
	r, err := hookapi.Ask(f.sock, hookapi.Request{Event: hookapi.EventConnect, CN: f.device}, time.Second)
	if err != nil || !r.Allow || len(r.Push) != 1 {
		t.Fatalf("%+v %v", r, err)
	}
	r, err = hookapi.Ask(f.sock, hookapi.Request{Event: hookapi.EventConnect, CN: "nope"}, time.Second)
	if err != nil || r.Allow {
		t.Fatalf("%+v %v", r, err)
	}
}

func TestServeRefusesNonSocketPath(t *testing.T) {
	f := newFixture(t)
	p := filepath.Join(t.TempDir(), "file")
	os.WriteFile(p, []byte("x"), 0o600)
	if err := f.s.Serve(context.Background(), p); err == nil {
		t.Fatal("served over a regular file")
	}
}

func writeMeta(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "meta")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestMainVerify(t *testing.T) {
	f := newFixture(t)
	f.serve(t)
	t.Setenv("untrusted_ip", "not-an-ip;rm -rf /")
	t.Setenv("trusted_ip", "x")
	cases := []struct {
		name  string
		typ   string
		file  string
		allow bool
	}{
		{"known", "0", writeMeta(t, f.device), true},
		{"unknown", "0", writeMeta(t, "ffffffffffffffff"), false},
		{"timestamp type", "1", writeMeta(t, f.device), false},
		{"missing type", "", writeMeta(t, f.device), false},
		{"bad chars", "0", writeMeta(t, f.device+"\n"), false},
		{"too big", "0", writeMeta(t, strings.Repeat("a", 300)), false},
		{"empty", "0", writeMeta(t, ""), false},
		{"missing file", "0", "/nonexistent/meta", false},
		{"relative", "0", "meta", false},
	}
	for _, c := range cases {
		t.Setenv("metadata_type", c.typ)
		t.Setenv("metadata_file", c.file)
		got := Main([]string{"-socket", f.sock, "verify"})
		if (got == 0) != c.allow {
			t.Errorf("%s: exit %d", c.name, got)
		}
	}
	t.Setenv("metadata_type", "0")
	t.Setenv("metadata_file", writeMeta(t, f.device))
	link := filepath.Join(t.TempDir(), "link")
	os.Symlink(os.Getenv("metadata_file"), link)
	t.Setenv("metadata_file", link)
	if Main([]string{"-socket", f.sock, "verify"}) == 0 {
		t.Error("followed symlink")
	}
	t.Setenv("metadata_file", writeMeta(t, f.device))
	if Main([]string{"-socket", "/nonexistent/hook.sock", "verify"}) == 0 {
		t.Error("allowed without server")
	}
	if Main([]string{"-socket", f.sock, "verify", "extra"}) == 0 {
		t.Error("allowed extra args")
	}
}

func TestMainConnect(t *testing.T) {
	f := newFixture(t)
	f.serve(t)
	out := filepath.Join(t.TempDir(), "ccd")
	t.Setenv("common_name", f.device)
	t.Setenv("untrusted_ip", "203.0.113.1")
	if got := Main([]string{"-socket", f.sock, "connect", out}); got != 0 {
		t.Fatalf("exit %d", got)
	}
	b, _ := os.ReadFile(out)
	want := "push \"dhcp-option DNS " + config.DNSAddr(config.Defaults().DNS.Default) + "\"\n"
	if string(b) != want {
		t.Fatalf("%q", b)
	}
	out2 := filepath.Join(t.TempDir(), "ccd")
	for _, cn := range []string{"ffffffffffffffff", "", "a\"b", strings.Repeat("a", 65)} {
		t.Setenv("common_name", cn)
		if Main([]string{"-socket", f.sock, "connect", out2}) == 0 {
			t.Errorf("allowed cn %q", cn)
		}
	}
	if _, err := os.Stat(out2); err == nil {
		t.Error("wrote push file for denied client")
	}
	t.Setenv("common_name", f.device)
	for _, args := range [][]string{{"-socket", f.sock, "connect"}, {"-socket", f.sock, "connect", "rel/path"}, {"-socket", "/nonexistent/s", "connect", out2}, {"-bogus", "connect", out2}, {}, {"learn-address"}} {
		if Main(args) == 0 {
			t.Errorf("allowed %v", args)
		}
	}
	if Main([]string{"disconnect"}) != 0 {
		t.Error("disconnect must succeed")
	}
}

func TestValidPush(t *testing.T) {
	good := []string{"dhcp-option DNS 10.64.0.1", "dhcp-option DNS 10.64.0.64"}
	bad := []string{"dhcp-option DNS 8.8.8.8", "dhcp-option DNS 10.64.0.65", "route 0.0.0.0 0.0.0.0", "dhcp-option DNS 10.64.0.1\"\nup /bin/sh", "dhcp-option  DNS 10.64.0.1", ""}
	for _, p := range good {
		if !validPush(p) {
			t.Errorf("rejected %q", p)
		}
	}
	for _, p := range bad {
		if validPush(p) {
			t.Errorf("accepted %q", p)
		}
	}
}

func TestNeverReadsAddressEnv(t *testing.T) {
	for _, f := range []string{"main.go", "server.go"} {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, bad := range []string{"untrusted_ip", "trusted_ip", "ifconfig_pool", "untrusted_port", "trusted_port", "remote_", "Environ("} {
			if strings.Contains(string(b), bad) {
				t.Errorf("%s references %s", f, bad)
			}
		}
	}
}
