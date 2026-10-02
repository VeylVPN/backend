//go:build !windows

package agent

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/veylvpn/backend/internal/agentapi"
	"github.com/veylvpn/backend/internal/config"
	"github.com/veylvpn/backend/internal/render"
	"github.com/veylvpn/backend/internal/web"
)

type fakeRunner struct {
	mu       sync.Mutex
	calls    []string
	fail     map[string]int
	out      map[string]string
	inactive map[string]bool
}

func newFakeRunner() *fakeRunner {
	return &fakeRunner{
		fail:     map[string]int{},
		inactive: map[string]bool{},
		out: map[string]string{
			"openvpn --version": "OpenVPN 2.6.19 x86_64-pc-linux-gnu [SSL (OpenSSL)] [DCO]\nlibrary versions: OpenSSL 3.5.1 1 Jul 2025, LZO 2.10\n",
			"openssl version":   "OpenSSL 3.5.1 1 Jul 2025 (Library: OpenSSL 3.5.1 1 Jul 2025)\n",
			"sshd -T":           "port 22\nlistenaddress [::]:22\nlistenaddress 0.0.0.0:2222\nloglevel QUIET\n",
			"ss -H -ltnp":       "LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:((\"sshd\",pid=1,fd=3))\nLISTEN 0 128 127.0.0.1:8080 0.0.0.0:* users:((\"veyl\",pid=2,fd=3))\n",
			"ss -H -lntu": strings.Join([]string{
				"udp UNCONN 0 0 0.0.0.0:1194 0.0.0.0:*",
				"udp UNCONN 0 0 127.0.0.1:5335 0.0.0.0:*",
				"udp UNCONN 0 0 10.64.0.1:53 0.0.0.0:*",
				"tcp LISTEN 0 4096 127.0.0.1:5335 0.0.0.0:*",
				"tcp LISTEN 0 4096 10.64.0.1:53 0.0.0.0:*",
				"tcp LISTEN 0 4096 0.0.0.0:80 0.0.0.0:*",
				"tcp LISTEN 0 4096 0.0.0.0:443 0.0.0.0:*",
				"tcp LISTEN 0 4096 127.0.0.1:8443 0.0.0.0:*",
				"tcp LISTEN 0 4096 127.0.0.1:8080 0.0.0.0:*",
				"tcp LISTEN 0 4096 [::]:22 [::]:*",
			}, "\n"),
		},
	}
}

func (f *fakeRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := strings.TrimSpace(name + " " + strings.Join(args, " "))
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, cmd)
	if name == "sh" || name == "bash" || strings.Contains(name, " ") {
		return nil, errors.New("shell not allowed")
	}
	if n, ok := f.fail[cmd]; ok && n != 0 {
		if n > 0 {
			f.fail[cmd] = n - 1
		}
		if o, ok := f.out[cmd]; ok {
			return []byte(o), errors.New("exit status 1")
		}
		return []byte("boom"), errors.New("exit status 1")
	}
	if name == "systemctl" && len(args) == 2 && args[0] == "is-active" {
		if f.inactive[args[1]] {
			return []byte("inactive\n"), errors.New("exit status 3")
		}
		return []byte("active\n"), nil
	}
	if name == "systemctl" && (args[0] == "restart" || args[0] == "reload-or-restart") && len(args) == 2 {
		delete(f.inactive, args[1])
	}
	if name == "systemctl" && len(args) >= 3 && args[0] == "disable" && args[1] == "--now" {
		for _, u := range args[2:] {
			f.inactive[u] = true
		}
	}
	return []byte(f.out[cmd]), nil
}

func (f *fakeRunner) list() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

func (f *fakeRunner) reset() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = nil
}

func (f *fakeRunner) index(t *testing.T, cmd string) int {
	t.Helper()
	for i, c := range f.list() {
		if c == cmd {
			return i
		}
	}
	return -1
}

func (f *fakeRunner) count(cmd string) int {
	n := 0
	for _, c := range f.list() {
		if c == cmd {
			n++
		}
	}
	return n
}

type fakeProbe struct {
	dnsErr    error
	healthErr error
	health    int
}

func (p *fakeProbe) DNS(ctx context.Context, server, name string) error {
	if server != "10.64.0.1:53" {
		return errors.New("wrong server")
	}
	return p.dnsErr
}

func (p *fakeProbe) Health(ctx context.Context, host string, insecure bool) error {
	p.health++
	return p.healthErr
}

func (p *fakeProbe) PublicIP(ctx context.Context, v6 bool) (string, error) {
	if v6 {
		return "", errors.New("none")
	}
	return "203.0.113.7", nil
}

func (p *fakeProbe) CertExpiry(ctx context.Context, host string) (time.Time, error) {
	return time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC), nil
}

func writeFile(t *testing.T, root, p, data string) {
	t.Helper()
	full := filepath.Join(root, p)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
}

func readFile(t *testing.T, root, p string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, p))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

type harness struct {
	a      *Agent
	r      *fakeRunner
	p      *fakeProbe
	root   string
	events []agentapi.Event
	mu     sync.Mutex
}

func (h *harness) emit(ev agentapi.Event) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.events = append(h.events, ev)
}

func (h *harness) status(stepName string) string {
	h.mu.Lock()
	defer h.mu.Unlock()
	st := ""
	for _, e := range h.events {
		if e.Step == stepName {
			st = e.Status
		}
	}
	return st
}

func testSettings() config.Settings {
	s := config.Defaults()
	s.Host = "vpn.example.com"
	s.ACMEEmail = "admin@example.com"
	return s
}

func newHarness(t *testing.T, s config.Settings) *harness {
	t.Helper()
	root := t.TempDir()
	paths := config.DefaultPaths()
	if err := config.Save(filepath.Join(root, paths.Settings()), s); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"ca.crt", "ca.key", "server.crt", "server.key", "crl.pem", render.TLSCryptV2Server} {
		writeFile(t, root, filepath.Join(paths.Data, f), "x")
	}
	writeFile(t, root, "/proc/net/route", "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\neth0\t00000000\t0100000A\t0003\t0\t0\t100\t00000000\t0\t0\t0\neth0\t0000000A\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n")
	writeFile(t, root, "/proc/net/ipv6_route", "00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000001 00000400 00000001 00000000 00000003 eth0\n00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 ffffffff 00000001 00000000 00200200 lo\n")
	writeFile(t, root, "/etc/os-release", "NAME=\"Debian GNU/Linux\"\nPRETTY_NAME=\"Debian GNU/Linux 13 (trixie)\"\n")
	writeFile(t, root, "/etc/fstab", "UUID=1 / ext4 defaults 0 1\n/swapfile none swap sw 0 0\n")
	writeFile(t, root, "/proc/uptime", "12345.67 100.0\n")
	writeFile(t, root, "/proc/loadavg", "0.10 0.20 0.30 1/100 999\n")
	writeFile(t, root, "/proc/meminfo", "MemTotal:        1000 kB\nMemFree:          500 kB\nMemAvailable:     800 kB\n")
	if err := os.MkdirAll(filepath.Join(root, "/etc/ssh/sshd_config.d"), 0o755); err != nil {
		t.Fatal(err)
	}
	h := &harness{r: newFakeRunner(), p: &fakeProbe{}, root: root}
	h.a = &Agent{
		Root:   root,
		Paths:  paths,
		Runner: h.r,
		Probe:  h.p,
		HTTP:   &http.Client{},
		Download: func(ctx context.Context, dir string, client *http.Client) (map[string]int, error) {
			if err := os.WriteFile(filepath.Join(dir, "ads.txt"), []byte("ads.example\n"), 0o644); err != nil {
				return nil, err
			}
			return map[string]int{"ads": 1000, "malware": 200}, nil
		},
		Font: func(context.Context, *http.Client) ([]byte, error) {
			return []byte("font"), nil
		},
		Lookup:        func(string) (int, int, error) { return 990, 990, nil },
		AllowUID:      func(uid uint32) bool { return uid == 0 || uid == uint32(os.Getuid()) },
		Chown:         func(string, int, int) error { return nil },
		Sleep:         func(context.Context, time.Duration) error { return nil },
		HealthTimeout: time.Millisecond,
		VerifyTimeout: time.Millisecond,
	}
	return h
}

func (h *harness) do(op string) (map[string]string, error) {
	return h.a.Do(context.Background(), op, h.emit)
}

func facts() render.Facts {
	return render.Facts{OpenSSLVersion: "3.5.1", OpenVPNVersion: "2.6.19", SSHPorts: []int{22, 2222}, WANIface: "eth0", HasIPv6: true}
}

func TestApplyConverges(t *testing.T) {
	h := newHarness(t, testSettings())
	if _, err := h.do(agentapi.OpApply); err != nil {
		t.Fatal(err, h.events)
	}
	s := testSettings()
	s.Configured = true
	f := facts()
	want := map[string]func() (string, error){
		render.OpenVPNPath(config.InstanceUDP): func() (string, error) { return render.OpenVPN(s, f, config.InstanceUDP) },
		render.OpenVPNPath(config.InstanceTCP): func() (string, error) { return render.OpenVPN(s, f, config.InstanceTCP) },
		render.NFTFile:                         func() (string, error) { return render.NFTables(s, f) },
		render.UnboundFile:                     func() (string, error) { return render.Unbound(s, f) },
		render.CaddyFile:                       func() (string, error) { return render.Caddyfile(s, true) },
		render.SysctlFile:                      func() (string, error) { return render.Sysctl(f) },
		render.UnattendedFile:                  func() (string, error) { return render.Unattended(s) },
		render.JournaldFile:                    func() (string, error) { return render.Journald(), nil },
		render.SSHDFile:                        func() (string, error) { return render.SSHD(), nil },
		render.DNSIfFile:                       func() (string, error) { return render.DNSInterface(), nil },
		render.TmpfilesFile:                    func() (string, error) { return render.Tmpfiles(), nil },
	}
	for p, fn := range want {
		exp, err := fn()
		if err != nil {
			t.Fatal(err)
		}
		if got := readFile(t, h.root, p); got != exp {
			t.Errorf("%s differs:\n%s\nwant\n%s", p, got, exp)
		}
	}
	for _, u := range render.Units() {
		if readFile(t, h.root, u.Path) != u.Data {
			t.Errorf("unit %s differs", u.Path)
		}
	}
	if !strings.Contains(readFile(t, h.root, render.NFTFile), "udp dport 1194 accept") {
		t.Error("udp port not opened")
	}
	if strings.Contains(readFile(t, h.root, "/etc/fstab"), "swap") {
		t.Error("swap left in fstab")
	}
	if dst, err := os.Readlink(filepath.Join(h.root, "/var/log/wtmp")); err != nil || dst != "/dev/null" {
		t.Error("wtmp not linked to /dev/null")
	}
	fi, err := os.Stat(filepath.Join(h.root, config.RunDir))
	if err != nil || fi.Mode()&os.ModeSetgid == 0 || fi.Mode().Perm() != 0o770 {
		t.Errorf("run dir mode %v %v", fi.Mode(), err)
	}
	if fi, _ := os.Stat(filepath.Join(h.root, config.DataDir, render.TLSCryptV2Server)); fi.Mode().Perm() != 0o640 {
		t.Errorf("tls-crypt-v2 mode %v", fi.Mode())
	}
	order := []string{
		"systemctl daemon-reload",
		"sysctl -e -q -p /etc/sysctl.d/99-veyl.conf",
		"sshd -t",
		"nft -c -f /etc/veyl/veyl.nft",
		"systemctl reload-or-restart veyl-firewall.service",
		"systemctl restart veyl-dnsif.service",
		"unbound-checkconf",
		"systemctl restart unbound.service",
		"caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile",
		"systemctl restart caddy.service",
		"systemctl restart openvpn-server@veyl-udp.service",
		"systemctl restart openvpn-server@veyl-tcp.service",
		"systemctl enable veyl-dns.service",
		"ss -H -lntu",
	}
	last := -1
	for _, c := range order {
		i := h.r.index(t, c)
		if i < 0 {
			t.Fatalf("missing %q in\n%s", c, strings.Join(h.r.list(), "\n"))
		}
		if i < last {
			t.Errorf("%q out of order", c)
		}
		last = i
	}
	for _, st := range []string{"firewall", "resolver", "web", "vpn-udp", "vpn-tcp", "verify-ports", "verify-dns", "verify-https"} {
		if h.status(st) != agentapi.StatusOK {
			t.Errorf("step %s = %q", st, h.status(st))
		}
	}
	if h.status("blocklists") != agentapi.StatusOK || readFile(t, h.root, filepath.Join(config.DataDir, "blocklists/ads.txt")) == "" {
		t.Error("blocklists not downloaded")
	}
	for _, c := range h.r.list() {
		if strings.HasPrefix(c, "sh ") || strings.HasPrefix(c, "bash ") {
			t.Errorf("shell used: %s", c)
		}
	}

	h.r.reset()
	if _, err := h.do(agentapi.OpApply); err != nil {
		t.Fatal(err)
	}
	for _, c := range []string{"systemctl restart openvpn-server@veyl-udp.service", "systemctl restart openvpn-server@veyl-tcp.service", "systemctl restart caddy.service", "systemctl restart unbound.service", "systemctl daemon-reload", "systemctl reload-or-restart veyl-firewall.service"} {
		if h.r.count(c) != 0 {
			t.Errorf("second apply ran %q", c)
		}
	}
}

func TestApplyRollsBackCaddy(t *testing.T) {
	h := newHarness(t, testSettings())
	writeFile(t, h.root, render.CaddyFile, "old caddy\n")
	h.r.fail["systemctl restart caddy.service"] = 1
	if _, err := h.do(agentapi.OpApply); err == nil {
		t.Fatal("apply succeeded")
	}
	if got := readFile(t, h.root, render.CaddyFile); got != "old caddy\n" {
		t.Fatalf("caddyfile not restored: %q", got)
	}
	if readFile(t, h.root, render.CaddyFile+".veyl-orig") != "old caddy\n" {
		t.Fatal("original not kept")
	}
	if h.r.count("systemctl restart caddy.service") != 2 {
		t.Fatal("caddy not restarted with previous config")
	}
	if h.status("web") != agentapi.StatusFail || h.status("vpn-udp") != "" {
		t.Fatal("apply continued after failure")
	}
}

func TestApplyFirewallCheckFails(t *testing.T) {
	h := newHarness(t, testSettings())
	writeFile(t, h.root, render.NFTFile, "old rules\n")
	h.r.fail["nft -c -f /etc/veyl/veyl.nft"] = -1
	if _, err := h.do(agentapi.OpApply); err == nil {
		t.Fatal("apply succeeded")
	}
	if readFile(t, h.root, render.NFTFile) != "old rules\n" {
		t.Fatal("ruleset not restored")
	}
	if h.r.count("systemctl reload-or-restart veyl-firewall.service") != 0 {
		t.Fatal("broken ruleset loaded")
	}
}

func TestApplyRollsBackOpenVPN(t *testing.T) {
	h := newHarness(t, testSettings())
	writeFile(t, h.root, render.OpenVPNPath(config.InstanceUDP), "old udp\n")
	h.r.inactive[render.UnitOpenVPNUDP] = true
	h.r.fail["systemctl restart openvpn-server@veyl-udp.service"] = 1
	if _, err := h.do(agentapi.OpApply); err == nil {
		t.Fatal("apply succeeded")
	}
	if readFile(t, h.root, render.OpenVPNPath(config.InstanceUDP)) != "old udp\n" {
		t.Fatal("openvpn config not restored")
	}
	if h.status("vpn-udp") != agentapi.StatusFail {
		t.Fatal(h.events)
	}
}

func TestApplyFirstInstallFailureRemovesNewFile(t *testing.T) {
	h := newHarness(t, testSettings())
	h.r.fail["systemctl restart openvpn-server@veyl-udp.service"] = 1
	if _, err := h.do(agentapi.OpApply); err == nil {
		t.Fatal("apply succeeded")
	}
	if _, err := os.Stat(filepath.Join(h.root, render.OpenVPNPath(config.InstanceUDP))); !os.IsNotExist(err) {
		t.Fatal("broken new config left in place")
	}
}

func TestApplyStealthOff(t *testing.T) {
	s := testSettings()
	s.Stealth = false
	h := newHarness(t, s)
	writeFile(t, h.root, render.OpenVPNPath(config.InstanceTCP), "old tcp\n")
	if _, err := h.do(agentapi.OpApply); err != nil {
		t.Fatal(err, h.events)
	}
	if _, err := os.Stat(filepath.Join(h.root, render.OpenVPNPath(config.InstanceTCP))); !os.IsNotExist(err) {
		t.Fatal("tcp config left")
	}
	stop := h.r.index(t, "systemctl disable --now openvpn-server@veyl-tcp.service")
	caddy := h.r.index(t, "systemctl restart caddy.service")
	if stop < 0 || caddy < 0 || stop > caddy {
		t.Fatal("tcp instance must stop before caddy takes port 443")
	}
	if strings.Contains(readFile(t, h.root, render.CaddyFile), "8443") {
		t.Fatal("caddy still in stealth mode")
	}
	if h.status("vpn-tcp") != agentapi.StatusSkip {
		t.Fatal("tcp not skipped")
	}
}

func TestApplyNeedsHost(t *testing.T) {
	h := newHarness(t, config.Defaults())
	if _, err := h.do(agentapi.OpApply); err == nil {
		t.Fatal("applied without host")
	}
}

func TestApplyVerifyFailures(t *testing.T) {
	h := newHarness(t, testSettings())
	h.r.out["ss -H -lntu"] = "udp UNCONN 0 0 0.0.0.0:1194 0.0.0.0:*\n"
	if _, err := h.do(agentapi.OpApply); err == nil || !strings.Contains(err.Error(), "not listening") {
		t.Fatal(err)
	}
	h = newHarness(t, testSettings())
	h.p.dnsErr = errors.New("timeout")
	if _, err := h.do(agentapi.OpApply); err == nil || h.status("verify-dns") != agentapi.StatusFail {
		t.Fatal(err)
	}
	h = newHarness(t, testSettings())
	h.p.healthErr = errors.New("502")
	if _, err := h.do(agentapi.OpApply); err == nil || h.status("verify-https") != agentapi.StatusFail {
		t.Fatal(err)
	}
}

func TestApplyBlocklistFailureIsSoft(t *testing.T) {
	h := newHarness(t, testSettings())
	h.a.Download = func(context.Context, string, *http.Client) (map[string]int, error) {
		return nil, errors.New("offline")
	}
	if _, err := h.do(agentapi.OpApply); err != nil {
		t.Fatal(err)
	}
	if h.status("blocklists") != agentapi.StatusSkip {
		t.Fatal(h.status("blocklists"))
	}
	h = newHarness(t, testSettings())
	h.a.Download = nil
	saved := DownloadBlocklists
	DownloadBlocklists = nil
	defer func() { DownloadBlocklists = saved }()
	if _, err := h.do(agentapi.OpApply); err != nil || h.status("blocklists") != agentapi.StatusSkip {
		t.Fatal(err)
	}
}

func TestTLS(t *testing.T) {
	h := newHarness(t, testSettings())
	h.r.inactive[render.UnitOpenVPNTCP] = true
	if _, err := h.do(agentapi.OpTLS); err != nil {
		t.Fatal(err)
	}
	c := readFile(t, h.root, render.CaddyFile)
	if strings.Contains(c, "8443") || !strings.Contains(c, "vpn.example.com {") {
		t.Fatalf("tls op must not use stealth while the tcp instance is down:\n%s", c)
	}
	delete(h.r.inactive, render.UnitOpenVPNTCP)
	if _, err := h.do(agentapi.OpTLS); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(readFile(t, h.root, render.CaddyFile), "https_port 8443") {
		t.Fatal("stealth not used with tcp instance active")
	}
	h.p.healthErr = errors.New("no cert")
	if _, err := h.do(agentapi.OpTLS); err == nil || h.status("certificate") != agentapi.StatusFail {
		t.Fatal("health failure not reported")
	}
	h = newHarness(t, config.Defaults())
	if _, err := h.do(agentapi.OpTLS); err == nil {
		t.Fatal("tls without host")
	}
}

func TestDNSUpdate(t *testing.T) {
	h := newHarness(t, testSettings())
	data, err := h.do(agentapi.OpDNSUpdate)
	if err != nil {
		t.Fatal(err)
	}
	if data["blocklist.ads"] != "1000" || data["blocklist.malware"] != "200" {
		t.Fatal(data)
	}
	if h.r.count("systemctl reload veyl-dns.service") != 1 {
		t.Fatal(h.r.list())
	}
	h.a.Download = func(context.Context, string, *http.Client) (map[string]int, error) {
		return nil, errors.New("offline")
	}
	if _, err := h.do(agentapi.OpDNSUpdate); err == nil {
		t.Fatal("download failure hidden")
	}
}

func TestRestart(t *testing.T) {
	h := newHarness(t, testSettings())
	if _, err := h.do(agentapi.OpRestart); err != nil {
		t.Fatal(err)
	}
	if h.r.index(t, "systemctl restart openvpn-server@veyl-tcp.service") < 0 || h.r.index(t, "systemctl restart --no-block veyl.service") != len(h.r.list())-1 {
		t.Fatal(h.r.list())
	}
}

func TestStatus(t *testing.T) {
	h := newHarness(t, testSettings())
	h.r.inactive[render.UnitOpenVPNTCP] = true
	data, err := h.do(agentapi.OpStatus)
	if err != nil {
		t.Fatal(err)
	}
	checks := map[string]string{
		"service.veyl":                    "active",
		"service.openvpn-server@veyl-tcp": "inactive",
		"openvpn":                         "2.6.19",
		"openssl":                         "3.5.1",
		"post_quantum":                    "true",
		"uptime":                          "12345",
		"load":                            "0.10 0.20 0.30",
		"mem_total":                       "1024000",
		"mem_available":                   "819200",
		"public_ipv4":                     "203.0.113.7",
		"cert_expiry":                     "2027-01-01T00:00:00Z",
		"distro":                          "Debian GNU/Linux 13 (trixie)",
	}
	for k, v := range checks {
		if data[k] != v {
			t.Errorf("%s = %q want %q", k, data[k], v)
		}
	}
	if _, ok := data["public_ipv6"]; ok {
		t.Error("ipv6 reported without one")
	}
	if data["disk_total"] == "" {
		t.Error("disk missing")
	}
}

func TestUnknownOp(t *testing.T) {
	h := newHarness(t, testSettings())
	if _, err := h.do("rm"); !errors.Is(err, ErrUnknownOp) {
		t.Fatal(err)
	}
}

func TestBootstrapSetupMode(t *testing.T) {
	h := newHarness(t, config.Defaults())
	if err := h.a.Bootstrap(context.Background(), h.emit, "", ""); err != nil {
		t.Fatal(err, h.events)
	}
	c := readFile(t, h.root, render.CaddyFile)
	if !strings.Contains(c, ":80 {") || strings.Contains(c, "8443") {
		t.Fatal(c)
	}
	nft := readFile(t, h.root, render.NFTFile)
	if strings.Contains(nft, "udp dport 1194") || !strings.Contains(nft, "tcp dport { 22, 2222 } accept") {
		t.Fatal(nft)
	}
	if h.r.index(t, "systemctl enable --now veyl-agent.service veyl.service veyl-blocklists.timer") < 0 {
		t.Fatal(h.r.list())
	}
	if h.r.count("systemctl restart openvpn-server@veyl-udp.service") != 0 {
		t.Fatal("openvpn started in setup mode")
	}
}

func TestBootstrapDomain(t *testing.T) {
	h := newHarness(t, config.Defaults())
	if err := h.a.Bootstrap(context.Background(), h.emit, "VPN.Example.com", "me@example.com"); err != nil {
		t.Fatal(err)
	}
	s, err := config.Load(filepath.Join(h.root, config.DefaultPaths().Settings()))
	if err != nil || s.Host != "vpn.example.com" || s.ACMEEmail != "me@example.com" || s.Configured {
		t.Fatal(s, err)
	}
	if !strings.Contains(readFile(t, h.root, render.CaddyFile), "vpn.example.com {") {
		t.Fatal("domain site not deployed")
	}
	h = newHarness(t, config.Defaults())
	h.p.healthErr = errors.New("dns not pointing here")
	if err := h.a.Bootstrap(context.Background(), h.emit, "vpn.example.com", ""); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(readFile(t, h.root, render.CaddyFile), ":80 {") || h.status("https") != agentapi.StatusSkip {
		t.Fatal("did not fall back to setup mode")
	}
	h = newHarness(t, config.Defaults())
	if err := h.a.Bootstrap(context.Background(), h.emit, "bad host\n", ""); err == nil {
		t.Fatal("accepted bad domain")
	}
}

func TestBootstrapConfiguredApplies(t *testing.T) {
	s := testSettings()
	s.Configured = true
	h := newHarness(t, s)
	if err := h.a.Bootstrap(context.Background(), h.emit, "", ""); err != nil {
		t.Fatal(err)
	}
	if h.r.count("systemctl restart openvpn-server@veyl-udp.service") != 1 {
		t.Fatal("repair did not converge")
	}
}

func TestUninstall(t *testing.T) {
	h := newHarness(t, testSettings())
	writeFile(t, h.root, render.CaddyFile, "distro default\n")
	if _, err := h.do(agentapi.OpApply); err != nil {
		t.Fatal(err)
	}
	if err := h.a.Uninstall(context.Background(), h.emit, false); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{render.NFTFile, render.UnboundFile, render.OpenVPNPath(config.InstanceUDP), render.SysctlFile, filepath.Join(render.UnitDir, render.UnitVeyl)} {
		if _, err := os.Stat(filepath.Join(h.root, p)); !os.IsNotExist(err) {
			t.Errorf("%s left behind", p)
		}
	}
	if readFile(t, h.root, render.CaddyFile) != "distro default\n" {
		t.Error("caddyfile not restored")
	}
	for _, c := range []string{"nft delete table inet veyl", "nft delete table ip veyl_nat", "nft delete table ip6 veyl_nat6", "userdel veyl-ovpn", "userdel veyl"} {
		if h.r.index(t, c) < 0 {
			t.Errorf("missing %q", c)
		}
	}
	if h.r.index(t, "nft flush ruleset") >= 0 {
		t.Error("flushed ruleset")
	}
	if _, err := os.Stat(filepath.Join(h.root, config.DataDir, "ca.key")); err != nil {
		t.Error("data removed without purge")
	}
	if err := h.a.Uninstall(context.Background(), h.emit, true); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(h.root, config.DataDir)); !os.IsNotExist(err) {
		t.Error("purge kept data")
	}
}

func TestUpdateArgs(t *testing.T) {
	argv, err := UpdateArgs("main")
	if err != nil || strings.Join(argv, " ") != "/bin/bash /opt/veyl/src/install.sh --yes --branch main" {
		t.Fatal(argv, err)
	}
	for _, b := range []string{"--force", "a b", "x;rm", "$(id)"} {
		if _, err := UpdateArgs(b); err == nil {
			t.Errorf("accepted %q", b)
		}
	}
}

func TestDisplayAliases(t *testing.T) {
	d := map[string]string{
		"service.veyl":     "active",
		"public_ipv4":      "203.0.113.5",
		"distro":           "Debian GNU/Linux 13 (trixie)",
		"mem_memtotal":     "1073741824",
		"mem_memavailable": "536870912",
		"disk_total":       "21474836480",
		"disk_free":        "10737418240",
	}
	displayAliases(d)
	want := map[string]string{
		"svc.veyl":  "active",
		"public_ip": "203.0.113.5",
		"os":        "Debian GNU/Linux 13 (trixie)",
		"ram_mb":    "1024",
		"mem":       "512.0 MB used of 1.0 GB",
		"disk":      "10.0 GB free of 20.0 GB",
	}
	for k, v := range want {
		if d[k] != v {
			t.Errorf("%s = %q, want %q", k, d[k], v)
		}
	}
}

func TestFontsStep(t *testing.T) {
	h := newHarness(t, testSettings())
	calls := 0
	h.a.Font = func(context.Context, *http.Client) ([]byte, error) {
		calls++
		return []byte("font-bytes"), nil
	}
	if _, err := h.do(agentapi.OpApply); err != nil {
		t.Fatal(err)
	}
	if h.status("fonts") != agentapi.StatusOK || readFile(t, h.root, web.FontPath(config.DataDir)) != "font-bytes" || calls != 1 {
		t.Fatal(h.status("fonts"), calls)
	}
	fi, err := os.Stat(filepath.Join(h.root, web.FontPath(config.DataDir)))
	if err != nil || fi.Mode().Perm() != 0o644 {
		t.Fatal(fi, err)
	}
	h2 := newHarness(t, testSettings())
	h2.a.Font = func(context.Context, *http.Client) ([]byte, error) { return nil, web.ErrFontChecksum }
	if _, err := h2.do(agentapi.OpApply); err != nil {
		t.Fatal("font failure must not fail apply", err)
	}
	if h2.status("fonts") != agentapi.StatusSkip {
		t.Fatal(h2.status("fonts"))
	}
	h3 := newHarness(t, config.Defaults())
	h3.a.Font = func(context.Context, *http.Client) ([]byte, error) { return []byte("f"), nil }
	if err := h3.a.Bootstrap(context.Background(), h3.emit, "", ""); err != nil {
		t.Fatal(err)
	}
	if h3.status("fonts") != agentapi.StatusOK {
		t.Fatal(h3.status("fonts"))
	}
}
