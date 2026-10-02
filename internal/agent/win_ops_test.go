package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/veylvpn/backend/internal/agentapi"
	"github.com/veylvpn/backend/internal/config"
	"github.com/veylvpn/backend/internal/render"
	"github.com/veylvpn/backend/internal/winps"
)

const scQueryRunning = "\r\nSERVICE_NAME: %s\r\n        TYPE               : 10  WIN32_OWN_PROCESS\r\n        STATE              : %d  %s\r\n                                (STOPPABLE, NOT_PAUSABLE, ACCEPTS_SHUTDOWN)\r\n        WIN32_EXIT_CODE    : 0  (0x0)\r\n"

type winFake struct {
	mu       sync.Mutex
	root     string
	calls    []string
	scripts  []string
	services map[string]int
	adapters map[string]string
	fail     map[string]int
	stuck    map[string]bool
	ports    []string
}

func newWinFake(root string) *winFake {
	return &winFake{
		root:     root,
		services: map[string]int{"mpssvc": 4},
		adapters: map[string]string{},
		fail:     map[string]int{},
		stuck:    map[string]bool{},
		ports: []string{
			"udp 0.0.0.0 1194", "tcp 0.0.0.0 80", "tcp :: 443", "tcp 0.0.0.0 993", "tcp 127.0.0.1 8080",
			"udp 127.0.0.1 5335", "tcp 127.0.0.1 5335", "udp 10.64.0.1 53", "tcp 10.64.0.1 53",
			"tcp 127.0.0.1 7505", "tcp 127.0.0.1 7506", "tcp 0.0.0.0 3389",
		},
	}
}

func (f *winFake) failing(key string) bool {
	for k, n := range f.fail {
		if n != 0 && strings.Contains(key, k) {
			if n > 0 {
				f.fail[k] = n - 1
			}
			return true
		}
	}
	return false
}

func scName(n int) string {
	return map[int]string{1: "STOPPED", 2: "START_PENDING", 3: "STOP_PENDING", 4: "RUNNING"}[n]
}

func (f *winFake) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !validCommand(name) {
		return nil, errors.New("invalid command")
	}
	if name == config.WinPowerShell {
		if len(args) != 6 || strings.Join(args[:5], " ") != strings.Join(winps.Flags, " ") {
			return nil, fmt.Errorf("bad powershell argv %q", args)
		}
		body := args[5]
		if strings.ContainsAny(body, "\"\x00") || !strings.HasPrefix(body, "$ErrorActionPreference = 'Stop'") {
			return nil, errors.New("unsafe script")
		}
		f.scripts = append(f.scripts, body)
		f.calls = append(f.calls, "powershell")
		if f.failing(body) {
			return []byte("New-NetNat : boom"), errors.New("exit status 1")
		}
		switch {
		case strings.Contains(body, "Get-NetAdapter -Name"):
			for n, d := range f.adapters {
				if strings.Contains(body, "'"+n+"'") {
					return []byte("adapter=" + d + "\r\n"), nil
				}
			}
			return nil, nil
		case strings.Contains(body, "Get-NetRoute"):
			return []byte("wan=6\r\nos=Microsoft Windows Server 2022 Datacenter\r\n"), nil
		case strings.Contains(body, "Get-NetTCPConnection"):
			return []byte(strings.Join(f.ports, "\r\n") + "\r\n"), nil
		case strings.Contains(body, "LastBootUpTime"):
			return []byte("os=Microsoft Windows Server 2022 Datacenter 10.0.20348\r\nuptime=3600\r\nmem_total=4294967296\r\nmem_avail=2147483648\r\ndisk_total=137438953472\r\ndisk_free=68719476736\r\nfirewall=7\r\n"), nil
		case strings.Contains(body, "New-NetNat"):
			return []byte("nat created\r\n"), nil
		}
		return nil, nil
	}
	cmd := strings.TrimSpace(name + " " + strings.Join(args, " "))
	f.calls = append(f.calls, cmd)
	if f.failing(cmd) {
		return []byte("boom"), errors.New("exit status 1")
	}
	switch name {
	case config.WinSC:
		svc := ""
		if len(args) > 1 {
			svc = args[1]
		}
		st, ok := f.services[svc]
		missing := []byte("[SC] OpenService FAILED 1060:\r\n\r\nThe specified service does not exist as an installed service.\r\n")
		switch args[0] {
		case "query":
			if !ok {
				return missing, errors.New("exit status 1060")
			}
			return []byte(fmt.Sprintf(scQueryRunning, svc, st, scName(st))), nil
		case "create":
			if ok {
				return []byte("[SC] CreateService FAILED 1073"), errors.New("exit status 1073")
			}
			f.services[svc] = 1
		case "config", "description", "failure", "failureflag", "sidtype":
			if !ok {
				return missing, errors.New("exit status 1060")
			}
		case "start":
			if !ok {
				return missing, errors.New("exit status 1060")
			}
			if st == 4 {
				return []byte("[SC] StartService FAILED 1056:\r\n\r\nAn instance of the service is already running.\r\n"), errors.New("exit status 1056")
			}
			if !f.stuck[svc] {
				f.services[svc] = 4
			}
		case "stop":
			if !ok {
				return missing, errors.New("exit status 1060")
			}
			if st != 4 {
				return []byte("[SC] ControlService FAILED 1062:\r\n\r\nThe service has not been started.\r\n"), errors.New("exit status 1062")
			}
			f.services[svc] = 1
		case "delete":
			delete(f.services, svc)
		}
	case config.WinTapctl:
		if len(args) == 5 && args[0] == "create" && args[1] == "--name" && args[3] == "--hwid" && args[4] == config.TapHWID {
			f.adapters[args[2]] = "TAP-Windows Adapter V9"
		}
		if len(args) == 2 && args[0] == "delete" {
			delete(f.adapters, args[1])
		}
	case config.WinOpenVPNBin:
		if len(args) == 1 && args[0] == "--version" {
			return []byte("OpenVPN 2.7.7 [git:v2.7.7/1a2b] Windows [SSL (OpenSSL)] [LZO] [LZ4] [PKCS11] [AEAD] built on Sep 30 2026\r\nlibrary versions: OpenSSL 3.6.3 30 Sep 2026, LZO 2.10\r\n"), nil
		}
		if len(args) == 3 && args[0] == "--genkey" {
			p := (&Agent{Root: f.root}).path(args[2])
			if err := os.WriteFile(p, []byte("-----BEGIN OpenVPN tls-crypt-v2 server key-----\n"), 0o600); err != nil {
				return nil, err
			}
		}
	}
	return nil, nil
}

func (f *winFake) list() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

func (f *winFake) allScripts() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.scripts...)
}

func (f *winFake) reset() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = nil
	f.scripts = nil
}

func (f *winFake) has(cmd string) bool {
	for _, c := range f.list() {
		if c == cmd {
			return true
		}
	}
	return false
}

func (f *winFake) index(cmd string) int {
	for i, c := range f.list() {
		if c == cmd {
			return i
		}
	}
	return -1
}

func (f *winFake) ranScript(t *testing.T, script string) {
	t.Helper()
	want, err := winps.Command(script)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range f.allScripts() {
		if s == want[5] {
			return
		}
	}
	t.Fatalf("script not run:\n%s", script)
}

type winProbe struct {
	healthErr error
}

func (p *winProbe) DNS(ctx context.Context, server, name string) error { return nil }
func (p *winProbe) Health(ctx context.Context, host string, insecure bool) error {
	return p.healthErr
}
func (p *winProbe) PublicIP(ctx context.Context, v6 bool) (string, error) {
	if v6 {
		return "", errors.New("none")
	}
	return "203.0.113.7", nil
}
func (p *winProbe) CertExpiry(ctx context.Context, host string) (time.Time, error) {
	return time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC), nil
}

func winAgent(t *testing.T, mutate func(*config.Settings)) (*Agent, *winFake) {
	t.Helper()
	root := t.TempDir()
	f := newWinFake(root)
	a := &Agent{
		Root:          root,
		Paths:         config.WindowsPaths(),
		Runner:        f,
		Probe:         &winProbe{},
		Windows:       true,
		Sleep:         func(ctx context.Context, d time.Duration) error { return ctx.Err() },
		Async:         func(fn func()) { fn() },
		MgmtState:     func(string) (string, error) { return "CONNECTED", nil },
		HealthTimeout: time.Millisecond,
		VerifyTimeout: time.Millisecond,
		Download: func(ctx context.Context, dir string, c *http.Client) (map[string]int, error) {
			if err := os.MkdirAll(dir, 0o755); err != nil {
				return nil, err
			}
			return map[string]int{"ads": 1200}, os.WriteFile(dir+"/ads.txt", []byte("ads.example\n"), 0o644)
		},
	}
	s := config.Defaults()
	s.Configured = true
	s.Host = "vpn.example.com"
	if mutate != nil {
		mutate(&s)
	}
	if err := config.Save(a.path(a.Paths.Settings()), s); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"ca.crt", "ca.key", "server.crt", "server.key", "crl.pem"} {
		if err := os.WriteFile(a.path(config.Join(a.Paths.Data, n)), []byte(n), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	key := a.path(config.Join(config.WinUnboundDir, "root.key"))
	if err := os.MkdirAll(filepath.Dir(key), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(key, []byte(". IN DS 20326 8 2 E06D44B8"), 0o644); err != nil {
		t.Fatal(err)
	}
	return a, f
}

func collect() (Emit, func() []agentapi.Event) {
	var mu sync.Mutex
	var evs []agentapi.Event
	return func(e agentapi.Event) {
			mu.Lock()
			evs = append(evs, e)
			mu.Unlock()
		}, func() []agentapi.Event {
			mu.Lock()
			defer mu.Unlock()
			return append([]agentapi.Event(nil), evs...)
		}
}

func stepStatus(evs []agentapi.Event) map[string]string {
	m := map[string]string{}
	for _, e := range evs {
		if e.Status != agentapi.StatusRun {
			m[e.Step] = e.Status
		}
	}
	return m
}

func winRead(t *testing.T, a *Agent, p string) string {
	t.Helper()
	b, err := os.ReadFile(a.path(p))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestWinApplyConverges(t *testing.T) {
	a, f := winAgent(t, nil)
	emit, events := collect()
	if _, err := a.Do(context.Background(), agentapi.OpApply, emit); err != nil {
		t.Fatalf("%v %v", err, events())
	}
	st := stepStatus(events())
	for _, s := range []string{"settings", "system", "services", "directories", "certificates", "adapters", "network", "firewall", "resolver", "blocklists", "web", "vpn-udp", "vpn-tcp", "dns-filter", "services-start", "verify-ports", "verify-dns"} {
		if st[s] != agentapi.StatusOK {
			t.Errorf("step %s = %q", s, st[s])
		}
	}
	for _, s := range []string{"updates", "stealth-off", "fonts"} {
		if st[s] != agentapi.StatusSkip {
			t.Errorf("step %s = %q", s, st[s])
		}
	}
	veyl, _ := render.FindWinService(config.WinServiceVeyl)
	bin, _ := veyl.BinPath()
	want := strings.Join([]string{config.WinSC, "create", "Veyl", "binPath=", bin, "start=", "delayed-auto", "obj=", `NT SERVICE\Veyl`, "DisplayName=", "Veyl server", "type=", "own"}, " ")
	if !f.has(want) {
		t.Fatalf("missing %s in %q", want, f.list())
	}
	for _, svc := range render.WinServices() {
		for _, c := range []string{
			config.WinSC + " failure " + svc.Name + " reset= 86400 actions= restart/5000/restart/10000/restart/30000",
			config.WinSC + " failureflag " + svc.Name + " 1",
			config.WinSC + " sidtype " + svc.Name + " unrestricted",
		} {
			if !f.has(c) {
				t.Errorf("missing %s", c)
			}
		}
	}
	for _, d := range render.WinDirs() {
		found := false
		for _, c := range f.list() {
			found = found || strings.HasPrefix(c, config.WinIcacls+" "+d+" /inheritance:r ")
		}
		if !found {
			t.Errorf("no acl for %s", d)
		}
	}
	for _, n := range []string{config.TapUDP, config.TapTCP} {
		if !f.has(config.WinTapctl + " create --name " + n + " --hwid " + config.TapHWID) {
			t.Errorf("adapter %s not created", n)
		}
	}
	s, _ := a.settings()
	s.Configured = true
	wf := render.WinFacts{OpenVPNVersion: "2.7.7", OpenSSLVersion: "3.6.3", WANIndex: 6, OS: "Microsoft Windows Server 2022 Datacenter"}
	for _, in := range []string{config.InstanceUDP, config.InstanceTCP} {
		want, _ := render.WinOpenVPN(s, wf, in)
		if got := winRead(t, a, render.WinOpenVPNPath(in)); got != want {
			t.Errorf("%s config differs", in)
		}
		pw := winRead(t, a, a.Paths.MgmtPassword(in))
		if len(strings.TrimSpace(pw)) != 43 {
			t.Errorf("management password %q", pw)
		}
	}
	ub, _ := render.WinUnbound(s)
	cf, _ := render.WinCaddyfile(s)
	if winRead(t, a, render.WinUnboundPath()) != ub || winRead(t, a, render.WinCaddyfilePath()) != cf {
		t.Fatal("resolver or web config differs")
	}
	if winRead(t, a, render.WinUnboundAnchor()) == "" {
		t.Fatal("root key not seeded")
	}
	fw, _ := render.WinFirewallScript(s)
	nw, _ := render.WinNetworkScript(wf)
	f.ranScript(t, fw)
	f.ranScript(t, nw)
	for _, svc := range []string{config.WinServiceUnbnd, config.WinServiceCaddy, config.WinServiceUDP, config.WinServiceTCP, config.WinServiceDNS, config.WinServiceAgent, config.WinServiceVeyl} {
		if f.services[svc] != 4 {
			t.Errorf("%s not running", svc)
		}
	}
	if f.index(config.WinSC+" start "+config.WinServiceUnbnd) > f.index(config.WinSC+" start "+config.WinServiceUDP) {
		t.Error("resolver must start before the VPN")
	}
	if f.index(config.WinOpenVPNBin+" --genkey tls-crypt-v2-server "+config.Join(a.Paths.Data, render.TLSCryptV2Server)) < 0 {
		t.Error("tls-crypt-v2 key not generated")
	}

	f.reset()
	emit2, events2 := collect()
	if _, err := a.Do(context.Background(), agentapi.OpApply, emit2); err != nil {
		t.Fatalf("%v %v", err, events2())
	}
	for _, c := range f.list() {
		if strings.Contains(c, " create ") || strings.HasPrefix(c, config.WinSC+" stop "+config.WinServiceUDP) || strings.HasPrefix(c, config.WinSC+" stop "+config.WinServiceCaddy) {
			t.Errorf("second apply was not idempotent: %s", c)
		}
	}
	st2 := stepStatus(events2())
	if st2["vpn-udp"] != agentapi.StatusOK {
		t.Fatal(st2)
	}
}

func TestWinApplyRollsBackCaddy(t *testing.T) {
	a, f := winAgent(t, nil)
	if _, err := a.Do(context.Background(), agentapi.OpApply, nil); err != nil {
		t.Fatal(err)
	}
	before := winRead(t, a, render.WinCaddyfilePath())
	s, _ := a.settings()
	s.ACMEEmail = "ops@example.com"
	if err := config.Save(a.path(a.Paths.Settings()), s); err != nil {
		t.Fatal(err)
	}
	f.fail[config.WinCaddyBin+" validate"] = 1
	emit, events := collect()
	_, err := a.Do(context.Background(), agentapi.OpApply, emit)
	if err == nil || !strings.Contains(err.Error(), "previous configuration kept") {
		t.Fatalf("%v %v", err, events())
	}
	if winRead(t, a, render.WinCaddyfilePath()) != before {
		t.Fatal("caddyfile not rolled back")
	}
}

func TestWinApplyRestoresOpenVPNWhenItWillNotStart(t *testing.T) {
	a, f := winAgent(t, nil)
	if _, err := a.Do(context.Background(), agentapi.OpApply, nil); err != nil {
		t.Fatal(err)
	}
	before := winRead(t, a, render.WinOpenVPNPath(config.InstanceUDP))
	s, _ := a.settings()
	s.UDPPort = 1195
	if err := config.Save(a.path(a.Paths.Settings()), s); err != nil {
		t.Fatal(err)
	}
	f.fail[config.WinSC+" start "+config.WinServiceUDP] = 1
	_, err := a.Do(context.Background(), agentapi.OpApply, nil)
	if err == nil || !strings.Contains(err.Error(), "previous configuration restored") {
		t.Fatal(err)
	}
	if winRead(t, a, render.WinOpenVPNPath(config.InstanceUDP)) != before {
		t.Fatal("openvpn config not restored")
	}
	if f.services[config.WinServiceUDP] != 4 {
		t.Fatal("previous openvpn not restarted")
	}
}

func TestWinStealthOff(t *testing.T) {
	a, f := winAgent(t, func(s *config.Settings) { s.Stealth = false })
	f.services[config.WinServiceTCP] = 4
	emit, events := collect()
	if _, err := a.Do(context.Background(), agentapi.OpApply, emit); err != nil {
		t.Fatalf("%v %v", err, events())
	}
	st := stepStatus(events())
	if st["stealth-off"] != agentapi.StatusOK || st["vpn-tcp"] != agentapi.StatusSkip {
		t.Fatal(st)
	}
	tcp, _ := render.FindWinService(config.WinServiceTCP)
	bin, _ := tcp.BinPath()
	if !f.has(strings.Join([]string{config.WinSC, "config", tcp.Name, "binPath=", bin, "start=", "disabled", "obj=", "LocalSystem", "DisplayName=", tcp.Display}, " ")) {
		t.Fatalf("tcp service not disabled: %q", f.list())
	}
	if f.services[config.WinServiceTCP] != 1 || a.exists(render.WinOpenVPNPath(config.InstanceTCP)) {
		t.Fatal("tcp instance still present")
	}
	if f.has(config.WinTapctl + " create --name " + config.TapTCP + " --hwid " + config.TapHWID) {
		t.Fatal("tcp adapter created without stealth")
	}
	for _, sc := range f.allScripts() {
		if strings.Contains(sc, "Veyl-VPN-TCP") {
			t.Fatal("tcp firewall rule without stealth")
		}
	}
}

func TestWinAdapterOfWrongTypeIsRefused(t *testing.T) {
	a, f := winAgent(t, nil)
	f.adapters[config.TapUDP] = "OpenVPN Data Channel Offload"
	_, err := a.Do(context.Background(), agentapi.OpApply, nil)
	if err == nil || !strings.Contains(err.Error(), "not a TAP-Windows adapter") {
		t.Fatal(err)
	}
}

func TestWinApplyNATFailureStops(t *testing.T) {
	a, f := winAgent(t, nil)
	f.fail["New-NetNat"] = -1
	emit, events := collect()
	_, err := a.Do(context.Background(), agentapi.OpApply, emit)
	if err == nil || stepStatus(events())["network"] != agentapi.StatusFail {
		t.Fatalf("%v %v", err, events())
	}
	if f.has(config.WinSC + " start " + config.WinServiceUDP) {
		t.Fatal("vpn started without nat")
	}
}

func TestWinVerifyPortsReportsMissing(t *testing.T) {
	a, f := winAgent(t, nil)
	f.ports = f.ports[:3]
	_, err := a.Do(context.Background(), agentapi.OpApply, nil)
	if err == nil || !strings.Contains(err.Error(), "not listening") || !strings.Contains(err.Error(), "udp 10.64.0.1:53") {
		t.Fatal(err)
	}
}

func TestWinStatusKeys(t *testing.T) {
	a, _ := winAgent(t, nil)
	data, err := a.Do(context.Background(), agentapi.OpStatus, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"svc.veyl", "svc.veyl-agent", "svc.veyl-dns", "svc.openvpn-server@veyl-udp", "svc.openvpn-server@veyl-tcp", "svc.unbound", "svc.caddy", "svc.veyl-firewall", "svc.nftables", "public_ip", "os", "ram_mb", "mem", "disk", "uptime", "openvpn", "openssl", "post_quantum", "platform", "cert_expiry", "host"} {
		if data[k] == "" {
			t.Errorf("missing %s", k)
		}
	}
	if data["platform"] != "windows" || data["openvpn"] != "2.7.7" || data["openssl"] != "3.6.3" || data["post_quantum"] != "true" || data["ram_mb"] != "4096" || data["svc.veyl-firewall"] != "active" || data["svc.nftables"] != "active" || data["svc.veyl"] != "inactive" || data["stealth_port"] != "993" {
		keys := make([]string, 0, len(data))
		for k, v := range data {
			keys = append(keys, k+"="+v)
		}
		sort.Strings(keys)
		t.Fatal(keys)
	}
}

func TestWinBootstrapSetupMode(t *testing.T) {
	a, f := winAgent(t, func(s *config.Settings) { s.Configured = false; s.Host = "" })
	emit, events := collect()
	if err := a.Bootstrap(context.Background(), emit, "", ""); err != nil {
		t.Fatalf("%v %v", err, events())
	}
	cf := winRead(t, a, render.WinCaddyfilePath())
	if !strings.Contains(cf, ":80 {") || f.services[config.WinServiceVeyl] != 4 || f.services[config.WinServiceAgent] != 4 || f.services[config.WinServiceCaddy] != 4 {
		t.Fatalf("%s %v", cf, f.services)
	}
	if f.services[config.WinServiceUDP] == 4 {
		t.Fatal("vpn started before setup")
	}
}

func TestWinBootstrapDomainFallsBackToHTTP(t *testing.T) {
	a, _ := winAgent(t, func(s *config.Settings) { s.Configured = false; s.Host = "" })
	a.Probe = &winProbe{healthErr: errors.New("no certificate yet")}
	emit, events := collect()
	if err := a.Bootstrap(context.Background(), emit, "vpn.example.org", "ops@example.org"); err != nil {
		t.Fatal(err)
	}
	if stepStatus(events())["https"] != agentapi.StatusSkip || !strings.Contains(winRead(t, a, render.WinCaddyfilePath()), ":80 {") {
		t.Fatal(events())
	}
	s, _ := a.settings()
	if s.Host != "vpn.example.org" || s.ACMEEmail != "ops@example.org" {
		t.Fatal(s)
	}
}

func TestWinRestartTLSAndDNSUpdate(t *testing.T) {
	a, f := winAgent(t, nil)
	if _, err := a.Do(context.Background(), agentapi.OpApply, nil); err != nil {
		t.Fatal(err)
	}
	f.reset()
	if _, err := a.Do(context.Background(), agentapi.OpRestart, nil); err != nil {
		t.Fatal(err)
	}
	order := []string{config.WinServiceUnbnd, config.WinServiceDNS, config.WinServiceUDP, config.WinServiceTCP, config.WinServiceCaddy, config.WinServiceVeyl}
	last := -1
	for _, n := range order {
		i := f.index(config.WinSC + " start " + n)
		if i <= last {
			t.Fatalf("restart order wrong at %s: %q", n, f.list())
		}
		last = i
	}
	f.reset()
	data, err := a.Do(context.Background(), agentapi.OpDNSUpdate, nil)
	if err != nil || data["blocklist.ads"] != "1200" || !f.has(config.WinSC+" start "+config.WinServiceDNS) {
		t.Fatal(data, err)
	}
	f.reset()
	if _, err := a.Do(context.Background(), agentapi.OpTLS, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Do(context.Background(), "rm -rf", nil); err != ErrUnknownOp {
		t.Fatal(err)
	}
}

func TestWinServiceThatWillNotStart(t *testing.T) {
	a, f := winAgent(t, nil)
	f.stuck[config.WinServiceUnbnd] = true
	_, err := a.Do(context.Background(), agentapi.OpApply, nil)
	if err == nil || !strings.Contains(err.Error(), config.WinServiceUnbnd) {
		t.Fatal(err)
	}
}

func TestWinUninstall(t *testing.T) {
	a, f := winAgent(t, nil)
	if _, err := a.Do(context.Background(), agentapi.OpApply, nil); err != nil {
		t.Fatal(err)
	}
	f.reset()
	if err := a.Uninstall(context.Background(), nil, false); err != nil {
		t.Fatal(err)
	}
	for _, svc := range render.WinServices() {
		if _, ok := f.services[svc.Name]; ok {
			t.Errorf("%s still installed", svc.Name)
		}
	}
	if f.index(config.WinSC+" delete "+config.WinServiceAgent) < f.index(config.WinSC+" delete "+config.WinServiceVeyl) {
		t.Fatal("agent must be removed last")
	}
	f.ranScript(t, render.WinUninstallScript())
	if len(f.adapters) != 0 || a.exists(config.WinConfDir) || !a.exists(a.Paths.Settings()) {
		t.Fatal("uninstall left adapters or config, or removed data")
	}
	if err := a.Uninstall(context.Background(), nil, true); err != nil {
		t.Fatal(err)
	}
	if a.exists(a.Paths.Settings()) {
		t.Fatal("purge kept data")
	}
	if mpssvc := f.services["mpssvc"]; mpssvc != 4 {
		t.Fatal("uninstall touched the Windows firewall service")
	}
}

func TestWinPowerShellRefusesUnsafeScripts(t *testing.T) {
	a, f := winAgent(t, nil)
	a.init()
	for _, bad := range []string{"Write-Output \"$(calc)\"", "a\x00b", ""} {
		if _, err := a.ps(context.Background(), quick, bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	if len(f.list()) != 0 {
		t.Fatal("runner called for an unsafe script")
	}
}

func TestWinSettingsInjectionNeverReachesScripts(t *testing.T) {
	a, f := winAgent(t, nil)
	raw := `{"version":1,"configured":true,"name":"x","host":"vpn.example.com'; Remove-Item C:\\ -Recurse; '","tls":"acme","udp_port":1194,"registration":"invite","device_limit":5,"dns":{"default":[],"upstream":"recursive"}}`
	if err := os.WriteFile(a.path(a.Paths.Settings()), []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Do(context.Background(), agentapi.OpApply, nil); err == nil {
		t.Fatal("hostile settings applied")
	}
	for _, s := range f.allScripts() {
		if strings.Contains(s, "Remove-Item") {
			t.Fatal("hostile value reached powershell")
		}
	}
}

func TestParseSCStateAndListeners(t *testing.T) {
	if n, ok := parseSCState(fmt.Sprintf(scQueryRunning, "Veyl", 4, "RUNNING")); !ok || n != 4 {
		t.Fatal(n, ok)
	}
	for _, bad := range []string{"", "STATE : x", "STATE              : 99  WHAT", "NOTSTATE : 4 RUNNING"} {
		if _, ok := parseSCState(bad); ok {
			t.Errorf("parsed %q", bad)
		}
	}
	ls := parseWinListeners("tcp 0.0.0.0 443\r\nudp :: 1194\r\nudp fe80::1%5 53\r\ntcp x\r\ntcp 1.2.3.4 99999\r\n")
	if len(ls) != 3 || !matches(ls, expect{"udp", "", 1194}) || !matches(ls, expect{"tcp", "", 443}) || ls[2].addr != "fe80::1" {
		t.Fatal(ls)
	}
	kv := parseKV("os=Windows <script>\"\r\nbad\r\n=x\r\nwan=6\r\n")
	if kv["wan"] != "6" || cleanText(kv["os"]) != "Windows script" {
		t.Fatal(kv)
	}
}

func TestWinUpdateArgs(t *testing.T) {
	old := config.Platform
	config.Platform = config.PlatformWindows
	defer func() { config.Platform = old }()
	argv, err := UpdateArgs("main")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{config.WinPowerShell, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", config.WinInstaller, "-Yes", "-Branch", "main"}
	if strings.Join(argv, "|") != strings.Join(want, "|") {
		t.Fatalf("%q", argv)
	}
	for _, bad := range []string{"-Uninstall", "main; calc", "x y", "a'b", strings.Repeat("a", 101)} {
		if _, err := UpdateArgs(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestWinFontDownload(t *testing.T) {
	body := []byte("wOF2 fake font bytes")
	sum := sha256.Sum256(body)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(body) }))
	defer srv.Close()
	a, _ := winAgent(t, nil)
	a.init()
	a.HTTP = srv.Client()
	oldURL, oldSum := FontURL, FontSHA256
	defer func() { FontURL, FontSHA256 = oldURL, oldSum }()
	FontURL, FontSHA256 = "", ""
	if _, err := a.winFont(context.Background()); !errors.Is(err, errSkip) {
		t.Fatal(err)
	}
	FontURL, FontSHA256 = srv.URL+"/Satoshi-Variable.woff2", hex.EncodeToString(sum[:])
	if d, err := a.winFont(context.Background()); err != nil || d != "installed" {
		t.Fatal(d, err)
	}
	if d, err := a.winFont(context.Background()); err != nil || d != "present" {
		t.Fatal(d, err)
	}
	if err := os.Remove(a.path(config.Join(a.Paths.Fonts(), fontFile))); err != nil {
		t.Fatal(err)
	}
	FontSHA256 = strings.Repeat("0", 64)
	if _, err := a.winFont(context.Background()); err == nil || errors.Is(err, errSkip) {
		t.Fatal("checksum mismatch accepted")
	}
	FontURL = "http://example.com/x"
	if _, err := a.winFont(context.Background()); err == nil {
		t.Fatal("plain http accepted")
	}
}

func TestWinDNSFilterWaitsForTunnel(t *testing.T) {
	a, f := winAgent(t, nil)
	up := false
	a.MgmtState = func(inst string) (string, error) {
		if inst != config.InstanceUDP {
			t.Errorf("asked %s", inst)
		}
		if up {
			return "CONNECTED", nil
		}
		return "ASSIGN_IP", nil
	}
	_, err := a.Do(context.Background(), agentapi.OpApply, nil)
	if err == nil || !strings.Contains(err.Error(), "did not finish starting") {
		t.Fatal(err)
	}
	if f.has(config.WinSC + " start " + config.WinServiceDNS) {
		t.Fatal("dns filter started before the tunnel addresses exist")
	}
	up = true
	f.reset()
	if _, err := a.Do(context.Background(), agentapi.OpApply, nil); err != nil {
		t.Fatal(err)
	}
	tap, _ := render.WinTapScript(config.InstanceUDP)
	f.ranScript(t, tap)
}
