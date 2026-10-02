package render

import (
	"errors"
	"strings"
	"testing"

	"github.com/veylvpn/backend/internal/config"
	"github.com/veylvpn/backend/internal/winps"
)

func winFacts() WinFacts {
	return WinFacts{OpenVPNVersion: "2.7.7", OpenSSLVersion: "3.6.3", WANIndex: 6, OS: "Microsoft Windows Server 2022 Datacenter"}
}

func onWindows(t *testing.T) {
	t.Helper()
	old := config.Platform
	config.Platform = config.PlatformWindows
	t.Cleanup(func() { config.Platform = old })
}

func TestWinOpenVPNGolden(t *testing.T) {
	s, f := settings(), winFacts()
	golden(t, "win-openvpn-udp.conf", must(WinOpenVPN(s, f, config.InstanceUDP)))
	golden(t, "win-openvpn-tcp.conf", must(WinOpenVPN(s, f, config.InstanceTCP)))
	old := f
	old.OpenVPNVersion = "2.6.15"
	old.OpenSSLVersion = "3.3.2"
	golden(t, "win-openvpn-udp-2.6.conf", must(WinOpenVPN(s, old, config.InstanceUDP)))
	onWindows(t)
	s.StealthPort = 8443 + 1
	got := must(WinOpenVPN(s, f, config.InstanceTCP))
	if !strings.Contains(got, "\nport 8444\n") {
		t.Fatal(got)
	}
}

func TestWinOpenVPNHooksAreQuotedForOpenVPN(t *testing.T) {
	got := must(WinOpenVPN(settings(), winFacts(), config.InstanceUDP))
	for _, want := range []string{
		`tls-crypt-v2-verify "'C:\\Program Files\\Veyl\\veyl.exe' hook verify"`,
		`client-connect "'C:\\Program Files\\Veyl\\veyl.exe' hook connect"`,
		`management 127.0.0.1 7505 "C:\\ProgramData\\Veyl\\data\\mgmt-udp.pw"`,
		`dev-node "Veyl UDP"`,
		"disable-dco",
		"verb 0",
	} {
		if !strings.Contains(got, want+"\n") {
			t.Errorf("missing %s", want)
		}
	}
	for _, bad := range []string{"port-share", "\nuser ", "\ngroup ", "log ", "status ", "server-ipv6", "windows-driver"} {
		if strings.Contains(got, bad) {
			t.Errorf("unexpected %q", bad)
		}
	}
}

func TestWinOpenVPNRejects(t *testing.T) {
	s := settings()
	if _, err := WinOpenVPN(s, winFacts(), "evil"); !errors.Is(err, ErrInstance) {
		t.Fatal(err)
	}
	bad := winFacts()
	bad.OpenVPNVersion = "2.7.7\nup calc.exe"
	if _, err := WinOpenVPN(s, bad, config.InstanceUDP); !errors.Is(err, ErrFacts) {
		t.Fatal(err)
	}
	s.Host = "vpn.example.com\nup calc"
	if _, err := WinOpenVPN(s, winFacts(), config.InstanceUDP); err == nil {
		t.Fatal("bad host accepted")
	}
	if _, err := ovpnScript(`C:\x' & calc '`, "hook"); err == nil {
		t.Fatal("quote in script path accepted")
	}
	if _, err := ovpnScript(config.WinBinPath, "hook verify"); err == nil {
		t.Fatal("space in script argument accepted")
	}
	if _, err := ovpnPath("C:\\a\"b"); err == nil {
		t.Fatal("double quote accepted")
	}
}

func TestWinUnboundGolden(t *testing.T) {
	s := settings()
	golden(t, "win-unbound-recursive.conf", must(WinUnbound(s)))
	s.DNS.Upstream = config.UpQuad9
	got := must(WinUnbound(s))
	golden(t, "win-unbound-quad9.conf", got)
	if strings.Contains(got, CertBundle) || !strings.Contains(got, "tls-win-cert: yes") || strings.Contains(got, "2620:fe::fe") {
		t.Fatal(got)
	}
}

func TestWinCaddyfileHasNoPortShare(t *testing.T) {
	got := must(WinCaddyfile(settings()))
	golden(t, "win-Caddyfile", got)
	if strings.Contains(got, "8443") || strings.Contains(got, "default_bind") {
		t.Fatal(got)
	}
}

func TestWinFirewallGolden(t *testing.T) {
	s := settings()
	golden(t, "win-firewall.ps1", must(WinFirewallScript(s)))
	s.Stealth = false
	s.AdminVPNOnly = true
	golden(t, "win-firewall-nostealth-admin.ps1", must(WinFirewallScript(s)))
}

func TestWinScriptsGolden(t *testing.T) {
	golden(t, "win-network.ps1", must(WinNetworkScript(winFacts())))
	golden(t, "win-tap-udp.ps1", must(WinTapScript(config.InstanceUDP)))
	golden(t, "win-tap-tcp.ps1", must(WinTapScript(config.InstanceTCP)))
	golden(t, "win-adapter-udp.ps1", must(WinAdapterScript(config.InstanceUDP)))
	golden(t, "win-facts.ps1", WinFactsScript())
	golden(t, "win-status.ps1", WinStatusScript())
	golden(t, "win-listeners.ps1", WinListenersScript())
	golden(t, "win-uninstall.ps1", WinUninstallScript())
	for _, sc := range []string{must(WinNetworkScript(winFacts())), must(WinTapScript(config.InstanceUDP)), WinStatusScript(), WinUninstallScript(), must(WinFirewallScript(settings()))} {
		if _, err := winps.Command(sc); err != nil {
			t.Fatalf("%v\n%s", err, sc)
		}
	}
	if _, err := WinNetworkScript(WinFacts{}); err == nil {
		t.Fatal("missing wan accepted")
	}
	if _, err := WinTapScript("x"); err == nil {
		t.Fatal("bad instance accepted")
	}
}

func TestWinServices(t *testing.T) {
	var b strings.Builder
	keys := map[string]bool{}
	for _, s := range WinServices() {
		bin, err := s.BinPath()
		if err != nil {
			t.Fatal(err)
		}
		sid, err := s.SID()
		if err != nil {
			t.Fatal(err)
		}
		b.WriteString(s.Name + "|" + s.Account() + "|" + sid + "|" + s.Key + "|" + bin + "\n")
		keys[s.Key] = true
	}
	golden(t, "win-services.txt", b.String())
	for _, k := range []string{"veyl", "veyl-agent", "veyl-dns", "openvpn-server@veyl-udp", "openvpn-server@veyl-tcp", "unbound", "caddy"} {
		if !keys[k] {
			t.Errorf("missing status key %s", k)
		}
	}
	if _, err := (WinService{Name: "X", Args: []string{"a\"b"}}).BinPath(); err == nil {
		t.Fatal("quote accepted in service argument")
	}
	if _, err := (WinService{Name: "X", Args: []string{`C:\dir with space\`}}).BinPath(); err == nil {
		t.Fatal("trailing backslash accepted in quoted argument")
	}
}

func TestWinGrants(t *testing.T) {
	for _, d := range WinDirs() {
		g, err := WinGrants(d)
		if err != nil || len(g) < 2 {
			t.Fatalf("%s %v %v", d, g, err)
		}
		for _, x := range g {
			if x.SID == "S-1-5-32-545" || x.SID == "S-1-1-0" || x.SID == "S-1-5-11" {
				t.Fatalf("%s grants users", d)
			}
		}
	}
	if _, err := WinGrants(`C:\Windows`); err == nil {
		t.Fatal("unknown directory accepted")
	}
	if len(WinMgmtGrants()) != 3 || WinMgmtGrants()[2].Rights != "RX" {
		t.Fatal(WinMgmtGrants())
	}
}
