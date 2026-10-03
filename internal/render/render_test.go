package render

import (
	"errors"
	"flag"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/veylvpn/backend/internal/config"
)

var update = flag.Bool("update", false, "rewrite golden files")

func golden(t *testing.T, name, got string) {
	t.Helper()
	p := filepath.Join("testdata", name+".golden")
	if *update {
		if err := os.WriteFile(p, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if string(want) != got {
		t.Errorf("%s mismatch\n--- got\n%s\n--- want\n%s", name, got, want)
	}
	assertNoComments(t, name, got)
}

var blockComment = regexp.MustCompile(`(^|\s)/\*`)

func assertNoComments(t *testing.T, name, s string) {
	t.Helper()
	for _, line := range strings.Split(s, "\n") {
		x := strings.TrimSpace(line)
		if strings.HasPrefix(x, "#") || strings.HasPrefix(x, "//") || strings.HasPrefix(x, ";") || blockComment.MatchString(x) {
			t.Errorf("%s has a comment line %q", name, line)
		}
	}
}

func settings() config.Settings {
	s := config.Defaults()
	s.Configured = true
	s.Host = "vpn.example.com"
	return s
}

func facts() Facts {
	return Facts{
		OpenSSLVersion: "3.5.1",
		OpenVPNVersion: "2.6.19",
		SSHPorts:       []int{22, 2222, 22},
		WANIface:       "eth0",
		PublicIPv4:     "203.0.113.7",
		HasIPv6:        true,
		Distro:         "Debian GNU/Linux 13 (trixie)",
	}
}

func must(s string, err error) string {
	if err != nil {
		panic(err)
	}
	return s
}

func TestOpenVPNGolden(t *testing.T) {
	s, f := settings(), facts()
	golden(t, "openvpn-udp.conf", must(OpenVPN(s, f, config.InstanceUDP)))
	golden(t, "openvpn-tcp.conf", must(OpenVPN(s, f, config.InstanceTCP)))
	old := f
	old.OpenSSLVersion = "3.0.13"
	old.OpenVPNVersion = "2.5.11"
	old.HasIPv6 = false
	s.UDPPort = 51820
	golden(t, "openvpn-udp-legacy.conf", must(OpenVPN(s, old, config.InstanceUDP)))
}

func TestOpenVPNPostQuantumGate(t *testing.T) {
	s, f := settings(), facts()
	for _, c := range []struct {
		ssl  string
		pq   bool
		want bool
	}{{"3.5.0", true, true}, {"3.5.1", false, false}, {"3.4.9", true, false}, {"3.0.13", true, false}, {"4.0.0", true, true}, {"", true, false}} {
		f.OpenSSLVersion = c.ssl
		s.PostQuantum = c.pq
		out := must(OpenVPN(s, f, config.InstanceUDP))
		if strings.Contains(out, "tls-groups") != c.want {
			t.Errorf("openssl %q pq %v: tls-groups present=%v", c.ssl, c.pq, !c.want)
		}
	}
}

func TestOpenVPNNeverLogs(t *testing.T) {
	for _, in := range []string{config.InstanceUDP, config.InstanceTCP} {
		out := must(OpenVPN(settings(), facts(), in))
		for _, bad := range []string{"\nlog ", "log-append", "status ", "ifconfig-pool-persist", "duplicate-cn", "dhcp-option DNS", "verb 3", "client-to-client"} {
			if strings.Contains(out, bad) {
				t.Errorf("%s contains %q", in, bad)
			}
		}
	}
}

func TestOpenVPNRejects(t *testing.T) {
	if _, err := OpenVPN(settings(), facts(), "x"); !errors.Is(err, ErrInstance) {
		t.Fatal(err)
	}
	f := facts()
	f.OpenVPNVersion = "2.6\nup /bin/sh"
	if _, err := OpenVPN(settings(), f, config.InstanceUDP); !errors.Is(err, ErrFacts) {
		t.Fatal(err)
	}
	s := settings()
	s.Host = "vpn.example.com\nup /bin/sh"
	if _, err := OpenVPN(s, facts(), config.InstanceUDP); !errors.Is(err, ErrSettings) {
		t.Fatal(err)
	}
	s = settings()
	s.UDPPort = 443
	if _, err := OpenVPN(s, facts(), config.InstanceUDP); !errors.Is(err, ErrSettings) {
		t.Fatal(err)
	}
}

func TestNFTablesGolden(t *testing.T) {
	golden(t, "veyl.nft", must(NFTables(settings(), facts())))
	s := config.Defaults()
	s.AdminVPNOnly = true
	f := facts()
	f.HasIPv6 = false
	f.SSHPorts = []int{22}
	f.WANIface = "ens3"
	golden(t, "veyl-setup.nft", must(NFTables(s, f)))
	golden(t, "veyl-delete.nft", NFTDelete())
}

func TestNFTablesSafety(t *testing.T) {
	out := must(NFTables(settings(), facts()))
	for _, bad := range []string{"flush ruleset", " log", "counter", "table ip filter", "table inet filter"} {
		if strings.Contains(out, bad) {
			t.Errorf("ruleset contains %q", bad)
		}
	}
	if !strings.Contains(out, "tcp dport { 22, 2222 } accept") {
		t.Error("ssh ports missing")
	}
	f := facts()
	f.SSHPorts = nil
	if _, err := NFTables(settings(), f); !errors.Is(err, ErrFacts) {
		t.Fatal("rendered firewall without ssh ports")
	}
	f = facts()
	f.SSHPorts = []int{70000}
	if _, err := NFTables(settings(), f); !errors.Is(err, ErrFacts) {
		t.Fatal("accepted bad ssh port")
	}
	for _, iface := range []string{"", "eth0\"; flush ruleset", "a b", "averyveryverylongname0", "eth0\n"} {
		f = facts()
		f.WANIface = iface
		if _, err := NFTables(settings(), f); !errors.Is(err, ErrFacts) {
			t.Errorf("accepted iface %q", iface)
		}
	}
}

func TestUnboundGolden(t *testing.T) {
	s := settings()
	golden(t, "unbound-recursive.conf", must(Unbound(s, facts())))
	s.DNS.Upstream = config.UpQuad9
	golden(t, "unbound-quad9.conf", must(Unbound(s, facts())))
	f := facts()
	f.HasIPv6 = false
	s.DNS.Upstream = config.UpMullvad
	golden(t, "unbound-mullvad-v4.conf", must(Unbound(s, f)))
	s.DNS.Upstream = config.UpCloudflare
	out := must(Unbound(s, f))
	if !strings.Contains(out, "1.1.1.1@853#cloudflare-dns.com") || strings.Contains(out, "2606:") {
		t.Fatal(out)
	}
}

func TestCaddyGolden(t *testing.T) {
	s := config.Defaults()
	golden(t, "Caddyfile-setup", must(Caddyfile(s, true)))
	s = settings()
	s.ACMEEmail = "admin@example.com"
	golden(t, "Caddyfile-stealth", must(Caddyfile(s, true)))
	golden(t, "Caddyfile-direct", must(Caddyfile(s, false)))
	s.Configured = false
	golden(t, "Caddyfile-setup-stealth", must(Caddyfile(s, true)))
	golden(t, "Caddyfile-setup-direct", must(Caddyfile(s, false)))
	s = settings()
	s.Host = "203.0.113.7"
	s.TLS = config.TLSInternal
	golden(t, "Caddyfile-internal", must(Caddyfile(s, true)))
	s.Host = "2001:db8:1::7"
	out := must(Caddyfile(s, false))
	if !strings.Contains(out, "[2001:db8:1::7] {") {
		t.Fatal(out)
	}
}

func TestCaddyRejects(t *testing.T) {
	s := settings()
	s.Host = "x.com {\n}\n:9999"
	if _, err := Caddyfile(s, true); err == nil {
		t.Fatal("accepted injected host")
	}
	s = settings()
	s.ACMEEmail = "a@b.com\n}"
	if _, err := Caddyfile(s, true); err == nil {
		t.Fatal("accepted injected email")
	}
}

func TestSystemGolden(t *testing.T) {
	golden(t, "sysctl.conf", must(Sysctl(facts())))
	golden(t, "journald.conf", Journald())
	golden(t, "sshd.conf", SSHD())
	golden(t, "unattended.conf", must(Unattended(settings())))
	golden(t, "tmpfiles.conf", Tmpfiles())
	golden(t, "dnsif.ip", DNSInterface())
	golden(t, "dnsif-down.ip", DNSInterfaceDown())
	off := settings()
	off.AutoUpdates = false
	if !strings.Contains(must(Unattended(off)), "Unattended-Upgrade \"0\"") {
		t.Fatal("auto updates not disabled")
	}
	f := facts()
	f.WANIface = "../x"
	if _, err := Sysctl(f); err == nil {
		t.Fatal("accepted bad iface")
	}
	if strings.Count(DNSInterface(), "address replace") != 64 {
		t.Fatal("dns address count")
	}
}

func TestUnitsGolden(t *testing.T) {
	seen := map[string]bool{}
	for _, f := range Units() {
		if !strings.HasPrefix(f.Path, UnitDir+"/") || f.Mode != 0o644 {
			t.Fatal(f.Path, f.Mode)
		}
		name := strings.ReplaceAll(strings.TrimPrefix(f.Path, UnitDir+"/"), "/", "_")
		seen[name] = true
		golden(t, "unit-"+name, f.Data)
	}
	for _, n := range UnitNames() {
		if !seen[n] {
			t.Errorf("missing unit %s", n)
		}
	}
}

func TestStripSwap(t *testing.T) {
	in := "UUID=a / ext4 defaults 0 1\n/swapfile none swap sw 0 0\n# /old none swap sw 0 0\n"
	out, changed := StripSwap(in)
	if !changed || out != "UUID=a / ext4 defaults 0 1\n# /old none swap sw 0 0\n" {
		t.Fatalf("%v %q", changed, out)
	}
	if _, changed := StripSwap("UUID=a / ext4 defaults 0 1\n"); changed {
		t.Fatal("changed without swap")
	}
}

func TestVersions(t *testing.T) {
	cases := map[string]bool{"3.5.0": true, "3.5": true, "3.10.1": true, "3.4.99": false, "2.6.19": false, "x": false, "": false}
	for v, want := range cases {
		if AtLeast(v, 3, 5, 0) != want {
			t.Errorf("%q", v)
		}
	}
	if _, err := HealthURL("2001:db8::1"); err != nil {
		t.Fatal(err)
	}
	if u, _ := HealthURL("vpn.example.com"); u != "https://vpn.example.com/v1/health" {
		t.Fatal(u)
	}
}
