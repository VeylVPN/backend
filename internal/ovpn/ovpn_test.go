package ovpn

import (
	"bufio"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const status = "TITLE\tOpenVPN 2.6\nTIME\tx\t1\nHEADER\tCLIENT_LIST\tCommon Name\tReal Address\nCLIENT_LIST\taaaa\t203.0.113.7:5555\t10.8.0.2\nCLIENT_LIST\tbbbb\t203.0.113.8:5555\t10.8.0.3\nEND\n"

func fake(t *testing.T, killed chan string) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "v")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	p := filepath.Join(dir, "m")
	l, err := net.Listen("unix", p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				c.Write([]byte(">INFO:OpenVPN Management Interface Version 5\n"))
				sc := bufio.NewScanner(c)
				for sc.Scan() {
					line := sc.Text()
					switch {
					case line == "status 3":
						c.Write([]byte(status))
					case strings.HasPrefix(line, "kill "):
						killed <- strings.TrimPrefix(line, "kill ")
						c.Write([]byte("SUCCESS: common name 'x' found, 1 client(s) killed\n"))
					case line == "exit":
						return
					}
				}
			}()
		}
	}()
	return p
}

func TestOnline(t *testing.T) {
	c := &Client{Socket: fake(t, make(chan string, 1))}
	m, err := c.Online()
	if err != nil {
		t.Fatal(err)
	}
	if len(m) != 2 || !m["aaaa"] || !m["bbbb"] {
		t.Fatalf("%v", m)
	}
}

func TestKill(t *testing.T) {
	k := make(chan string, 1)
	c := &Client{Socket: fake(t, k)}
	if err := c.Kill("aaaa"); err != nil {
		t.Fatal(err)
	}
	if got := <-k; got != "aaaa" {
		t.Fatalf("%q", got)
	}
	if err := c.Kill("a b\nexit"); err != ErrBadName {
		t.Fatalf("%v", err)
	}
}

func TestMissingSocket(t *testing.T) {
	c := &Client{Socket: "/nonexistent/sock"}
	if _, err := c.Online(); err == nil {
		t.Fatal("expected error")
	}
}

func TestProfile(t *testing.T) {
	base := Params{Host: "vpn.example.com", UDPPort: 1194, CA: []byte("CA\n"), Cert: []byte("CERT\n"), TLSCryptV2: []byte("TC2\n")}
	p, err := Profile(base)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"client\n", "remote vpn.example.com 1194 udp\n", "<ca>\nCA\n</ca>\n", "<cert>\nCERT\n</cert>\n", "<key>\n__PRIVATE_KEY__\n</key>\n", "<tls-crypt-v2>\nTC2\n</tls-crypt-v2>\n", "verify-x509-name veyl-server name\n", "remote-cert-tls server\n", "data-ciphers AES-256-GCM:CHACHA20-POLY1305:AES-128-GCM\n", "connect-retry 2 5\n", "server-poll-timeout 4\n", "tls-version-min 1.2\n", "setenv opt block-outside-dns\n", "auth-nocache\n", "verb 1\n"} {
		if !strings.Contains(p, want) {
			t.Errorf("missing %q", want)
		}
	}
	for _, bad := range []string{"data-ciphers-fallback", "<tls-crypt>", "tcp-client", "proto ", "remote-random-hostname", "explicit-exit-notify", "#"} {
		if strings.Contains(p, bad) {
			t.Errorf("unexpected %q", bad)
		}
	}
	st := base
	st.Stealth = true
	p, err = Profile(st)
	if err != nil {
		t.Fatal(err)
	}
	u := strings.Index(p, "remote vpn.example.com 1194 udp\n")
	tc := strings.Index(p, "remote vpn.example.com 443 tcp-client\n")
	if u < 0 || tc < 0 || tc < u {
		t.Fatalf("remotes out of order:\n%s", p)
	}
	bads := []func(*Params){
		func(p *Params) { p.Host = "" },
		func(p *Params) { p.Host = "vpn.example.com\nup /bin/sh" },
		func(p *Params) { p.Host = "10.0.0.1" },
		func(p *Params) { p.UDPPort = 80 },
		func(p *Params) { p.TLSCryptV2 = nil },
		func(p *Params) { p.Cert = []byte("x</cert>\nup /bin/sh\n<cert>") },
	}
	for i, f := range bads {
		c := base
		f(&c)
		if _, err := Profile(c); err != ErrProfile {
			t.Errorf("case %d: %v", i, err)
		}
	}
}

func TestMulti(t *testing.T) {
	k1 := make(chan string, 1)
	k2 := make(chan string, 1)
	a := &Client{Socket: fake(t, k1)}
	b := &Client{Socket: fake(t, k2)}
	down := &Client{Socket: "/nonexistent/sock"}
	m := &Multi{Clients: []*Client{a, down, b}}
	on, err := m.Online()
	if err != nil || len(on) != 2 || !on["aaaa"] {
		t.Fatalf("%v %v", on, err)
	}
	if err := m.Kill("aaaa"); err != nil {
		t.Fatal(err)
	}
	if <-k1 != "aaaa" || <-k2 != "aaaa" {
		t.Fatal("kill not sent to all instances")
	}
	if err := m.Kill("bad name"); err != ErrBadName {
		t.Fatal(err)
	}
	none := &Multi{Clients: []*Client{down}}
	if _, err := none.Online(); err == nil {
		t.Fatal("expected error when all instances are down")
	}
	if err := none.Kill("aaaa"); err == nil {
		t.Fatal("expected kill error")
	}
}
