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
	p := Profile(Params{Host: "vpn.example.com", Port: 1194, Proto: "udp", CA: []byte("CA\n"), Cert: []byte("CERT\n"), TLSCrypt: []byte("TC\n")})
	for _, want := range []string{"client\n", "proto udp\n", "remote vpn.example.com 1194\n", "<ca>\nCA\n</ca>\n", "<cert>\nCERT\n</cert>\n", "<key>\n__PRIVATE_KEY__\n</key>\n", "<tls-crypt>\nTC\n</tls-crypt>\n", "verify-x509-name veyl-server name\n"} {
		if !strings.Contains(p, want) {
			t.Errorf("missing %q", want)
		}
	}
}
