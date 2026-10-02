package ovpn

import (
	"bufio"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

type tcpFake struct {
	addr   string
	cmds   chan string
	reject string
}

func fakeTCP(t *testing.T, pw string, reprompt bool) *tcpFake {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	f := &tcpFake{addr: TCPPrefix + l.Addr().String(), cmds: make(chan string, 16)}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				r := bufio.NewReader(c)
				c.Write([]byte("ENTER PASSWORD:"))
				line, err := r.ReadString('\n')
				if err != nil {
					return
				}
				if strings.TrimRight(line, "\r\n") != pw {
					if reprompt {
						c.Write([]byte("ENTER PASSWORD:"))
						time.Sleep(200 * time.Millisecond)
					} else {
						c.Write([]byte("ERROR: bad password\r\n"))
					}
					return
				}
				c.Write([]byte("SUCCESS: password is correct\r\n>INFO:OpenVPN Management Interface Version 5 -- type 'help' for more info\r\n"))
				for {
					line, err := r.ReadString('\n')
					if err != nil {
						return
					}
					line = strings.TrimSpace(line)
					f.cmds <- line
					switch {
					case line == "status 3":
						c.Write([]byte(strings.ReplaceAll(status, "\n", "\r\n")))
					case line == "state":
						c.Write([]byte("1790974089,CONNECTED,SUCCESS,10.8.0.1,,,,\r\nEND\r\n"))
					case strings.HasPrefix(line, "kill "):
						c.Write([]byte("SUCCESS: common name found, 1 client(s) killed\r\n"))
					case strings.HasPrefix(line, "signal "):
						c.Write([]byte("SUCCESS: signal SIGTERM thrown\r\n"))
					case line == "exit":
						return
					}
				}
			}()
		}
	}()
	return f
}

func pwFile(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "mgmt.pw")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestTCPPasswordClient(t *testing.T) {
	f := fakeTCP(t, "s3cret", false)
	c := &Client{Socket: f.addr, PasswordFile: pwFile(t, "s3cret\r\n")}
	on, err := c.Online()
	if err != nil || len(on) != 2 || !on["aaaa"] {
		t.Fatalf("%v %v", on, err)
	}
	st, err := c.State()
	if err != nil || st != "CONNECTED" {
		t.Fatalf("%q %v", st, err)
	}
	if err := c.Kill("bbbb"); err != nil {
		t.Fatal(err)
	}
	if err := c.Signal("SIGTERM"); err != nil {
		t.Fatal(err)
	}
	if err := c.Signal("SIGKILL\nexit"); err == nil {
		t.Fatal("unsupported signal accepted")
	}
	seen := map[string]bool{}
	for len(f.cmds) > 0 {
		seen[<-f.cmds] = true
	}
	for _, want := range []string{"status 3", "state", "kill bbbb", "signal SIGTERM"} {
		if !seen[want] {
			t.Errorf("missing command %q in %v", want, seen)
		}
	}
	m := &Multi{Clients: []*Client{{Socket: "/nonexistent/sock"}, c}}
	if on, err := m.Online(); err != nil || len(on) != 2 {
		t.Fatalf("multi over unix and tcp: %v %v", on, err)
	}
}

func TestTCPPasswordRejected(t *testing.T) {
	for _, reprompt := range []bool{false, true} {
		f := fakeTCP(t, "right", reprompt)
		c := &Client{Socket: f.addr, Password: "wrong", Timeout: 2 * time.Second}
		if _, err := c.Online(); err != ErrPassword {
			t.Fatalf("reprompt=%v: %v", reprompt, err)
		}
	}
}

func TestTCPAddressAndPasswordChecks(t *testing.T) {
	for _, bad := range []string{"tcp:203.0.113.1:7505", "tcp:example.com:7505", "tcp:127.0.0.1", "tcp:[::1]"} {
		c := &Client{Socket: bad, Password: "x"}
		if _, err := c.Online(); err != ErrAddress {
			t.Errorf("%s: %v", bad, err)
		}
	}
	f := fakeTCP(t, "x", false)
	if _, err := (&Client{Socket: f.addr}).Online(); err != ErrNoPassword {
		t.Fatal(err)
	}
	if _, err := (&Client{Socket: f.addr, PasswordFile: pwFile(t, "\n")}).Online(); err != ErrNoPassword {
		t.Fatal(err)
	}
	if _, err := (&Client{Socket: f.addr, PasswordFile: filepath.Join(t.TempDir(), "missing")}).Online(); err == nil {
		t.Fatal("missing password file accepted")
	}
}

func TestRealOpenVPNManagementPassword(t *testing.T) {
	if os.Getenv("VEYL_REAL_OPENVPN") != "1" {
		t.Skip("set VEYL_REAL_OPENVPN=1 to run against the openvpn binary")
	}
	bin, err := exec.LookPath("openvpn")
	if err != nil {
		t.Skip("openvpn not installed")
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	pw := pwFile(t, "real-secret\n")
	cmd := exec.Command(bin, "--dev", "null", "--ifconfig-noexec", "--verb", "0", "--management", "127.0.0.1", strconv.Itoa(port), pw, "--management-hold")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()
	addr := TCPPrefix + "127.0.0.1:" + strconv.Itoa(port)
	good := &Client{Socket: addr, PasswordFile: pw}
	var st string
	for i := 0; i < 50; i++ {
		if st, err = good.State(); err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil || st == "" {
		t.Fatalf("state %q %v", st, err)
	}
	bad := &Client{Socket: addr, Password: "nope", Timeout: 2 * time.Second}
	if _, err := bad.State(); err != ErrPassword {
		t.Fatalf("wrong password: %v", err)
	}
	if err := good.Signal("SIGTERM"); err != nil {
		t.Fatal(err)
	}
}
