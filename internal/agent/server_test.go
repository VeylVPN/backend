package agent

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/veylvpn/backend/internal/agentapi"
)

func startServer(t *testing.T, h *harness) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "veyl-agent")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "agent.sock")
	ln, err := h.a.Listen(sock)
	if err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(sock)
	if err != nil || fi.Mode().Perm() != 0o660 {
		t.Fatalf("socket mode %v %v", fi.Mode(), err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		_ = h.a.Serve(ctx, ln)
		close(done)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	return sock
}

func TestSocketPingStatus(t *testing.T) {
	h := newHarness(t, testSettings())
	sock := startServer(t, h)
	c := agentapi.SocketClient{Path: sock}
	var last agentapi.Event
	if err := c.Do(context.Background(), agentapi.Request{Op: agentapi.OpPing}, func(ev agentapi.Event) { last = ev }); err != nil {
		t.Fatal(err)
	}
	if !last.Done || last.Data["pong"] != "1" {
		t.Fatal(last)
	}
	if err := c.Do(context.Background(), agentapi.Request{Op: agentapi.OpStatus}, func(ev agentapi.Event) { last = ev }); err != nil {
		t.Fatal(err)
	}
	if last.Data["openvpn"] != "2.6.19" {
		t.Fatal(last.Data)
	}
	err := c.Do(context.Background(), agentapi.Request{Op: "reboot"}, nil)
	if !errors.Is(err, agentapi.ErrAgent) || !strings.Contains(err.Error(), "unknown operation") {
		t.Fatal(err)
	}
}

func TestSocketStreamsApply(t *testing.T) {
	h := newHarness(t, testSettings())
	sock := startServer(t, h)
	var steps []string
	err := agentapi.SocketClient{Path: sock}.Do(context.Background(), agentapi.Request{Op: agentapi.OpApply}, func(ev agentapi.Event) {
		if ev.Status == agentapi.StatusOK {
			steps = append(steps, ev.Step)
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(steps) < 15 || steps[0] != "settings" || steps[len(steps)-1] != "verify-https" {
		t.Fatal(steps)
	}
}

func TestSocketRejectsPeer(t *testing.T) {
	h := newHarness(t, testSettings())
	var seen atomic.Uint32
	seen.Store(99999)
	h.a.AllowUID = func(uid uint32) bool {
		seen.Store(uid)
		return false
	}
	sock := startServer(t, h)
	err := agentapi.SocketClient{Path: sock}.Do(context.Background(), agentapi.Request{Op: agentapi.OpPing}, nil)
	if err == nil || !strings.Contains(err.Error(), "forbidden") {
		t.Fatal(err)
	}
	if seen.Load() != uint32(os.Getuid()) {
		t.Fatalf("peer uid %d, want %d", seen.Load(), os.Getuid())
	}
}

func TestDefaultAllowedUIDs(t *testing.T) {
	a := &Agent{Lookup: func(string) (int, int, error) { return 990, 991, nil }}
	if !a.allowed(0) || !a.allowed(990) || a.allowed(991) || a.allowed(1000) {
		t.Fatal("uid policy")
	}
	a.Lookup = func(string) (int, int, error) { return 0, 0, errors.New("no user") }
	if a.allowed(1000) || !a.allowed(0) {
		t.Fatal("uid policy without veyl user")
	}
}

func rawRequest(t *testing.T, sock, body string) agentapi.Event {
	t.Helper()
	conn, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	_, _ = conn.Write([]byte(body))
	var ev agentapi.Event
	if err := json.NewDecoder(conn).Decode(&ev); err != nil {
		t.Fatal(err)
	}
	return ev
}

func TestSocketRejectsBadRequests(t *testing.T) {
	h := newHarness(t, testSettings())
	sock := startServer(t, h)
	for _, body := range []string{
		"not json\n",
		"{\"op\":\"ping\",\"extra\":1}\n",
		strings.Repeat("a", 5000) + "\n",
		"{\"op\":\"" + strings.Repeat("x", 40) + "\"}\n",
	} {
		ev := rawRequest(t, sock, body)
		if !ev.Done || ev.Error != "bad request" {
			t.Errorf("%.30q -> %+v", body, ev)
		}
	}
}

func TestOneOperationAtATime(t *testing.T) {
	h := newHarness(t, testSettings())
	release := make(chan struct{})
	var running, maxRunning atomic.Int32
	h.a.Download = func(ctx context.Context, dir string, client *http.Client) (map[string]int, error) {
		n := running.Add(1)
		if n > maxRunning.Load() {
			maxRunning.Store(n)
		}
		<-release
		running.Add(-1)
		return map[string]int{"ads": 1}, nil
	}
	sock := startServer(t, h)
	c := agentapi.SocketClient{Path: sock}
	errs := make(chan error, 2)
	queued := make(chan struct{}, 1)
	go func() { errs <- c.Do(context.Background(), agentapi.Request{Op: agentapi.OpDNSUpdate}, nil) }()
	deadline := time.Now().Add(5 * time.Second)
	for running.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	go func() {
		errs <- c.Do(context.Background(), agentapi.Request{Op: agentapi.OpDNSUpdate}, func(ev agentapi.Event) {
			if ev.Step == "queue" && ev.Status == agentapi.StatusRun {
				queued <- struct{}{}
			}
		})
	}()
	select {
	case <-queued:
	case <-time.After(5 * time.Second):
		t.Fatal("second operation was not queued")
	}
	if err := c.Do(context.Background(), agentapi.Request{Op: agentapi.OpPing}, nil); err != nil {
		t.Fatal("ping blocked by running operation")
	}
	close(release)
	for i := 0; i < 2; i++ {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	if maxRunning.Load() != 1 {
		t.Fatalf("%d operations ran at once", maxRunning.Load())
	}
}

func TestParsers(t *testing.T) {
	ov, ssl := parseOpenVPNVersion("OpenVPN 2.6.19 x86_64-pc-linux-gnu [SSL (OpenSSL)]\nlibrary versions: OpenSSL 3.0.13 30 Jan 2024, LZO 2.10\n")
	if ov != "2.6.19" || ssl != "3.0.13" {
		t.Fatal(ov, ssl)
	}
	if v := parseOpenSSLVersion("OpenSSL 3.5.1 1 Jul 2025 (Library: OpenSSL 3.5.1 1 Jul 2025)"); v != "3.5.1" {
		t.Fatal(v)
	}
	if v := parseOpenSSLVersion("LibreSSL 3.3.6"); v != "" {
		t.Fatal(v)
	}
	ports := parseSSHDPorts("port 22\nport 2200\nlistenaddress 0.0.0.0:2201\nlistenaddress [::]:22\nmaxauthtries 6\n")
	if len(ports) != 4 || ports[0] != 22 || ports[1] != 2200 || ports[2] != 2201 {
		t.Fatal(ports)
	}
	l, ok := ssLocal("udp UNCONN 0 0 [::]:1194 [::]:*")
	if !ok || l.proto != "udp" || l.addr != "::" || l.port != 1194 {
		t.Fatal(l, ok)
	}
	l, ok = ssLocal("LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:((\"sshd\",pid=1,fd=3))")
	if !ok || l.port != 22 || l.proto != "" {
		t.Fatal(l, ok)
	}
	if p := parseSSListeners("LISTEN 0 128 0.0.0.0:2022 0.0.0.0:* users:((\"sshd\",pid=1,fd=3))\nLISTEN 0 128 0.0.0.0:80 0.0.0.0:* users:((\"caddy\",pid=1,fd=3))\n", "\"sshd\""); len(p) != 1 || p[0] != 2022 {
		t.Fatal(p)
	}
	if _, ok := ssLocal("garbage"); ok {
		t.Fatal("parsed garbage")
	}
}

func TestFactsDetection(t *testing.T) {
	h := newHarness(t, testSettings())
	f, err := h.a.Facts(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if f.WANIface != "eth0" || !f.HasIPv6 || f.OpenVPNVersion != "2.6.19" || f.OpenSSLVersion != "3.5.1" || len(f.SSHPorts) != 2 || f.SSHPorts[1] != 2222 {
		t.Fatalf("%+v", f)
	}
	writeFile(t, h.root, "/proc/net/ipv6_route", "00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 ffffffff 00000001 00000000 00200200 lo\n")
	h.r.fail["sshd -T"] = -1
	h.r.out["ss -H -ltnp"] = ""
	f, err = h.a.Facts(context.Background())
	if err != nil || f.HasIPv6 || len(f.SSHPorts) != 1 || f.SSHPorts[0] != 22 {
		t.Fatalf("%+v %v", f, err)
	}
	writeFile(t, h.root, "/proc/net/route", "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\n")
	if _, err := h.a.Facts(context.Background()); err == nil {
		t.Fatal("no default route accepted")
	}
}

func TestExecRunner(t *testing.T) {
	r := ExecRunner{}
	out, err := r.Run(context.Background(), "echo", "$(id)", ";", "x")
	if err != nil || strings.TrimSpace(string(out)) != "$(id) ; x" {
		t.Fatal(string(out), err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := r.Run(ctx, "sleep", "10"); err == nil || time.Since(start) > 7*time.Second {
		t.Fatal("timeout not enforced", err)
	}
	if _, err := r.Run(context.Background(), "echo hi"); err == nil {
		t.Fatal("accepted command with spaces")
	}
	a := &Agent{Runner: r}
	_, err = a.run(context.Background(), time.Second, "false")
	var ce *cmdError
	if !errors.As(err, &ce) {
		t.Fatal(err)
	}
}

func TestMainUsage(t *testing.T) {
	if Main([]string{"nope"}) != 2 {
		t.Fatal("usage")
	}
	if Main([]string{"run"}) != 2 {
		t.Fatal("run usage")
	}
}
