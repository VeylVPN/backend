package hook_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/veylvpn/backend/internal/api"
	"github.com/veylvpn/backend/internal/app"
	"github.com/veylvpn/backend/internal/config"
	"github.com/veylvpn/backend/internal/hook"
	"github.com/veylvpn/backend/internal/ovpn"
	"github.com/veylvpn/backend/internal/pki"
	"github.com/veylvpn/backend/internal/pki/pkitest"
	"github.com/veylvpn/backend/internal/store"
)

const hookArg = "veyl-hook"

func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == hookArg {
		os.Exit(hook.Main(os.Args[2:]))
	}
	os.Exit(pkitest.Main(m))
}

const realBin = "/usr/sbin/openvpn"

type itEnv struct {
	t      *testing.T
	dir    string
	port   int
	api    *httptest.Server
	d      app.Deps
	token  string
	procs  []*exec.Cmd
	server string
}

func (e *itEnv) call(method, path string, body any) (int, map[string]any) {
	e.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	r, _ := http.NewRequest(method, e.api.URL+path, rd)
	if body != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	if e.token != "" {
		r.Header.Set("Authorization", "Bearer "+e.token)
	}
	res, err := http.DefaultClient.Do(r)
	if err != nil {
		e.t.Fatal(err)
	}
	defer res.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(res.Body).Decode(&out)
	return res.StatusCode, out
}

type device struct {
	id      string
	profile string
	keyPEM  string
	certPEM string
}

func (e *itEnv) enroll() device {
	e.t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, k)
	csr := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
	code, out := e.call("POST", "/v1/me/devices", map[string]any{"csr": csr})
	if code != 200 {
		e.t.Fatalf("enroll %d %v", code, out)
	}
	kd, _ := x509.MarshalPKCS8PrivateKey(k)
	p := out["profile"].(string)
	s := strings.Index(p, "<cert>\n") + len("<cert>\n")
	return device{
		id:      out["id"].(string),
		profile: p,
		keyPEM:  strings.TrimSpace(string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kd}))),
		certPEM: p[s:strings.Index(p, "</cert>")],
	}
}

func (e *itEnv) clientConfig(name, profile, key string) string {
	e.t.Helper()
	p := strings.Replace(profile, "remote vpn.example.com "+strconv.Itoa(e.port)+" udp", "remote 127.0.0.1 "+strconv.Itoa(e.port)+" udp", 1)
	p = strings.Replace(p, ovpn.KeyPlaceholder, key, 1)
	p += "disable-dco\nverb 4\nconnect-retry-max 1\n"
	path := filepath.Join(e.dir, name+".conf")
	if err := os.WriteFile(path, []byte(p), 0o600); err != nil {
		e.t.Fatal(err)
	}
	return path
}

func (e *itEnv) start(name, conf string) (*exec.Cmd, string) {
	e.t.Helper()
	log := filepath.Join(e.dir, name+".log")
	f, err := os.Create(log)
	if err != nil {
		e.t.Fatal(err)
	}
	cmd := exec.Command(realBin, "--config", conf)
	cmd.Stdout = f
	cmd.Stderr = f
	cmd.Dir = e.dir
	if err := cmd.Start(); err != nil {
		e.t.Fatal(err)
	}
	f.Close()
	e.procs = append(e.procs, cmd)
	return cmd, log
}

func stop(cmd *exec.Cmd) {
	if cmd.Process != nil {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	}
}

func read(path string) string {
	b, _ := os.ReadFile(path)
	return string(b)
}

func waitFor(path, needle string, d time.Duration) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if strings.Contains(read(path), needle) {
			return true
		}
		time.Sleep(100 * time.Millisecond)
	}
	return false
}

func freeUDPPort(t *testing.T) int {
	for i := 0; i < 50; i++ {
		c, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		p := c.LocalAddr().(*net.UDPAddr).Port
		c.Close()
		if config.ValidPort(p) {
			return p
		}
	}
	t.Fatal("no port")
	return 0
}

func TestRealOpenVPN(t *testing.T) {
	if os.Getenv("VEYL_REAL_OPENVPN") != "1" {
		t.Skip("set VEYL_REAL_OPENVPN=1 to run against /usr/sbin/openvpn")
	}
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	old := pki.OpenVPNBin
	pki.OpenVPNBin = realBin
	t.Cleanup(func() { pki.OpenVPNBin = old })

	dir, err := os.MkdirTemp("/tmp", "veyl-it-")
	if err != nil {
		t.Fatal(err)
	}
	os.Chmod(dir, 0o755)
	t.Cleanup(func() {
		if !t.Failed() {
			os.RemoveAll(dir)
		}
	})
	e := &itEnv{t: t, dir: dir, port: freeUDPPort(t)}
	t.Cleanup(func() {
		for _, p := range e.procs {
			stop(p)
		}
	})

	paths := config.Paths{Data: dir, Run: dir}
	ca, err := pki.Init(paths.PKI())
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(paths.State())
	if err != nil {
		t.Fatal(err)
	}
	set := config.Defaults()
	set.Host = "vpn.example.com"
	set.UDPPort = e.port
	set.Stealth = false
	set.Registration = config.RegOpen
	if err := config.Save(paths.Settings(), set); err != nil {
		t.Fatal(err)
	}
	live, err := config.NewLive(paths.Settings())
	if err != nil {
		t.Fatal(err)
	}
	mgmtSock := filepath.Join(dir, "mgmt")
	mgmt := &ovpn.Multi{Clients: []*ovpn.Client{{Socket: mgmtSock}, {Socket: filepath.Join(dir, "mgmt-down")}}}
	e.d = app.Deps{Paths: paths, Settings: live, Store: st, CA: ca, Mgmt: mgmt}

	hookSock := filepath.Join(dir, "hook.sock")
	hs := hook.NewServer(e.d)
	hs.Group = ""
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go hs.Serve(ctx, hookSock)

	e.api = httptest.NewServer(api.New(e.d).Handler())
	t.Cleanup(e.api.Close)

	code, out := e.call("POST", "/v1/register", map[string]any{"password": "correct horse"})
	if code != 200 {
		t.Fatalf("register %d %v", code, out)
	}
	number := out["account"].(string)
	code, out = e.call("POST", "/v1/auth/token", map[string]any{"account": number, "password": "correct horse"})
	if code != 200 {
		t.Fatalf("token %d %v", code, out)
	}
	e.token = out["access_token"].(string)
	devA := e.enroll()
	devB := e.enroll()

	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	hookCmd := exe + " " + hookArg + " -socket " + hookSock
	serverConf := strings.Join([]string{
		"dev tun",
		"dev-type tun",
		"topology subnet",
		"proto udp",
		"local 127.0.0.1",
		"port " + strconv.Itoa(e.port),
		"server 10.213.0.0 255.255.255.0",
		"ca " + filepath.Join(dir, pki.CAFile),
		"cert " + filepath.Join(dir, pki.ServerCertFile),
		"key " + filepath.Join(dir, pki.ServerKeyFile),
		"dh none",
		"tls-crypt-v2 " + filepath.Join(dir, pki.TLSCryptV2File) + " force-cookie",
		"tls-crypt-v2-verify \"" + hookCmd + " verify\"",
		"client-connect \"" + hookCmd + " connect\"",
		"script-security 2",
		"crl-verify " + paths.CRL(),
		"remote-cert-tls client",
		"verify-client-cert require",
		"tls-version-min 1.2",
		"data-ciphers " + ovpn.DataCiphers,
		"allow-compression no",
		"push \"block-outside-dns\"",
		"keepalive 10 60",
		"disable-dco",
		"tmp-dir " + dir,
		"management " + mgmtSock + " unix",
		"verb 3",
		"",
	}, "\n")
	sconf := filepath.Join(dir, "server.conf")
	if err := os.WriteFile(sconf, []byte(serverConf), 0o600); err != nil {
		t.Fatal(err)
	}
	_, slog := e.start("server", sconf)
	e.server = slog
	if !waitFor(slog, "Initialization Sequence Completed", 15*time.Second) {
		t.Fatalf("server did not start:\n%s", read(slog))
	}

	defDNS := config.DNSAddr(set.DNS.Default)
	ca2, clog := e.start("client-a", e.clientConfig("client-a", devA.profile, devA.keyPEM))
	if !waitFor(clog, "Initialization Sequence Completed", 20*time.Second) {
		t.Fatalf("allowed device did not connect:\nclient:\n%s\nserver:\n%s", read(clog), read(slog))
	}
	if !strings.Contains(read(clog), "dhcp-option DNS "+defDNS) {
		t.Fatalf("pushed DNS %s missing:\n%s", defDNS, read(clog))
	}
	if !strings.Contains(read(slog), "TLS CRYPT V2 VERIFY SCRIPT OK") {
		t.Fatalf("verify script did not run:\n%s", read(slog))
	}
	t.Logf("device A connected and received dhcp-option DNS %s", defDNS)

	deadline := time.Now().Add(10 * time.Second)
	online := false
	for time.Now().Before(deadline) && !online {
		_, out = e.call("GET", "/v1/me/devices", nil)
		for _, d := range out["devices"].([]any) {
			dm := d.(map[string]any)
			if dm["id"] == devA.id && dm["online"] == true {
				online = true
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	if !online {
		t.Fatalf("device A not reported online via management: %v", out)
	}
	t.Log("device A reported online through the management socket")

	code, _ = e.call("PUT", "/v1/me/dns", map[string]any{"blocking": []string{"ads"}})
	if code != 200 {
		t.Fatalf("dns %d", code)
	}
	customDNS := config.DNSAddr([]string{"ads"})
	_, blog := e.start("client-b", e.clientConfig("client-b", devB.profile, devB.keyPEM))
	if !waitFor(blog, "Initialization Sequence Completed", 20*time.Second) {
		t.Fatalf("device B did not connect:\n%s\nserver:\n%s", read(blog), read(slog))
	}
	if !strings.Contains(read(blog), "dhcp-option DNS "+customDNS) {
		t.Fatalf("custom DNS %s missing:\n%s", customDNS, read(blog))
	}
	t.Logf("device B connected and received per-account dhcp-option DNS %s", customDNS)

	verifyErrors := strings.Count(read(slog), "TLS CRYPT V2 VERIFY SCRIPT ERROR")
	code, _ = e.call("DELETE", "/v1/me/devices/"+devA.id, nil)
	if code != 204 {
		t.Fatalf("revoke %d", code)
	}
	if !waitFor(slog, devA.id+"/", 5*time.Second) || !waitFor(slog, "client-instance exiting", 10*time.Second) {
		t.Fatalf("revoked device A was not killed:\n%s", read(slog))
	}
	if on, err := mgmt.Online(); err != nil || on[devA.id] || !on[devB.id] {
		t.Fatalf("online after revoke %v %v", on, err)
	}
	stop(ca2)
	t.Log("device A revoked: CRL rewritten and session killed through the management socket")

	_, rlog := e.start("client-a2", e.clientConfig("client-a2", devA.profile, devA.keyPEM))
	deadline = time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) && strings.Count(read(slog), "TLS CRYPT V2 VERIFY SCRIPT ERROR") <= verifyErrors {
		time.Sleep(100 * time.Millisecond)
	}
	if strings.Count(read(slog), "TLS CRYPT V2 VERIFY SCRIPT ERROR") <= verifyErrors {
		t.Fatalf("revoked device not rejected by tls-crypt-v2-verify:\n%s", read(slog))
	}
	time.Sleep(2 * time.Second)
	if strings.Contains(read(rlog), "Initialization Sequence Completed") {
		t.Fatalf("revoked device connected:\n%s", read(rlog))
	}
	t.Log("revoked device A rejected by tls-crypt-v2-verify before TLS")

	cases := []struct {
		name string
		key  func() []byte
	}{
		{"unknown-metadata", func() []byte {
			k, err := ca.TLSCryptV2Client([]byte("ffffffffffffffff"))
			if err != nil {
				t.Fatal(err)
			}
			return k
		}},
		{"timestamp-metadata", func() []byte {
			out := filepath.Join(dir, "ts.key")
			if err := exec.Command(realBin, "--tls-crypt-v2", ca.TLSCryptV2ServerPath(), "--genkey", "tls-crypt-v2-client", out).Run(); err != nil {
				t.Fatal(err)
			}
			return []byte(read(out))
		}},
		{"injection-metadata", func() []byte {
			k, err := ca.TLSCryptV2Client([]byte(devB.id + "\nx"))
			if err != nil {
				t.Fatal(err)
			}
			return k
		}},
	}
	for _, c := range cases {
		before := strings.Count(read(slog), "TLS CRYPT V2 VERIFY SCRIPT ERROR")
		start := strings.Index(devB.profile, "<tls-crypt-v2>\n") + len("<tls-crypt-v2>\n")
		end := strings.Index(devB.profile, "</tls-crypt-v2>")
		forged := devB.profile[:start] + strings.TrimSpace(string(c.key())) + "\n" + devB.profile[end:]
		_, flog := e.start("client-"+c.name, e.clientConfig("client-"+c.name, forged, devB.keyPEM))
		deadline := time.Now().Add(20 * time.Second)
		for time.Now().Before(deadline) && strings.Count(read(slog), "TLS CRYPT V2 VERIFY SCRIPT ERROR") <= before {
			time.Sleep(100 * time.Millisecond)
		}
		if strings.Count(read(slog), "TLS CRYPT V2 VERIFY SCRIPT ERROR") <= before {
			t.Fatalf("%s not rejected:\n%s", c.name, read(slog))
		}
		time.Sleep(time.Second)
		if strings.Contains(read(flog), "Initialization Sequence Completed") {
			t.Fatalf("%s connected with a valid certificate:\n%s", c.name, read(flog))
		}
		t.Logf("%s rejected by tls-crypt-v2-verify even with device B's valid certificate", c.name)
	}

	fmt.Fprintf(os.Stderr, "server log excerpt:\n%s\n", excerpt(read(slog)))
}

func excerpt(log string) string {
	var out []string
	for _, l := range strings.Split(log, "\n") {
		if strings.Contains(l, "TLS CRYPT V2") || strings.Contains(l, "client-connect") || strings.Contains(l, "PUSH") || strings.Contains(l, "Initialization Sequence") || strings.Contains(l, "SIGTERM") || strings.Contains(l, "kill") {
			out = append(out, l)
		}
	}
	return strings.Join(out, "\n")
}
