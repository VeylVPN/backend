package agent

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/veylvpn/backend/internal/agentapi"
	"github.com/veylvpn/backend/internal/config"
	"github.com/veylvpn/backend/internal/ovpn"
	"github.com/veylvpn/backend/internal/pki"
	"github.com/veylvpn/backend/internal/render"
	"github.com/veylvpn/backend/internal/winacl"
	"github.com/veylvpn/backend/internal/winps"
)

var PowerShellFlags = winps.Flags[:len(winps.Flags)-1]

var (
	FontURL    string
	FontSHA256 string
)

const (
	fontFile    = "Satoshi-Variable.woff2"
	maxFontSize = 2 << 20
)

const (
	winStartAuto     = "delayed-auto"
	winStartDisabled = "disabled"
	scMissingCode    = "1060"
	scRunningCode    = "1056"
	scNotActiveCode  = "1062"
	winWaitTries     = 60
)

func RunDirGrants() ([]winacl.Grant, error) {
	return render.WinGrants(config.WindowsPaths().Run)
}

func (a *Agent) doWindows(ctx context.Context, op string, emit Emit) (map[string]string, error) {
	switch op {
	case agentapi.OpPing:
		return map[string]string{"pong": "1"}, nil
	case agentapi.OpStatus:
		return a.winStatus(ctx)
	}
	if !mutating(op) {
		return nil, ErrUnknownOp
	}
	if err := a.acquire(ctx, emit); err != nil {
		return nil, err
	}
	defer a.release()
	switch op {
	case agentapi.OpApply:
		return nil, a.winApply(ctx, emit)
	case agentapi.OpTLS:
		return nil, a.winTLS(ctx, emit)
	case agentapi.OpDNSUpdate:
		return a.winDNSUpdate(ctx, emit)
	case agentapi.OpRestart:
		return nil, a.winRestartAll(ctx, emit)
	}
	return nil, ErrUnknownOp
}

func (a *Agent) ps(ctx context.Context, timeout time.Duration, script string) (string, error) {
	argv, err := winps.Command(script)
	if err != nil {
		return "", err
	}
	c, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	out, err := a.Runner.Run(c, config.WinPowerShell, argv...)
	if err != nil {
		if t := tail(string(out)); t != "" {
			return string(out), fmt.Errorf("powershell: %s", t)
		}
		return string(out), fmt.Errorf("powershell: %w", err)
	}
	return string(out), nil
}

func (a *Agent) sc(ctx context.Context, args ...string) (string, error) {
	return a.run(ctx, service, config.WinSC, args...)
}

func parseSCState(out string) (int, bool) {
	for _, line := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(line, ":")
		if !ok || strings.TrimSpace(k) != "STATE" {
			continue
		}
		f := strings.Fields(v)
		if len(f) == 0 {
			return 0, false
		}
		n, err := strconv.Atoi(f[0])
		if err != nil || n < 1 || n > 7 {
			return 0, false
		}
		return n, true
	}
	return 0, false
}

func scMissing(out string) bool {
	return strings.Contains(out, scMissingCode)
}

func (a *Agent) winState(ctx context.Context, name string) string {
	out, _ := a.run(ctx, quick, config.WinSC, "query", name)
	if scMissing(out) {
		return "inactive"
	}
	n, ok := parseSCState(out)
	if !ok {
		return "unknown"
	}
	switch n {
	case 1, 7:
		return "inactive"
	case 2, 5:
		return "activating"
	case 3, 6:
		return "deactivating"
	case 4:
		return "active"
	}
	return "unknown"
}

func (a *Agent) winWait(ctx context.Context, name, want string) error {
	for i := 0; i < winWaitTries; i++ {
		st := a.winState(ctx, name)
		if st == want {
			return nil
		}
		if want == "active" && st == "inactive" && i > 2 {
			return fmt.Errorf("%s stopped right after starting", name)
		}
		if err := a.Sleep(ctx, time.Second); err != nil {
			return err
		}
	}
	return fmt.Errorf("%s did not become %s", name, want)
}

func (a *Agent) winStart(ctx context.Context, name string) error {
	out, err := a.sc(ctx, "start", name)
	if err != nil && !strings.Contains(out, scRunningCode) {
		return err
	}
	return a.winWait(ctx, name, "active")
}

func (a *Agent) winStop(ctx context.Context, name string) error {
	out, err := a.sc(ctx, "stop", name)
	if err != nil && !strings.Contains(out, scNotActiveCode) && !scMissing(out) {
		return err
	}
	if scMissing(out) {
		return nil
	}
	return a.winWait(ctx, name, "inactive")
}

func (a *Agent) winRestart(ctx context.Context, name string) error {
	if err := a.winStop(ctx, name); err != nil {
		return err
	}
	return a.winStart(ctx, name)
}

func (a *Agent) winRegister(ctx context.Context, svc render.WinService, start string) (bool, error) {
	bin, err := svc.BinPath()
	if err != nil {
		return false, err
	}
	out, _ := a.run(ctx, quick, config.WinSC, "query", svc.Name)
	created := scMissing(out)
	verb := "config"
	if created {
		verb = "create"
	}
	args := []string{verb, svc.Name, "binPath=", bin, "start=", start, "obj=", svc.Account(), "DisplayName=", svc.Display}
	if created {
		args = append(args, "type=", "own")
	}
	if _, err := a.sc(ctx, args...); err != nil {
		return false, err
	}
	for _, extra := range [][]string{
		{"description", svc.Name, svc.Desc},
		{"failure", svc.Name, "reset=", "86400", "actions=", "restart/5000/restart/10000/restart/30000"},
		{"failureflag", svc.Name, "1"},
		{"sidtype", svc.Name, "unrestricted"},
	} {
		if _, err := a.sc(ctx, extra...); err != nil {
			return false, err
		}
	}
	return created, nil
}

func (a *Agent) winServices(ctx context.Context, s config.Settings) (string, error) {
	created := []string{}
	for _, svc := range render.WinServices() {
		start := winStartAuto
		if svc.Name == config.WinServiceTCP && !s.Stealth {
			start = winStartDisabled
		}
		c, err := a.winRegister(ctx, svc, start)
		if err != nil {
			return "", err
		}
		if c {
			created = append(created, svc.Name)
		}
	}
	if len(created) == 0 {
		return "registered", nil
	}
	return "created " + strings.Join(created, ", "), nil
}

func (a *Agent) icacls(ctx context.Context, path string, dir bool, grants []winacl.Grant) error {
	args, err := winacl.IcaclsArgs(path, dir, grants)
	if err != nil {
		return err
	}
	_, err = a.run(ctx, quick, config.WinIcacls, args...)
	return err
}

func (a *Agent) winDirs(ctx context.Context) (string, error) {
	for _, d := range render.WinDirs() {
		if err := os.MkdirAll(a.path(d), 0o755); err != nil {
			return "", err
		}
		grants, err := render.WinGrants(d)
		if err != nil {
			return "", err
		}
		if err := a.icacls(ctx, d, true, grants); err != nil {
			return "", err
		}
	}
	return "folders locked to SYSTEM, Administrators and Veyl services", nil
}

func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func (a *Agent) winPKI(ctx context.Context) (string, error) {
	data := a.Paths.Data
	for _, f := range []string{pki.CAFile, pki.CAKeyFile, pki.ServerCertFile, pki.ServerKeyFile, pki.CRLFile} {
		if !a.exists(config.Join(data, f)) {
			return "", fmt.Errorf("%s missing, run veyl init", f)
		}
	}
	done := []string{}
	v2 := config.Join(data, render.TLSCryptV2Server)
	if !a.exists(v2) {
		if _, err := a.run(ctx, quick, config.WinOpenVPNBin, "--genkey", "tls-crypt-v2-server", v2); err != nil {
			return "", err
		}
		done = append(done, "created tls-crypt-v2 server key")
	}
	for _, inst := range []string{config.InstanceUDP, config.InstanceTCP} {
		pw := a.Paths.MgmtPassword(inst)
		if !a.exists(pw) {
			tok, err := randomToken(32)
			if err != nil {
				return "", err
			}
			if err := writeAtomic(a.path(pw), []byte(tok+"\n"), 0o600); err != nil {
				return "", err
			}
			done = append(done, "created management password "+inst)
		}
		if err := a.icacls(ctx, pw, false, render.WinMgmtGrants()); err != nil {
			return "", err
		}
	}
	if len(done) == 0 {
		return "ok", nil
	}
	return strings.Join(done, ", "), nil
}

func parseKV(out string) map[string]string {
	m := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(strings.TrimRight(line, "\r"), "=")
		if !ok || k == "" || len(k) > 32 {
			continue
		}
		v = strings.TrimSpace(v)
		if len(v) > 128 {
			v = v[:128]
		}
		m[k] = v
	}
	return m
}

func cleanText(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= 0x20 && r != 0x7f && r != '<' && r != '>' && r != '"' {
			b.WriteRune(r)
		}
	}
	out := strings.TrimSpace(b.String())
	if len(out) > 64 {
		out = out[:64]
	}
	return out
}

func (a *Agent) WinFacts(ctx context.Context) (render.WinFacts, error) {
	var f render.WinFacts
	vout, _ := a.run(ctx, quick, config.WinOpenVPNBin, "--version")
	f.OpenVPNVersion, f.OpenSSLVersion = parseOpenVPNVersion(vout)
	out, err := a.ps(ctx, quick, render.WinFactsScript())
	if err != nil {
		return f, err
	}
	kv := parseKV(out)
	f.OS = cleanText(kv["os"])
	n, err := strconv.Atoi(kv["wan"])
	if err != nil || n < 1 {
		return f, errors.New("no default ipv4 route")
	}
	f.WANIndex = n
	return f, nil
}

func (a *Agent) winAdapter(ctx context.Context, instance string) (string, error) {
	script, err := render.WinAdapterScript(instance)
	if err != nil {
		return "", err
	}
	out, err := a.ps(ctx, quick, script)
	if err != nil {
		return "", err
	}
	desc := parseKV(out)["adapter"]
	name := config.TapName(instance)
	if desc != "" {
		if !strings.Contains(strings.ToLower(desc), "tap-windows") {
			return "", fmt.Errorf("an adapter named %q exists but is not a TAP-Windows adapter, remove or rename it", name)
		}
		return "present", nil
	}
	if _, err := a.run(ctx, service, config.WinTapctl, "create", "--name", name, "--hwid", config.TapHWID); err != nil {
		return "", err
	}
	return "created", nil
}

func (a *Agent) winAdapters(ctx context.Context, s config.Settings) (string, error) {
	insts := []string{config.InstanceUDP}
	if s.Stealth {
		insts = append(insts, config.InstanceTCP)
	}
	parts := []string{}
	for _, in := range insts {
		d, err := a.winAdapter(ctx, in)
		if err != nil {
			return "", err
		}
		parts = append(parts, config.TapName(in)+" "+d)
	}
	return strings.Join(parts, ", "), nil
}

func (a *Agent) winNetwork(ctx context.Context, f render.WinFacts) (string, error) {
	script, err := render.WinNetworkScript(f)
	if err != nil {
		return "", err
	}
	out, err := a.ps(ctx, service, script)
	if err != nil {
		return "", err
	}
	detail := "forwarding on"
	if strings.Contains(out, "nat created") {
		detail += ", nat created"
	}
	return detail, nil
}

func (a *Agent) TapUp(ctx context.Context, instance string) error {
	a.init()
	script, err := render.WinTapScript(instance)
	if err != nil {
		return err
	}
	_, err = a.ps(ctx, service, script)
	return err
}

func (a *Agent) winFirewall(ctx context.Context, s config.Settings) (string, error) {
	script, err := render.WinFirewallScript(s)
	if err != nil {
		return "", err
	}
	if _, err := a.ps(ctx, service, script); err != nil {
		return "", err
	}
	return "rules in group " + config.FirewallGroup + ", logging off", nil
}

type winDeployment struct {
	files   []fileOut
	check   func() error
	service string
	restart bool
}

func (a *Agent) winDeploy(ctx context.Context, d winDeployment) (string, error) {
	t := a.txn()
	for _, f := range d.files {
		if _, err := t.put(f.path, f.data, f.mode); err != nil {
			_ = t.rollback()
			return "", err
		}
	}
	if d.check != nil {
		if err := d.check(); err != nil {
			_ = t.rollback()
			return "", fmt.Errorf("%w (previous configuration kept)", err)
		}
	}
	if d.service == "" {
		if t.changed() {
			return "updated", nil
		}
		return "unchanged", nil
	}
	if !t.changed() && !d.restart && a.winState(ctx, d.service) == "active" {
		return "unchanged", nil
	}
	err := a.winRestart(ctx, d.service)
	if err == nil {
		if t.changed() {
			return "updated", nil
		}
		return "started", nil
	}
	if !t.changed() {
		return "", err
	}
	restorable := false
	for _, c := range t.changes {
		restorable = restorable || c.existed
	}
	if rerr := t.rollback(); rerr != nil {
		return "", errors.Join(err, rerr)
	}
	if restorable {
		_ = a.winRestart(ctx, d.service)
		return "", fmt.Errorf("%w (previous configuration restored)", err)
	}
	return "", err
}

func (a *Agent) winUnbound(ctx context.Context, s config.Settings) (string, error) {
	data, err := render.WinUnbound(s)
	if err != nil {
		return "", err
	}
	anchor := render.WinUnboundAnchor()
	if !a.exists(anchor) {
		src := config.Join(config.WinUnboundDir, "root.key")
		b, err := os.ReadFile(a.path(src))
		if err != nil {
			return "", fmt.Errorf("unbound root key missing: %w", err)
		}
		if err := writeAtomic(a.path(anchor), b, 0o644); err != nil {
			return "", err
		}
	}
	conf := render.WinUnboundPath()
	return a.winDeploy(ctx, winDeployment{
		files: []fileOut{{conf, data, 0o644}},
		check: func() error {
			_, err := a.run(ctx, quick, config.Join(config.WinUnboundDir, "unbound-checkconf.exe"), conf)
			return err
		},
		service: config.WinServiceUnbnd,
	})
}

func (a *Agent) winCaddy(ctx context.Context, s config.Settings) (string, error) {
	data, err := render.WinCaddyfile(s)
	if err != nil {
		return "", err
	}
	file := render.WinCaddyfilePath()
	return a.winDeploy(ctx, winDeployment{
		files: []fileOut{{file, data, 0o644}},
		check: func() error {
			_, err := a.run(ctx, quick, config.WinCaddyBin, "validate", "--config", file, "--adapter", "caddyfile")
			return err
		},
		service: config.WinServiceCaddy,
	})
}

func (a *Agent) winOpenVPN(ctx context.Context, s config.Settings, f render.WinFacts, instance string) (string, error) {
	data, err := render.WinOpenVPN(s, f, instance)
	if err != nil {
		return "", err
	}
	svc := config.WinServiceUDP
	if instance == config.InstanceTCP {
		svc = config.WinServiceTCP
	}
	return a.winDeploy(ctx, winDeployment{
		files:   []fileOut{{render.WinOpenVPNPath(instance), data, 0o640}},
		service: svc,
	})
}

func (a *Agent) winStealthOff(ctx context.Context) (string, error) {
	if err := a.winStop(ctx, config.WinServiceTCP); err != nil {
		return "", err
	}
	removed, err := a.remove(render.WinOpenVPNPath(config.InstanceTCP))
	if err != nil {
		return "", err
	}
	if removed {
		return "stealth disabled", nil
	}
	return "stealth off", nil
}

func (a *Agent) winFont(ctx context.Context) (string, error) {
	if FontURL == "" || FontSHA256 == "" {
		return "", skip("no font source configured")
	}
	dst := config.Join(a.Paths.Fonts(), fontFile)
	want, err := hex.DecodeString(FontSHA256)
	if err != nil || len(want) != sha256.Size {
		return "", errors.New("invalid font checksum")
	}
	if b, err := os.ReadFile(a.path(dst)); err == nil {
		if sum := sha256.Sum256(b); string(sum[:]) == string(want) {
			return "present", nil
		}
	}
	if !strings.HasPrefix(FontURL, "https://") {
		return "", errors.New("font url must be https")
	}
	c, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(c, http.MethodGet, FontURL, nil)
	if err != nil {
		return "", err
	}
	resp, err := a.HTTP.Do(req)
	if err != nil {
		return "", skip("font download failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", skip("font download returned %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxFontSize+1))
	if err != nil || len(b) > maxFontSize {
		return "", skip("font download too large or interrupted")
	}
	if sum := sha256.Sum256(b); string(sum[:]) != string(want) {
		return "", errors.New("font checksum mismatch")
	}
	if err := writeAtomic(a.path(dst), b, 0o644); err != nil {
		return "", err
	}
	return "installed", nil
}

func (a *Agent) winStartCore(ctx context.Context) (string, error) {
	for _, name := range []string{config.WinServiceAgent, config.WinServiceVeyl} {
		if a.winState(ctx, name) == "active" {
			continue
		}
		if err := a.winStart(ctx, name); err != nil {
			return "", err
		}
	}
	return "running", nil
}

func (a *Agent) mgmtState(instance string) (string, error) {
	if a.MgmtState != nil {
		return a.MgmtState(instance)
	}
	c := &ovpn.Client{Socket: fmt.Sprintf("%s%s:%d", ovpn.TCPPrefix, config.MgmtHost, config.MgmtPort(instance)), PasswordFile: a.path(a.Paths.MgmtPassword(instance))}
	return c.State()
}

func (a *Agent) waitTunnel(ctx context.Context, instance string) error {
	for i := 0; i < winWaitTries; i++ {
		if st, err := a.mgmtState(instance); err == nil && st == "CONNECTED" {
			return nil
		}
		if err := a.Sleep(ctx, time.Second); err != nil {
			return err
		}
	}
	return fmt.Errorf("openvpn %s did not finish starting", instance)
}

func (a *Agent) winDNSFilter(ctx context.Context) (string, error) {
	if err := a.waitTunnel(ctx, config.InstanceUDP); err != nil {
		return "", err
	}
	if err := a.TapUp(ctx, config.InstanceUDP); err != nil {
		return "", err
	}
	if err := a.winRestart(ctx, config.WinServiceDNS); err != nil {
		return "", err
	}
	return "restarted", nil
}

func parseWinListeners(out string) []listener {
	var ls []listener
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) != 3 || (f[0] != "tcp" && f[0] != "udp") {
			continue
		}
		p, err := strconv.Atoi(f[2])
		if err != nil || p <= 0 || p > 65535 {
			continue
		}
		addr := f[1]
		if i := strings.Index(addr, "%"); i >= 0 {
			addr = addr[:i]
		}
		ls = append(ls, listener{proto: f[0], addr: addr, port: p})
	}
	return ls
}

func (a *Agent) winVerifyPorts(ctx context.Context, s config.Settings) (string, error) {
	want := []expect{
		{"udp", "", s.UDPPort},
		{"tcp", "", 80},
		{"tcp", "", 443},
		{"tcp", "127.0.0.1", 8080},
		{"udp", "127.0.0.1", 5335},
		{"tcp", "127.0.0.1", 5335},
		{"udp", config.DNSPrefix + ".1", 53},
		{"tcp", config.DNSPrefix + ".1", 53},
		{"tcp", config.MgmtHost, config.MgmtPortUDP},
	}
	if s.Stealth {
		want = append(want, expect{"tcp", "", s.StealthTCPPortFor(config.PlatformWindows)}, expect{"tcp", config.MgmtHost, config.MgmtPortTCP})
	}
	deadline := time.Now().Add(a.VerifyTimeout)
	for {
		out, err := a.ps(ctx, quick, render.WinListenersScript())
		if err != nil {
			return "", err
		}
		ls := parseWinListeners(out)
		var missing []string
		for _, e := range want {
			if !matches(ls, e) {
				missing = append(missing, e.String())
			}
		}
		if len(missing) == 0 {
			return fmt.Sprintf("%d listeners ok", len(want)), nil
		}
		if time.Now().After(deadline) {
			return "", fmt.Errorf("not listening: %s", strings.Join(missing, ", "))
		}
		if err := a.Sleep(ctx, 2*time.Second); err != nil {
			return "", err
		}
	}
}

type winStep struct {
	name string
	fn   func() (string, error)
}

func runSteps(emit Emit, steps []winStep) error {
	for _, st := range steps {
		if err := step(emit, st.name, st.fn); err != nil {
			return err
		}
	}
	return nil
}

func (a *Agent) winApply(ctx context.Context, emit Emit) error {
	a.init()
	var s config.Settings
	var f render.WinFacts
	return runSteps(emit, []winStep{
		{"settings", func() (string, error) {
			var err error
			s, err = a.settings()
			if err != nil {
				return "", err
			}
			if s.Host == "" {
				return "", errors.New("no server address configured")
			}
			s.Configured = true
			return s.Host, s.Validate()
		}},
		{"system", func() (string, error) {
			var err error
			f, err = a.WinFacts(ctx)
			if err != nil {
				return "", err
			}
			if _, ok := render.ParseVersion(f.OpenVPNVersion); !ok {
				return "", errors.New("openvpn is not installed")
			}
			return fmt.Sprintf("openvpn %s, openssl %s, wan interface %d, %s", f.OpenVPNVersion, f.OpenSSLVersion, f.WANIndex, f.OS), nil
		}},
		{"services", func() (string, error) { return a.winServices(ctx, s) }},
		{"directories", func() (string, error) { return a.winDirs(ctx) }},
		{"certificates", func() (string, error) { return a.winPKI(ctx) }},
		{"adapters", func() (string, error) { return a.winAdapters(ctx, s) }},
		{"network", func() (string, error) { return a.winNetwork(ctx, f) }},
		{"firewall", func() (string, error) { return a.winFirewall(ctx, s) }},
		{"resolver", func() (string, error) { return a.winUnbound(ctx, s) }},
		{"blocklists", func() (string, error) {
			d, _, err := a.stepBlocklists(ctx, false)
			if err != nil && !errors.Is(err, errSkip) {
				return "", skip("download failed, retried daily: %v", err)
			}
			return d, err
		}},
		{"fonts", func() (string, error) { return a.winFont(ctx) }},
		{"stealth-off", func() (string, error) {
			if s.Stealth {
				return "", skip("stealth on")
			}
			return a.winStealthOff(ctx)
		}},
		{"web", func() (string, error) { return a.winCaddy(ctx, s) }},
		{"vpn-udp", func() (string, error) { return a.winOpenVPN(ctx, s, f, config.InstanceUDP) }},
		{"vpn-tcp", func() (string, error) {
			if !s.Stealth {
				return "", skip("stealth off")
			}
			return a.winOpenVPN(ctx, s, f, config.InstanceTCP)
		}},
		{"updates", func() (string, error) { return "", skip("Windows Update manages system updates") }},
		{"dns-filter", func() (string, error) { return a.winDNSFilter(ctx) }},
		{"services-start", func() (string, error) { return a.winStartCore(ctx) }},
		{"verify-ports", func() (string, error) { return a.winVerifyPorts(ctx, s) }},
		{"verify-dns", func() (string, error) { return a.verifyDNS(ctx) }},
		{"verify-https", func() (string, error) { return a.waitHealth(ctx, emit, "verify-https", s, a.HealthTimeout) }},
	})
}

func (a *Agent) winTLS(ctx context.Context, emit Emit) error {
	a.init()
	var s config.Settings
	return runSteps(emit, []winStep{
		{"settings", func() (string, error) {
			var err error
			s, err = a.settings()
			if err != nil {
				return "", err
			}
			if s.Host == "" {
				return "", errors.New("no server address configured")
			}
			return s.Host, nil
		}},
		{"web", func() (string, error) { return a.winCaddy(ctx, s) }},
		{"certificate", func() (string, error) { return a.waitHealth(ctx, emit, "certificate", s, a.HealthTimeout) }},
	})
}

func (a *Agent) winDNSUpdate(ctx context.Context, emit Emit) (map[string]string, error) {
	a.init()
	var counts map[string]int
	if err := runSteps(emit, []winStep{
		{"blocklists", func() (string, error) {
			d, c, err := a.stepBlocklists(ctx, true)
			counts = c
			return d, err
		}},
		{"dns-filter", func() (string, error) {
			if a.winState(ctx, config.WinServiceDNS) != "active" {
				return "", skip("not running")
			}
			return a.winDNSFilter(ctx)
		}},
	}); err != nil {
		return nil, err
	}
	data := map[string]string{}
	for k, v := range counts {
		data["blocklist."+k] = strconv.Itoa(v)
	}
	return data, nil
}

func (a *Agent) winRestartAll(ctx context.Context, emit Emit) error {
	a.init()
	s, err := a.settings()
	if err != nil {
		return err
	}
	names := []string{config.WinServiceUnbnd, config.WinServiceDNS, config.WinServiceUDP}
	if s.Stealth {
		names = append(names, config.WinServiceTCP)
	}
	names = append(names, config.WinServiceCaddy)
	steps := []winStep{}
	for _, n := range names {
		svc, _ := render.FindWinService(n)
		steps = append(steps, winStep{svc.Key, func() (string, error) { return "restarted", a.winRestart(ctx, n) }})
	}
	steps = append(steps, winStep{"veyl", func() (string, error) {
		a.Async(func() {
			c, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			_ = a.Sleep(c, time.Second)
			_ = a.winRestart(c, config.WinServiceVeyl)
		})
		return "restart queued", nil
	}})
	return runSteps(emit, steps)
}

func (a *Agent) winStatus(ctx context.Context) (map[string]string, error) {
	a.init()
	data := map[string]string{"platform": config.PlatformWindows}
	for _, svc := range render.WinServices() {
		data["service."+svc.Key] = a.winState(ctx, svc.Name)
	}
	data["service.nftables"] = a.winState(ctx, "mpssvc")
	vout, _ := a.run(ctx, quick, config.WinOpenVPNBin, "--version")
	ovpn, ssl := parseOpenVPNVersion(vout)
	data["openvpn"] = ovpn
	data["openssl"] = ssl
	data["post_quantum"] = strconv.FormatBool(render.WinPostQuantum(render.WinFacts{OpenSSLVersion: ssl}))
	if out, err := a.ps(ctx, quick, render.WinStatusScript()); err == nil {
		kv := parseKV(out)
		data["distro"] = cleanText(kv["os"])
		for src, dst := range map[string]string{"uptime": "uptime", "mem_total": "mem_memtotal", "mem_avail": "mem_memavailable", "disk_total": "disk_total", "disk_free": "disk_free"} {
			if v, err := strconv.ParseUint(kv[src], 10, 64); err == nil {
				data[dst] = strconv.FormatUint(v, 10)
			}
		}
		fw := "inactive"
		if n, err := strconv.Atoi(kv["firewall"]); err == nil && n > 0 {
			fw = "active"
		}
		data["service.veyl-firewall"] = fw
	} else {
		data["service.veyl-firewall"] = "unknown"
	}
	pctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	if ip, err := a.Probe.PublicIP(pctx, false); err == nil {
		data["public_ipv4"] = ip
	}
	if s, err := a.settings(); err == nil && s.Host != "" {
		data["host"] = s.Host
		data["stealth_port"] = strconv.Itoa(s.StealthTCPPortFor(config.PlatformWindows))
		if exp, err := a.Probe.CertExpiry(pctx, s.Host); err == nil {
			data["cert_expiry"] = exp.UTC().Format(time.RFC3339)
		}
	}
	displayAliases(data)
	return data, nil
}

func (a *Agent) winBootstrap(ctx context.Context, emit Emit, domain, email string) error {
	if emit == nil {
		emit = func(agentapi.Event) {}
	}
	if domain != "" || email != "" {
		if err := step(emit, "address", func() (string, error) { return a.seed(domain, email) }); err != nil {
			return err
		}
	}
	s, err := a.settings()
	if err != nil {
		return err
	}
	if s.Configured {
		return a.winApply(ctx, emit)
	}
	var f render.WinFacts
	if err := runSteps(emit, []winStep{
		{"system", func() (string, error) {
			var err error
			f, err = a.WinFacts(ctx)
			if err != nil {
				return "", err
			}
			return fmt.Sprintf("openvpn %s, openssl %s, wan interface %d, %s", f.OpenVPNVersion, f.OpenSSLVersion, f.WANIndex, f.OS), nil
		}},
		{"services", func() (string, error) { return a.winServices(ctx, s) }},
		{"directories", func() (string, error) { return a.winDirs(ctx) }},
		{"certificates", func() (string, error) { return a.winPKI(ctx) }},
		{"firewall", func() (string, error) { return a.winFirewall(ctx, s) }},
		{"services-start", func() (string, error) { return a.winStartCore(ctx) }},
		{"web", func() (string, error) { return a.winCaddy(ctx, setupMode(s)) }},
	}); err != nil {
		return err
	}
	if s.Host == "" {
		return nil
	}
	return step(emit, "https", func() (string, error) {
		if _, err := a.winCaddy(ctx, s); err != nil {
			return "", err
		}
		d, err := a.waitHealth(ctx, emit, "https", s, a.HealthTimeout)
		if err != nil {
			_, _ = a.winCaddy(ctx, setupMode(s))
			return "", skip("could not get a certificate for %s yet, setup continues over http: %v", s.Host, err)
		}
		return d, nil
	})
}

func (a *Agent) winUninstall(ctx context.Context, emit Emit, purge bool) error {
	if emit == nil {
		emit = func(agentapi.Event) {}
	}
	_ = step(emit, "services", func() (string, error) {
		for _, svc := range render.WinServices() {
			if svc.Name == config.WinServiceAgent {
				continue
			}
			_ = a.winStop(ctx, svc.Name)
			_, _ = a.sc(ctx, "delete", svc.Name)
		}
		return "removed", nil
	})
	_ = step(emit, "network", func() (string, error) {
		if _, err := a.ps(ctx, service, render.WinUninstallScript()); err != nil {
			return "", err
		}
		return "firewall rules, nat and dns addresses removed", nil
	})
	_ = step(emit, "adapters", func() (string, error) {
		for _, n := range []string{config.TapUDP, config.TapTCP} {
			_, _ = a.run(ctx, service, config.WinTapctl, "delete", n)
		}
		return "removed", nil
	})
	_ = step(emit, "files", func() (string, error) {
		for _, d := range []string{config.WinConfDir, config.WinUnboundData, config.WinCaddyData, a.Paths.Run} {
			_ = os.RemoveAll(a.path(d))
		}
		return "removed", nil
	})
	if purge {
		_ = step(emit, "data", func() (string, error) {
			if err := os.RemoveAll(a.path(config.WinRoot)); err != nil {
				return "", err
			}
			return "removed " + config.WinRoot, nil
		})
	} else {
		emit(agentapi.Event{Step: "data", Status: agentapi.StatusSkip, Detail: "kept " + a.Paths.Data})
	}
	_ = step(emit, "agent", func() (string, error) {
		_ = a.winStop(ctx, config.WinServiceAgent)
		_, _ = a.sc(ctx, "delete", config.WinServiceAgent)
		return "removed", nil
	})
	return nil
}

func (a *Agent) DailyBlocklists(ctx context.Context) {
	a.init()
	t := time.NewTimer(10 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		_, _ = a.Do(ctx, agentapi.OpDNSUpdate, nil)
		t.Reset(24 * time.Hour)
	}
}
