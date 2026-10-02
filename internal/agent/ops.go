package agent

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/veylvpn/backend/internal/agentapi"
	"github.com/veylvpn/backend/internal/config"
	"github.com/veylvpn/backend/internal/pki"
	"github.com/veylvpn/backend/internal/render"
)

type fileOut struct {
	path string
	data string
	mode os.FileMode
}

type deployment struct {
	files   []fileOut
	check   func() error
	unit    string
	action  string
	enable  bool
	restart bool
}

func (a *Agent) deploy(ctx context.Context, d deployment) (string, error) {
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
	if d.unit == "" {
		if t.changed() {
			return "updated", nil
		}
		return "unchanged", nil
	}
	if d.enable {
		if err := a.systemctl(ctx, "enable", d.unit); err != nil {
			_ = t.rollback()
			return "", err
		}
	}
	if !t.changed() && !d.restart && a.active(ctx, d.unit) {
		return "unchanged", nil
	}
	action := d.action
	if action == "" {
		action = "restart"
	}
	err := a.systemctl(ctx, action, d.unit)
	if err == nil && !a.active(ctx, d.unit) {
		err = fmt.Errorf("%s is not running", d.unit)
	}
	if err == nil {
		if t.changed() {
			return "updated", nil
		}
		return "started", nil
	}
	restorable := false
	for _, c := range t.changes {
		restorable = restorable || c.existed
	}
	if !t.changed() {
		return "", err
	}
	if rerr := t.rollback(); rerr != nil {
		return "", errors.Join(err, rerr)
	}
	if restorable {
		_ = a.systemctl(ctx, action, d.unit)
		return "", fmt.Errorf("%w (previous configuration restored)", err)
	}
	return "", err
}

func (a *Agent) ids() (int, int, error) {
	uid, gid, err := a.Lookup(config.ServiceUser)
	if err != nil {
		return 0, 0, fmt.Errorf("user %s missing: %w", config.ServiceUser, err)
	}
	return uid, gid, nil
}

func (a *Agent) stepUsers(ctx context.Context) (string, error) {
	created := []string{}
	if _, err := a.run(ctx, quick, "getent", "group", config.ServiceUser); err != nil {
		if _, err := a.run(ctx, quick, "groupadd", "--system", config.ServiceUser); err != nil {
			return "", err
		}
		created = append(created, "group "+config.ServiceUser)
	}
	if _, err := a.run(ctx, quick, "getent", "passwd", config.ServiceUser); err != nil {
		if _, err := a.run(ctx, quick, "useradd", "--system", "--gid", config.ServiceUser, "--home-dir", config.DataDir, "--no-create-home", "--shell", "/usr/sbin/nologin", config.ServiceUser); err != nil {
			return "", err
		}
		created = append(created, config.ServiceUser)
	}
	if _, err := a.run(ctx, quick, "getent", "passwd", config.OpenVPNUser); err != nil {
		if _, err := a.run(ctx, quick, "useradd", "--system", "--gid", config.ServiceUser, "--home-dir", "/nonexistent", "--no-create-home", "--shell", "/usr/sbin/nologin", config.OpenVPNUser); err != nil {
			return "", err
		}
		created = append(created, config.OpenVPNUser)
	}
	if len(created) == 0 {
		return "unchanged", nil
	}
	return "created " + strings.Join(created, ", "), nil
}

func (a *Agent) stepDirs(ctx context.Context) (string, error) {
	uid, gid, err := a.ids()
	if err != nil {
		return "", err
	}
	if err := a.ensureDir(a.Paths.Data, 0o750, uid, gid); err != nil {
		return "", err
	}
	if err := a.ensureDir(a.Paths.Blocklists(), 0o755, 0, 0); err != nil {
		return "", err
	}
	if err := a.ensureDir(render.EtcDir, 0o755, 0, 0); err != nil {
		return "", err
	}
	if err := a.ensureDir(a.Paths.Run, 0o770|os.ModeSetgid, 0, gid); err != nil {
		return "", err
	}
	t := a.txn()
	if _, err := t.put(render.TmpfilesFile, render.Tmpfiles(), 0o644); err != nil {
		return "", err
	}
	return "ok", nil
}

func (a *Agent) stepPKI(ctx context.Context) (string, error) {
	uid, gid, err := a.ids()
	if err != nil {
		return "", err
	}
	data := a.Paths.Data
	for _, f := range []string{pki.CAFile, pki.CAKeyFile, pki.ServerCertFile, pki.ServerKeyFile, pki.CRLFile} {
		if !a.exists(filepath.Join(data, f)) {
			return "", fmt.Errorf("%s missing, run veyl init", f)
		}
	}
	detail := "ok"
	v2 := filepath.Join(data, render.TLSCryptV2Server)
	if !a.exists(v2) {
		if _, err := a.run(ctx, quick, "openvpn", "--genkey", "tls-crypt-v2-server", v2); err != nil {
			return "", err
		}
		detail = "created tls-crypt-v2 server key"
	}
	perms := []struct {
		name     string
		mode     os.FileMode
		uid, gid int
	}{
		{pki.CAFile, 0o644, uid, gid},
		{pki.CAKeyFile, 0o600, uid, gid},
		{pki.ServerCertFile, 0o644, uid, gid},
		{pki.ServerKeyFile, 0o600, uid, gid},
		{pki.CRLFile, 0o644, uid, gid},
		{render.TLSCryptV2Server, 0o640, 0, gid},
		{"settings.json", 0o600, uid, gid},
		{"state.json", 0o600, uid, gid},
		{"admin.json", 0o600, uid, gid},
		{"setup-token", 0o600, uid, gid},
	}
	for _, p := range perms {
		path := filepath.Join(data, p.name)
		if !a.exists(path) {
			continue
		}
		if err := a.setPerm(path, p.mode, p.uid, p.gid); err != nil {
			return "", err
		}
	}
	return detail, nil
}

func (a *Agent) stepUnits(ctx context.Context) (string, error) {
	t := a.txn()
	for _, f := range render.Units() {
		if _, err := t.put(f.Path, f.Data, os.FileMode(f.Mode)); err != nil {
			return "", err
		}
	}
	if !t.changed() {
		return "unchanged", nil
	}
	if err := a.systemctl(ctx, "daemon-reload"); err != nil {
		return "", err
	}
	return "updated", nil
}

func (a *Agent) stepSysctl(ctx context.Context, f render.Facts) (string, error) {
	data, err := render.Sysctl(f)
	if err != nil {
		return "", err
	}
	t := a.txn()
	changed, err := t.put(render.SysctlFile, data, 0o644)
	if err != nil {
		return "", err
	}
	_, _ = a.run(ctx, quick, "modprobe", "nf_conntrack")
	if _, err := a.run(ctx, quick, "sysctl", "-e", "-q", "-p", render.SysctlFile); err != nil {
		return "", err
	}
	if changed {
		return "updated", nil
	}
	return "unchanged", nil
}

func (a *Agent) stepPrivacy(ctx context.Context) (string, error) {
	plan := render.PrivacyPlan()
	done := []string{}
	t := a.txn()
	jchanged, err := t.put(render.JournaldFile, render.Journald(), 0o644)
	if err != nil {
		return "", err
	}
	if jchanged {
		if err := a.systemctl(ctx, "restart", "systemd-journald.service"); err != nil {
			return "", err
		}
		done = append(done, "journald")
	}
	for _, u := range plan.Disable {
		_ = a.systemctl(ctx, "disable", "--now", u)
	}
	for _, u := range plan.Mask {
		_ = a.systemctl(ctx, "mask", "--now", u)
	}
	for _, p := range plan.NullLinks {
		full := a.path(p)
		if dst, err := os.Readlink(full); err == nil && dst == "/dev/null" {
			continue
		}
		if err := os.RemoveAll(full); err != nil {
			return "", err
		}
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			return "", err
		}
		if err := os.Symlink("/dev/null", full); err != nil {
			return "", err
		}
		done = append(done, filepath.Base(p))
	}
	for _, p := range plan.Remove {
		if a.exists(p) {
			if err := os.RemoveAll(a.path(p)); err != nil {
				return "", err
			}
			done = append(done, "removed "+filepath.Base(p))
		}
	}
	_, _ = a.run(ctx, quick, "swapoff", "-a")
	if b, err := os.ReadFile(a.path("/etc/fstab")); err == nil {
		if out, changed := render.StripSwap(string(b)); changed {
			ft := a.txn()
			if _, err := ft.put("/etc/fstab", out, 0o644); err != nil {
				return "", err
			}
			done = append(done, "swap disabled")
		}
	}
	if fi, err := os.Stat(a.path(filepath.Dir(render.SSHDFile))); err == nil && fi.IsDir() {
		st := a.txn()
		changed, err := st.put(render.SSHDFile, render.SSHD(), 0o644)
		if err != nil {
			return "", err
		}
		if changed {
			if _, err := a.run(ctx, quick, "sshd", "-t"); err != nil {
				_ = st.rollback()
				return "", fmt.Errorf("sshd rejected the drop-in, left unchanged: %w", err)
			}
			if a.systemctl(ctx, "reload", "ssh.service") != nil {
				_ = a.systemctl(ctx, "reload", "sshd.service")
			}
			done = append(done, "sshd quiet")
		}
	}
	if len(done) == 0 {
		return "unchanged", nil
	}
	return strings.Join(done, ", "), nil
}

func (a *Agent) stepFirewall(ctx context.Context, s config.Settings, f render.Facts) (string, error) {
	data, err := render.NFTables(s, f)
	if err != nil {
		return "", err
	}
	return a.deploy(ctx, deployment{
		files: []fileOut{{render.NFTFile, data, 0o600}},
		check: func() error {
			_, err := a.run(ctx, quick, "nft", "-c", "-f", render.NFTFile)
			return err
		},
		unit:   render.UnitFirewall,
		action: "reload-or-restart",
		enable: true,
	})
}

func (a *Agent) stepDNSIf(ctx context.Context) (string, error) {
	return a.deploy(ctx, deployment{
		files: []fileOut{
			{render.DNSIfFile, render.DNSInterface(), 0o644},
			{render.DNSIfDownFile, render.DNSInterfaceDown(), 0o644},
		},
		unit:   render.UnitDNSIf,
		enable: true,
	})
}

func (a *Agent) stepUnbound(ctx context.Context, s config.Settings, f render.Facts) (string, error) {
	data, err := render.Unbound(s, f)
	if err != nil {
		return "", err
	}
	_ = a.systemctl(ctx, "disable", "--now", "unbound-resolvconf.service")
	return a.deploy(ctx, deployment{
		files: []fileOut{{render.UnboundFile, data, 0o644}},
		check: func() error {
			_, err := a.run(ctx, quick, "unbound-checkconf")
			return err
		},
		unit:   render.UnitUnbound,
		enable: true,
	})
}

func (a *Agent) stepBlocklists(ctx context.Context, force bool) (string, map[string]int, error) {
	dir := a.Paths.Blocklists()
	if !force {
		if m, _ := filepath.Glob(filepath.Join(a.path(dir), "*.txt")); len(m) > 0 {
			return "present", nil, nil
		}
	}
	dl := a.download()
	if dl == nil {
		return "", nil, skip("blocklist downloader not available")
	}
	if err := a.ensureDir(dir, 0o755, 0, 0); err != nil {
		return "", nil, err
	}
	c, cancel := context.WithTimeout(ctx, slow)
	defer cancel()
	counts, err := dl(c, a.path(dir), a.HTTP)
	if err != nil && len(counts) == 0 {
		return "", nil, err
	}
	cats := make([]string, 0, len(counts))
	total := 0
	for k, v := range counts {
		cats = append(cats, fmt.Sprintf("%s %d", k, v))
		total += v
	}
	sort.Strings(cats)
	detail := fmt.Sprintf("%d entries", total)
	if len(cats) > 0 {
		detail += " (" + strings.Join(cats, ", ") + ")"
	}
	return detail, counts, nil
}

func (a *Agent) saveCaddyOrig() error {
	orig := render.CaddyFile + ".veyl-orig"
	if a.exists(orig) || !a.exists(render.CaddyFile) {
		return nil
	}
	b, err := os.ReadFile(a.path(render.CaddyFile))
	if err != nil {
		return err
	}
	return writeAtomic(a.path(orig), b, 0o644)
}

func (a *Agent) stepCaddy(ctx context.Context, s config.Settings, stealth bool) (string, error) {
	data, err := render.Caddyfile(s, stealth)
	if err != nil {
		return "", err
	}
	if err := a.saveCaddyOrig(); err != nil {
		return "", err
	}
	return a.deploy(ctx, deployment{
		files: []fileOut{{render.CaddyFile, data, 0o644}},
		check: func() error {
			_, err := a.run(ctx, quick, "caddy", "validate", "--config", render.CaddyFile, "--adapter", "caddyfile")
			return err
		},
		unit:   render.UnitCaddy,
		enable: true,
	})
}

func (a *Agent) stopTCP(ctx context.Context) (string, error) {
	_ = a.systemctl(ctx, "disable", "--now", render.UnitOpenVPNTCP)
	removed, err := a.remove(render.OpenVPNPath(config.InstanceTCP))
	if err != nil {
		return "", err
	}
	if removed {
		return "stealth disabled", nil
	}
	return "stealth off", nil
}

func (a *Agent) stepOpenVPN(ctx context.Context, s config.Settings, f render.Facts, instance, unit string) (string, error) {
	data, err := render.OpenVPN(s, f, instance)
	if err != nil {
		return "", err
	}
	return a.deploy(ctx, deployment{
		files:  []fileOut{{render.OpenVPNPath(instance), data, 0o640}},
		unit:   unit,
		enable: true,
	})
}

func (a *Agent) stepUpdates(s config.Settings) (string, error) {
	data, err := render.Unattended(s)
	if err != nil {
		return "", err
	}
	t := a.txn()
	if _, err := t.put(render.UnattendedFile, data, 0o644); err != nil {
		return "", err
	}
	if s.AutoUpdates {
		return "automatic security updates on", nil
	}
	return "automatic updates off", nil
}

func (a *Agent) stepVeylDNS(ctx context.Context) (string, error) {
	if err := a.systemctl(ctx, "enable", render.UnitDNS); err != nil {
		return "", err
	}
	if a.active(ctx, render.UnitDNS) {
		if err := a.systemctl(ctx, "reload", render.UnitDNS); err != nil {
			return "", err
		}
		return "reloaded", nil
	}
	if err := a.systemctl(ctx, "restart", render.UnitDNS); err != nil {
		return "", err
	}
	if !a.active(ctx, render.UnitDNS) {
		return "", errors.New("veyl-dns is not running")
	}
	return "started", nil
}

func (a *Agent) stepServices(ctx context.Context, start bool) (string, error) {
	units := []string{render.UnitAgent, render.UnitVeyl, render.UnitBlocklistsTmr}
	args := append([]string{"enable"}, units...)
	if start {
		args = append([]string{"enable", "--now"}, units...)
	}
	if err := a.systemctl(ctx, args...); err != nil {
		return "", err
	}
	if !start {
		if err := a.systemctl(ctx, "start", render.UnitBlocklistsTmr); err != nil {
			return "", err
		}
	}
	return "enabled", nil
}

func (a *Agent) listeners(ctx context.Context) ([]listener, error) {
	out, err := a.run(ctx, quick, "ss", "-H", "-lntu")
	if err != nil {
		return nil, err
	}
	var ls []listener
	for _, line := range strings.Split(out, "\n") {
		if l, ok := ssLocal(line); ok {
			ls = append(ls, l)
		}
	}
	return ls, nil
}

type expect struct {
	proto string
	addr  string
	port  int
}

func (e expect) String() string {
	a := e.addr
	if a == "" {
		a = "*"
	}
	return e.proto + " " + a + ":" + strconv.Itoa(e.port)
}

func matches(ls []listener, e expect) bool {
	for _, l := range ls {
		if l.proto != e.proto || l.port != e.port {
			continue
		}
		if e.addr == "" || l.addr == e.addr || l.addr == "*" || l.addr == "0.0.0.0" || l.addr == "::" {
			return true
		}
	}
	return false
}

func (a *Agent) verifyPorts(ctx context.Context, s config.Settings) (string, error) {
	want := []expect{
		{"udp", "", s.UDPPort},
		{"tcp", "", 80},
		{"tcp", "", 443},
		{"tcp", "127.0.0.1", 8080},
		{"udp", "127.0.0.1", 5335},
		{"tcp", "127.0.0.1", 5335},
		{"udp", config.DNSPrefix + ".1", 53},
		{"tcp", config.DNSPrefix + ".1", 53},
	}
	if s.Stealth {
		want = append(want, expect{"tcp", "127.0.0.1", config.CaddyTLSPort})
	}
	deadline := time.Now().Add(a.VerifyTimeout)
	for {
		ls, err := a.listeners(ctx)
		if err != nil {
			return "", err
		}
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

func (a *Agent) verifyDNS(ctx context.Context) (string, error) {
	deadline := time.Now().Add(a.VerifyTimeout)
	for {
		err := a.Probe.DNS(ctx, config.DNSPrefix+".1:53", "example.com")
		if err == nil {
			return "resolver answers", nil
		}
		if time.Now().After(deadline) {
			return "", err
		}
		if err := a.Sleep(ctx, 2*time.Second); err != nil {
			return "", err
		}
	}
}

func (a *Agent) waitHealth(ctx context.Context, emit Emit, name string, s config.Settings, timeout time.Duration) (string, error) {
	if s.Host == "" {
		return "", skip("no server address yet")
	}
	insecure := s.TLS == config.TLSInternal
	start := time.Now()
	last := start
	var err error
	for {
		if err = a.Probe.Health(ctx, s.Host, insecure); err == nil {
			return "https://" + hostPort(s.Host) + " is reachable", nil
		}
		if time.Since(start) > timeout {
			return "", fmt.Errorf("https not reachable after %s: %w", timeout.Round(time.Second), err)
		}
		if time.Since(last) >= 15*time.Second {
			last = time.Now()
			emit(agentapi.Event{Step: name, Status: agentapi.StatusRun, Detail: "waiting for the certificate"})
		}
		if serr := a.Sleep(ctx, 3*time.Second); serr != nil {
			return "", serr
		}
	}
}

func (a *Agent) Apply(ctx context.Context, emit Emit) error {
	a.init()
	var s config.Settings
	var f render.Facts
	steps := []struct {
		name string
		fn   func() (string, error)
	}{
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
			f, err = a.Facts(ctx)
			if err != nil {
				return "", err
			}
			if _, ok := render.ParseVersion(f.OpenVPNVersion); !ok {
				return "", errors.New("openvpn is not installed")
			}
			return fmt.Sprintf("openvpn %s, openssl %s, wan %s, ssh %v", f.OpenVPNVersion, f.OpenSSLVersion, f.WANIface, f.SSHPorts), nil
		}},
		{"users", func() (string, error) { return a.stepUsers(ctx) }},
		{"directories", func() (string, error) { return a.stepDirs(ctx) }},
		{"certificates", func() (string, error) { return a.stepPKI(ctx) }},
		{"units", func() (string, error) { return a.stepUnits(ctx) }},
		{"kernel", func() (string, error) { return a.stepSysctl(ctx, f) }},
		{"privacy", func() (string, error) { return a.stepPrivacy(ctx) }},
		{"firewall", func() (string, error) { return a.stepFirewall(ctx, s, f) }},
		{"dns-addresses", func() (string, error) { return a.stepDNSIf(ctx) }},
		{"resolver", func() (string, error) { return a.stepUnbound(ctx, s, f) }},
		{"blocklists", func() (string, error) {
			d, _, err := a.stepBlocklists(ctx, false)
			if err != nil && !errors.Is(err, errSkip) {
				return "", skip("download failed, retried daily: %v", err)
			}
			return d, err
		}},
		{"stealth-off", func() (string, error) {
			if s.Stealth {
				return "", skip("stealth on")
			}
			return a.stopTCP(ctx)
		}},
		{"web", func() (string, error) { return a.stepCaddy(ctx, s, s.Stealth) }},
		{"vpn-udp", func() (string, error) {
			return a.stepOpenVPN(ctx, s, f, config.InstanceUDP, render.UnitOpenVPNUDP)
		}},
		{"vpn-tcp", func() (string, error) {
			if !s.Stealth {
				return "", skip("stealth off")
			}
			return a.stepOpenVPN(ctx, s, f, config.InstanceTCP, render.UnitOpenVPNTCP)
		}},
		{"updates", func() (string, error) { return a.stepUpdates(s) }},
		{"dns-filter", func() (string, error) { return a.stepVeylDNS(ctx) }},
		{"services", func() (string, error) { return a.stepServices(ctx, false) }},
		{"verify-ports", func() (string, error) { return a.verifyPorts(ctx, s) }},
		{"verify-dns", func() (string, error) { return a.verifyDNS(ctx) }},
		{"verify-https", func() (string, error) { return a.waitHealth(ctx, emit, "verify-https", s, a.HealthTimeout) }},
	}
	for _, st := range steps {
		if err := step(emit, st.name, st.fn); err != nil {
			return err
		}
	}
	return nil
}

func (a *Agent) TLS(ctx context.Context, emit Emit) error {
	a.init()
	var s config.Settings
	if err := step(emit, "settings", func() (string, error) {
		var err error
		s, err = a.settings()
		if err != nil {
			return "", err
		}
		if s.Host == "" {
			return "", errors.New("no server address configured")
		}
		return s.Host, nil
	}); err != nil {
		return err
	}
	if err := step(emit, "web", func() (string, error) {
		stealth := s.Stealth && a.active(ctx, render.UnitOpenVPNTCP)
		return a.stepCaddy(ctx, s, stealth)
	}); err != nil {
		return err
	}
	return step(emit, "certificate", func() (string, error) {
		return a.waitHealth(ctx, emit, "certificate", s, a.HealthTimeout)
	})
}

func (a *Agent) DNSUpdate(ctx context.Context, emit Emit) (map[string]string, error) {
	a.init()
	var counts map[string]int
	if err := step(emit, "blocklists", func() (string, error) {
		d, c, err := a.stepBlocklists(ctx, true)
		counts = c
		return d, err
	}); err != nil {
		return nil, err
	}
	if err := step(emit, "dns-filter", func() (string, error) {
		if !a.active(ctx, render.UnitDNS) {
			return "", skip("not running")
		}
		return "reloaded", a.systemctl(ctx, "reload", render.UnitDNS)
	}); err != nil {
		return nil, err
	}
	data := map[string]string{}
	for k, v := range counts {
		data["blocklist."+k] = strconv.Itoa(v)
	}
	return data, nil
}

func (a *Agent) Restart(ctx context.Context, emit Emit) error {
	a.init()
	s, err := a.settings()
	if err != nil {
		return err
	}
	units := []string{render.UnitUnbound, render.UnitDNS, render.UnitOpenVPNUDP}
	if s.Stealth {
		units = append(units, render.UnitOpenVPNTCP)
	}
	units = append(units, render.UnitCaddy)
	for _, u := range units {
		if err := step(emit, strings.TrimSuffix(u, ".service"), func() (string, error) {
			return "restarted", a.systemctl(ctx, "restart", u)
		}); err != nil {
			return err
		}
	}
	return step(emit, "veyl", func() (string, error) {
		return "restart queued", a.systemctl(ctx, "restart", "--no-block", render.UnitVeyl)
	})
}

func (a *Agent) Status(ctx context.Context) (map[string]string, error) {
	a.init()
	data := map[string]string{}
	for _, u := range []string{render.UnitVeyl, render.UnitAgent, render.UnitDNS, render.UnitOpenVPNUDP, render.UnitOpenVPNTCP, render.UnitUnbound, render.UnitCaddy, render.UnitFirewall, "nftables.service"} {
		data["service."+strings.TrimSuffix(u, ".service")] = a.state(ctx, u)
	}
	vout, _ := a.run(ctx, quick, "openvpn", "--version")
	ovpn, ssl := parseOpenVPNVersion(vout)
	if sout, err := a.run(ctx, quick, "openssl", "version"); err == nil && ssl == "" {
		ssl = parseOpenSSLVersion(sout)
	}
	data["openvpn"] = ovpn
	data["openssl"] = ssl
	data["post_quantum"] = strconv.FormatBool(render.PostQuantumAvailable(render.Facts{OpenSSLVersion: ssl}))
	data["distro"] = osRelease(a.path("/etc/os-release"))
	if b, err := os.ReadFile(a.path("/proc/uptime")); err == nil {
		if fs := strings.Fields(string(b)); len(fs) > 0 {
			if v, err := strconv.ParseFloat(fs[0], 64); err == nil {
				data["uptime"] = strconv.FormatInt(int64(v), 10)
			}
		}
	}
	if b, err := os.ReadFile(a.path("/proc/loadavg")); err == nil {
		if fs := strings.Fields(string(b)); len(fs) >= 3 {
			data["load"] = strings.Join(fs[:3], " ")
		}
	}
	if b, err := os.ReadFile(a.path("/proc/meminfo")); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			fs := strings.Fields(line)
			if len(fs) >= 2 && (fs[0] == "MemTotal:" || fs[0] == "MemAvailable:") {
				if kb, err := strconv.ParseInt(fs[1], 10, 64); err == nil {
					data["mem_"+strings.ToLower(strings.TrimSuffix(fs[0][3:], ":"))] = strconv.FormatInt(kb*1024, 10)
				}
			}
		}
	}
	if total, free, err := diskUsage(a.path("/")); err == nil {
		data["disk_total"] = strconv.FormatUint(total, 10)
		data["disk_free"] = strconv.FormatUint(free, 10)
	}
	pctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	if ip, err := a.Probe.PublicIP(pctx, false); err == nil {
		data["public_ipv4"] = ip
	}
	if ip, err := a.Probe.PublicIP(pctx, true); err == nil {
		data["public_ipv6"] = ip
	}
	if s, err := a.settings(); err == nil && s.Host != "" {
		data["host"] = s.Host
		if exp, err := a.Probe.CertExpiry(pctx, s.Host); err == nil {
			data["cert_expiry"] = exp.UTC().Format(time.RFC3339)
		}
	}
	displayAliases(data)
	return data, nil
}

func humanBytes(n uint64) string {
	const unit = 1024
	if n < unit {
		return strconv.FormatUint(n, 10) + " B"
	}
	div, exp := uint64(unit), 0
	for v := n / unit; v >= unit && exp < 4; v /= unit {
		div *= unit
		exp++
	}
	return strconv.FormatFloat(float64(n)/float64(div), 'f', 1, 64) + " " + string("KMGTP"[exp]) + "B"
}

func displayAliases(data map[string]string) {
	for k, v := range data {
		if name, ok := strings.CutPrefix(k, "service."); ok {
			data["svc."+name] = v
		}
	}
	if v, ok := data["public_ipv4"]; ok {
		data["public_ip"] = v
	}
	if v, ok := data["distro"]; ok {
		data["os"] = v
	}
	total, terr := strconv.ParseUint(data["mem_memtotal"], 10, 64)
	avail, aerr := strconv.ParseUint(data["mem_memavailable"], 10, 64)
	if terr == nil && total > 0 {
		data["ram_mb"] = strconv.FormatUint(total/(1<<20), 10)
		if aerr == nil && avail <= total {
			data["mem"] = humanBytes(total-avail) + " used of " + humanBytes(total)
		}
	}
	dt, derr := strconv.ParseUint(data["disk_total"], 10, 64)
	df, ferr := strconv.ParseUint(data["disk_free"], 10, 64)
	if derr == nil && ferr == nil && dt > 0 {
		data["disk"] = humanBytes(df) + " free of " + humanBytes(dt)
	}
}

func (a *Agent) Bootstrap(ctx context.Context, emit Emit, domain, email string) error {
	a.init()
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
		return a.Apply(ctx, emit)
	}
	var f render.Facts
	steps := []struct {
		name string
		fn   func() (string, error)
	}{
		{"system", func() (string, error) {
			var err error
			f, err = a.Facts(ctx)
			if err != nil {
				return "", err
			}
			return fmt.Sprintf("openvpn %s, openssl %s, wan %s, ssh %v", f.OpenVPNVersion, f.OpenSSLVersion, f.WANIface, f.SSHPorts), nil
		}},
		{"users", func() (string, error) { return a.stepUsers(ctx) }},
		{"directories", func() (string, error) { return a.stepDirs(ctx) }},
		{"certificates", func() (string, error) { return a.stepPKI(ctx) }},
		{"units", func() (string, error) { return a.stepUnits(ctx) }},
		{"kernel", func() (string, error) { return a.stepSysctl(ctx, f) }},
		{"privacy", func() (string, error) { return a.stepPrivacy(ctx) }},
		{"firewall", func() (string, error) { return a.stepFirewall(ctx, s, f) }},
		{"services", func() (string, error) { return a.stepServices(ctx, true) }},
		{"web", func() (string, error) { return a.stepCaddy(ctx, setupMode(s), false) }},
	}
	for _, st := range steps {
		if err := step(emit, st.name, st.fn); err != nil {
			return err
		}
	}
	if s.Host == "" {
		return nil
	}
	return step(emit, "https", func() (string, error) {
		if _, err := a.stepCaddy(ctx, s, false); err != nil {
			return "", err
		}
		d, err := a.waitHealth(ctx, emit, "https", s, a.HealthTimeout)
		if err != nil {
			_, _ = a.stepCaddy(ctx, setupMode(s), false)
			return "", skip("could not get a certificate for %s yet, setup continues over http: %v", s.Host, err)
		}
		return d, nil
	})
}

func setupMode(s config.Settings) config.Settings {
	s.Host = ""
	if s.TLS == config.TLSInternal {
		s.TLS = config.TLSACME
	}
	return s
}

func (a *Agent) seed(domain, email string) (string, error) {
	p := a.path(a.Paths.Settings())
	s, err := config.Load(p)
	if err != nil {
		return "", err
	}
	if s.Configured {
		return "", skip("already configured")
	}
	if domain != "" {
		if !config.ValidHost(domain) {
			return "", config.ErrHost
		}
		s.Host = strings.ToLower(domain)
		s.TLS = config.TLSACME
		if config.IsIP(s.Host) {
			s.TLS = config.TLSInternal
		}
	}
	if email != "" {
		if !config.ValidEmail(email) {
			return "", config.ErrEmail
		}
		s.ACMEEmail = email
	}
	if err := config.Save(p, s); err != nil {
		return "", err
	}
	if uid, gid, err := a.Lookup(config.ServiceUser); err == nil {
		_ = a.Chown(p, uid, gid)
	}
	return s.Host, nil
}

func (a *Agent) Uninstall(ctx context.Context, emit Emit, purge bool) error {
	a.init()
	units := []string{render.UnitVeyl, render.UnitDNS, render.UnitBlocklistsTmr, render.UnitBlocklists, render.UnitOpenVPNUDP, render.UnitOpenVPNTCP, render.UnitDNSIf, render.UnitFirewall}
	_ = step(emit, "services", func() (string, error) {
		for _, u := range units {
			_ = a.systemctl(ctx, "disable", "--now", u)
		}
		return "stopped", nil
	})
	_ = step(emit, "firewall", func() (string, error) {
		for _, t := range []string{"inet veyl", "ip veyl_nat", "ip6 veyl_nat6"} {
			_, _ = a.run(ctx, quick, "nft", append([]string{"delete", "table"}, strings.Fields(t)...)...)
		}
		return "veyl tables removed", nil
	})
	_ = step(emit, "files", func() (string, error) {
		paths := []string{render.OpenVPNPath(config.InstanceUDP), render.OpenVPNPath(config.InstanceTCP), render.UnboundFile, render.SysctlFile, render.JournaldFile, render.SSHDFile, render.UnattendedFile, render.TmpfilesFile}
		for _, f := range render.Units() {
			paths = append(paths, f.Path)
		}
		for _, p := range paths {
			_, _ = a.remove(p)
			_, _ = a.remove(p + prevSuffix)
		}
		for _, u := range []string{render.UnitOpenVPNUDP, render.UnitOpenVPNTCP} {
			_ = os.Remove(a.path(filepath.Join(render.UnitDir, u+".d")))
		}
		_ = os.RemoveAll(a.path(render.EtcDir))
		orig := a.path(render.CaddyFile + ".veyl-orig")
		if _, err := os.Stat(orig); err == nil {
			_ = os.Rename(orig, a.path(render.CaddyFile))
		}
		_, _ = a.remove(render.CaddyFile + prevSuffix)
		_ = a.systemctl(ctx, "daemon-reload")
		_ = a.systemctl(ctx, "restart", "systemd-journald.service")
		_ = a.systemctl(ctx, "try-restart", render.UnitUnbound)
		_ = a.systemctl(ctx, "try-restart", render.UnitCaddy)
		if a.systemctl(ctx, "reload", "ssh.service") != nil {
			_ = a.systemctl(ctx, "reload", "sshd.service")
		}
		return "removed", nil
	})
	_ = step(emit, "users", func() (string, error) {
		_, _ = a.run(ctx, quick, "userdel", config.OpenVPNUser)
		_, _ = a.run(ctx, quick, "userdel", config.ServiceUser)
		_, _ = a.run(ctx, quick, "groupdel", config.ServiceUser)
		return "removed", nil
	})
	if purge {
		_ = step(emit, "data", func() (string, error) {
			if err := os.RemoveAll(a.path(a.Paths.Data)); err != nil && !errors.Is(err, fs.ErrNotExist) {
				return "", err
			}
			return "removed " + a.Paths.Data, nil
		})
	} else {
		emit(agentapi.Event{Step: "data", Status: agentapi.StatusSkip, Detail: "kept " + a.Paths.Data})
	}
	_ = step(emit, "agent", func() (string, error) {
		_ = a.systemctl(ctx, "disable", render.UnitAgent)
		_, _ = a.remove(filepath.Join(render.UnitDir, render.UnitAgent))
		_ = a.systemctl(ctx, "daemon-reload")
		_ = a.systemctl(ctx, "stop", "--no-block", render.UnitAgent)
		return "removed", nil
	})
	return nil
}
