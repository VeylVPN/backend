package agent

import (
	"bufio"
	"context"
	"errors"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/veylvpn/backend/internal/render"
)

func (a *Agent) Facts(ctx context.Context) (render.Facts, error) {
	var f render.Facts
	vout, _ := a.run(ctx, quick, "openvpn", "--version")
	f.OpenVPNVersion, f.OpenSSLVersion = parseOpenVPNVersion(vout)
	if f.OpenSSLVersion == "" {
		sout, _ := a.run(ctx, quick, "openssl", "version")
		f.OpenSSLVersion = parseOpenSSLVersion(sout)
	}
	f.SSHPorts = a.sshPorts(ctx)
	wan, err := parseDefaultRoute(a.path("/proc/net/route"))
	if err != nil {
		return f, err
	}
	f.WANIface = wan
	f.HasIPv6 = hasIPv6Default(a.path("/proc/net/ipv6_route"))
	f.Distro = osRelease(a.path("/etc/os-release"))
	return f, nil
}

func parseOpenVPNVersion(out string) (string, string) {
	var ovpn, ssl string
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "OpenVPN" && ovpn == "" {
			if _, ok := render.ParseVersion(fields[1]); ok {
				ovpn = fields[1]
			}
		}
		if i := strings.Index(line, "library versions: OpenSSL "); i >= 0 && ssl == "" {
			rest := strings.Fields(line[i+len("library versions: OpenSSL "):])
			if len(rest) > 0 {
				v := strings.TrimSuffix(rest[0], ",")
				if _, ok := render.ParseVersion(v); ok {
					ssl = v
				}
			}
		}
	}
	return ovpn, ssl
}

func parseOpenSSLVersion(out string) string {
	fields := strings.Fields(out)
	if len(fields) >= 2 && fields[0] == "OpenSSL" {
		if _, ok := render.ParseVersion(fields[1]); ok {
			return fields[1]
		}
	}
	return ""
}

func (a *Agent) sshPorts(ctx context.Context) []int {
	set := map[int]bool{}
	if out, err := a.run(ctx, quick, "sshd", "-T"); err == nil {
		for _, p := range parseSSHDPorts(out) {
			set[p] = true
		}
	}
	if out, err := a.run(ctx, quick, "ss", "-H", "-ltnp"); err == nil {
		for _, p := range parseSSListeners(out, "\"sshd\"") {
			set[p] = true
		}
	}
	if len(set) == 0 {
		set[22] = true
	}
	ports := make([]int, 0, len(set))
	for p := range set {
		ports = append(ports, p)
	}
	sort.Ints(ports)
	if len(ports) > 16 {
		ports = ports[:16]
	}
	return ports
}

func parseSSHDPorts(out string) []int {
	var ports []int
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && strings.EqualFold(fields[0], "port") {
			if p, err := strconv.Atoi(fields[1]); err == nil && p > 0 && p < 65536 {
				ports = append(ports, p)
			}
		}
		if len(fields) == 2 && strings.EqualFold(fields[0], "listenaddress") {
			if _, port, err := net.SplitHostPort(fields[1]); err == nil {
				if p, err := strconv.Atoi(port); err == nil && p > 0 && p < 65536 {
					ports = append(ports, p)
				}
			}
		}
	}
	return ports
}

func parseSSListeners(out, proc string) []int {
	var ports []int
	for _, line := range strings.Split(out, "\n") {
		if proc != "" && !strings.Contains(line, proc) {
			continue
		}
		if l, ok := ssLocal(line); ok {
			ports = append(ports, l.port)
		}
	}
	return ports
}

type listener struct {
	proto string
	addr  string
	port  int
}

func ssLocal(line string) (listener, bool) {
	fields := strings.Fields(line)
	if len(fields) < 5 {
		return listener{}, false
	}
	idx := 3
	proto := ""
	if fields[0] == "tcp" || fields[0] == "udp" {
		proto = fields[0]
		idx = 4
	}
	if len(fields) <= idx {
		return listener{}, false
	}
	local := fields[idx]
	i := strings.LastIndex(local, ":")
	if i < 0 {
		return listener{}, false
	}
	p, err := strconv.Atoi(local[i+1:])
	if err != nil || p <= 0 || p > 65535 {
		return listener{}, false
	}
	addr := strings.Trim(local[:i], "[]")
	if j := strings.Index(addr, "%"); j >= 0 {
		addr = addr[:j]
	}
	return listener{proto: proto, addr: addr, port: p}, true
}

func parseDefaultRoute(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	best, bestMetric := "", -1
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 8 || fields[0] == "Iface" {
			continue
		}
		if fields[1] != "00000000" || fields[7] != "00000000" {
			continue
		}
		flags, err := strconv.ParseUint(fields[3], 16, 32)
		if err != nil || flags&1 == 0 {
			continue
		}
		metric, _ := strconv.Atoi(fields[6])
		if bestMetric < 0 || metric < bestMetric {
			best, bestMetric = fields[0], metric
		}
	}
	if best == "" || !render.ValidIface(best) {
		return "", errors.New("no default ipv4 route")
	}
	return best, nil
}

func hasIPv6Default(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 10 {
			continue
		}
		if fields[0] != strings.Repeat("0", 32) || fields[1] != "00" || fields[9] == "lo" {
			continue
		}
		flags, err := strconv.ParseUint(fields[8], 16, 32)
		if err != nil || flags&1 == 0 || flags&0x200 != 0 {
			continue
		}
		return true
	}
	return false
}

func osRelease(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(line, "PRETTY_NAME="); ok {
			v = strings.Trim(v, "\"'")
			if len(v) > 64 {
				v = v[:64]
			}
			return v
		}
	}
	return ""
}
