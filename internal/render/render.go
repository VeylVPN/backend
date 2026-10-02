package render

import (
	"errors"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/veylvpn/backend/internal/config"
)

const (
	OpenVPNConfDir   = config.OpenVPNDir
	EtcDir           = "/etc/veyl"
	NFTFile          = "/etc/veyl/veyl.nft"
	DNSIfFile        = "/etc/veyl/dnsif.ip"
	DNSIfDownFile    = "/etc/veyl/dnsif-down.ip"
	UnboundFile      = "/etc/unbound/unbound.conf.d/veyl.conf"
	CaddyFile        = config.CaddyfileOut
	SysctlFile       = "/etc/sysctl.d/99-veyl.conf"
	JournaldFile     = "/etc/systemd/journald.conf.d/veyl.conf"
	SSHDFile         = "/etc/ssh/sshd_config.d/00-veyl.conf"
	UnattendedFile   = "/etc/apt/apt.conf.d/21veyl-auto-upgrades"
	TmpfilesFile     = "/etc/tmpfiles.d/veyl.conf"
	UnitDir          = "/etc/systemd/system"
	TLSCryptV2Server = "tls-crypt-v2-server.key"
	AdminVPNPort     = 8081
	CertBundle       = "/etc/ssl/certs/ca-certificates.crt"
)

const (
	UnitVeyl          = "veyl.service"
	UnitAgent         = "veyl-agent.service"
	UnitDNS           = "veyl-dns.service"
	UnitDNSIf         = "veyl-dnsif.service"
	UnitFirewall      = "veyl-firewall.service"
	UnitBlocklists    = "veyl-blocklists.service"
	UnitBlocklistsTmr = "veyl-blocklists.timer"
	UnitOpenVPNUDP    = "openvpn-server@veyl-udp.service"
	UnitOpenVPNTCP    = "openvpn-server@veyl-tcp.service"
	UnitUnbound       = "unbound.service"
	UnitCaddy         = "caddy.service"
)

type Facts struct {
	OpenSSLVersion string
	OpenVPNVersion string
	SSHPorts       []int
	WANIface       string
	PublicIPv4     string
	PublicIPv6     string
	HasIPv6        bool
	Distro         string
}

type File struct {
	Path string
	Mode uint32
	Data string
}

var (
	ErrFacts    = errors.New("render: invalid system facts")
	ErrSettings = errors.New("render: invalid settings")
	ErrInstance = errors.New("render: unknown openvpn instance")
)

var (
	ifaceRE   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,14}$`)
	versionRE = regexp.MustCompile(`^([0-9]{1,4})\.([0-9]{1,4})(?:\.([0-9]{1,4}))?(?:[A-Za-z0-9._~+-]{0,32})$`)
)

func ValidIface(s string) bool {
	return ifaceRE.MatchString(s) && s != "." && s != ".."
}

func ParseVersion(v string) ([3]int, bool) {
	var out [3]int
	m := versionRE.FindStringSubmatch(v)
	if m == nil {
		return out, false
	}
	for i := 0; i < 3; i++ {
		if m[i+1] == "" {
			continue
		}
		n, err := strconv.Atoi(m[i+1])
		if err != nil {
			return out, false
		}
		out[i] = n
	}
	return out, true
}

func AtLeast(v string, major, minor, patch int) bool {
	p, ok := ParseVersion(v)
	if !ok {
		return false
	}
	want := [3]int{major, minor, patch}
	for i := 0; i < 3; i++ {
		if p[i] != want[i] {
			return p[i] > want[i]
		}
	}
	return true
}

func PostQuantumAvailable(f Facts) bool {
	return AtLeast(f.OpenSSLVersion, 3, 5, 0)
}

func IPv6(s config.Settings, f Facts) bool {
	return s.IPv6 && f.HasIPv6
}

func checkSettings(s config.Settings) error {
	if err := s.Validate(); err != nil {
		return fmt.Errorf("%w: %v", ErrSettings, err)
	}
	if s.Host != "" && !config.ValidHost(s.Host) {
		return fmt.Errorf("%w: host", ErrSettings)
	}
	if !config.ValidPort(s.UDPPort) {
		return fmt.Errorf("%w: port", ErrSettings)
	}
	if !config.ValidEmail(s.ACMEEmail) {
		return fmt.Errorf("%w: email", ErrSettings)
	}
	return nil
}

func sshPorts(f Facts) ([]int, error) {
	if len(f.SSHPorts) == 0 || len(f.SSHPorts) > 16 {
		return nil, fmt.Errorf("%w: ssh ports", ErrFacts)
	}
	seen := map[int]bool{}
	out := []int{}
	for _, p := range f.SSHPorts {
		if p < 1 || p > 65535 {
			return nil, fmt.Errorf("%w: ssh port %d", ErrFacts, p)
		}
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	sort.Ints(out)
	return out, nil
}

func checkWAN(f Facts) error {
	if !ValidIface(f.WANIface) {
		return fmt.Errorf("%w: wan interface", ErrFacts)
	}
	return nil
}

func hostLiteral(h string) string {
	if ip := net.ParseIP(h); ip != nil && ip.To4() == nil {
		return "[" + h + "]"
	}
	return h
}

func HealthURL(host string) (string, error) {
	if !config.ValidHost(host) {
		return "", fmt.Errorf("%w: host", ErrSettings)
	}
	return "https://" + hostLiteral(host) + "/v1/health", nil
}

func joinInts(v []int) string {
	s := make([]string, len(v))
	for i, n := range v {
		s[i] = strconv.Itoa(n)
	}
	return strings.Join(s, ", ")
}

type lines struct {
	b      strings.Builder
	indent string
}

func (l *lines) add(format string, a ...any) {
	l.b.WriteString(l.indent)
	if len(a) == 0 {
		l.b.WriteString(format)
	} else {
		fmt.Fprintf(&l.b, format, a...)
	}
	l.b.WriteByte('\n')
}

func (l *lines) blank() {
	l.b.WriteByte('\n')
}

func (l *lines) String() string {
	return l.b.String()
}
