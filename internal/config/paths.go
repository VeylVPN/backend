package config

import "path/filepath"

const (
	DataDir      = "/var/lib/veyl"
	RunDir       = "/run/veyl"
	BinPath      = "/usr/local/bin/veyl"
	ServiceUser  = "veyl"
	OpenVPNUser  = "veyl-ovpn"
	WebListen    = "127.0.0.1:8080"
	CaddyTLSPort = 8443

	UDPNet4  = "10.8.0.0"
	UDPNet6  = "fd88:88:88::/64"
	UDPGW4   = "10.8.0.1"
	TCPNet4  = "10.9.0.0"
	TCPNet6  = "fd88:88:89::/64"
	TCPGW4   = "10.9.0.1"
	Netmask4 = "255.255.255.0"

	DNSPrefix    = "10.64.0"
	DNSIface     = "veyl-dns"
	UnboundAddr  = "127.0.0.1:5335"
	TunUDP       = "veyl-udp"
	TunTCP       = "veyl-tcp"
	InstanceUDP  = "udp"
	InstanceTCP  = "tcp"
	StealthPort  = 443
	OpenVPNDir   = "/etc/openvpn/server"
	CaddyfileOut = "/etc/caddy/Caddyfile"
)

type Paths struct {
	Data string
	Run  string
}

func DefaultPaths() Paths {
	return Paths{Data: DataDir, Run: RunDir}
}

func (p Paths) Settings() string   { return filepath.Join(p.Data, "settings.json") }
func (p Paths) State() string      { return filepath.Join(p.Data, "state.json") }
func (p Paths) Admin() string      { return filepath.Join(p.Data, "admin.json") }
func (p Paths) SetupToken() string { return filepath.Join(p.Data, "setup-token") }
func (p Paths) PKI() string        { return p.Data }
func (p Paths) CRL() string        { return filepath.Join(p.Data, "crl.pem") }
func (p Paths) Blocklists() string { return filepath.Join(p.Data, "blocklists") }
func (p Paths) AgentSock() string  { return filepath.Join(p.Run, "agent.sock") }
func (p Paths) HookSock() string   { return filepath.Join(p.Run, "hook.sock") }
func (p Paths) Mgmt(instance string) string {
	return filepath.Join(p.Run, "mgmt-"+instance)
}
