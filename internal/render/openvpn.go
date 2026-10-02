package render

import (
	"fmt"
	"path"

	"github.com/veylvpn/backend/internal/config"
	"github.com/veylvpn/backend/internal/pki"
)

type instance struct {
	name  string
	tun   string
	net4  string
	net6  string
	proto string
}

func lookupInstance(name string) (instance, error) {
	switch name {
	case config.InstanceUDP:
		return instance{name: name, tun: config.TunUDP, net4: config.UDPNet4, net6: config.UDPNet6, proto: "udp"}, nil
	case config.InstanceTCP:
		return instance{name: name, tun: config.TunTCP, net4: config.TCPNet4, net6: config.TCPNet6, proto: "tcp-server"}, nil
	}
	return instance{}, ErrInstance
}

func OpenVPNPath(name string) string {
	return path.Join(OpenVPNConfDir, "veyl-"+name+".conf")
}

func OpenVPN(s config.Settings, f Facts, name string) (string, error) {
	if err := checkSettings(s); err != nil {
		return "", err
	}
	in, err := lookupInstance(name)
	if err != nil {
		return "", err
	}
	if _, ok := ParseVersion(f.OpenVPNVersion); !ok {
		return "", fmt.Errorf("%w: openvpn version", ErrFacts)
	}
	if f.OpenSSLVersion != "" {
		if _, ok := ParseVersion(f.OpenSSLVersion); !ok {
			return "", fmt.Errorf("%w: openssl version", ErrFacts)
		}
	}
	p := config.LinuxPaths()
	data := p.Data
	v6 := IPv6(s, f)
	var l lines
	l.add("dev %s", in.tun)
	l.add("dev-type tun")
	l.add("topology subnet")
	l.add("server %s %s", in.net4, config.Netmask4)
	if v6 {
		l.add("server-ipv6 %s", in.net6)
	}
	if in.name == config.InstanceUDP {
		l.add("proto udp")
		l.add("port %d", s.UDPPort)
		l.add("explicit-exit-notify 1")
	} else {
		l.add("proto tcp-server")
		l.add("port %d", config.StealthPort)
		l.add("port-share 127.0.0.1 %d", config.CaddyTLSPort)
	}
	l.add("ca %s", path.Join(data, pki.CAFile))
	l.add("cert %s", path.Join(data, pki.ServerCertFile))
	l.add("key %s", path.Join(data, pki.ServerKeyFile))
	l.add("dh none")
	if AtLeast(f.OpenVPNVersion, 2, 6, 0) {
		l.add("tls-crypt-v2 %s force-cookie", path.Join(data, TLSCryptV2Server))
	} else {
		l.add("tls-crypt-v2 %s", path.Join(data, TLSCryptV2Server))
	}
	l.add("tls-crypt-v2-verify \"%s hook verify\"", config.BinPath)
	l.add("client-connect \"%s hook connect\"", config.BinPath)
	l.add("script-security 2")
	l.add("crl-verify %s", p.CRL())
	l.add("remote-cert-tls client")
	l.add("verify-client-cert require")
	l.add("tls-server")
	l.add("tls-cert-profile preferred")
	l.add("tls-version-min 1.2")
	if s.PostQuantum && PostQuantumAvailable(f) {
		l.add("tls-groups X25519MLKEM768:X25519:secp256r1")
	}
	l.add("data-ciphers AES-256-GCM:CHACHA20-POLY1305:AES-128-GCM")
	l.add("allow-compression no")
	if v6 {
		l.add("push \"redirect-gateway def1 ipv6 bypass-dhcp\"")
	} else {
		l.add("push \"redirect-gateway def1 bypass-dhcp\"")
	}
	l.add("push \"block-outside-dns\"")
	l.add("keepalive 10 60")
	l.add("max-clients 250")
	l.add("user %s", config.OpenVPNUser)
	l.add("group %s", config.ServiceUser)
	l.add("persist-key")
	l.add("persist-tun")
	l.add("verb 0")
	l.add("mute-replay-warnings")
	l.add("management %s unix", p.Mgmt(in.name))
	l.add("management-client-group %s", config.ServiceUser)
	return l.String(), nil
}
