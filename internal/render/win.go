package render

import (
	"fmt"
	"strings"

	"github.com/veylvpn/backend/internal/config"
	"github.com/veylvpn/backend/internal/pki"
)

type WinFacts struct {
	OpenVPNVersion string
	OpenSSLVersion string
	WANIndex       int
	OS             string
}

func checkWinFacts(f WinFacts) error {
	if _, ok := ParseVersion(f.OpenVPNVersion); !ok {
		return fmt.Errorf("%w: openvpn version", ErrFacts)
	}
	if f.OpenSSLVersion != "" {
		if _, ok := ParseVersion(f.OpenSSLVersion); !ok {
			return fmt.Errorf("%w: openssl version", ErrFacts)
		}
	}
	return nil
}

func WinPostQuantum(f WinFacts) bool {
	return AtLeast(f.OpenSSLVersion, 3, 5, 0)
}

func safeWinPath(p string) bool {
	return p != "" && len(p) < 240 && !strings.ContainsAny(p, "\"'\r\n\x00*?<>|")
}

func ovpnQuote(s string) (string, error) {
	if strings.ContainsAny(s, "\"\r\n\x00") {
		return "", fmt.Errorf("%w: unsafe value", ErrSettings)
	}
	return "\"" + strings.ReplaceAll(s, `\`, `\\`) + "\"", nil
}

func ovpnPath(p string) (string, error) {
	if !safeWinPath(p) {
		return "", fmt.Errorf("%w: unsafe path", ErrSettings)
	}
	return ovpnQuote(p)
}

func ovpnScript(bin string, args ...string) (string, error) {
	if !safeWinPath(bin) {
		return "", fmt.Errorf("%w: unsafe path", ErrSettings)
	}
	cmd := "'" + bin + "'"
	for _, a := range args {
		for _, r := range a {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
				return "", fmt.Errorf("%w: unsafe argument", ErrSettings)
			}
		}
		cmd += " " + a
	}
	return ovpnQuote(cmd)
}

func WinOpenVPNPath(name string) string {
	return config.Join(config.WinConfDir, "veyl-"+name+".conf")
}

func WinOpenVPN(s config.Settings, f WinFacts, name string) (string, error) {
	if err := checkSettings(s); err != nil {
		return "", err
	}
	in, err := lookupInstance(name)
	if err != nil {
		return "", err
	}
	if err := checkWinFacts(f); err != nil {
		return "", err
	}
	if !config.ValidStealthPort(config.PlatformWindows, s.StealthPort) {
		return "", fmt.Errorf("%w: stealth port", ErrSettings)
	}
	p := config.WindowsPaths()
	q := map[string]string{}
	for k, v := range map[string]string{
		"ca":   config.Join(p.Data, pki.CAFile),
		"cert": config.Join(p.Data, pki.ServerCertFile),
		"key":  config.Join(p.Data, pki.ServerKeyFile),
		"tc":   config.Join(p.Data, TLSCryptV2Server),
		"crl":  p.CRL(),
		"pw":   p.MgmtPassword(in.name),
		"tmp":  p.Run,
	} {
		if q[k], err = ovpnPath(v); err != nil {
			return "", err
		}
	}
	verify, err := ovpnScript(config.WinBinPath, "hook", "verify")
	if err != nil {
		return "", err
	}
	connect, err := ovpnScript(config.WinBinPath, "hook", "connect")
	if err != nil {
		return "", err
	}
	node, err := ovpnQuote(config.TapName(in.name))
	if err != nil {
		return "", err
	}
	var l lines
	l.add("dev tun")
	l.add("dev-node %s", node)
	if !AtLeast(f.OpenVPNVersion, 2, 7, 0) {
		l.add("windows-driver tap-windows6")
	}
	l.add("disable-dco")
	l.add("topology subnet")
	l.add("server %s %s", in.net4, config.Netmask4)
	l.add("ip-win32 netsh")
	if in.name == config.InstanceUDP {
		l.add("proto udp")
		l.add("port %d", s.UDPPort)
		l.add("explicit-exit-notify 1")
	} else {
		l.add("proto tcp-server")
		l.add("port %d", s.StealthTCPPortFor(config.PlatformWindows))
	}
	l.add("ca %s", q["ca"])
	l.add("cert %s", q["cert"])
	l.add("key %s", q["key"])
	l.add("dh none")
	l.add("tls-crypt-v2 %s force-cookie", q["tc"])
	l.add("tls-crypt-v2-verify %s", verify)
	l.add("client-connect %s", connect)
	l.add("script-security 2")
	l.add("tmp-dir %s", q["tmp"])
	l.add("crl-verify %s", q["crl"])
	l.add("remote-cert-tls client")
	l.add("verify-client-cert require")
	l.add("tls-server")
	l.add("tls-cert-profile preferred")
	l.add("tls-version-min 1.2")
	if s.PostQuantum && WinPostQuantum(f) {
		l.add("tls-groups X25519MLKEM768:X25519:secp256r1")
	}
	l.add("data-ciphers AES-256-GCM:CHACHA20-POLY1305:AES-128-GCM")
	l.add("allow-compression no")
	l.add("push \"redirect-gateway def1 bypass-dhcp\"")
	l.add("push \"block-outside-dns\"")
	l.add("keepalive 10 60")
	l.add("max-clients 250")
	l.add("persist-key")
	l.add("persist-tun")
	l.add("verb 0")
	l.add("mute-replay-warnings")
	l.add("management %s %d %s", config.MgmtHost, config.MgmtPort(in.name), q["pw"])
	return l.String(), nil
}

type winUnbound struct {
	dir    string
	anchor string
}

func (w *winUnbound) head(l *lines) {
	l.add("directory: \"%s\"", w.dir)
	l.add("auto-trust-anchor-file: \"%s\"", w.anchor)
	l.add("do-daemonize: no")
}

func WinUnboundPath() string {
	return config.Join(config.WinUnboundData, "unbound.conf")
}

func WinUnboundAnchor() string {
	return config.Join(config.WinUnboundData, "root.key")
}

func WinUnbound(s config.Settings) (string, error) {
	return unbound(s, false, &winUnbound{dir: config.WinUnboundData, anchor: WinUnboundAnchor()})
}

func WinCaddyfilePath() string {
	return config.Join(config.WinCaddyData, "Caddyfile")
}

func WinCaddyfile(s config.Settings) (string, error) {
	return Caddyfile(s, false)
}
