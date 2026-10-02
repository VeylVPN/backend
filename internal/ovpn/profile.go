package ovpn

import (
	"errors"
	"strconv"
	"strings"

	"github.com/veylvpn/backend/internal/config"
)

const KeyPlaceholder = "__PRIVATE_KEY__"

const DataCiphers = "AES-256-GCM:CHACHA20-POLY1305:AES-128-GCM"

var ErrProfile = errors.New("invalid profile parameters")

type Params struct {
	Host        string
	UDPPort     int
	Stealth     bool
	StealthPort int
	CA          []byte
	Cert        []byte
	TLSCryptV2  []byte
}

func block(name string, body []byte) (string, bool) {
	b := strings.TrimSpace(string(body))
	if b == "" || strings.Contains(b, "<") || strings.Contains(b, ">") {
		return "", false
	}
	return "<" + name + ">\n" + b + "\n</" + name + ">\n", true
}

func Profile(p Params) (string, error) {
	if !config.ValidHost(p.Host) || !config.ValidPort(p.UDPPort) {
		return "", ErrProfile
	}
	var sb strings.Builder
	sb.WriteString("client\n")
	sb.WriteString("dev tun\n")
	sb.WriteString("nobind\n")
	sb.WriteString("remote " + p.Host + " " + strconv.Itoa(p.UDPPort) + " udp\n")
	if p.Stealth {
		port := p.StealthPort
		if port == 0 {
			port = config.StealthPort
		}
		if port < 1 || port > 65535 {
			return "", ErrProfile
		}
		sb.WriteString("remote " + p.Host + " " + strconv.Itoa(port) + " tcp-client\n")
	}
	sb.WriteString("connect-retry 2 5\n")
	sb.WriteString("server-poll-timeout 4\n")
	sb.WriteString("resolv-retry infinite\n")
	sb.WriteString("persist-key\n")
	sb.WriteString("persist-tun\n")
	sb.WriteString("remote-cert-tls server\n")
	sb.WriteString("verify-x509-name veyl-server name\n")
	sb.WriteString("tls-version-min 1.2\n")
	sb.WriteString("data-ciphers " + DataCiphers + "\n")
	sb.WriteString("auth-nocache\n")
	sb.WriteString("setenv opt block-outside-dns\n")
	sb.WriteString("verb 1\n")
	for _, b := range []struct {
		name string
		body []byte
	}{{"ca", p.CA}, {"cert", p.Cert}} {
		s, ok := block(b.name, b.body)
		if !ok {
			return "", ErrProfile
		}
		sb.WriteString(s)
	}
	sb.WriteString("<key>\n" + KeyPlaceholder + "\n</key>\n")
	s, ok := block("tls-crypt-v2", p.TLSCryptV2)
	if !ok {
		return "", ErrProfile
	}
	sb.WriteString(s)
	return sb.String(), nil
}
