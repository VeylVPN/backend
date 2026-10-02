package ovpn

import (
	"strconv"
	"strings"
)

const KeyPlaceholder = "__PRIVATE_KEY__"

func block(name string, body []byte) string {
	return "<" + name + ">\n" + strings.TrimSpace(string(body)) + "\n</" + name + ">\n"
}

func Profile(p Params) string {
	proto := "udp"
	if p.Proto == "tcp" {
		proto = "tcp-client"
	}
	port := p.Port
	if port == 0 {
		port = 1194
	}
	var sb strings.Builder
	sb.WriteString("client\n")
	sb.WriteString("dev tun\n")
	sb.WriteString("proto " + proto + "\n")
	sb.WriteString("remote " + p.Host + " " + strconv.Itoa(port) + "\n")
	sb.WriteString("nobind\n")
	sb.WriteString("resolv-retry infinite\n")
	sb.WriteString("persist-key\n")
	sb.WriteString("persist-tun\n")
	sb.WriteString("remote-cert-tls server\n")
	sb.WriteString("verify-x509-name veyl-server name\n")
	sb.WriteString("tls-version-min 1.2\n")
	sb.WriteString("data-ciphers AES-256-GCM:CHACHA20-POLY1305\n")
	sb.WriteString("data-ciphers-fallback AES-256-GCM\n")
	sb.WriteString("auth SHA256\n")
	sb.WriteString("auth-nocache\n")
	sb.WriteString("setenv opt block-outside-dns\n")
	sb.WriteString("verb 1\n")
	sb.WriteString(block("ca", p.CA))
	sb.WriteString(block("cert", p.Cert))
	sb.WriteString("<key>\n" + KeyPlaceholder + "\n</key>\n")
	sb.WriteString(block("tls-crypt", p.TLSCrypt))
	return sb.String()
}
