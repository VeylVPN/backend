package pkitest

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"os"
	"strings"
	"testing"

	"github.com/veylvpn/backend/internal/pki"
)

const (
	serverHeader = "-----BEGIN OpenVPN tls-crypt-v2 server key-----"
	serverFooter = "-----END OpenVPN tls-crypt-v2 server key-----"
	clientHeader = "-----BEGIN OpenVPN tls-crypt-v2 client key-----"
	clientFooter = "-----END OpenVPN tls-crypt-v2 client key-----"
	fakeTag      = "veyl-fake:"
)

func IsFakeInvocation(args []string) bool {
	return len(args) > 1 && (args[1] == "--genkey" || args[1] == "--tls-crypt-v2")
}

func Main(m *testing.M) int {
	if IsFakeInvocation(os.Args) {
		return Fake(os.Args[1:])
	}
	if exe, err := os.Executable(); err == nil {
		pki.OpenVPNBin = exe
	}
	return m.Run()
}

func Fake(args []string) int {
	switch {
	case len(args) == 3 && args[0] == "--genkey" && args[1] == "tls-crypt-v2-server":
		raw := make([]byte, 128)
		if _, err := rand.Read(raw); err != nil {
			return 1
		}
		body := serverHeader + "\n" + base64.StdEncoding.EncodeToString(raw) + "\n" + serverFooter + "\n"
		if os.WriteFile(args[2], []byte(body), 0o600) != nil {
			return 1
		}
		return 0
	case len(args) == 6 && args[0] == "--tls-crypt-v2" && args[2] == "--genkey" && args[3] == "tls-crypt-v2-client":
		srv, err := os.ReadFile(args[1])
		if err != nil || !bytes.HasPrefix(srv, []byte(serverHeader)) {
			return 1
		}
		md, err := base64.StdEncoding.DecodeString(args[5])
		if err != nil || len(md) == 0 {
			return 1
		}
		body := clientHeader + "\n" + base64.StdEncoding.EncodeToString(append([]byte(fakeTag), md...)) + "\n" + clientFooter + "\n"
		if os.WriteFile(args[4], []byte(body), 0o600) != nil {
			return 1
		}
		return 0
	}
	return 2
}

func Metadata(key string) (string, bool) {
	lines := strings.Split(strings.TrimSpace(key), "\n")
	if len(lines) != 3 || lines[0] != clientHeader || lines[2] != clientFooter {
		return "", false
	}
	b, err := base64.StdEncoding.DecodeString(lines[1])
	if err != nil || !bytes.HasPrefix(b, []byte(fakeTag)) {
		return "", false
	}
	return string(b[len(fakeTag):]), true
}
