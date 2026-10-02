package ovpn

import (
	"strings"
	"testing"
)

func TestProfileStealthPort(t *testing.T) {
	p := Params{Host: "vpn.example.com", UDPPort: 1194, Stealth: true, StealthPort: 993, CA: []byte("CA"), Cert: []byte("C"), TLSCryptV2: []byte("T")}
	got, err := Profile(p)
	if err != nil || !strings.Contains(got, "remote vpn.example.com 993 tcp-client\n") || strings.Contains(got, " 443 ") {
		t.Fatal(got, err)
	}
	p.StealthPort = 70000
	if _, err := Profile(p); err != ErrProfile {
		t.Fatal(err)
	}
}
