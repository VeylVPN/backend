package config

import (
	"path/filepath"
	"testing"
)

func TestHostValidationBlocksInjection(t *testing.T) {
	good := []string{"vpn.example.com", "a.b.co", "203-0-113-5.sslip.io", "8.8.8.8", "2001:4860:4860::8888"}
	bad := []string{"", "localhost", "vpn.example.com\nup /bin/sh", "vpn example.com", "x;rm", "10.0.0.1", "192.168.1.1", "127.0.0.1", "-bad.com", "a..b.com", "vpn.example.com\"", "exa_mple.com", "vpn.example.com#"}
	for _, h := range good {
		if !ValidHost(h) {
			t.Errorf("rejected %q", h)
		}
	}
	for _, h := range bad {
		if ValidHost(h) {
			t.Errorf("accepted %q", h)
		}
	}
}

func TestSettingsValidate(t *testing.T) {
	s := Defaults()
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	cases := []func(*Settings){
		func(s *Settings) { s.UDPPort = 80 },
		func(s *Settings) { s.UDPPort = 8443 },
		func(s *Settings) { s.Registration = "maybe" },
		func(s *Settings) { s.DeviceLimit = 0 },
		func(s *Settings) { s.DNS.Default = []string{"ads", "ads"} },
		func(s *Settings) { s.DNS.Upstream = "evil" },
		func(s *Settings) { s.ACMEEmail = "a@b.com\nx" },
		func(s *Settings) { s.Name = "bad\nname" },
		func(s *Settings) { s.Host = "1.1.1.1"; s.TLS = TLSACME },
		func(s *Settings) { s.Configured = true; s.Host = "" },
		func(s *Settings) { s.AppURL = "javascript:alert(1)" },
	}
	for i, f := range cases {
		c := Defaults()
		f(&c)
		if c.Validate() == nil {
			t.Errorf("case %d accepted", i)
		}
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	p := filepath.Join(t.TempDir(), "settings.json")
	s := Defaults()
	s.Host = "vpn.example.com"
	s.Configured = true
	if err := Save(p, s); err != nil {
		t.Fatal(err)
	}
	got, err := Load(p)
	if err != nil || got.Host != "vpn.example.com" || !got.Configured {
		t.Fatalf("%+v %v", got, err)
	}
	bad := s
	bad.UDPPort = 1
	if Save(p, bad) == nil {
		t.Fatal("saved invalid settings")
	}
}

func TestDNSAddressing(t *testing.T) {
	if DNSAddr(nil) != "10.64.0.1" {
		t.Fatal(DNSAddr(nil))
	}
	a := DNSAddr([]string{CatTrackers, CatAds})
	if a != "10.64.0.4" {
		t.Fatal(a)
	}
	m, ok := MaskForAddr(a)
	if !ok || m != 3 {
		t.Fatal(m, ok)
	}
	if got := FromMask(m); len(got) != 2 || got[0] != CatAds {
		t.Fatal(got)
	}
	if _, ok := MaskForAddr("10.64.0.66"); ok {
		t.Fatal("out of range accepted")
	}
	if MaxMask() != 63 {
		t.Fatal(MaxMask())
	}
}

func TestLiveReloadsAndValidates(t *testing.T) {
	p := filepath.Join(t.TempDir(), "settings.json")
	l, err := NewLive(p)
	if err != nil {
		t.Fatal(err)
	}
	if l.Get().UDPPort != 1194 {
		t.Fatal("defaults")
	}
	if _, err := l.Update(func(s *Settings) error { s.UDPPort = 1195; return nil }); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Update(func(s *Settings) error { s.UDPPort = 22; return nil }); err == nil {
		t.Fatal("invalid update saved")
	}
	if l.Get().UDPPort != 1195 {
		t.Fatal(l.Get().UDPPort)
	}
	other := Defaults()
	other.UDPPort = 1300
	if err := Save(p, other); err != nil {
		t.Fatal(err)
	}
	if l.Get().UDPPort != 1300 {
		t.Fatal("did not pick up external change")
	}
}
