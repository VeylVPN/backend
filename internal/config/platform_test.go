package config

import "testing"

func withPlatform(t *testing.T, p string) {
	t.Helper()
	old := Platform
	Platform = p
	t.Cleanup(func() { Platform = old })
}

func TestStealthPortPerPlatform(t *testing.T) {
	s := Defaults()
	withPlatform(t, PlatformLinux)
	if s.StealthTCPPort() != 443 {
		t.Fatal(s.StealthTCPPort())
	}
	s.StealthPort = 993
	if err := s.Validate(); err != ErrStealthPort {
		t.Fatalf("linux accepted stealth port 993: %v", err)
	}
	s.StealthPort = 443
	if err := s.Validate(); err != nil || s.StealthTCPPort() != 443 {
		t.Fatal(err)
	}
	withPlatform(t, PlatformWindows)
	s.StealthPort = 0
	if s.StealthTCPPort() != 993 {
		t.Fatal(s.StealthTCPPort())
	}
	for _, ok := range []int{993, 995, 1194, 8444, 65535} {
		s.StealthPort = ok
		if err := s.Validate(); err != nil || s.StealthTCPPort() != ok {
			t.Errorf("%d: %v", ok, err)
		}
	}
	for _, bad := range []int{-1, 53, 80, 443, 5335, 7505, 7506, 8080, 8081, 8443, 65536} {
		s.StealthPort = bad
		if err := s.Validate(); err != ErrStealthPort {
			t.Errorf("accepted %d", bad)
		}
	}
}

func TestPathsPerPlatform(t *testing.T) {
	w := WindowsPaths()
	for got, want := range map[string]string{
		w.Settings():          `C:\ProgramData\Veyl\data\settings.json`,
		w.AgentSock():         `C:\ProgramData\Veyl\run\agent.sock`,
		w.HookSock():          `C:\ProgramData\Veyl\run\hook.sock`,
		w.Blocklists():        `C:\ProgramData\Veyl\data\blocklists`,
		w.MgmtPassword("udp"): `C:\ProgramData\Veyl\data\mgmt-udp.pw`,
		w.Fonts():             `C:\ProgramData\Veyl\data\fonts`,
	} {
		if got != want {
			t.Errorf("%s != %s", got, want)
		}
	}
	l := LinuxPaths()
	if l.Settings() != "/var/lib/veyl/settings.json" || l.Mgmt("tcp") != "/run/veyl/mgmt-tcp" || l.AgentSock() != "/run/veyl/agent.sock" {
		t.Fatal(l.Settings(), l.Mgmt("tcp"))
	}
	withPlatform(t, PlatformWindows)
	if DefaultPaths() != w {
		t.Fatal(DefaultPaths())
	}
	withPlatform(t, PlatformLinux)
	if DefaultPaths() != l {
		t.Fatal(DefaultPaths())
	}
	if Join(`C:\a\`, "b/c") != `C:\a\b\c` || Join("/a", "b") != "/a/b" {
		t.Fatal(Join(`C:\a\`, "b/c"))
	}
	if TapName(InstanceTCP) != "Veyl TCP" || MgmtPort(InstanceTCP) != 7506 || MgmtPort(InstanceUDP) != 7505 {
		t.Fatal("instance mapping")
	}
}
