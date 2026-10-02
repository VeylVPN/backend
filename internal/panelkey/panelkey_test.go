package panelkey

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestPairingLifecycle(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	path := filepath.Join(t.TempDir(), FileName)
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	s.Now = func() time.Time { return now }
	code, exp, err := s.NewPairing("https://vpn.example.com", ScopeManage)
	if err != nil || exp.Sub(now) != CodeTTL {
		t.Fatal(err, exp)
	}
	if u, err := Decode(code); err != nil || u != "https://vpn.example.com" {
		t.Fatal(u, err)
	}
	now = now.Add(CodeTTL + time.Second)
	if _, _, err := s.Redeem(code, "x"); err != ErrCode {
		t.Fatal("expired code accepted", err)
	}
	code, _, _ = s.NewPairing("https://vpn.example.com", ScopeMonitor)
	secret, k, err := s.Redeem(code, "")
	if err != nil || k.Scope != ScopeMonitor || k.Name != "Veyl Control" || !ValidSecret(secret) {
		t.Fatal(err, k)
	}
	if _, _, err := s.Redeem(code, ""); err != ErrCode {
		t.Fatal("code reused")
	}
	fi, _ := os.Stat(path)
	if runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
		t.Fatal(fi.Mode())
	}
	raw, _ := os.ReadFile(path)
	if strings.Contains(string(raw), secret[4:]) || strings.Contains(string(raw), code) {
		t.Fatal("secret material stored")
	}
	now = now.Add(48 * time.Hour)
	got, ok := s.Authenticate(secret)
	if !ok || got.LastUsed != day(now) || got.LastUsed%86400 != 0 {
		t.Fatal(got)
	}
	if _, ok := s.Authenticate(secret + "x"); ok {
		t.Fatal("modified secret accepted")
	}
	s2, err := Open(path)
	if err != nil || len(s2.List()) != 1 || s2.List()[0].Hash != "" {
		t.Fatal(err)
	}
	if err := s2.Revoke(got.ID); err != nil {
		t.Fatal(err)
	}
	if _, ok := s2.Authenticate(secret); ok {
		t.Fatal("revoked key accepted")
	}
}

func TestLimitsAndValidation(t *testing.T) {
	s, _ := Open(filepath.Join(t.TempDir(), FileName))
	for _, u := range []string{"http://vpn.example.com", "https://user@vpn.example.com", "https://vpn.example.com/x", "https://", "https://vpn.example.com?a"} {
		if _, _, err := s.NewPairing(u, ScopeManage); err == nil {
			t.Errorf("%s accepted", u)
		}
	}
	if _, _, err := s.NewPairing("https://vpn.example.com", "root"); err != ErrScope {
		t.Fatal(err)
	}
	for i := 0; i < MaxPending+3; i++ {
		if _, _, err := s.NewPairing("https://vpn.example.com", ScopeManage); err != nil {
			t.Fatal(err)
		}
	}
	if s.Pending() != MaxPending {
		t.Fatal(s.Pending())
	}
	for _, c := range []string{"", "vpp_", "vpp_aGVsbG8.short", "xyz_aHR0cHM6Ly92cG4uZXhhbXBsZS5jb20.aaaaaaaaaaaaaaaaaaaaaaaa", "vpp_" + strings.Repeat("a", 500)} {
		if _, err := Decode(c); err == nil {
			t.Errorf("%q decoded", c)
		}
	}
	if u, err := NodeURL("2001:db8::1"); err != nil || u != "https://[2001:db8::1]" {
		t.Fatal(u, err)
	}
	if _, err := NodeURL("a/b"); err == nil {
		t.Fatal("bad host")
	}
	if n := CleanName(strings.Repeat("é", 100)); len([]rune(n)) != MaxName {
		t.Fatal(len(n))
	}
}
