package store

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func open(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestClaim(t *testing.T) {
	s := open(t)
	n, err := s.NewAccount()
	if err != nil {
		t.Fatal(err)
	}
	if len(n) != 16 {
		t.Fatalf("account length %d", len(n))
	}
	cases := []struct {
		name string
		acct string
		pw   string
		want error
	}{
		{"short password", n, "short", ErrWeakPassword},
		{"unknown account", "0000000000000000", "longenoughpw1", ErrBadCredentials},
		{"first claim", n, "correct horse", nil},
		{"second claim", n, "another password", ErrClaimed},
	}
	for _, c := range cases {
		if got := s.Claim(c.acct, c.pw); !errors.Is(got, c.want) {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}
	if _, err := s.Auth(n, "correct horse"); err != nil {
		t.Fatalf("auth after claim: %v", err)
	}
}

func TestAuth(t *testing.T) {
	s := open(t)
	claimed, _ := s.NewAccount()
	unclaimed, _ := s.NewAccount()
	if err := s.Claim(claimed, "correct horse"); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		acct string
		pw   string
		want error
	}{
		{"ok", claimed, "correct horse", nil},
		{"wrong password", claimed, "wrong password", ErrBadCredentials},
		{"unknown account", "1111111111111111", "correct horse", ErrBadCredentials},
		{"unclaimed", unclaimed, "", ErrBadCredentials},
	}
	for _, c := range cases {
		if _, got := s.Auth(c.acct, c.pw); !errors.Is(got, c.want) {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}
}

func TestDeviceLimitAndRevoke(t *testing.T) {
	s := open(t)
	n, _ := s.NewAccount()
	pw := "correct horse"
	if err := s.Claim(n, pw); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < MaxDevices; i++ {
		d := Device{ID: string(rune('a'+i)) + "id", Name: "d", Serial: "1" + string(rune('0'+i)), Created: 1}
		if err := s.AddDevice(n, d); err != nil {
			t.Fatalf("add %d: %v", i, err)
		}
	}
	if err := s.AddDevice(n, Device{ID: "x", Name: "x", Serial: "ff"}); !errors.Is(err, ErrDeviceLimit) {
		t.Fatalf("limit: %v", err)
	}
	cases := []struct {
		name string
		pw   string
		id   string
		want error
	}{
		{"wrong password", "bad password!", "aid", ErrBadCredentials},
		{"unknown device", pw, "nope", ErrNoDevice},
		{"ok", pw, "aid", nil},
	}
	for _, c := range cases {
		if _, got := s.Revoke(n, c.pw, c.id); !errors.Is(got, c.want) {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}
	devs, err := s.Devices(n, pw)
	if err != nil || len(devs) != MaxDevices-1 {
		t.Fatalf("devices %v %v", len(devs), err)
	}
	rev, _ := s.Revoked()
	if len(rev) != 1 || rev[0] != "10" {
		t.Fatalf("revoked %v", rev)
	}
	if err := s.AddDevice(n, Device{ID: "x", Name: "x", Serial: "ff"}); err != nil {
		t.Fatalf("add after revoke: %v", err)
	}
}

func TestChangePassword(t *testing.T) {
	s := open(t)
	n, _ := s.NewAccount()
	_ = s.Claim(n, "correct horse")
	if err := s.ChangePassword(n, "wrong one here", "new password 1"); !errors.Is(err, ErrBadCredentials) {
		t.Fatalf("wrong: %v", err)
	}
	if err := s.ChangePassword(n, "correct horse", "short"); !errors.Is(err, ErrWeakPassword) {
		t.Fatalf("weak: %v", err)
	}
	if err := s.ChangePassword(n, "correct horse", "new password 1"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Auth(n, "correct horse"); !errors.Is(err, ErrBadCredentials) {
		t.Fatalf("old password still works: %v", err)
	}
	if _, err := s.Auth(n, "new password 1"); err != nil {
		t.Fatal(err)
	}
}

func TestDeleteAccountRevokesDevices(t *testing.T) {
	s := open(t)
	n, _ := s.NewAccount()
	_ = s.Claim(n, "correct horse")
	_ = s.AddDevice(n, Device{ID: "a", Name: "a", Serial: "abc"})
	devs, err := s.DeleteAccount(n)
	if err != nil || len(devs) != 1 {
		t.Fatalf("%v %v", devs, err)
	}
	rev, _ := s.Revoked()
	if len(rev) != 1 || rev[0] != "abc" {
		t.Fatalf("revoked %v", rev)
	}
	if _, err := s.DeleteAccount(n); !errors.Is(err, ErrNoAccount) {
		t.Fatalf("second delete: %v", err)
	}
}

func TestPersistence(t *testing.T) {
	p := filepath.Join(t.TempDir(), "state.json")
	s, _ := Open(p)
	n, _ := s.NewAccount()
	_ = s.Claim(n, "correct horse")
	fi, err := os.Stat(p)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v %v", fi, err)
	}
	s2, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s2.Auth(n, "correct horse"); err != nil {
		t.Fatal(err)
	}
}

func TestCleanName(t *testing.T) {
	cases := []struct {
		in   string
		want string
		err  error
	}{
		{"  laptop ", "laptop", nil},
		{"", "", ErrBadName},
		{"   ", "", ErrBadName},
		{"line\nbreak", "", ErrBadName},
		{"12345678901234567890123456789012", "12345678901234567890123456789012", nil},
		{"123456789012345678901234567890123", "", ErrBadName},
	}
	for _, c := range cases {
		got, err := CleanName(c.in)
		if got != c.want || !errors.Is(err, c.err) {
			t.Errorf("%q: got %q %v", c.in, got, err)
		}
	}
}

func TestThrottle(t *testing.T) {
	now := time.Unix(1000, 0)
	th := NewThrottle()
	th.now = func() time.Time { return now }
	for i := 0; i < 4; i++ {
		th.Fail("k")
		if th.Locked("k") {
			t.Fatalf("locked after %d", i+1)
		}
	}
	th.Fail("k")
	if !th.Locked("k") {
		t.Fatal("not locked after 5")
	}
	now = now.Add(59 * time.Second)
	if !th.Locked("k") {
		t.Fatal("unlocked early")
	}
	now = now.Add(2 * time.Second)
	if th.Locked("k") {
		t.Fatal("still locked after 60s")
	}
	th.Fail("k")
	now = now.Add(61 * time.Second)
	if !th.Locked("k") {
		t.Fatal("second lock should be 120s")
	}
	now = now.Add(60 * time.Second)
	if th.Locked("k") {
		t.Fatal("should be unlocked after 120s")
	}
	for i := 0; i < 20; i++ {
		th.Fail("k")
	}
	now = now.Add(14 * time.Minute)
	if !th.Locked("k") {
		t.Fatal("cap should be 15 minutes")
	}
	now = now.Add(2 * time.Minute)
	if th.Locked("k") {
		t.Fatal("lock exceeded cap")
	}
	th.Fail("k")
	th.Reset("k")
	if th.Locked("k") {
		t.Fatal("reset failed")
	}
}

func TestAuthThrottles(t *testing.T) {
	s := open(t)
	n, _ := s.NewAccount()
	_ = s.Claim(n, "correct horse")
	for i := 0; i < 5; i++ {
		if _, err := s.Auth(n, "wrong password"); !errors.Is(err, ErrBadCredentials) {
			t.Fatalf("attempt %d: %v", i, err)
		}
	}
	if _, err := s.Auth(n, "correct horse"); !errors.Is(err, ErrLocked) {
		t.Fatalf("expected lock: %v", err)
	}
}
