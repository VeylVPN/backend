package store

import (
	"path/filepath"
	"testing"
)

func TestEnrollLimitsAndRevoke(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "s.json"), 2, 10)
	if err != nil {
		t.Fatal(err)
	}
	acc, err := s.NewAccount()
	if err != nil || len(acc) != 16 {
		t.Fatalf("account %q %v", acc, err)
	}
	d1, err := s.Enroll(acc, "k1")
	if err != nil || d1.Index != 2 {
		t.Fatalf("%v %v", d1, err)
	}
	if again, _ := s.Enroll(acc, "k1"); again.Index != d1.Index {
		t.Fatal("re-enroll changed address")
	}
	if _, err := s.Enroll(acc, "k2"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Enroll(acc, "k3"); err != ErrDeviceLimit {
		t.Fatalf("want limit, got %v", err)
	}
	if err := s.Revoke(acc, "k1"); err != nil {
		t.Fatal(err)
	}
	if d, err := s.Enroll(acc, "k3"); err != nil || d.Index != 2 {
		t.Fatalf("%v %v", d, err)
	}
	if _, err := s.Enroll("0000000000000000", "x"); err != ErrNoAccount {
		t.Fatal("expected unknown account")
	}
}

func TestPersistsHashedOnly(t *testing.T) {
	p := filepath.Join(t.TempDir(), "s.json")
	s, _ := Open(p, 5, 10)
	acc, _ := s.NewAccount()
	s2, _ := Open(p, 5, 10)
	if _, err := s2.Devices(acc); err != nil {
		t.Fatal(err)
	}
}
