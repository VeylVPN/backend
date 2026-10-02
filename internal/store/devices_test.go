package store

import (
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestAddDeviceNamedAndRename(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	s.SetDefaultLimit(2)
	n, err := s.CreateClaimed("correct horse")
	if err != nil {
		t.Fatal(err)
	}
	key := HashAccount(n)
	var seen map[string]bool
	pick := func(taken map[string]bool) string {
		seen = taken
		if taken["quiet otter"] {
			return "Brave Fox"
		}
		return "Quiet Otter"
	}
	d1, err := s.AddDeviceNamed(key, Device{ID: "a1", Serial: "1"}, pick)
	if err != nil || d1.Name != "Quiet Otter" || d1.Created == 0 {
		t.Fatalf("%+v %v", d1, err)
	}
	d2, err := s.AddDeviceNamed(key, Device{ID: "a2", Serial: "2"}, pick)
	if err != nil || d2.Name != "Brave Fox" || !seen["quiet otter"] {
		t.Fatalf("%+v %v %v", d2, err, seen)
	}
	if _, err := s.AddDeviceNamed(key, Device{ID: "a3", Name: "x", Serial: "3"}, pick); !errors.Is(err, ErrDeviceLimit) {
		t.Fatal(err)
	}
	if _, err := s.AddDeviceNamed(HashAccount("0000000000000000"), Device{ID: "a4"}, pick); !errors.Is(err, ErrBadCredentials) {
		t.Fatal(err)
	}
	r, err := s.RenameDevice(key, "a1", "  Work laptop ")
	if err != nil || r.Name != "Work laptop" {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := s.RenameDevice(key, "a1", "  "); !errors.Is(err, ErrBadName) {
		t.Fatal(err)
	}
	if _, err := s.RenameDevice(key, "zz", "ok"); !errors.Is(err, ErrNoDevice) {
		t.Fatal(err)
	}
	a, _ := s.AccountKey(key)
	if a.Devices[0].Name != "Work laptop" {
		t.Fatal(a.Devices)
	}
	exp := time.Now().Add(-time.Hour).Unix()
	if _, err := s.UpdateKey(key, Patch{Expires: &exp}); err != nil {
		t.Fatal(err)
	}
	s.SetDefaultLimit(5)
	if _, err := s.AddDeviceNamed(key, Device{ID: "a5", Name: "x"}, pick); !errors.Is(err, ErrExpired) {
		t.Fatal(err)
	}
}
