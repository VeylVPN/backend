package store

import (
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func openStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestCreateAccountAndAdminOps(t *testing.T) {
	s := openStore(t)
	num, acc, err := s.CreateAccount(CreateOpts{Label: " Mum ", Password: "correct horse battery"})
	if err != nil {
		t.Fatal(err)
	}
	if !ValidNumber(num) || acc.ID == "" || acc.Label != "Mum" || acc.Created%86400 != 0 {
		t.Fatalf("%q %+v", num, acc)
	}
	list, _ := s.Accounts()
	if len(list) != 1 || list[0].Hash != "" || list[0].Password != "" {
		t.Fatalf("leaked secrets: %+v", list)
	}
	dis := true
	if _, err := s.UpdateID(acc.ID, Patch{Disabled: &dis}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Auth(num, "correct horse battery"); !errors.Is(err, ErrDisabled) {
		t.Fatalf("want disabled, got %v", err)
	}
	dis = false
	past := time.Now().Add(-time.Hour).Unix()
	if _, err := s.UpdateID(acc.ID, Patch{Disabled: &dis, Expires: &past}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Auth(num, "correct horse battery"); err != nil {
		t.Fatalf("expired accounts can still sign in: %v", err)
	}
	if err := s.AddDevice(num, Device{ID: "d1", Name: "x", Serial: "aa"}); !errors.Is(err, ErrExpired) {
		t.Fatalf("want expired, got %v", err)
	}
	var zero int64
	lim := 1
	if _, err := s.UpdateID(acc.ID, Patch{Expires: &zero, Limit: &lim}); err != nil {
		t.Fatal(err)
	}
	if err := s.AddDevice(num, Device{ID: "d1", Name: "x", Serial: "aa", Created: 1700000123}); err != nil {
		t.Fatal(err)
	}
	if err := s.AddDevice(num, Device{ID: "d2", Name: "y", Serial: "bb"}); !errors.Is(err, ErrDeviceLimit) {
		t.Fatalf("per-account limit not enforced: %v", err)
	}
	a, d, ok := s.LookupDevice("d1")
	if !ok || a.ID != acc.ID || d.Created != Day(1700000123) {
		t.Fatalf("lookup %v %+v", ok, d)
	}
	if _, err := s.RevokeID(acc.ID, "d1"); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := s.LookupDevice("d1"); ok {
		t.Fatal("revoked device still found")
	}
	rev, _ := s.Revoked()
	if len(rev) != 1 || rev[0] != "aa" {
		t.Fatalf("%v", rev)
	}
	if _, err := s.DeleteID(acc.ID); err != nil {
		t.Fatal(err)
	}
	if n, _, _ := s.Counts(); n != 0 {
		t.Fatal("not deleted")
	}
}

func TestDNSPreferences(t *testing.T) {
	s := openStore(t)
	num, _, _ := s.CreateAccount(CreateOpts{Password: "correct horse battery"})
	key := HashAccount(num)
	def := []string{"ads"}
	a, _ := s.AccountKey(key)
	if got := a.DNSCategories(def); len(got) != 1 || got[0] != "ads" {
		t.Fatalf("%v", got)
	}
	cats := []string{"malware", "ads"}
	if _, err := s.UpdateKey(key, Patch{DNS: &cats}); err != nil {
		t.Fatal(err)
	}
	a, _ = s.AccountKey(key)
	if got := a.DNSCategories(def); len(got) != 2 || got[0] != "ads" || got[1] != "malware" {
		t.Fatalf("%v", got)
	}
	bad := []string{"nope"}
	if _, err := s.UpdateKey(key, Patch{DNS: &bad}); err == nil {
		t.Fatal("accepted unknown category")
	}
	empty := []string{}
	if _, err := s.UpdateKey(key, Patch{DNS: &empty}); err != nil {
		t.Fatal(err)
	}
	a, _ = s.AccountKey(key)
	if got := a.DNSCategories(def); len(got) != 0 {
		t.Fatalf("explicit no-blocking lost: %v", got)
	}
	_ = s.ResetDNS(key)
	a, _ = s.AccountKey(key)
	if got := a.DNSCategories(def); len(got) != 1 {
		t.Fatalf("%v", got)
	}
}

func TestInvites(t *testing.T) {
	s := openStore(t)
	code, inv, err := s.NewInvite(2, 0)
	if err != nil || inv.Hash != "" {
		t.Fatal(err)
	}
	n1, err := s.RedeemInvite(" "+code+" ", "correct horse battery")
	if err != nil || !ValidNumber(n1) {
		t.Fatalf("%v", err)
	}
	if _, err := s.Auth(n1, "correct horse battery"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RedeemInvite(code, "short"); !errors.Is(err, ErrWeakPassword) {
		t.Fatal(err)
	}
	if _, err := s.RedeemInvite(code, "correct horse battery"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RedeemInvite(code, "correct horse battery"); !errors.Is(err, ErrBadInvite) {
		t.Fatalf("used-up invite accepted: %v", err)
	}
	list, _ := s.Invites()
	if len(list) != 0 {
		t.Fatalf("exhausted invite kept: %v", list)
	}
	code2, inv2, _ := s.NewInvite(1, time.Now().Add(-time.Minute).Unix())
	if _, err := s.RedeemInvite(code2, "correct horse battery"); !errors.Is(err, ErrBadInvite) {
		t.Fatal("expired invite accepted")
	}
	if err := s.DeleteInvite(inv2.ID); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		_, _ = s.RedeemInvite("VEYL-NOPE", "correct horse battery")
	}
	if _, err := s.RedeemInvite("VEYL-NOPE", "correct horse battery"); !errors.Is(err, ErrLocked) {
		t.Fatalf("invite guessing not throttled: %v", err)
	}
}

func TestBadNumberShortCircuits(t *testing.T) {
	s := openStore(t)
	long := make([]byte, 500000)
	for i := range long {
		long[i] = '1'
	}
	if _, err := s.Auth(string(long), "x"); !errors.Is(err, ErrBadCredentials) {
		t.Fatal(err)
	}
	if err := s.Claim("12ab", "correct horse battery"); !errors.Is(err, ErrBadCredentials) {
		t.Fatal(err)
	}
}

func TestMigrationAddsIDs(t *testing.T) {
	p := filepath.Join(t.TempDir(), "state.json")
	if err := writeRaw(p, `{"accounts":[{"hash":"abc","devices":[{"id":"x","name":"n","serial":"s","created":1700000123}]}],"revoked":null}`); err != nil {
		t.Fatal(err)
	}
	s, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	list, _ := s.Accounts()
	if len(list) != 1 || list[0].ID == "" || list[0].Devices[0].Created != Day(1700000123) {
		t.Fatalf("%+v", list)
	}
}

func writeRaw(p, body string) error {
	return osWriteFile(p, []byte(body))
}
