package backup

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/veylvpn/backend/internal/config"
	"github.com/veylvpn/backend/internal/pki"
)

func fixture(t *testing.T) config.Paths {
	t.Helper()
	dir := t.TempDir()
	p := config.Paths{Data: dir, Run: dir}
	if _, err := pki.Init(dir); err != nil {
		t.Fatal(err)
	}
	s := config.Defaults()
	s.Host = "vpn.example.com"
	s.Configured = true
	if err := config.Save(p.Settings(), s); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(p.State(), []byte(`{"accounts":[],"revoked":["ab"]}`), 0o600)
	_ = os.WriteFile(p.Admin(), []byte(`{"password":"x","epoch":"e"}`), 0o600)
	_ = os.WriteFile(filepath.Join(dir, "tls-crypt-v2-server.key"), []byte("v2key"), 0o640)
	_ = os.WriteFile(filepath.Join(dir, "unrelated.txt"), []byte("nope"), 0o644)
	return p
}

func TestRoundTrip(t *testing.T) {
	src := fixture(t)
	data, err := Create(src, "a strong passphrase")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(data, []byte(Magic)) {
		t.Fatal("magic")
	}
	if bytes.Contains(data, []byte("PRIVATE KEY")) {
		t.Fatal("plaintext in backup")
	}
	dst := config.Paths{Data: t.TempDir()}
	if err := Restore(dst, data, "a strong passphrase"); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"settings.json", "state.json", "admin.json", "ca.crt", "ca.key", "server.crt", "server.key", "tls-crypt.key", "tls-crypt-v2-server.key", "crl.pem"} {
		a, err1 := os.ReadFile(filepath.Join(src.Data, f))
		b, err2 := os.ReadFile(filepath.Join(dst.Data, f))
		if err1 != nil || err2 != nil || !bytes.Equal(a, b) {
			t.Fatal("mismatch", f, err1, err2)
		}
		e, _ := lookup(f)
		fi, _ := os.Stat(filepath.Join(dst.Data, f))
		if fi.Mode().Perm() != e.perm {
			t.Fatal("perm", f, fi.Mode().Perm())
		}
	}
	if _, err := os.Stat(filepath.Join(dst.Data, "unrelated.txt")); err == nil {
		t.Fatal("unrelated file included")
	}
	if _, err := pki.Load(dst.Data); err != nil {
		t.Fatal("restored pki unusable", err)
	}
}

func TestWrongPassphraseAndTamper(t *testing.T) {
	src := fixture(t)
	data, err := Create(src, "a strong passphrase")
	if err != nil {
		t.Fatal(err)
	}
	dst := config.Paths{Data: t.TempDir()}
	if err := Restore(dst, data, "the wrong passphrase"); !errors.Is(err, ErrPassphrase) {
		t.Fatal(err)
	}
	bad := append([]byte(nil), data...)
	bad[len(bad)-5] ^= 1
	if err := Restore(dst, bad, "a strong passphrase"); !errors.Is(err, ErrPassphrase) {
		t.Fatal(err)
	}
	salt := append([]byte(nil), data...)
	salt[len(Magic)] ^= 1
	if err := Restore(dst, salt, "a strong passphrase"); !errors.Is(err, ErrPassphrase) {
		t.Fatal(err)
	}
	if err := Restore(dst, []byte("garbage"), "x"); !errors.Is(err, ErrFormat) {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(dst.Data)
	if len(entries) != 0 {
		t.Fatal("failed restore wrote files")
	}
	if _, err := Create(src, "short"); !errors.Is(err, ErrWeak) {
		t.Fatal(err)
	}
}

func TestRestoreRefusesConfiguredUnlessForced(t *testing.T) {
	src := fixture(t)
	data, _ := Create(src, "a strong passphrase")
	dst := fixture(t)
	if err := Restore(dst, data, "a strong passphrase"); !errors.Is(err, ErrConfigured) {
		t.Fatal(err)
	}
	if err := RestoreForce(dst, data, "a strong passphrase"); err != nil {
		t.Fatal(err)
	}
}

func TestRestoreAdjust(t *testing.T) {
	src := fixture(t)
	data, _ := Create(src, "a strong passphrase")
	dst := config.Paths{Data: t.TempDir()}
	err := RestoreAdjust(dst, data, "a strong passphrase", func(s *config.Settings) {
		s.Configured = false
		s.Host = "new.example.com"
	})
	if err != nil {
		t.Fatal(err)
	}
	s, err := config.Load(dst.Settings())
	if err != nil || s.Configured || s.Host != "new.example.com" {
		t.Fatal(s, err)
	}
	if err := RestoreAdjust(dst, data, "a strong passphrase", func(s *config.Settings) { s.Host = "bad host" }); err == nil {
		t.Fatal("invalid adjusted settings accepted")
	}
}

func TestCreateNeedsCA(t *testing.T) {
	if _, err := Create(config.Paths{Data: t.TempDir()}, "a strong passphrase"); !errors.Is(err, ErrIncomplete) {
		t.Fatal(err)
	}
}
