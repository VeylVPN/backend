package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func csrPEM(t *testing.T, key any) []byte {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

func newCA(t *testing.T) (*CA, string) {
	t.Helper()
	dir := t.TempDir()
	ca, err := Init(dir)
	if err != nil {
		t.Fatal(err)
	}
	return ca, dir
}

func TestInitFiles(t *testing.T) {
	ca, dir := newCA(t)
	for f, perm := range map[string]os.FileMode{CAKeyFile: 0o600, ServerKeyFile: 0o600, TLSCryptV2File: 0o640} {
		fi, err := os.Stat(filepath.Join(dir, f))
		if err != nil || fi.Mode().Perm() != perm {
			t.Errorf("%s: %v %v", f, fi, err)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "tls-crypt.key")); err == nil {
		t.Error("legacy tls-crypt v1 key generated")
	}
	for _, f := range []string{CAFile, ServerCertFile, CRLFile} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Errorf("%s: %v", f, err)
		}
	}
	again, err := Init(dir)
	if err != nil {
		t.Fatal(err)
	}
	if string(again.CertPEM()) != string(ca.CertPEM()) {
		t.Fatal("init regenerated the CA")
	}
	sb, _ := os.ReadFile(filepath.Join(dir, ServerCertFile))
	blk, _ := pem.Decode(sb)
	sc, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if sc.Subject.CommonName != ServerCN {
		t.Fatalf("cn %q", sc.Subject.CommonName)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert())
	if _, err := sc.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		t.Fatal(err)
	}
}

func TestTLSCryptV2Client(t *testing.T) {
	ca, dir := newCA(t)
	srv, err := os.ReadFile(filepath.Join(dir, TLSCryptV2File))
	if err != nil || !strings.HasPrefix(string(srv), serverKeyHeader) {
		t.Fatalf("server key %q %v", srv, err)
	}
	key, err := ca.TLSCryptV2Client([]byte("abcdef0123456789"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(key), clientKeyHeader) {
		t.Fatalf("client key %q", key)
	}
	for _, bad := range [][]byte{nil, {}, make([]byte, MaxMetadata+1)} {
		if _, err := ca.TLSCryptV2Client(bad); !errors.Is(err, ErrMetadata) {
			t.Errorf("metadata %d: %v", len(bad), err)
		}
	}
	again, err := Init(dir)
	if err != nil {
		t.Fatal(err)
	}
	srv2, _ := os.ReadFile(again.TLSCryptV2ServerPath())
	if string(srv2) != string(srv) {
		t.Fatal("init regenerated the tls-crypt-v2 server key")
	}
}

func TestOpenVPNMissing(t *testing.T) {
	ca, _ := newCA(t)
	old := OpenVPNBin
	OpenVPNBin = filepath.Join(t.TempDir(), "missing")
	defer func() { OpenVPNBin = old }()
	if _, err := ca.TLSCryptV2Client([]byte("x")); !errors.Is(err, ErrOpenVPN) {
		t.Fatalf("%v", err)
	}
	if _, err := Init(t.TempDir()); !errors.Is(err, ErrOpenVPN) {
		t.Fatalf("init without openvpn: %v", err)
	}
}

func TestRealOpenVPNKeys(t *testing.T) {
	if os.Getenv("VEYL_REAL_OPENVPN") != "1" {
		t.Skip("set VEYL_REAL_OPENVPN=1")
	}
	old := OpenVPNBin
	OpenVPNBin = "/usr/sbin/openvpn"
	defer func() { OpenVPNBin = old }()
	ca, _ := newCA(t)
	key, err := ca.TLSCryptV2Client([]byte("abcdef0123456789"))
	if err != nil || !strings.HasPrefix(string(key), clientKeyHeader) {
		t.Fatalf("%q %v", key, err)
	}
}

func TestSignCSR(t *testing.T) {
	ca, _ := newCA(t)
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	rk, _ := rsa.GenerateKey(rand.Reader, 2048)
	good := csrPEM(t, ec)

	tampered := []byte(string(good))
	blk, _ := pem.Decode(good)
	blk.Bytes[len(blk.Bytes)-3] ^= 0xff
	tampered = pem.EncodeToMemory(blk)

	cases := []struct {
		name string
		csr  []byte
		err  error
	}{
		{"ec p256", good, nil},
		{"rsa", csrPEM(t, rk), ErrBadCSR},
		{"p384", csrPEM(t, p384), ErrBadCSR},
		{"garbage", []byte("nope"), ErrBadCSR},
		{"bad signature", tampered, ErrBadCSR},
	}
	for _, c := range cases {
		certPEM, err := ca.SignCSR(c.csr, "abcdef0123456789")
		if !errors.Is(err, c.err) {
			t.Errorf("%s: got %v want %v", c.name, err, c.err)
			continue
		}
		if c.err != nil {
			continue
		}
		b, _ := pem.Decode(certPEM)
		cert, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		if cert.Subject.CommonName != "abcdef0123456789" {
			t.Errorf("cn %q", cert.Subject.CommonName)
		}
		pool := x509.NewCertPool()
		pool.AddCert(ca.Cert())
		if _, err := cert.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
			t.Errorf("chain: %v", err)
		}
		if got := cert.NotAfter.Sub(cert.NotBefore).Hours() / 24; got < 729 || got > 732 {
			t.Errorf("validity days %v", got)
		}
		s, err := SerialHex(certPEM)
		if err != nil || s != cert.SerialNumber.Text(16) {
			t.Errorf("serial %q %v", s, err)
		}
	}
}

func TestCRL(t *testing.T) {
	ca, dir := newCA(t)
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	var serials []string
	for i := 0; i < 2; i++ {
		c, err := ca.SignCSR(csrPEM(t, ec), "dev")
		if err != nil {
			t.Fatal(err)
		}
		s, _ := SerialHex(c)
		serials = append(serials, s)
	}
	path := filepath.Join(dir, CRLFile)
	if err := ca.WriteCRL(path, serials[:1]); err != nil {
		t.Fatal(err)
	}
	read := func() *x509.RevocationList {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		blk, _ := pem.Decode(b)
		rl, err := x509.ParseRevocationList(blk.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		if err := rl.CheckSignatureFrom(ca.Cert()); err != nil {
			t.Fatal(err)
		}
		return rl
	}
	rl := read()
	if len(rl.RevokedCertificateEntries) != 1 || rl.RevokedCertificateEntries[0].SerialNumber.Text(16) != serials[0] {
		t.Fatalf("entries %v", rl.RevokedCertificateEntries)
	}
	if err := ca.WriteCRL(path, serials); err != nil {
		t.Fatal(err)
	}
	if n := len(read().RevokedCertificateEntries); n != 2 {
		t.Fatalf("entries %d", n)
	}
	if err := ca.WriteCRL(path, []string{"zz"}); !errors.Is(err, ErrBadSerial) {
		t.Fatalf("bad serial: %v", err)
	}
}
