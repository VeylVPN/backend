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
	for _, f := range []string{CAKeyFile, ServerKeyFile, TLSCryptFile} {
		fi, err := os.Stat(filepath.Join(dir, f))
		if err != nil || fi.Mode().Perm() != 0o600 {
			t.Errorf("%s: %v %v", f, fi, err)
		}
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

func TestTLSCryptFormat(t *testing.T) {
	ca, _ := newCA(t)
	lines := strings.Split(strings.TrimSpace(string(ca.TLSCrypt())), "\n")
	if len(lines) != 18 || lines[0] != "-----BEGIN OpenVPN Static key V1-----" || lines[17] != "-----END OpenVPN Static key V1-----" {
		t.Fatalf("bad format: %d lines", len(lines))
	}
	for _, l := range lines[1:17] {
		if len(l) != 32 {
			t.Fatalf("line length %d", len(l))
		}
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
