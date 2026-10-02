package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

const (
	CAFile         = "ca.crt"
	CAKeyFile      = "ca.key"
	ServerCertFile = "server.crt"
	ServerKeyFile  = "server.key"
	TLSCryptV2File = "tls-crypt-v2-server.key"
	CRLFile        = "crl.pem"
	ServerCN       = "veyl-server"
)

var (
	ErrBadCSR    = errors.New("invalid csr")
	ErrBadSerial = errors.New("invalid serial")
)

type CA struct {
	dir     string
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
	certPEM []byte
}

func writeFile(path string, data []byte, perm os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return err
	}
	if err := os.Chmod(tmp, perm); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func randSerial() (*big.Int, error) {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, err
	}
	return n.Add(n, big.NewInt(1)), nil
}

func keyID(pub *ecdsa.PublicKey) []byte {
	sum := sha1.Sum(elliptic.Marshal(pub.Curve, pub.X, pub.Y))
	return sum[:]
}

func encodeKey(k *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

func decodeKey(b []byte) (*ecdsa.PrivateKey, error) {
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, errors.New("bad key pem")
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, err
	}
	ek, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("not an ecdsa key")
	}
	return ek, nil
}

func decodeCert(b []byte) (*x509.Certificate, error) {
	blk, _ := pem.Decode(b)
	if blk == nil || blk.Type != "CERTIFICATE" {
		return nil, errors.New("bad certificate pem")
	}
	return x509.ParseCertificate(blk.Bytes)
}

func createCA(dir string) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serial, err := randSerial()
	if err != nil {
		return err
	}
	now := time.Now()
	tpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "veyl-ca"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
		SubjectKeyId:          keyID(&key.PublicKey),
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	kp, err := encodeKey(key)
	if err != nil {
		return err
	}
	if err := writeFile(filepath.Join(dir, CAKeyFile), kp, 0o600); err != nil {
		return err
	}
	return writeFile(filepath.Join(dir, CAFile), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
}

func (c *CA) createServer() error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serial, err := randSerial()
	if err != nil {
		return err
	}
	now := time.Now()
	tpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: ServerCN},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              c.cert.NotAfter.Add(-24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		SubjectKeyId:          keyID(&key.PublicKey),
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, c.cert, &key.PublicKey, c.key)
	if err != nil {
		return err
	}
	kp, err := encodeKey(key)
	if err != nil {
		return err
	}
	if err := writeFile(filepath.Join(c.dir, ServerKeyFile), kp, 0o600); err != nil {
		return err
	}
	return writeFile(filepath.Join(c.dir, ServerCertFile), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
}

func Load(dir string) (*CA, error) {
	cb, err := os.ReadFile(filepath.Join(dir, CAFile))
	if err != nil {
		return nil, err
	}
	kb, err := os.ReadFile(filepath.Join(dir, CAKeyFile))
	if err != nil {
		return nil, err
	}
	cert, err := decodeCert(cb)
	if err != nil {
		return nil, err
	}
	key, err := decodeKey(kb)
	if err != nil {
		return nil, err
	}
	return &CA{dir: dir, cert: cert, key: key, certPEM: cb}, nil
}

func Init(dir string) (*CA, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	if !exists(filepath.Join(dir, CAKeyFile)) || !exists(filepath.Join(dir, CAFile)) {
		if err := createCA(dir); err != nil {
			return nil, err
		}
	}
	if !exists(filepath.Join(dir, TLSCryptV2File)) {
		if err := GenerateTLSCryptV2Server(filepath.Join(dir, TLSCryptV2File)); err != nil {
			return nil, err
		}
	}
	ca, err := Load(dir)
	if err != nil {
		return nil, err
	}
	if !exists(filepath.Join(dir, ServerKeyFile)) || !exists(filepath.Join(dir, ServerCertFile)) {
		if err := ca.createServer(); err != nil {
			return nil, err
		}
	}
	if !exists(filepath.Join(dir, CRLFile)) {
		if err := ca.WriteCRL(filepath.Join(dir, CRLFile), nil); err != nil {
			return nil, err
		}
	}
	return ca, nil
}

func (c *CA) CertPEM() []byte { return c.certPEM }

func (c *CA) Cert() *x509.Certificate { return c.cert }

func SerialHex(certPEM []byte) (string, error) {
	cert, err := decodeCert(certPEM)
	if err != nil {
		return "", err
	}
	return cert.SerialNumber.Text(16), nil
}

func (c *CA) SignCSR(csrPEM []byte, cn string) ([]byte, error) {
	blk, _ := pem.Decode(csrPEM)
	if blk == nil || (blk.Type != "CERTIFICATE REQUEST" && blk.Type != "NEW CERTIFICATE REQUEST") {
		return nil, ErrBadCSR
	}
	csr, err := x509.ParseCertificateRequest(blk.Bytes)
	if err != nil {
		return nil, ErrBadCSR
	}
	if csr.CheckSignature() != nil {
		return nil, ErrBadCSR
	}
	pub, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return nil, ErrBadCSR
	}
	serial, err := randSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(2, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		SubjectKeyId:          keyID(pub),
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, c.cert, pub, c.key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

func (c *CA) WriteCRL(path string, serials []string) error {
	now := time.Now()
	entries := make([]x509.RevocationListEntry, 0, len(serials))
	for _, s := range serials {
		n, ok := new(big.Int).SetString(s, 16)
		if !ok || n.Sign() <= 0 {
			return ErrBadSerial
		}
		entries = append(entries, x509.RevocationListEntry{SerialNumber: n, RevocationTime: now})
	}
	tpl := &x509.RevocationList{
		Number:                    big.NewInt(now.UnixNano()),
		ThisUpdate:                now.Add(-time.Hour),
		NextUpdate:                now.AddDate(9, 0, 0),
		RevokedCertificateEntries: entries,
	}
	der, err := x509.CreateRevocationList(rand.Reader, tpl, c.cert, c.key)
	if err != nil {
		return err
	}
	return writeFile(path, pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der}), 0o644)
}
