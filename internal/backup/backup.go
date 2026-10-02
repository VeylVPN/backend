package backup

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"
	"unicode/utf8"

	"github.com/veylvpn/backend/internal/config"
)

const (
	Magic      = "VEYLBK1"
	Iterations = 600000
	saltLen    = 16
	nonceLen   = 12
	MaxSize    = 32 << 20
	maxFile    = 24 << 20
	MinPass    = 10
	MaxPass    = 256
)

var (
	ErrFormat     = errors.New("this is not a Veyl backup file")
	ErrPassphrase = errors.New("wrong passphrase or damaged backup")
	ErrWeak       = errors.New("passphrase must be at least 10 characters")
	ErrConfigured = errors.New("this server is already set up; restore needs --force")
	ErrIncomplete = errors.New("backup is missing the certificate authority")
)

type entry struct {
	name     string
	perm     os.FileMode
	required bool
}

var files = []entry{
	{"settings.json", 0o600, false},
	{"state.json", 0o600, false},
	{"admin.json", 0o600, false},
	{"ca.crt", 0o644, true},
	{"ca.key", 0o600, true},
	{"server.crt", 0o644, false},
	{"server.key", 0o600, false},
	{"tls-crypt-v2-server.key", 0o640, false},
	{"crl.pem", 0o644, false},
	{"panel-keys.json", 0o600, false},
}

func lookup(name string) (entry, bool) {
	for _, e := range files {
		if e.name == name {
			return e, true
		}
	}
	return entry{}, false
}

func checkPass(p string) error {
	n := utf8.RuneCountInString(p)
	if n < MinPass || n > MaxPass || !utf8.ValidString(p) {
		return ErrWeak
	}
	return nil
}

func key(pass string, salt []byte) ([]byte, error) {
	return pbkdf2.Key(sha256.New, pass, salt, Iterations, 32)
}

func Create(p config.Paths, passphrase string) ([]byte, error) {
	if err := checkPass(passphrase); err != nil {
		return nil, err
	}
	var raw bytes.Buffer
	gz := gzip.NewWriter(&raw)
	tw := tar.NewWriter(gz)
	mod := time.Unix(0, 0)
	for _, e := range files {
		b, err := os.ReadFile(filepath.Join(p.Data, e.name))
		if errors.Is(err, os.ErrNotExist) {
			if e.required {
				return nil, ErrIncomplete
			}
			continue
		}
		if err != nil {
			return nil, err
		}
		if len(b) > maxFile {
			return nil, errors.New("file too large to back up")
		}
		hdr := &tar.Header{Name: e.name, Mode: int64(e.perm), Size: int64(len(b)), ModTime: mod, Typeflag: tar.TypeReg, Format: tar.FormatPAX}
		if err := tw.WriteHeader(hdr); err != nil {
			return nil, err
		}
		if _, err := tw.Write(b); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	salt := make([]byte, saltLen)
	nonce := make([]byte, nonceLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	k, err := key(passphrase, salt)
	if err != nil {
		return nil, err
	}
	aead, err := newAEAD(k)
	if err != nil {
		return nil, err
	}
	head := make([]byte, 0, len(Magic)+saltLen+nonceLen)
	head = append(head, Magic...)
	head = append(head, salt...)
	head = append(head, nonce...)
	out := aead.Seal(head, nonce, raw.Bytes(), head[:len(Magic)+saltLen])
	if len(out) > MaxSize {
		return nil, errors.New("backup too large")
	}
	return out, nil
}

func newAEAD(k []byte) (cipher.AEAD, error) {
	blk, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(blk)
}

func Open(data []byte, passphrase string) (map[string][]byte, error) {
	if len(data) > MaxSize || len(data) < len(Magic)+saltLen+nonceLen+16 || string(data[:len(Magic)]) != Magic {
		return nil, ErrFormat
	}
	if len(passphrase) == 0 || len(passphrase) > MaxPass*4 {
		return nil, ErrPassphrase
	}
	salt := data[len(Magic) : len(Magic)+saltLen]
	nonce := data[len(Magic)+saltLen : len(Magic)+saltLen+nonceLen]
	k, err := key(passphrase, salt)
	if err != nil {
		return nil, err
	}
	aead, err := newAEAD(k)
	if err != nil {
		return nil, err
	}
	plain, err := aead.Open(nil, nonce, data[len(Magic)+saltLen+nonceLen:], data[:len(Magic)+saltLen])
	if err != nil {
		return nil, ErrPassphrase
	}
	gz, err := gzip.NewReader(bytes.NewReader(plain))
	if err != nil {
		return nil, ErrFormat
	}
	tr := tar.NewReader(io.LimitReader(gz, 4*maxFile))
	out := map[string][]byte{}
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, ErrFormat
		}
		if hdr.Typeflag != tar.TypeReg {
			return nil, ErrFormat
		}
		if _, ok := lookup(hdr.Name); !ok || hdr.Size < 0 || hdr.Size > maxFile {
			return nil, ErrFormat
		}
		if _, dup := out[hdr.Name]; dup {
			return nil, ErrFormat
		}
		b, err := io.ReadAll(io.LimitReader(tr, maxFile+1))
		if err != nil || int64(len(b)) != hdr.Size {
			return nil, ErrFormat
		}
		out[hdr.Name] = b
	}
	for _, e := range files {
		if _, ok := out[e.name]; e.required && !ok {
			return nil, ErrIncomplete
		}
	}
	if b, ok := out["settings.json"]; ok {
		s := config.Defaults()
		if json.Unmarshal(b, &s) != nil || s.Validate() != nil {
			return nil, ErrFormat
		}
	}
	for _, name := range []string{"state.json", "admin.json", "panel-keys.json"} {
		if b, ok := out[name]; ok && !json.Valid(b) {
			return nil, ErrFormat
		}
	}
	return out, nil
}

func Configured(p config.Paths) bool {
	s, err := config.Load(p.Settings())
	return err == nil && s.Configured
}

func Restore(p config.Paths, data []byte, passphrase string) error {
	if Configured(p) {
		return ErrConfigured
	}
	return RestoreForce(p, data, passphrase)
}

func RestoreForce(p config.Paths, data []byte, passphrase string) error {
	return RestoreAdjust(p, data, passphrase, nil)
}

func RestoreAdjust(p config.Paths, data []byte, passphrase string, adjust func(*config.Settings)) error {
	content, err := Open(data, passphrase)
	if err != nil {
		return err
	}
	if adjust != nil {
		s, err := config.Load(p.Settings())
		if err != nil {
			s = config.Defaults()
		}
		if b, ok := content["settings.json"]; ok {
			s = config.Defaults()
			if err := json.Unmarshal(b, &s); err != nil {
				return ErrFormat
			}
		}
		adjust(&s)
		s.Version = config.SchemaVersion
		if err := s.Validate(); err != nil {
			return err
		}
		b, err := json.MarshalIndent(s, "", "  ")
		if err != nil {
			return err
		}
		content["settings.json"] = b
	}
	if err := os.MkdirAll(p.Data, 0o755); err != nil {
		return err
	}
	var tmps []string
	cleanup := func() {
		for _, t := range tmps {
			_ = os.Remove(t)
		}
	}
	for _, e := range files {
		b, ok := content[e.name]
		if !ok {
			continue
		}
		tmp := filepath.Join(p.Data, "."+e.name+".restore")
		if err := os.WriteFile(tmp, b, e.perm); err != nil {
			cleanup()
			return err
		}
		if err := os.Chmod(tmp, e.perm); err != nil {
			cleanup()
			return err
		}
		tmps = append(tmps, tmp)
	}
	for _, e := range files {
		if _, ok := content[e.name]; !ok {
			continue
		}
		tmp := filepath.Join(p.Data, "."+e.name+".restore")
		if err := os.Rename(tmp, filepath.Join(p.Data, e.name)); err != nil {
			cleanup()
			return err
		}
	}
	return nil
}
