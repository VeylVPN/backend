package panel

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"os"
	"strings"

	"github.com/veylvpn/backend/internal/panelcfg"
)

const sealPrefix = "v1:"

var ErrSealed = errors.New("cannot decrypt stored secret")

type Sealer struct {
	aead cipher.AEAD
}

func LoadOrCreateKey(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err == nil {
		if len(b) != 32 {
			return nil, errors.New("secret key file has the wrong size")
		}
		if fi, err := os.Stat(path); err == nil && fi.Mode().Perm()&0o077 != 0 {
			_ = os.Chmod(path, 0o600)
		}
		return b, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	b = make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	if err := panelcfg.WriteFile(path, b, 0o600); err != nil {
		return nil, err
	}
	return b, nil
}

func NewSealer(key []byte) (*Sealer, error) {
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	g, err := cipher.NewGCM(blk)
	if err != nil {
		return nil, err
	}
	return &Sealer{aead: g}, nil
}

func (s *Sealer) Seal(plain, purpose string) (string, error) {
	if plain == "" {
		return "", nil
	}
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	out := s.aead.Seal(nonce, nonce, []byte(plain), []byte(purpose))
	return sealPrefix + base64.RawStdEncoding.EncodeToString(out), nil
}

func (s *Sealer) Open(sealed, purpose string) (string, error) {
	if sealed == "" {
		return "", nil
	}
	raw, ok := strings.CutPrefix(sealed, sealPrefix)
	if !ok {
		return "", ErrSealed
	}
	b, err := base64.RawStdEncoding.DecodeString(raw)
	if err != nil || len(b) < s.aead.NonceSize()+s.aead.Overhead() {
		return "", ErrSealed
	}
	n := s.aead.NonceSize()
	out, err := s.aead.Open(nil, b[:n], b[n:], []byte(purpose))
	if err != nil {
		return "", ErrSealed
	}
	return string(out), nil
}
