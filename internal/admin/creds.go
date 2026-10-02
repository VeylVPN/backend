package admin

import (
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/veylvpn/backend/internal/config"
)

const (
	MinPassword = 12
	MaxPassword = 256
	iterations  = 600000
	maxIter     = 5000000
	prefix      = "pbkdf2-sha256"
	TOTPPeriod  = 30
	TOTPDigits  = 6
	TOTPSkew    = 1
)

var (
	ErrWeakPassword = errors.New("password must be at least 12 characters")
	ErrNoAdmin      = errors.New("admin account is not set up")
	ErrBadCode      = errors.New("invalid code")
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

type Creds struct {
	Password   string `json:"password"`
	TOTPSecret string `json:"totp_secret,omitempty"`
	TOTPLast   int64  `json:"totp_last,omitempty"`
	Epoch      string `json:"epoch"`
}

var fileMu sync.Mutex

func ValidPassword(pw string) error {
	n := utf8.RuneCountInString(pw)
	if n < MinPassword || n > MaxPassword || !utf8.ValidString(pw) {
		return ErrWeakPassword
	}
	return nil
}

func randHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

func hashPassword(pw string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	dk, err := pbkdf2.Key(sha256.New, pw, salt, iterations, 32)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s$%d$%s$%s", prefix, iterations, hex.EncodeToString(salt), hex.EncodeToString(dk)), nil
}

func verifyPassword(stored, pw string) bool {
	p := strings.Split(stored, "$")
	if len(p) != 4 || p[0] != prefix {
		return false
	}
	iter, err := strconv.Atoi(p[1])
	if err != nil || iter < 1 || iter > maxIter {
		return false
	}
	salt, err := hex.DecodeString(p[2])
	if err != nil {
		return false
	}
	want, err := hex.DecodeString(p[3])
	if err != nil || len(want) == 0 {
		return false
	}
	dk, err := pbkdf2.Key(sha256.New, pw, salt, iter, len(want))
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(dk, want) == 1
}

var (
	dummyOnce sync.Once
	dummyHash string
)

func dummy() string {
	dummyOnce.Do(func() {
		dummyHash, _ = hashPassword("veyl-admin-dummy-password")
	})
	return dummyHash
}

func LoadCreds(p config.Paths) (Creds, error) {
	b, err := os.ReadFile(p.Admin())
	if errors.Is(err, os.ErrNotExist) {
		return Creds{}, ErrNoAdmin
	}
	if err != nil {
		return Creds{}, err
	}
	var c Creds
	if err := json.Unmarshal(b, &c); err != nil {
		return Creds{}, err
	}
	if c.Password == "" {
		return Creds{}, ErrNoAdmin
	}
	return c, nil
}

func saveCreds(p config.Paths, c Creds) error {
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p.Admin()), 0o755); err != nil {
		return err
	}
	tmp := p.Admin() + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, p.Admin())
}

func Exists(p config.Paths) bool {
	_, err := LoadCreds(p)
	return err == nil
}

func SetPassword(p config.Paths, pw string) error {
	if err := ValidPassword(pw); err != nil {
		return err
	}
	h, err := hashPassword(pw)
	if err != nil {
		return err
	}
	fileMu.Lock()
	defer fileMu.Unlock()
	c, err := LoadCreds(p)
	if err != nil && !errors.Is(err, ErrNoAdmin) {
		return err
	}
	c.Password = h
	c.Epoch = randHex(8)
	return saveCreds(p, c)
}

func ResetPassword(p config.Paths, pw string) error {
	if err := ValidPassword(pw); err != nil {
		return err
	}
	h, err := hashPassword(pw)
	if err != nil {
		return err
	}
	fileMu.Lock()
	defer fileMu.Unlock()
	return saveCreds(p, Creds{Password: h, Epoch: randHex(8)})
}

func updateCreds(p config.Paths, fn func(*Creds) error) error {
	fileMu.Lock()
	defer fileMu.Unlock()
	c, err := LoadCreds(p)
	if err != nil {
		return err
	}
	if err := fn(&c); err != nil {
		return err
	}
	return saveCreds(p, c)
}

func TOTPCode(secret []byte, counter int64, digits int) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(counter))
	m := hmac.New(sha1.New, secret)
	m.Write(msg[:])
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	v := (uint32(sum[off])&0x7f)<<24 | uint32(sum[off+1])<<16 | uint32(sum[off+2])<<8 | uint32(sum[off+3])
	mod := uint32(1)
	for i := 0; i < digits; i++ {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", digits, v%mod)
}

func NewTOTPSecret() string {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b32.EncodeToString(b)
}

func cleanCode(code string) string {
	code = strings.ReplaceAll(strings.TrimSpace(code), " ", "")
	if len(code) != TOTPDigits {
		return ""
	}
	for _, r := range code {
		if r < '0' || r > '9' {
			return ""
		}
	}
	return code
}

func CheckTOTP(secret, code string, now time.Time, last int64) (int64, bool) {
	key, err := b32.DecodeString(strings.ToUpper(secret))
	if err != nil || len(key) == 0 {
		return 0, false
	}
	code = cleanCode(code)
	if code == "" {
		return 0, false
	}
	cur := now.Unix() / TOTPPeriod
	found := int64(0)
	ok := 0
	for d := int64(-TOTPSkew); d <= TOTPSkew; d++ {
		step := cur + d
		if step <= last {
			continue
		}
		if subtle.ConstantTimeCompare([]byte(TOTPCode(key, step, TOTPDigits)), []byte(code)) == 1 && ok == 0 {
			found = step
			ok = 1
		}
	}
	return found, ok == 1
}
