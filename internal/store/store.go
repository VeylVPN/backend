package store

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"
)

const (
	MaxDevices    = 5
	MinPassword   = 10
	MaxPassword   = 256
	MaxName       = 32
	pbkdf2Iter    = 600000
	pbkdf2MaxIter = 5000000
	pbkdf2Prefix  = "pbkdf2-sha256"
)

var (
	ErrNoAccount      = errors.New("unknown account")
	ErrBadCredentials = errors.New("invalid credentials")
	ErrLocked         = errors.New("too many attempts")
	ErrClaimed        = errors.New("account already claimed")
	ErrWeakPassword   = errors.New("password must be at least 10 characters")
	ErrBadName        = errors.New("invalid device name")
	ErrDeviceLimit    = errors.New("device limit reached")
	ErrNoDevice       = errors.New("unknown device")
)

type Device struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Serial  string `json:"serial"`
	Created int64  `json:"created"`
}

type Account struct {
	Hash     string   `json:"hash"`
	Password string   `json:"password,omitempty"`
	Devices  []Device `json:"devices"`
}

type state struct {
	Accounts []Account `json:"accounts"`
	Revoked  []string  `json:"revoked"`
}

type Store struct {
	mu       sync.Mutex
	path     string
	st       state
	throttle *Throttle
}

func Open(path string) (*Store, error) {
	s := &Store{path: path, throttle: NewThrottle()}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) Throttle() *Throttle { return s.throttle }

func (s *Store) load() error {
	b, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		s.st = state{}
		return nil
	}
	if err != nil {
		return err
	}
	var n state
	if err := json.Unmarshal(b, &n); err != nil {
		return err
	}
	s.st = n
	return nil
}

func (s *Store) save() error {
	b, err := json.Marshal(s.st)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func hashAccount(number string) string {
	sum := sha256.Sum256([]byte(number))
	return hex.EncodeToString(sum[:])
}

func hashPassword(pw string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	dk, err := pbkdf2.Key(sha256.New, pw, salt, pbkdf2Iter, 32)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s$%d$%s$%s", pbkdf2Prefix, pbkdf2Iter, hex.EncodeToString(salt), hex.EncodeToString(dk)), nil
}

func verifyPassword(stored, pw string) bool {
	p := strings.Split(stored, "$")
	if len(p) != 4 || p[0] != pbkdf2Prefix {
		return false
	}
	iter, err := strconv.Atoi(p[1])
	if err != nil || iter < 1 || iter > pbkdf2MaxIter {
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
		dummyHash, _ = hashPassword("veyl-dummy-password")
	})
	return dummyHash
}

func checkPassword(pw string) error {
	n := utf8.RuneCountInString(pw)
	if n < MinPassword || n > MaxPassword {
		return ErrWeakPassword
	}
	return nil
}

func CleanName(name string) (string, error) {
	n := strings.TrimSpace(name)
	c := utf8.RuneCountInString(n)
	if c < 1 || c > MaxName || !utf8.ValidString(n) {
		return "", ErrBadName
	}
	for _, r := range n {
		if unicode.IsControl(r) {
			return "", ErrBadName
		}
	}
	return n, nil
}

func (s *Store) find(key string) *Account {
	for i := range s.st.Accounts {
		if s.st.Accounts[i].Hash == key {
			return &s.st.Accounts[i]
		}
	}
	return nil
}

func (s *Store) NewAccount() (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.load(); err != nil {
		return "", err
	}
	max := new(big.Int).Exp(big.NewInt(10), big.NewInt(16), nil)
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		return "", err
	}
	number := fmt.Sprintf("%016d", n)
	s.st.Accounts = append(s.st.Accounts, Account{Hash: hashAccount(number), Devices: []Device{}})
	return number, s.save()
}

func (s *Store) Claim(number, password string) error {
	if err := checkPassword(password); err != nil {
		return err
	}
	key := hashAccount(number)
	if s.throttle.Locked(key) {
		return ErrLocked
	}
	s.mu.Lock()
	if err := s.load(); err != nil {
		s.mu.Unlock()
		return err
	}
	a := s.find(key)
	missing := a == nil
	claimed := a != nil && a.Password != ""
	s.mu.Unlock()
	if missing {
		s.throttle.Fail(key)
		return ErrBadCredentials
	}
	if claimed {
		return ErrClaimed
	}
	h, err := hashPassword(password)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.load(); err != nil {
		return err
	}
	a = s.find(key)
	if a == nil {
		return ErrBadCredentials
	}
	if a.Password != "" {
		return ErrClaimed
	}
	a.Password = h
	return s.save()
}

func (s *Store) CreateClaimed(password string) (string, error) {
	if err := checkPassword(password); err != nil {
		return "", err
	}
	h, err := hashPassword(password)
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.load(); err != nil {
		return "", err
	}
	max := new(big.Int).Exp(big.NewInt(10), big.NewInt(16), nil)
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		return "", err
	}
	number := fmt.Sprintf("%016d", n)
	s.st.Accounts = append(s.st.Accounts, Account{Hash: hashAccount(number), Password: h, Devices: []Device{}})
	return number, s.save()
}

func (s *Store) Auth(number, password string) (Account, error) {
	key := hashAccount(number)
	if s.throttle.Locked(key) {
		return Account{}, ErrLocked
	}
	s.mu.Lock()
	if err := s.load(); err != nil {
		s.mu.Unlock()
		return Account{}, err
	}
	var acc Account
	stored := ""
	if a := s.find(key); a != nil {
		acc = *a
		acc.Devices = append([]Device(nil), a.Devices...)
		stored = a.Password
	}
	s.mu.Unlock()
	known := stored != ""
	if !known {
		stored = dummy()
	}
	if !verifyPassword(stored, password) || !known {
		s.throttle.Fail(key)
		return Account{}, ErrBadCredentials
	}
	s.throttle.Reset(key)
	return acc, nil
}

func (s *Store) Devices(number, password string) ([]Device, error) {
	a, err := s.Auth(number, password)
	if err != nil {
		return nil, err
	}
	return a.Devices, nil
}

func (s *Store) AddDevice(number string, d Device) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.load(); err != nil {
		return err
	}
	a := s.find(hashAccount(number))
	if a == nil {
		return ErrBadCredentials
	}
	if len(a.Devices) >= MaxDevices {
		return ErrDeviceLimit
	}
	a.Devices = append(a.Devices, d)
	return s.save()
}

func (s *Store) Revoke(number, password, id string) (Device, error) {
	if _, err := s.Auth(number, password); err != nil {
		return Device{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.load(); err != nil {
		return Device{}, err
	}
	a := s.find(hashAccount(number))
	if a == nil {
		return Device{}, ErrBadCredentials
	}
	for i, d := range a.Devices {
		if d.ID == id {
			a.Devices = append(a.Devices[:i], a.Devices[i+1:]...)
			s.st.Revoked = append(s.st.Revoked, d.Serial)
			return d, s.save()
		}
	}
	return Device{}, ErrNoDevice
}

func (s *Store) ChangePassword(number, password, newPassword string) error {
	if _, err := s.Auth(number, password); err != nil {
		return err
	}
	if err := checkPassword(newPassword); err != nil {
		return err
	}
	h, err := hashPassword(newPassword)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.load(); err != nil {
		return err
	}
	a := s.find(hashAccount(number))
	if a == nil {
		return ErrBadCredentials
	}
	a.Password = h
	return s.save()
}

func (s *Store) Revoked() ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.load(); err != nil {
		return nil, err
	}
	return append([]string(nil), s.st.Revoked...), nil
}

func (s *Store) DeleteAccount(number string) ([]Device, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.load(); err != nil {
		return nil, err
	}
	key := hashAccount(number)
	for i := range s.st.Accounts {
		if s.st.Accounts[i].Hash == key {
			devs := s.st.Accounts[i].Devices
			for _, d := range devs {
				s.st.Revoked = append(s.st.Revoked, d.Serial)
			}
			s.st.Accounts = append(s.st.Accounts[:i], s.st.Accounts[i+1:]...)
			return devs, s.save()
		}
	}
	return nil, ErrNoAccount
}
