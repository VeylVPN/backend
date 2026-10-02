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
	"time"
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
	ErrDisabled       = errors.New("account disabled")
	ErrExpired        = errors.New("account expired")
	ErrBadNumber      = errors.New("invalid account number")
	ErrBadInvite      = errors.New("invalid invite")
	ErrNoInvite       = errors.New("unknown invite")
	ErrBadLabel       = errors.New("invalid label")
)

type Device struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Serial  string `json:"serial"`
	Created int64  `json:"created"`
}

type Account struct {
	ID        string   `json:"id"`
	Hash      string   `json:"hash"`
	Password  string   `json:"password,omitempty"`
	Label     string   `json:"label,omitempty"`
	Created   int64    `json:"created"`
	Expires   int64    `json:"expires,omitempty"`
	Disabled  bool     `json:"disabled,omitempty"`
	Limit     int      `json:"limit,omitempty"`
	DNSCustom bool     `json:"dns_custom,omitempty"`
	DNS       []string `json:"dns,omitempty"`
	Devices   []Device `json:"devices"`
}

type Invite struct {
	ID      string `json:"id"`
	Hash    string `json:"hash"`
	Created int64  `json:"created"`
	Expires int64  `json:"expires,omitempty"`
	Uses    int    `json:"uses"`
	Used    int    `json:"used"`
}

type state struct {
	Accounts []Account `json:"accounts"`
	Revoked  []string  `json:"revoked"`
	Invites  []Invite  `json:"invites,omitempty"`
}

type Store struct {
	mu       sync.Mutex
	path     string
	st       state
	throttle *Throttle
	limit    int
	now      func() time.Time
}

func Open(path string) (*Store, error) {
	s := &Store{path: path, throttle: NewThrottle(), limit: MaxDevices, now: time.Now}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) Throttle() *Throttle { return s.throttle }

func (s *Store) SetDefaultLimit(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if n > 0 {
		s.limit = n
	}
}

func (s *Store) DefaultLimit() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.limit
}

func Day(t int64) int64 {
	return t - t%86400
}

func (s *Store) today() int64 {
	return Day(s.now().Unix())
}

func randHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

func ValidNumber(n string) bool {
	if len(n) != 16 {
		return false
	}
	for _, r := range n {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func HashAccount(number string) string {
	return hashAccount(number)
}

func (a Account) EffectiveLimit(def int) int {
	if a.Limit > 0 {
		return a.Limit
	}
	return def
}

func (a Account) Active(now int64) error {
	if a.Disabled {
		return ErrDisabled
	}
	if a.Expires > 0 && now >= a.Expires {
		return ErrExpired
	}
	return nil
}

func (a Account) copy() Account {
	c := a
	c.Devices = append([]Device(nil), a.Devices...)
	c.DNS = append([]string(nil), a.DNS...)
	return c
}

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
	if s.migrate() {
		return s.save()
	}
	return nil
}

func (s *Store) migrate() bool {
	changed := false
	for i := range s.st.Accounts {
		a := &s.st.Accounts[i]
		if a.ID == "" {
			a.ID = randHex(6)
			changed = true
		}
		if a.Devices == nil {
			a.Devices = []Device{}
			changed = true
		}
		if a.Created == 0 {
			a.Created = s.today()
			changed = true
		}
		for j := range a.Devices {
			if d := Day(a.Devices[j].Created); d != a.Devices[j].Created {
				a.Devices[j].Created = d
				changed = true
			}
		}
	}
	return changed
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

func newNumber() (string, error) {
	max := new(big.Int).Exp(big.NewInt(10), big.NewInt(16), nil)
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%016d", n), nil
}

func (s *Store) insert(a Account) (string, error) {
	for {
		number, err := newNumber()
		if err != nil {
			return "", err
		}
		h := hashAccount(number)
		if s.find(h) != nil {
			continue
		}
		a.Hash = h
		a.ID = randHex(6)
		a.Created = s.today()
		if a.Devices == nil {
			a.Devices = []Device{}
		}
		s.st.Accounts = append(s.st.Accounts, a)
		return number, nil
	}
}

func (s *Store) NewAccount() (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.load(); err != nil {
		return "", err
	}
	number, err := s.insert(Account{})
	if err != nil {
		return "", err
	}
	return number, s.save()
}

type CreateOpts struct {
	Label    string
	Expires  int64
	Password string
	Limit    int
}

func CleanLabel(l string) (string, error) {
	l = strings.TrimSpace(l)
	if l == "" {
		return "", nil
	}
	if utf8.RuneCountInString(l) > 40 || !utf8.ValidString(l) {
		return "", ErrBadLabel
	}
	for _, r := range l {
		if unicode.IsControl(r) {
			return "", ErrBadLabel
		}
	}
	return l, nil
}

func (s *Store) CreateAccount(o CreateOpts) (string, Account, error) {
	label, err := CleanLabel(o.Label)
	if err != nil {
		return "", Account{}, err
	}
	a := Account{Label: label, Expires: o.Expires, Limit: o.Limit}
	if o.Password != "" {
		if err := checkPassword(o.Password); err != nil {
			return "", Account{}, err
		}
		h, err := hashPassword(o.Password)
		if err != nil {
			return "", Account{}, err
		}
		a.Password = h
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.load(); err != nil {
		return "", Account{}, err
	}
	number, err := s.insert(a)
	if err != nil {
		return "", Account{}, err
	}
	if err := s.save(); err != nil {
		return "", Account{}, err
	}
	return number, s.find(hashAccount(number)).copy(), nil
}

func (s *Store) Claim(number, password string) error {
	if err := checkPassword(password); err != nil {
		return err
	}
	if !ValidNumber(number) {
		return ErrBadCredentials
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
	number, err := s.insert(Account{Password: h})
	if err != nil {
		return "", err
	}
	return number, s.save()
}

func (s *Store) Auth(number, password string) (Account, error) {
	if !ValidNumber(number) {
		_ = verifyPassword(dummy(), password)
		return Account{}, ErrBadCredentials
	}
	return s.AuthKey(hashAccount(number), password)
}

func (s *Store) AuthKey(key, password string) (Account, error) {
	if len(password) > MaxPassword*4 {
		return Account{}, ErrBadCredentials
	}
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
		acc = a.copy()
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
	if acc.Disabled {
		return Account{}, ErrDisabled
	}
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
	return s.AddDeviceKey(hashAccount(number), d)
}

func (s *Store) AddDeviceKey(key string, d Device) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.load(); err != nil {
		return err
	}
	a := s.find(key)
	if a == nil {
		return ErrBadCredentials
	}
	if err := a.Active(s.now().Unix()); err != nil {
		return err
	}
	if len(a.Devices) >= a.EffectiveLimit(s.limit) {
		return ErrDeviceLimit
	}
	d.Created = Day(d.Created)
	if d.Created == 0 {
		d.Created = s.today()
	}
	a.Devices = append(a.Devices, d)
	return s.save()
}

func (s *Store) Revoke(number, password, id string) (Device, error) {
	if _, err := s.Auth(number, password); err != nil {
		return Device{}, err
	}
	return s.RevokeKey(hashAccount(number), id)
}

func (s *Store) RevokeKey(key, id string) (Device, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.load(); err != nil {
		return Device{}, err
	}
	a := s.find(key)
	if a == nil {
		return Device{}, ErrBadCredentials
	}
	return s.revokeIn(a, id)
}

func (s *Store) revokeIn(a *Account, id string) (Device, error) {
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
	if !ValidNumber(number) {
		return ErrBadCredentials
	}
	return s.ChangePasswordKey(hashAccount(number), password, newPassword)
}

func (s *Store) ChangePasswordKey(key, password, newPassword string) error {
	if _, err := s.AuthKey(key, password); err != nil {
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
	a := s.find(key)
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
	return s.DeleteKey(hashAccount(number))
}

func (s *Store) DeleteKey(key string) ([]Device, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.load(); err != nil {
		return nil, err
	}
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
