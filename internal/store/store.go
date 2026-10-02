package store

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sync"
)

var (
	ErrNoAccount   = errors.New("unknown account")
	ErrDeviceLimit = errors.New("device limit reached")
	ErrPoolFull    = errors.New("address pool exhausted")
	ErrNoDevice    = errors.New("unknown device")
)

type Device struct {
	PublicKey string `json:"public_key"`
	Index     int    `json:"index"`
}

type Account struct {
	Hash    string   `json:"hash"`
	Devices []Device `json:"devices"`
}

type Store struct {
	mu       sync.Mutex
	path     string
	maxDev   int
	poolSize int
	Accounts []Account `json:"accounts"`
}

func Open(path string, maxDevices, poolSize int) (*Store, error) {
	s := &Store{path: path, maxDev: maxDevices, poolSize: poolSize}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, s); err != nil {
		return nil, err
	}
	return s, nil
}

func hashAccount(number string) string {
	sum := sha256.Sum256([]byte(number))
	return hex.EncodeToString(sum[:])
}

func (s *Store) save() error {
	b, err := json.Marshal(s)
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
	return os.Rename(tmp, s.path)
}

func (s *Store) NewAccount() (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	max := new(big.Int).Exp(big.NewInt(10), big.NewInt(16), nil)
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		return "", err
	}
	number := fmt.Sprintf("%016d", n)
	s.Accounts = append(s.Accounts, Account{Hash: hashAccount(number)})
	return number, s.save()
}

func (s *Store) find(number string) *Account {
	h := hashAccount(number)
	for i := range s.Accounts {
		if s.Accounts[i].Hash == h {
			return &s.Accounts[i]
		}
	}
	return nil
}

func (s *Store) usedIndexes() map[int]bool {
	used := map[int]bool{}
	for _, a := range s.Accounts {
		for _, d := range a.Devices {
			used[d.Index] = true
		}
	}
	return used
}

func (s *Store) Enroll(number, pub string) (Device, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a := s.find(number)
	if a == nil {
		return Device{}, ErrNoAccount
	}
	for _, d := range a.Devices {
		if d.PublicKey == pub {
			return d, nil
		}
	}
	if len(a.Devices) >= s.maxDev {
		return Device{}, ErrDeviceLimit
	}
	used := s.usedIndexes()
	idx := 0
	for i := 2; i < s.poolSize; i++ {
		if !used[i] {
			idx = i
			break
		}
	}
	if idx == 0 {
		return Device{}, ErrPoolFull
	}
	d := Device{PublicKey: pub, Index: idx}
	a.Devices = append(a.Devices, d)
	return d, s.save()
}

func (s *Store) Revoke(number, pub string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	a := s.find(number)
	if a == nil {
		return ErrNoAccount
	}
	for i, d := range a.Devices {
		if d.PublicKey == pub {
			a.Devices = append(a.Devices[:i], a.Devices[i+1:]...)
			return s.save()
		}
	}
	return ErrNoDevice
}

func (s *Store) Devices(number string) ([]Device, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a := s.find(number)
	if a == nil {
		return nil, ErrNoAccount
	}
	return append([]Device(nil), a.Devices...), nil
}

func (s *Store) All() []Device {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Device
	for _, a := range s.Accounts {
		out = append(out, a.Devices...)
	}
	return out
}

func (s *Store) DeleteAccount(number string) ([]Device, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	h := hashAccount(number)
	for i := range s.Accounts {
		if s.Accounts[i].Hash == h {
			devs := s.Accounts[i].Devices
			s.Accounts = append(s.Accounts[:i], s.Accounts[i+1:]...)
			return devs, s.save()
		}
	}
	return nil, ErrNoAccount
}
