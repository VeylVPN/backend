package panelkey

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

const (
	FileName     = "panel-keys.json"
	CodePrefix   = "vpp_"
	KeyPrefix    = "vpk_"
	CodeTTL      = 15 * time.Minute
	ScopeManage  = "manage"
	ScopeMonitor = "monitor"
	MaxKeys      = 32
	MaxPending   = 8
	MaxName      = 64
	maxURL       = 200
	maxCode      = 400
)

var (
	ErrCode    = errors.New("pairing code is not valid or has expired")
	ErrScope   = errors.New("unknown scope")
	ErrTooMany = errors.New("too many keys")
	ErrNoKey   = errors.New("key not found")
	ErrURL     = errors.New("invalid node address")
)

type Key struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Hash     string `json:"hash"`
	Scope    string `json:"scope"`
	Created  int64  `json:"created"`
	LastUsed int64  `json:"last_used,omitempty"`
}

type pending struct {
	Hash    string `json:"hash"`
	Scope   string `json:"scope"`
	Expires int64  `json:"expires"`
}

type file struct {
	Keys     []Key     `json:"keys"`
	Pairings []pending `json:"pairings"`
}

type Store struct {
	path string
	Now  func() time.Time

	mu sync.Mutex
	f  file
}

func Open(path string) (*Store, error) {
	s := &Store{path: path, Now: time.Now}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, &s.f); err != nil {
		return nil, err
	}
	return s, nil
}

func day(t time.Time) int64 {
	u := t.Unix()
	return u - u%86400
}

func hash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func random(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func (s *Store) save() error {
	b, err := json.MarshalIndent(s.f, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o750); err != nil {
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

func ValidScope(scope string) bool {
	return scope == ScopeManage || scope == ScopeMonitor
}

func NodeURL(host string) (string, error) {
	if host == "" || len(host) > 253 || strings.ContainsAny(host, "/?#@ \t\r\n") {
		return "", ErrURL
	}
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		host = "[" + host + "]"
	}
	return "https://" + host, nil
}

func checkURL(raw string) error {
	if len(raw) > maxURL {
		return ErrURL
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return ErrURL
	}
	return nil
}

func Encode(nodeURL, secret string) string {
	return CodePrefix + base64.RawURLEncoding.EncodeToString([]byte(nodeURL)) + "." + secret
}

func Decode(code string) (string, error) {
	code = strings.TrimSpace(code)
	if len(code) > maxCode || !strings.HasPrefix(code, CodePrefix) {
		return "", ErrCode
	}
	enc, secret, ok := strings.Cut(strings.TrimPrefix(code, CodePrefix), ".")
	if !ok || len(secret) < 20 {
		return "", ErrCode
	}
	raw, err := base64.RawURLEncoding.DecodeString(enc)
	if err != nil {
		return "", ErrCode
	}
	u := strings.TrimSuffix(string(raw), "/")
	if err := checkURL(u); err != nil {
		return "", ErrCode
	}
	return u, nil
}

func (s *Store) prune(now time.Time) {
	keep := s.f.Pairings[:0]
	for _, p := range s.f.Pairings {
		if p.Expires > now.Unix() {
			keep = append(keep, p)
		}
	}
	s.f.Pairings = keep
}

func (s *Store) NewPairing(nodeURL, scope string) (string, time.Time, error) {
	if !ValidScope(scope) {
		return "", time.Time{}, ErrScope
	}
	if err := checkURL(nodeURL); err != nil {
		return "", time.Time{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.Now()
	s.prune(now)
	for len(s.f.Pairings) >= MaxPending {
		s.f.Pairings = s.f.Pairings[1:]
	}
	code := Encode(nodeURL, random(24))
	exp := now.Add(CodeTTL)
	s.f.Pairings = append(s.f.Pairings, pending{Hash: hash(code), Scope: scope, Expires: exp.Unix()})
	if err := s.save(); err != nil {
		return "", time.Time{}, err
	}
	return code, exp, nil
}

func CleanName(name string) string {
	name = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, strings.TrimSpace(name))
	if !utf8.ValidString(name) {
		return ""
	}
	if utf8.RuneCountInString(name) > MaxName {
		name = string([]rune(name)[:MaxName])
	}
	return name
}

func (s *Store) Redeem(code, name string) (string, Key, error) {
	code = strings.TrimSpace(code)
	if len(code) > maxCode || !strings.HasPrefix(code, CodePrefix) {
		return "", Key{}, ErrCode
	}
	h := hash(code)
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.Now()
	s.prune(now)
	idx := -1
	for i, p := range s.f.Pairings {
		if subtle.ConstantTimeCompare([]byte(p.Hash), []byte(h)) == 1 {
			idx = i
		}
	}
	if idx < 0 {
		return "", Key{}, ErrCode
	}
	p := s.f.Pairings[idx]
	s.f.Pairings = append(s.f.Pairings[:idx], s.f.Pairings[idx+1:]...)
	if len(s.f.Keys) >= MaxKeys {
		_ = s.save()
		return "", Key{}, ErrTooMany
	}
	name = CleanName(name)
	if name == "" {
		name = "Veyl Control"
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", Key{}, err
	}
	secret := KeyPrefix + base64.RawURLEncoding.EncodeToString(b)
	idb := make([]byte, 8)
	if _, err := rand.Read(idb); err != nil {
		return "", Key{}, err
	}
	k := Key{ID: hex.EncodeToString(idb), Name: name, Hash: hash(secret), Scope: p.Scope, Created: day(now)}
	s.f.Keys = append(s.f.Keys, k)
	if err := s.save(); err != nil {
		return "", Key{}, err
	}
	return secret, k, nil
}

func ValidSecret(secret string) bool {
	if !strings.HasPrefix(secret, KeyPrefix) || len(secret) != len(KeyPrefix)+43 {
		return false
	}
	_, err := base64.RawURLEncoding.DecodeString(secret[len(KeyPrefix):])
	return err == nil
}

func (s *Store) Authenticate(secret string) (Key, bool) {
	if !ValidSecret(secret) {
		return Key{}, false
	}
	h := hash(secret)
	s.mu.Lock()
	defer s.mu.Unlock()
	idx := -1
	for i, k := range s.f.Keys {
		if subtle.ConstantTimeCompare([]byte(k.Hash), []byte(h)) == 1 {
			idx = i
		}
	}
	if idx < 0 {
		return Key{}, false
	}
	today := day(s.Now())
	if s.f.Keys[idx].LastUsed != today {
		s.f.Keys[idx].LastUsed = today
		_ = s.save()
	}
	return s.f.Keys[idx], true
}

func (s *Store) List() []Key {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Key, 0, len(s.f.Keys))
	for _, k := range s.f.Keys {
		k.Hash = ""
		out = append(out, k)
	}
	return out
}

func (s *Store) Pending() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.prune(s.Now())
	return len(s.f.Pairings)
}

func (s *Store) Revoke(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, k := range s.f.Keys {
		if k.ID == id {
			s.f.Keys = append(s.f.Keys[:i], s.f.Keys[i+1:]...)
			return s.save()
		}
	}
	return ErrNoKey
}
