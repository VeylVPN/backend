package store

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base32"
	"strings"

	"github.com/veylvpn/backend/internal/config"
)

type Patch struct {
	Label    *string
	Expires  *int64
	Disabled *bool
	Limit    *int
	DNS      *[]string
}

func (s *Store) byID(id string) *Account {
	for i := range s.st.Accounts {
		if subtle.ConstantTimeCompare([]byte(s.st.Accounts[i].ID), []byte(id)) == 1 {
			return &s.st.Accounts[i]
		}
	}
	return nil
}

func (s *Store) AccountKey(key string) (Account, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.load(); err != nil {
		return Account{}, err
	}
	a := s.find(key)
	if a == nil {
		return Account{}, ErrNoAccount
	}
	return a.copy(), nil
}

func (s *Store) AccountID(id string) (Account, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.load(); err != nil {
		return Account{}, err
	}
	a := s.byID(id)
	if a == nil {
		return Account{}, ErrNoAccount
	}
	return a.copy(), nil
}

func (s *Store) Accounts() ([]Account, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.load(); err != nil {
		return nil, err
	}
	out := make([]Account, 0, len(s.st.Accounts))
	for _, a := range s.st.Accounts {
		c := a.copy()
		c.Password = ""
		c.Hash = ""
		out = append(out, c)
	}
	return out, nil
}

func applyPatch(a *Account, p Patch) error {
	if p.Label != nil {
		l, err := CleanLabel(*p.Label)
		if err != nil {
			return err
		}
		a.Label = l
	}
	if p.Expires != nil {
		if *p.Expires < 0 {
			return ErrBadLabel
		}
		a.Expires = *p.Expires
	}
	if p.Disabled != nil {
		a.Disabled = *p.Disabled
	}
	if p.Limit != nil {
		if *p.Limit < 0 || *p.Limit > 20 {
			return ErrDeviceLimit
		}
		a.Limit = *p.Limit
	}
	if p.DNS != nil {
		if !config.ValidCategories(*p.DNS) {
			return config.ErrCategory
		}
		a.DNSCustom = true
		a.DNS = config.SortedCategories(*p.DNS)
	}
	return nil
}

func (s *Store) update(find func() *Account, p Patch) (Account, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.load(); err != nil {
		return Account{}, err
	}
	a := find()
	if a == nil {
		return Account{}, ErrNoAccount
	}
	tmp := a.copy()
	if err := applyPatch(&tmp, p); err != nil {
		return Account{}, err
	}
	*a = tmp
	return a.copy(), s.save()
}

func (s *Store) UpdateID(id string, p Patch) (Account, error) {
	return s.update(func() *Account { return s.byID(id) }, p)
}

func (s *Store) UpdateKey(key string, p Patch) (Account, error) {
	return s.update(func() *Account { return s.find(key) }, p)
}

func (s *Store) ResetDNS(key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.load(); err != nil {
		return err
	}
	a := s.find(key)
	if a == nil {
		return ErrNoAccount
	}
	a.DNSCustom = false
	a.DNS = nil
	return s.save()
}

func (s *Store) DeleteID(id string) ([]Device, error) {
	s.mu.Lock()
	a := s.byID(id)
	key := ""
	if a != nil {
		key = a.Hash
	}
	s.mu.Unlock()
	if key == "" {
		if err := func() error { s.mu.Lock(); defer s.mu.Unlock(); return s.load() }(); err != nil {
			return nil, err
		}
		s.mu.Lock()
		a = s.byID(id)
		if a != nil {
			key = a.Hash
		}
		s.mu.Unlock()
		if key == "" {
			return nil, ErrNoAccount
		}
	}
	return s.DeleteKey(key)
}

func (s *Store) RevokeID(accountID, deviceID string) (Device, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.load(); err != nil {
		return Device{}, err
	}
	a := s.byID(accountID)
	if a == nil {
		return Device{}, ErrNoAccount
	}
	return s.revokeIn(a, deviceID)
}

func (s *Store) LookupDevice(cn string) (Account, Device, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.load(); err != nil {
		return Account{}, Device{}, false
	}
	for _, a := range s.st.Accounts {
		for _, d := range a.Devices {
			if d.ID == cn {
				return a.copy(), d, true
			}
		}
	}
	return Account{}, Device{}, false
}

func (s *Store) Counts() (accounts, devices int, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.load(); err != nil {
		return 0, 0, err
	}
	for _, a := range s.st.Accounts {
		devices += len(a.Devices)
	}
	return len(s.st.Accounts), devices, nil
}

var inviteEnc = base32.StdEncoding.WithPadding(base32.NoPadding)

func newInviteCode() (string, error) {
	b := make([]byte, 10)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	c := inviteEnc.EncodeToString(b)
	return "VEYL-" + c[0:4] + "-" + c[4:8] + "-" + c[8:12] + "-" + c[12:16], nil
}

func NormalizeInvite(code string) string {
	c := strings.ToUpper(strings.TrimSpace(code))
	if len(c) > 64 {
		return ""
	}
	return c
}

func (s *Store) NewInvite(uses int, expires int64) (string, Invite, error) {
	if uses < 1 || uses > 1000 {
		return "", Invite{}, ErrBadInvite
	}
	code, err := newInviteCode()
	if err != nil {
		return "", Invite{}, err
	}
	inv := Invite{ID: randHex(6), Hash: hashAccount(code), Created: s.today(), Expires: expires, Uses: uses}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.load(); err != nil {
		return "", Invite{}, err
	}
	s.st.Invites = append(s.st.Invites, inv)
	if err := s.save(); err != nil {
		return "", Invite{}, err
	}
	inv.Hash = ""
	return code, inv, nil
}

func (s *Store) Invites() ([]Invite, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.load(); err != nil {
		return nil, err
	}
	out := make([]Invite, 0, len(s.st.Invites))
	for _, i := range s.st.Invites {
		i.Hash = ""
		out = append(out, i)
	}
	return out, nil
}

func (s *Store) DeleteInvite(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.load(); err != nil {
		return err
	}
	for i, inv := range s.st.Invites {
		if inv.ID == id {
			s.st.Invites = append(s.st.Invites[:i], s.st.Invites[i+1:]...)
			return s.save()
		}
	}
	return ErrNoInvite
}

func (s *Store) RedeemInvite(code, password string) (string, error) {
	if err := checkPassword(password); err != nil {
		return "", err
	}
	c := NormalizeInvite(code)
	if c == "" {
		return "", ErrBadInvite
	}
	key := "invite:" + hashAccount(c)
	if s.throttle.Locked(key) {
		return "", ErrLocked
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
	want := hashAccount(c)
	now := s.now().Unix()
	for i := range s.st.Invites {
		inv := &s.st.Invites[i]
		if subtle.ConstantTimeCompare([]byte(inv.Hash), []byte(want)) != 1 {
			continue
		}
		if inv.Used >= inv.Uses || (inv.Expires > 0 && now >= inv.Expires) {
			return "", ErrBadInvite
		}
		number, err := s.insert(Account{Password: h})
		if err != nil {
			return "", err
		}
		inv.Used++
		if inv.Used >= inv.Uses {
			s.st.Invites = append(s.st.Invites[:i], s.st.Invites[i+1:]...)
		}
		s.throttle.Reset(key)
		return number, s.save()
	}
	s.throttle.Fail(key)
	return "", ErrBadInvite
}

func (a Account) DNSCategories(def []string) []string {
	if a.DNSCustom {
		return append([]string(nil), a.DNS...)
	}
	return append([]string(nil), def...)
}
