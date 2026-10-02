package api

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/veylvpn/backend/internal/config"
	"github.com/veylvpn/backend/internal/ovpn"
	"github.com/veylvpn/backend/internal/pki"
	"github.com/veylvpn/backend/internal/store"
)

type creds struct {
	Account     string `json:"account"`
	Password    string `json:"password"`
	Name        string `json:"name"`
	CSR         string `json:"csr"`
	ID          string `json:"id"`
	NewPassword string `json:"new_password"`
	Invite      string `json:"invite"`
}

type deviceOut struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Created int64  `json:"created"`
	Online  bool   `json:"online"`
}

func decodeLegacy(w http.ResponseWriter, r *http.Request) (creds, bool) {
	var c creds
	if err := json.NewDecoder(r.Body).Decode(&c); err != nil {
		code := CodeBadRequest
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			code = CodeTooLarge
		}
		writeErr(w, http.StatusBadRequest, "bad request", code)
		return c, false
	}
	return c, true
}

func newID() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func (s *Server) enrollDevice(acc store.Account, name, csr string) (store.Device, string, error) {
	set := s.settings()
	if set.Host == "" {
		return store.Device{}, "", errNotConfigured
	}
	if err := acc.Active(s.now().Unix()); err != nil {
		return store.Device{}, "", err
	}
	if len(acc.Devices) >= acc.EffectiveLimit(s.d.Store.DefaultLimit()) {
		return store.Device{}, "", store.ErrDeviceLimit
	}
	id, err := newID()
	if err != nil {
		return store.Device{}, "", err
	}
	cert, err := s.d.CA.SignCSR([]byte(csr), id)
	if err != nil {
		return store.Device{}, "", err
	}
	serial, err := pki.SerialHex(cert)
	if err != nil {
		return store.Device{}, "", err
	}
	tc, err := s.d.CA.TLSCryptV2Client([]byte(id))
	if err != nil {
		return store.Device{}, "", err
	}
	profile, err := ovpn.Profile(ovpn.Params{
		Host:       set.Host,
		UDPPort:    set.UDPPort,
		Stealth:    set.Stealth,
		CA:         s.d.CA.CertPEM(),
		Cert:       cert,
		TLSCryptV2: tc,
	})
	if err != nil {
		return store.Device{}, "", err
	}
	d, err := s.d.Store.AddDeviceNamed(acc.Hash, store.Device{ID: id, Name: name, Serial: serial, Created: s.now().Unix()}, friendlyName)
	if err != nil {
		return store.Device{}, "", err
	}
	return d, profile, nil
}

func (s *Server) register(w http.ResponseWriter, r *http.Request) {
	c, ok := decodeLegacy(w, r)
	if !ok {
		return
	}
	mode := s.settings().Registration
	account := strings.TrimSpace(c.Account)
	invite := strings.TrimSpace(c.Invite)
	switch {
	case account != "" && invite != "":
		writeErr(w, http.StatusBadRequest, "send either an account number or an invite", CodeBadRequest)
	case account != "":
		if err := s.d.Store.Claim(account, c.Password); err != nil {
			fail(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"account": account})
	case invite != "":
		if mode == config.RegClosed {
			writeErr(w, http.StatusForbidden, "registration is closed", CodeRegClosed)
			return
		}
		if len(invite) > 64 {
			fail(w, store.ErrBadInvite)
			return
		}
		n, err := s.d.Store.RedeemInvite(invite, c.Password)
		if err != nil {
			fail(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"account": n})
	case mode == config.RegOpen:
		n, err := s.d.Store.CreateClaimed(c.Password)
		if err != nil {
			fail(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"account": n})
	case mode == config.RegInvite:
		writeErr(w, http.StatusBadRequest, "account or invite required", CodeInviteRequired)
	default:
		writeErr(w, http.StatusBadRequest, "account required", CodeRegClosed)
	}
}

func (s *Server) legacyDevices(w http.ResponseWriter, r *http.Request) {
	c, ok := decodeLegacy(w, r)
	if !ok {
		return
	}
	s.settings()
	acc, err := s.d.Store.Auth(c.Account, c.Password)
	if err != nil {
		fail(w, err)
		return
	}
	on := s.online()
	out := make([]deviceOut, 0, len(acc.Devices))
	for _, d := range acc.Devices {
		out = append(out, deviceOut{ID: d.ID, Name: d.Name, Created: d.Created, Online: on[d.ID]})
	}
	writeJSON(w, http.StatusOK, map[string]any{"limit": acc.EffectiveLimit(s.d.Store.DefaultLimit()), "devices": out})
}

func (s *Server) legacyEnroll(w http.ResponseWriter, r *http.Request) {
	c, ok := decodeLegacy(w, r)
	if !ok {
		return
	}
	acc, err := s.d.Store.Auth(c.Account, c.Password)
	if err != nil {
		fail(w, err)
		return
	}
	name, err := store.CleanName(c.Name)
	if err != nil {
		fail(w, err)
		return
	}
	d, profile, err := s.enrollDevice(acc, name, c.CSR)
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"id": d.ID, "profile": profile})
}

func (s *Server) legacyRevoke(w http.ResponseWriter, r *http.Request) {
	c, ok := decodeLegacy(w, r)
	if !ok {
		return
	}
	d, err := s.d.Store.Revoke(c.Account, c.Password, c.ID)
	if err != nil {
		fail(w, err)
		return
	}
	if err := RevokeEffects(s.d, []store.Device{d}); err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}

func (s *Server) legacyPassword(w http.ResponseWriter, r *http.Request) {
	c, ok := decodeLegacy(w, r)
	if !ok {
		return
	}
	if err := s.d.Store.ChangePassword(c.Account, c.Password, c.NewPassword); err != nil {
		fail(w, err)
		return
	}
	if store.ValidNumber(c.Account) {
		s.tokens.revokeAccount(store.HashAccount(c.Account))
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "changed"})
}

func rfc3339(unix int64) string {
	return time.Unix(unix, 0).UTC().Format(time.RFC3339)
}
