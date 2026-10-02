package api

import (
	"errors"
	"net/http"
	"strings"

	"github.com/veylvpn/backend/internal/config"
	"github.com/veylvpn/backend/internal/store"
)

type meOut struct {
	ID          string   `json:"id"`
	Created     string   `json:"created"`
	Expires     *string  `json:"expires"`
	DeviceLimit int      `json:"device_limit"`
	Devices     int      `json:"devices"`
	DNSBlocking []string `json:"dns_blocking"`
	DNSCustom   bool     `json:"dns_custom"`
	Status      string   `json:"status"`
}

type myDevice struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Created string `json:"created"`
	Online  bool   `json:"online"`
}

type dnsOut struct {
	DNSBlocking []string `json:"dns_blocking"`
	DNSCustom   bool     `json:"dns_custom"`
}

func (s *Server) status(acc store.Account) string {
	switch err := acc.Active(s.now().Unix()); {
	case errors.Is(err, store.ErrDisabled):
		return "disabled"
	case errors.Is(err, store.ErrExpired):
		return "expired"
	default:
		return "active"
	}
}

func (s *Server) me(w http.ResponseWriter, r *http.Request, acc store.Account, _ tokenHash) {
	set := s.settings()
	out := meOut{
		ID:          acc.ID,
		Created:     rfc3339(acc.Created),
		DeviceLimit: acc.EffectiveLimit(s.d.Store.DefaultLimit()),
		Devices:     len(acc.Devices),
		DNSBlocking: config.SortedCategories(acc.DNSCategories(set.DNS.Default)),
		DNSCustom:   acc.DNSCustom,
		Status:      s.status(acc),
	}
	if out.DNSBlocking == nil {
		out.DNSBlocking = []string{}
	}
	if acc.Expires > 0 {
		e := rfc3339(acc.Expires)
		out.Expires = &e
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) myDevices(w http.ResponseWriter, r *http.Request, acc store.Account, _ tokenHash) {
	s.settings()
	on := s.online()
	out := make([]myDevice, 0, len(acc.Devices))
	for _, d := range acc.Devices {
		out = append(out, myDevice{ID: d.ID, Name: d.Name, Created: rfc3339(d.Created), Online: on[d.ID]})
	}
	writeJSON(w, http.StatusOK, map[string]any{"limit": acc.EffectiveLimit(s.d.Store.DefaultLimit()), "devices": out})
}

type addDeviceReq struct {
	Name string `json:"name"`
	CSR  string `json:"csr"`
}

func (s *Server) addDevice(w http.ResponseWriter, r *http.Request, acc store.Account, _ tokenHash) {
	var req addDeviceReq
	if !decodeStrict(w, r, &req) {
		return
	}
	name := ""
	if strings.TrimSpace(req.Name) != "" {
		n, err := store.CleanName(req.Name)
		if err != nil {
			fail(w, err)
			return
		}
		name = n
	}
	d, profile, err := s.enrollDevice(acc, name, req.CSR)
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"id": d.ID, "name": d.Name, "profile": profile})
}

func deviceID(r *http.Request) (string, bool) {
	id := r.PathValue("id")
	return id, id != "" && len(id) <= maxDeviceID
}

type renameReq struct {
	Name string `json:"name"`
}

func (s *Server) renameDevice(w http.ResponseWriter, r *http.Request, acc store.Account, _ tokenHash) {
	id, ok := deviceID(r)
	if !ok {
		fail(w, store.ErrNoDevice)
		return
	}
	var req renameReq
	if !decodeStrict(w, r, &req) {
		return
	}
	d, err := s.d.Store.RenameDevice(acc.Hash, id, req.Name)
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, myDevice{ID: d.ID, Name: d.Name, Created: rfc3339(d.Created), Online: s.online()[d.ID]})
}

func (s *Server) deleteDevice(w http.ResponseWriter, r *http.Request, acc store.Account, _ tokenHash) {
	id, ok := deviceID(r)
	if !ok {
		fail(w, store.ErrNoDevice)
		return
	}
	d, err := s.d.Store.RevokeKey(acc.Hash, id)
	if err != nil {
		fail(w, err)
		return
	}
	if err := RevokeEffects(s.d, []store.Device{d}); err != nil {
		fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type dnsReq struct {
	Blocking *[]string `json:"blocking"`
}

func (s *Server) setDNS(w http.ResponseWriter, r *http.Request, acc store.Account, _ tokenHash) {
	var req dnsReq
	if !decodeStrict(w, r, &req) {
		return
	}
	if req.Blocking == nil {
		writeErr(w, http.StatusBadRequest, "blocking is required", CodeBadRequest)
		return
	}
	a, err := s.d.Store.UpdateKey(acc.Hash, store.Patch{DNS: req.Blocking})
	if err != nil {
		fail(w, err)
		return
	}
	cats := config.SortedCategories(a.DNS)
	if cats == nil {
		cats = []string{}
	}
	writeJSON(w, http.StatusOK, dnsOut{DNSBlocking: cats, DNSCustom: true})
}

func (s *Server) resetDNS(w http.ResponseWriter, r *http.Request, acc store.Account, _ tokenHash) {
	if err := s.d.Store.ResetDNS(acc.Hash); err != nil {
		fail(w, err)
		return
	}
	cats := config.SortedCategories(s.settings().DNS.Default)
	if cats == nil {
		cats = []string{}
	}
	writeJSON(w, http.StatusOK, dnsOut{DNSBlocking: cats, DNSCustom: false})
}

type passwordReq struct {
	Password    string `json:"password"`
	NewPassword string `json:"new_password"`
}

func (s *Server) changePassword(w http.ResponseWriter, r *http.Request, acc store.Account, _ tokenHash) {
	var req passwordReq
	if !decodeStrict(w, r, &req) {
		return
	}
	if err := s.d.Store.ChangePasswordKey(acc.Hash, req.Password, req.NewPassword); err != nil {
		fail(w, err)
		return
	}
	s.tokens.revokeAccount(acc.Hash)
	fresh, err := s.d.Store.AccountKey(acc.Hash)
	if err != nil {
		fail(w, err)
		return
	}
	s.issue(w, fresh)
}

type deleteMeReq struct {
	Password string `json:"password"`
}

func (s *Server) deleteMe(w http.ResponseWriter, r *http.Request, acc store.Account, _ tokenHash) {
	var req deleteMeReq
	if !decodeStrict(w, r, &req) {
		return
	}
	if _, err := s.d.Store.AuthKey(acc.Hash, req.Password); err != nil {
		fail(w, err)
		return
	}
	devs, err := s.d.Store.DeleteKey(acc.Hash)
	if err != nil {
		fail(w, err)
		return
	}
	s.tokens.revokeAccount(acc.Hash)
	if err := RevokeEffects(s.d, devs); err != nil {
		fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
