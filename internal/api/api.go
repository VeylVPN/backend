package api

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/veylvpn/backend/internal/ovpn"
	"github.com/veylvpn/backend/internal/pki"
	"github.com/veylvpn/backend/internal/store"
)

const bodyLimit = 8 << 10

type Mgmt interface {
	Online() (map[string]bool, error)
	Kill(cn string) error
}

type Config struct {
	Endpoint         string
	Port             int
	Proto            string
	StaticDir        string
	CRLPath          string
	OpenRegistration bool
}

type Server struct {
	cfg   Config
	store *store.Store
	ca    *pki.CA
	mgmt  Mgmt
}

func New(cfg Config, st *store.Store, ca *pki.CA, mgmt Mgmt) *Server {
	if cfg.Port == 0 {
		cfg.Port = 1194
	}
	if cfg.Proto == "" {
		cfg.Proto = "udp"
	}
	return &Server{cfg: cfg, store: st, ca: ca, mgmt: mgmt}
}

type creds struct {
	Account     string `json:"account"`
	Password    string `json:"password"`
	Name        string `json:"name"`
	CSR         string `json:"csr"`
	ID          string `json:"id"`
	NewPassword string `json:"new_password"`
}

type deviceOut struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Created int64  `json:"created"`
	Online  bool   `json:"online"`
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/info", s.info)
	mux.HandleFunc("POST /v1/register", s.register)
	mux.HandleFunc("POST /v1/devices", s.devices)
	mux.HandleFunc("POST /v1/enroll", s.enroll)
	mux.HandleFunc("POST /v1/revoke", s.revoke)
	mux.HandleFunc("POST /v1/password", s.password)
	if s.cfg.StaticDir != "" {
		mux.Handle("/", http.FileServer(http.Dir(s.cfg.StaticDir)))
	}
	return s.headers(mux)
}

func (s *Server) headers(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Cache-Control", "no-store")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'")
		r.Body = http.MaxBytesReader(w, r.Body, bodyLimit)
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func errJSON(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func fail(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrBadCredentials), errors.Is(err, store.ErrNoAccount):
		errJSON(w, http.StatusUnauthorized, "invalid credentials")
	case errors.Is(err, store.ErrLocked):
		errJSON(w, http.StatusTooManyRequests, "too many attempts")
	case errors.Is(err, store.ErrClaimed):
		errJSON(w, http.StatusConflict, "account already claimed")
	case errors.Is(err, store.ErrDeviceLimit):
		errJSON(w, http.StatusConflict, "device limit reached")
	case errors.Is(err, store.ErrNoDevice):
		errJSON(w, http.StatusNotFound, "unknown device")
	case errors.Is(err, store.ErrWeakPassword):
		errJSON(w, http.StatusBadRequest, "password must be at least 10 characters")
	case errors.Is(err, store.ErrBadName):
		errJSON(w, http.StatusBadRequest, "invalid device name")
	case errors.Is(err, pki.ErrBadCSR):
		errJSON(w, http.StatusBadRequest, "invalid csr")
	default:
		errJSON(w, http.StatusInternalServerError, "server error")
	}
}

func decode(w http.ResponseWriter, r *http.Request) (creds, bool) {
	var c creds
	if json.NewDecoder(r.Body).Decode(&c) != nil {
		errJSON(w, http.StatusBadRequest, "bad request")
		return c, false
	}
	return c, true
}

func (s *Server) info(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"endpoint": s.cfg.Endpoint, "port": s.cfg.Port, "proto": s.cfg.Proto})
}

func (s *Server) register(w http.ResponseWriter, r *http.Request) {
	c, ok := decode(w, r)
	if !ok {
		return
	}
	if c.Account == "" {
		if !s.cfg.OpenRegistration {
			errJSON(w, http.StatusBadRequest, "account required")
			return
		}
		n, err := s.store.CreateClaimed(c.Password)
		if err != nil {
			fail(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"account": n})
		return
	}
	if err := s.store.Claim(c.Account, c.Password); err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"account": c.Account})
}

func (s *Server) online() map[string]bool {
	m, err := s.mgmt.Online()
	if err != nil || m == nil {
		return map[string]bool{}
	}
	return m
}

func (s *Server) devices(w http.ResponseWriter, r *http.Request) {
	c, ok := decode(w, r)
	if !ok {
		return
	}
	ds, err := s.store.Devices(c.Account, c.Password)
	if err != nil {
		fail(w, err)
		return
	}
	on := s.online()
	out := make([]deviceOut, 0, len(ds))
	for _, d := range ds {
		out = append(out, deviceOut{ID: d.ID, Name: d.Name, Created: d.Created, Online: on[d.ID]})
	}
	writeJSON(w, http.StatusOK, map[string]any{"limit": store.MaxDevices, "devices": out})
}

func newID() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func (s *Server) enroll(w http.ResponseWriter, r *http.Request) {
	c, ok := decode(w, r)
	if !ok {
		return
	}
	acc, err := s.store.Auth(c.Account, c.Password)
	if err != nil {
		fail(w, err)
		return
	}
	name, err := store.CleanName(c.Name)
	if err != nil {
		fail(w, err)
		return
	}
	if len(acc.Devices) >= store.MaxDevices {
		fail(w, store.ErrDeviceLimit)
		return
	}
	id, err := newID()
	if err != nil {
		fail(w, err)
		return
	}
	cert, err := s.ca.SignCSR([]byte(c.CSR), id)
	if err != nil {
		fail(w, err)
		return
	}
	serial, err := pki.SerialHex(cert)
	if err != nil {
		fail(w, err)
		return
	}
	d := store.Device{ID: id, Name: name, Serial: serial, Created: time.Now().Unix()}
	if err := s.store.AddDevice(c.Account, d); err != nil {
		fail(w, err)
		return
	}
	profile := ovpn.Profile(ovpn.Params{
		Host:     s.cfg.Endpoint,
		Port:     s.cfg.Port,
		Proto:    s.cfg.Proto,
		CA:       s.ca.CertPEM(),
		Cert:     cert,
		TLSCrypt: s.ca.TLSCrypt(),
	})
	writeJSON(w, http.StatusOK, map[string]string{"id": id, "profile": profile})
}

func (s *Server) revoke(w http.ResponseWriter, r *http.Request) {
	c, ok := decode(w, r)
	if !ok {
		return
	}
	d, err := s.store.Revoke(c.Account, c.Password, c.ID)
	if err != nil {
		fail(w, err)
		return
	}
	serials, err := s.store.Revoked()
	if err == nil {
		err = s.ca.WriteCRL(s.cfg.CRLPath, serials)
	}
	_ = s.mgmt.Kill(d.ID)
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}

func (s *Server) password(w http.ResponseWriter, r *http.Request) {
	c, ok := decode(w, r)
	if !ok {
		return
	}
	if err := s.store.ChangePassword(c.Account, c.Password, c.NewPassword); err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "changed"})
}
