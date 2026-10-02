package api

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/veylvpn/backend/internal/store"
	"github.com/veylvpn/backend/internal/wg"
)

type Config struct {
	Endpoint  string
	DNS4      string
	DNS6      string
	Prefix    string
	Prefix6   string
	StaticDir string
	Origin    string
}

type Server struct {
	cfg   Config
	store *store.Store
	wg    wg.Manager
	pub   string
}

func New(cfg Config, st *store.Store, m wg.Manager, serverPub string) *Server {
	return &Server{cfg: cfg, store: st, wg: m, pub: serverPub}
}

type enrollReq struct {
	Account   string `json:"account"`
	PublicKey string `json:"public_key"`
}

type enrollResp struct {
	Address4  string `json:"address4"`
	Address6  string `json:"address6"`
	ServerKey string `json:"server_public_key"`
	Endpoint  string `json:"endpoint"`
	DNS       string `json:"dns"`
}

type deviceResp struct {
	PublicKey string `json:"public_key"`
	Address4  string `json:"address4"`
}

func validKey(k string) bool {
	b, err := base64.StdEncoding.DecodeString(k)
	return err == nil && len(b) == 32
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/enroll", s.enroll)
	mux.HandleFunc("POST /v1/devices", s.devices)
	mux.HandleFunc("POST /v1/revoke", s.revoke)
	mux.HandleFunc("GET /v1/info", s.info)
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
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'")
		if s.cfg.Origin != "" {
			h.Set("Access-Control-Allow-Origin", s.cfg.Origin)
			h.Set("Access-Control-Allow-Headers", "Content-Type")
			h.Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 4096)
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func fail(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrNoAccount):
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid account"})
	case errors.Is(err, store.ErrDeviceLimit):
		writeJSON(w, http.StatusConflict, map[string]string{"error": "device limit reached"})
	case errors.Is(err, store.ErrNoDevice):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown device"})
	default:
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server error"})
	}
}

func (s *Server) info(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"endpoint": s.cfg.Endpoint})
}

func (s *Server) enroll(w http.ResponseWriter, r *http.Request) {
	var req enrollReq
	if json.NewDecoder(r.Body).Decode(&req) != nil || !validKey(req.PublicKey) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request"})
		return
	}
	d, err := s.store.Enroll(req.Account, req.PublicKey)
	if err != nil {
		fail(w, err)
		return
	}
	if err := s.wg.AddPeer(d.PublicKey, d.Index); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server error"})
		return
	}
	writeJSON(w, http.StatusOK, enrollResp{
		Address4:  s.wg.Addr4(d.Index),
		Address6:  s.wg.Addr6(d.Index),
		ServerKey: s.pub,
		Endpoint:  s.cfg.Endpoint,
		DNS:       s.cfg.DNS4 + "," + s.cfg.DNS6,
	})
}

func (s *Server) devices(w http.ResponseWriter, r *http.Request) {
	var req enrollReq
	if json.NewDecoder(r.Body).Decode(&req) != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request"})
		return
	}
	ds, err := s.store.Devices(req.Account)
	if err != nil {
		fail(w, err)
		return
	}
	out := make([]deviceResp, 0, len(ds))
	for _, d := range ds {
		out = append(out, deviceResp{PublicKey: d.PublicKey, Address4: s.wg.Addr4(d.Index)})
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) revoke(w http.ResponseWriter, r *http.Request) {
	var req enrollReq
	if json.NewDecoder(r.Body).Decode(&req) != nil || !validKey(req.PublicKey) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request"})
		return
	}
	if err := s.store.Revoke(req.Account, req.PublicKey); err != nil {
		fail(w, err)
		return
	}
	_ = s.wg.RemovePeer(req.PublicKey)
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}

func Scrubber(m wg.Manager, st *store.Store, every, idle time.Duration, stop <-chan struct{}) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			idx := map[string]int{}
			for _, d := range st.All() {
				idx[d.PublicKey] = d.Index
			}
			m.ScrubIdle(idx, idle)
		}
	}
}
