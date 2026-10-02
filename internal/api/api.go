package api

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"mime"
	"net/http"
	"strconv"
	"time"

	"github.com/veylvpn/backend/docs"
	"github.com/veylvpn/backend/internal/app"
	"github.com/veylvpn/backend/internal/config"
	"github.com/veylvpn/backend/internal/ratelimit"
	"github.com/veylvpn/backend/internal/store"
)

const (
	bodyLimit   = 8 << 10
	maxDeviceID = 64
)

type Server struct {
	d       app.Deps
	tokens  *tokens
	auth    *ratelimit.Limiter
	general *ratelimit.Limiter
	now     func() time.Time
}

func New(d app.Deps) *Server {
	return &Server{
		d:       d,
		tokens:  newTokens(),
		auth:    ratelimit.New(ratelimit.Auth),
		general: ratelimit.New(ratelimit.General),
		now:     time.Now,
	}
}

func HTTPServer(addr string, h http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
		ErrorLog:          log.New(io.Discard, "", 0),
	}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/info", s.info)
	mux.HandleFunc("GET /v1/health", s.health)
	mux.HandleFunc("GET /v1/openapi.yaml", s.openapi)

	mux.Handle("POST /v1/register", s.authLimited(s.register))
	mux.Handle("POST /v1/devices", s.authLimited(s.legacyDevices))
	mux.Handle("POST /v1/enroll", s.authLimited(s.legacyEnroll))
	mux.Handle("POST /v1/revoke", s.authLimited(s.legacyRevoke))
	mux.Handle("POST /v1/password", s.authLimited(s.legacyPassword))

	mux.Handle("POST /v1/auth/token", s.authLimited(s.token))
	mux.Handle("POST /v1/auth/logout", s.bearer(s.logout))

	mux.Handle("GET /v1/me", s.bearer(s.me))
	mux.Handle("DELETE /v1/me", s.authLimited(s.bearer(s.deleteMe)))
	mux.Handle("GET /v1/me/devices", s.bearer(s.myDevices))
	mux.Handle("POST /v1/me/devices", s.bearer(s.addDevice))
	mux.Handle("PATCH /v1/me/devices/{id}", s.bearer(s.renameDevice))
	mux.Handle("DELETE /v1/me/devices/{id}", s.bearer(s.deleteDevice))
	mux.Handle("PUT /v1/me/dns", s.bearer(s.setDNS))
	mux.Handle("DELETE /v1/me/dns", s.bearer(s.resetDNS))
	mux.Handle("PUT /v1/me/password", s.authLimited(s.bearer(s.changePassword)))

	return s.headers(s.limitGeneral(s.jsonOnly(fallback(mux))))
}

func (s *Server) headers(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Cache-Control", "no-store")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		h.Set("Permissions-Policy", "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=(), interest-cohort=()")
		if r.Header.Get("X-Forwarded-Proto") == "https" {
			h.Set("Strict-Transport-Security", "max-age=63072000")
		}
		r.Body = http.MaxBytesReader(w, r.Body, bodyLimit)
		next.ServeHTTP(w, r)
	})
}

func tooMany(w http.ResponseWriter, wait time.Duration) {
	secs := int(wait / time.Second)
	if secs < 1 {
		secs = 1
	}
	w.Header().Set("Retry-After", strconv.Itoa(secs))
	writeErr(w, http.StatusTooManyRequests, "too many requests", CodeTooMany)
}

func (s *Server) limitGeneral(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ok, wait := s.general.AllowRequest(r); !ok {
			tooMany(w, wait)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) authLimited(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ok, wait := s.auth.AllowRequest(r); !ok {
			tooMany(w, wait)
			return
		}
		next(w, r)
	})
}

func hasBody(r *http.Request) bool {
	return r.ContentLength != 0 || len(r.TransferEncoding) > 0
}

func (s *Server) jsonOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
			if hasBody(r) {
				mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
				if err != nil || mt != "application/json" {
					writeErr(w, http.StatusUnsupportedMediaType, "content type must be application/json", CodeMediaType)
					return
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}

type capture struct {
	h    http.Header
	code int
}

func (c *capture) Header() http.Header         { return c.h }
func (c *capture) Write(b []byte) (int, error) { return len(b), nil }
func (c *capture) WriteHeader(code int) {
	if c.code == 0 {
		c.code = code
	}
}

func fallback(mux *http.ServeMux) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, pattern := mux.Handler(r); pattern != "" {
			mux.ServeHTTP(w, r)
			return
		}
		c := &capture{h: http.Header{}}
		mux.ServeHTTP(c, r)
		for _, k := range []string{"Allow", "Location"} {
			if v := c.h.Get(k); v != "" {
				w.Header().Set(k, v)
			}
		}
		switch c.code {
		case http.StatusMethodNotAllowed:
			writeErr(w, c.code, "method not allowed", CodeMethod)
		case http.StatusNotFound, 0:
			writeErr(w, http.StatusNotFound, "not found", CodeNotFound)
		default:
			w.WriteHeader(c.code)
		}
	})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func decodeStrict(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	err := dec.Decode(v)
	if err == nil {
		if _, terr := dec.Token(); terr != io.EOF {
			err = errors.New("trailing data")
		}
	}
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			writeErr(w, http.StatusRequestEntityTooLarge, "request body too large", CodeTooLarge)
			return false
		}
		writeErr(w, http.StatusBadRequest, "invalid request body", CodeBadRequest)
		return false
	}
	return true
}

func (s *Server) settings() config.Settings {
	set := s.d.Settings.Get()
	s.d.Store.SetDefaultLimit(set.DeviceLimit)
	return set
}

func (s *Server) online() map[string]bool {
	if s.d.Mgmt == nil {
		return map[string]bool{}
	}
	m, err := s.d.Mgmt.Online()
	if err != nil || m == nil {
		return map[string]bool{}
	}
	return m
}

func (s *Server) info(w http.ResponseWriter, r *http.Request) {
	set := s.settings()
	out := map[string]any{
		"endpoint":       set.Host,
		"port":           set.UDPPort,
		"proto":          "udp",
		"name":           set.Name,
		"version":        app.Version,
		"registration":   set.Registration,
		"device_limit":   set.DeviceLimit,
		"dns_categories": config.Categories,
		"dns_default":    config.SortedCategories(set.DNS.Default),
		"stealth":        set.Stealth,
		"post_quantum":   set.PostQuantum,
		"app_url":        set.AppURL,
	}
	if set.Stealth {
		out["stealth_port"] = config.StealthPort
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) openapi(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/yaml; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(docs.OpenAPI)
}

func RevokeEffects(d app.Deps, devices []store.Device) error {
	serials, err := d.Store.Revoked()
	if err == nil {
		err = d.CA.WriteCRL(d.Paths.CRL(), serials)
	}
	if d.Mgmt != nil {
		for _, dev := range devices {
			_ = d.Mgmt.Kill(dev.ID)
		}
	}
	return err
}
