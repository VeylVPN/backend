package web

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"mime"
	"net"
	"net/http"
	"path"
	"strings"
)

//go:embed assets
var assets embed.FS

const CSP = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; font-src 'self'; manifest-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"

func Assets() fs.FS {
	sub, err := fs.Sub(assets, "assets")
	if err != nil {
		panic(err)
	}
	return sub
}

func Secure(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	return FromProxy(r) && strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

func FromProxy(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func ClientIP(r *http.Request) net.IP {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return nil
	}
	if ip.IsLoopback() {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			last := strings.TrimSpace(parts[len(parts)-1])
			if p := net.ParseIP(last); p != nil {
				return p
			}
			return nil
		}
	}
	return ip
}

func Headers(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Content-Security-Policy", CSP)
	h.Set("Cross-Origin-Opener-Policy", "same-origin")
	h.Set("Cross-Origin-Resource-Policy", "same-origin")
	h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), interest-cohort=()")
	if Secure(r) {
		h.Set("Strict-Transport-Security", "max-age=31536000")
	}
}

func JSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func Error(w http.ResponseWriter, code int, machine, msg string) {
	JSON(w, code, map[string]string{"error": msg, "code": machine})
}

func NotFound(w http.ResponseWriter) {
	Error(w, http.StatusNotFound, "NOT_FOUND", "Not found.")
}

var ErrBody = errors.New("bad body")

func Decode(w http.ResponseWriter, r *http.Request, v any, limit int64) bool {
	ct, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if ct != "application/json" {
		Error(w, http.StatusUnsupportedMediaType, "BAD_REQUEST", "Expected JSON.")
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			Error(w, http.StatusRequestEntityTooLarge, "PAYLOAD_TOO_LARGE", "That was too large.")
			return false
		}
		Error(w, http.StatusBadRequest, "BAD_REQUEST", "That request didn't look right.")
		return false
	}
	if dec.More() {
		Error(w, http.StatusBadRequest, "BAD_REQUEST", "That request didn't look right.")
		return false
	}
	return true
}

type Pages struct {
	prefix string
	page   string
	files  fs.FS
	etags  map[string]string
}

func NewPages(prefix, page string) *Pages {
	return NewPagesFS(prefix, page, Assets())
}

func NewPagesFS(prefix, page string, files fs.FS) *Pages {
	p := &Pages{prefix: prefix, page: page, files: files, etags: map[string]string{}}
	_ = fs.WalkDir(p.files, ".", func(name string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := fs.ReadFile(p.files, name)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(b)
		p.etags[name] = `"` + hex.EncodeToString(sum[:8]) + `"`
		return nil
	})
	return p
}

var types = map[string]string{
	".html":  "text/html; charset=utf-8",
	".css":   "text/css; charset=utf-8",
	".js":    "text/javascript; charset=utf-8",
	".svg":   "image/svg+xml",
	".png":   "image/png",
	".json":  "application/json",
	".woff2": "font/woff2",
}

func (p *Pages) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		Error(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Method not allowed.")
		return
	}
	name := ""
	switch {
	case r.URL.Path == p.prefix || r.URL.Path == p.prefix+"/":
		name = p.page
	case strings.HasPrefix(r.URL.Path, p.prefix+"/"):
		name = strings.TrimPrefix(r.URL.Path, p.prefix+"/")
		if name != path.Base(name) || strings.HasSuffix(name, ".html") || strings.HasPrefix(name, ".") {
			NotFound(w)
			return
		}
	default:
		NotFound(w)
		return
	}
	ct, ok := types[path.Ext(name)]
	if !ok {
		NotFound(w)
		return
	}
	b, err := fs.ReadFile(p.files, name)
	if err != nil {
		NotFound(w)
		return
	}
	Headers(w, r)
	h := w.Header()
	h.Set("Content-Type", ct)
	if name != p.page {
		h.Set("Cache-Control", "no-cache")
		tag := p.etags[name]
		h.Set("ETag", tag)
		if r.Header.Get("If-None-Match") == tag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
	}
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodHead {
		return
	}
	_, _ = w.Write(b)
}
