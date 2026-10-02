package panel

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"io/fs"
	"net/http"
	"path"
	"strings"

	"github.com/veylvpn/backend/internal/web"
)

//go:embed web
var webFS embed.FS

var contentTypes = map[string]string{
	".html":  "text/html; charset=utf-8",
	".css":   "text/css; charset=utf-8",
	".js":    "text/javascript; charset=utf-8",
	".svg":   "image/svg+xml",
	".png":   "image/png",
	".woff2": "font/woff2",
}

type static struct {
	files  fs.FS
	shared fs.FS
	etags  map[string]string
}

func newStatic() *static {
	sub, err := fs.Sub(webFS, "web")
	if err != nil {
		panic(err)
	}
	s := &static{files: sub, shared: web.Assets(), etags: map[string]string{}}
	return s
}

func (s *static) read(name string) ([]byte, bool) {
	if b, err := fs.ReadFile(s.files, name); err == nil {
		return b, true
	}
	if sharedAsset(name) {
		if b, err := fs.ReadFile(s.shared, name); err == nil {
			return b, true
		}
	}
	return nil, false
}

func sharedAsset(name string) bool {
	return name == "brand.css" || name == "brand.js" || strings.HasPrefix(name, "brand-") || name == "ui.js"
}

func (s *static) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	name := ""
	switch r.URL.Path {
	case "/", "/join":
		name = "app.html"
	case "/setup":
		name = "setup.html"
	default:
		name = strings.TrimPrefix(r.URL.Path, "/")
		if name != path.Base(name) || strings.HasSuffix(name, ".html") || strings.HasPrefix(name, ".") {
			web.NotFound(w)
			return
		}
	}
	ct, ok := contentTypes[path.Ext(name)]
	if !ok {
		web.NotFound(w)
		return
	}
	b, ok := s.read(name)
	if !ok {
		web.NotFound(w)
		return
	}
	h := w.Header()
	h.Set("Content-Type", ct)
	if !strings.HasSuffix(name, ".html") {
		sum := sha256.Sum256(b)
		tag := `"` + hex.EncodeToString(sum[:8]) + `"`
		h.Set("Cache-Control", "no-cache")
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
