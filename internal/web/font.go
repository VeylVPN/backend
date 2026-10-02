package web

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

const (
	FontURL    = "https://cdn.fontshare.com/wf/NWBQYJIM7GCZ5XWD7D26ARB3VDY55ZRT/K63EV2KZIGKLE7RANQ2U42S6SVHU5RJ7/X6XYTKIVDUW7GZTZPZNN4EUM5KH54KHF.woff2"
	FontSHA256 = "e739aff9b4d02c264341d6d4872edcda28e79373aeda936f659566a1cd3eb47f"
	FontFile   = "Satoshi-Variable.woff2"
	FontRoute  = "/assets/fonts/" + FontFile
	FontMax    = 512 << 10
)

var (
	ErrFontChecksum = errors.New("font checksum mismatch")
	ErrFontSize     = errors.New("font download is unexpectedly large")
)

func FontDir(data string) string {
	return filepath.Join(data, "fonts")
}

func FontPath(data string) string {
	return filepath.Join(FontDir(data), FontFile)
}

func FontOK(b []byte) bool {
	if len(b) == 0 || len(b) > FontMax {
		return false
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]) == FontSHA256
}

func FetchFont(ctx context.Context, client *http.Client) ([]byte, error) {
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, FontURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "veyl")
	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("font download responded %d", res.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(res.Body, FontMax+1))
	if err != nil {
		return nil, err
	}
	if len(b) > FontMax {
		return nil, ErrFontSize
	}
	if !FontOK(b) {
		return nil, ErrFontChecksum
	}
	return b, nil
}

func Fonts(data string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		Headers(w, r)
		if r.URL.Path != FontRoute {
			NotFound(w)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			Error(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Method not allowed.")
			return
		}
		f, err := os.Open(FontPath(data))
		if err != nil {
			NotFound(w)
			return
		}
		defer f.Close()
		b, err := io.ReadAll(io.LimitReader(f, FontMax+1))
		if err != nil || !FontOK(b) {
			NotFound(w)
			return
		}
		h := w.Header()
		h.Set("Content-Type", "font/woff2")
		h.Set("Cache-Control", "public, max-age=604800")
		h.Set("ETag", `"`+FontSHA256[:16]+`"`)
		if r.Header.Get("If-None-Match") == h.Get("ETag") {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		http.ServeContent(w, r, FontFile, time.Time{}, bytes.NewReader(b))
	})
}
