package api

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/veylvpn/backend/internal/store"
)

const (
	tokenPrefix   = "vey_"
	tokenRawLen   = 32
	tokenLen      = len(tokenPrefix) + 43
	tokenTTL      = time.Hour
	maxPerAccount = 10
	maxTokens     = 100000
)

var errTokenCapacity = errors.New("token capacity reached")

type tokenHash [sha256.Size]byte

type session struct {
	account string
	pwFP    tokenHash
	issued  time.Time
	expires time.Time
}

type tokens struct {
	mu  sync.Mutex
	m   map[tokenHash]*session
	now func() time.Time
}

func newTokens() *tokens {
	return &tokens{m: map[tokenHash]*session{}, now: time.Now}
}

func fingerprint(acc store.Account) tokenHash {
	return sha256.Sum256([]byte("veyl-pw:" + acc.Password))
}

func parseToken(tok string) (tokenHash, bool) {
	if len(tok) != tokenLen || !strings.HasPrefix(tok, tokenPrefix) {
		return tokenHash{}, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(tok[len(tokenPrefix):])
	if err != nil || len(raw) != tokenRawLen {
		return tokenHash{}, false
	}
	return sha256.Sum256([]byte(tok)), true
}

func (t *tokens) issue(acc store.Account) (string, time.Time, error) {
	raw := make([]byte, tokenRawLen)
	if _, err := rand.Read(raw); err != nil {
		return "", time.Time{}, err
	}
	tok := tokenPrefix + base64.RawURLEncoding.EncodeToString(raw)
	h := sha256.Sum256([]byte(tok))
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	var mine []tokenHash
	for k, s := range t.m {
		if !now.Before(s.expires) {
			delete(t.m, k)
			continue
		}
		if s.account == acc.Hash {
			mine = append(mine, k)
		}
	}
	for len(mine) >= maxPerAccount {
		oldest := 0
		for i := range mine {
			if t.m[mine[i]].issued.Before(t.m[mine[oldest]].issued) {
				oldest = i
			}
		}
		delete(t.m, mine[oldest])
		mine = append(mine[:oldest], mine[oldest+1:]...)
	}
	if len(t.m) >= maxTokens {
		return "", time.Time{}, errTokenCapacity
	}
	exp := now.Add(tokenTTL)
	t.m[h] = &session{account: acc.Hash, pwFP: fingerprint(acc), issued: now, expires: exp}
	return tok, exp, nil
}

func (t *tokens) lookup(h tokenHash) (session, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	s := t.m[h]
	if s == nil {
		return session{}, false
	}
	if !t.now().Before(s.expires) {
		delete(t.m, h)
		return session{}, false
	}
	return *s, true
}

func (t *tokens) revoke(h tokenHash) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.m, h)
}

func (t *tokens) revokeAccount(account string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for k, s := range t.m {
		if s.account == account {
			delete(t.m, k)
		}
	}
}

func (t *tokens) count(account string) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	n := 0
	for _, s := range t.m {
		if s.account == account {
			n++
		}
	}
	return n
}

func bearerToken(r *http.Request) string {
	v := r.Header.Get("Authorization")
	if len(v) < 7 || !strings.EqualFold(v[:7], "Bearer ") {
		return ""
	}
	return strings.TrimSpace(v[7:])
}

func invalidToken(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
	writeErr(w, http.StatusUnauthorized, "invalid access token", CodeInvalidToken)
}

type bearerHandler func(w http.ResponseWriter, r *http.Request, acc store.Account, h tokenHash)

func (s *Server) bearer(next bearerHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h, ok := parseToken(bearerToken(r))
		if !ok {
			invalidToken(w)
			return
		}
		sess, ok := s.tokens.lookup(h)
		if !ok {
			invalidToken(w)
			return
		}
		acc, err := s.d.Store.AccountKey(sess.account)
		if errors.Is(err, store.ErrNoAccount) {
			s.tokens.revokeAccount(sess.account)
			invalidToken(w)
			return
		}
		if err != nil {
			fail(w, err)
			return
		}
		if fingerprint(acc) != sess.pwFP {
			s.tokens.revokeAccount(sess.account)
			invalidToken(w)
			return
		}
		if acc.Disabled {
			s.tokens.revokeAccount(sess.account)
			fail(w, store.ErrDisabled)
			return
		}
		next(w, r, acc, h)
	}
}

func (s *Server) issue(w http.ResponseWriter, acc store.Account) {
	tok, exp, err := s.tokens.issue(acc)
	if errors.Is(err, errTokenCapacity) {
		tooMany(w, time.Minute)
		return
	}
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"access_token": tok, "expires_at": exp.UTC().Format(time.RFC3339)})
}

type tokenReq struct {
	Account  string `json:"account"`
	Password string `json:"password"`
}

func (s *Server) token(w http.ResponseWriter, r *http.Request) {
	var req tokenReq
	if !decodeStrict(w, r, &req) {
		return
	}
	acc, err := s.d.Store.Auth(req.Account, req.Password)
	if err != nil {
		fail(w, err)
		return
	}
	s.issue(w, acc)
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request, acc store.Account, h tokenHash) {
	s.tokens.revoke(h)
	w.WriteHeader(http.StatusNoContent)
}
