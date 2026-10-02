package panel

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/veylvpn/backend/internal/web"
)

type route struct {
	method  string
	pattern string
	action  string
}

var proxyRoutes = []route{
	{"GET", "overview", ""},
	{"GET", "accounts", ""},
	{"GET", "accounts/:id/devices", ""},
	{"GET", "invites", ""},
	{"GET", "settings", ""},
	{"GET", "apply-progress", ""},
	{"GET", "job", ""},
	{"POST", "accounts", "node.account.create"},
	{"PATCH", "accounts/:id", "node.account.update"},
	{"DELETE", "accounts/:id", "node.account.delete"},
	{"DELETE", "accounts/:id/devices/:dev", "node.device.revoke"},
	{"POST", "invites", "node.invite.create"},
	{"DELETE", "invites/:id", "node.invite.delete"},
	{"PUT", "settings", "node.settings.update"},
	{"POST", "dns/update", "node.blocklists.update"},
	{"POST", "services/restart", "node.services.restart"},
	{"POST", "update", "node.update"},
}

func hexID(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, r := range s {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') {
			return false
		}
	}
	return true
}

func devID(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, r := range s {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r == '-' || r == '_' || r == '.') {
			return false
		}
	}
	return s != "." && s != ".."
}

func matchRoute(method, rest string) (route, []string, bool) {
	segs := strings.Split(rest, "/")
	for _, rt := range proxyRoutes {
		if rt.method != method {
			continue
		}
		pat := strings.Split(rt.pattern, "/")
		if len(pat) != len(segs) {
			continue
		}
		var ids []string
		ok := true
		for i, ps := range pat {
			switch ps {
			case ":id":
				ok = ok && hexID(segs[i])
				ids = append(ids, segs[i])
			case ":dev":
				ok = ok && devID(segs[i])
				ids = append(ids, segs[i])
			default:
				ok = ok && ps == segs[i]
			}
		}
		if ok {
			return rt, ids, true
		}
	}
	return route{}, nil, false
}

func bodyKeys(b []byte) string {
	var m map[string]json.RawMessage
	if json.Unmarshal(b, &m) != nil {
		return ""
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		if k != "password" {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	return strings.Join(keys, ", ")
}

func (p *Panel) proxy(w http.ResponseWriter, r *http.Request) {
	a := current(r)
	n, ok := p.nodeByID(r.PathValue("id"))
	if !ok {
		web.Error(w, http.StatusNotFound, "NOT_FOUND", "That node is no longer in your fleet.")
		return
	}
	rt, ids, ok := matchRoute(r.Method, r.PathValue("rest"))
	if !ok {
		web.Error(w, http.StatusNotFound, "NOT_FOUND", "Not found.")
		return
	}
	if rt.action != "" && roleLevel[a.User.Role] < roleLevel[RoleAdmin] {
		web.Error(w, http.StatusForbidden, "FORBIDDEN", "Viewers cannot change nodes.")
		return
	}
	var body []byte
	if r.Method != http.MethodGet && r.Method != http.MethodDelete {
		ct := r.Header.Get("Content-Type")
		if !strings.HasPrefix(ct, "application/json") {
			web.Error(w, http.StatusUnsupportedMediaType, "BAD_REQUEST", "Expected JSON.")
			return
		}
		b, err := io.ReadAll(io.LimitReader(r.Body, bodyLimit+1))
		if err != nil || len(b) > bodyLimit || !json.Valid(b) {
			web.Error(w, http.StatusBadRequest, "BAD_REQUEST", "That request didn't look right.")
			return
		}
		body = b
	}
	c, err := p.client(n)
	if err != nil {
		web.Error(w, http.StatusInternalServerError, "INTERNAL", "The stored node key could not be read.")
		return
	}
	path := "/v1/admin/" + r.PathValue("rest")
	sse := rt.pattern == "apply-progress"
	if sse {
		if q := r.URL.Query().Get("last"); q != "" && len(q) <= 64 {
			path += "?last=" + q
		}
	}
	ctx := r.Context()
	if !sse {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
	}
	res, err := c.request(ctx, r.Method, path, body, true)
	if err != nil {
		web.Error(w, http.StatusBadGateway, "UNREACHABLE", "The node did not answer: "+shortNetErr(err)+".")
		return
	}
	defer res.Body.Close()
	if rt.action != "" && res.StatusCode < 300 {
		p.audit(a.User.Username, rt.action, n.Name+targetSuffix(ids), bodyKeys(body))
	}
	if sse && res.StatusCode == http.StatusOK {
		h := w.Header()
		h.Set("Content-Type", "text/event-stream")
		h.Set("Cache-Control", "no-store")
		h.Set("X-Accel-Buffering", "no")
		w.WriteHeader(http.StatusOK)
		rc := http.NewResponseController(w)
		_ = rc.SetWriteDeadline(time.Time{})
		buf := make([]byte, 4096)
		for {
			k, err := res.Body.Read(buf)
			if k > 0 {
				if _, werr := w.Write(buf[:k]); werr != nil {
					return
				}
				_ = rc.Flush()
			}
			if err != nil {
				return
			}
		}
	}
	if ct := res.Header.Get("Content-Type"); strings.HasPrefix(ct, "application/json") {
		w.Header().Set("Content-Type", ct)
	} else {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
	}
	w.WriteHeader(res.StatusCode)
	_, _ = io.Copy(w, io.LimitReader(res.Body, maxNodeBody))
}

func targetSuffix(ids []string) string {
	if len(ids) == 0 {
		return ""
	}
	return " / " + strings.Join(ids, " / ")
}

type bulkIn struct {
	Action string          `json:"action"`
	Nodes  []string        `json:"nodes"`
	Params json.RawMessage `json:"params"`
}

type bulkResult struct {
	NodeID string         `json:"node_id"`
	Name   string         `json:"name"`
	OK     bool           `json:"ok"`
	Status int            `json:"status"`
	Error  string         `json:"error,omitempty"`
	Data   map[string]any `json:"data,omitempty"`
}

var bulkActions = map[string]struct {
	path   string
	audit  string
	params bool
}{
	"invite":     {"/v1/admin/invites", "node.invite.create", true},
	"blocklists": {"/v1/admin/dns/update", "node.blocklists.update", false},
	"restart":    {"/v1/admin/services/restart", "node.services.restart", true},
	"update":     {"/v1/admin/update", "node.update", false},
}

func (p *Panel) bulk(w http.ResponseWriter, r *http.Request) {
	var in bulkIn
	if !web.Decode(w, r, &in, bodyLimit) {
		return
	}
	act, ok := bulkActions[in.Action]
	if !ok {
		web.Error(w, http.StatusBadRequest, "BAD_REQUEST", "Unknown bulk action.")
		return
	}
	if len(in.Nodes) == 0 || len(in.Nodes) > maxNodes {
		web.Error(w, http.StatusBadRequest, "BAD_REQUEST", "Pick at least one node.")
		return
	}
	params := []byte("{}")
	if act.params && len(in.Params) > 0 && string(in.Params) != "null" {
		var m map[string]any
		if json.Unmarshal(in.Params, &m) != nil {
			web.Error(w, http.StatusBadRequest, "BAD_REQUEST", "That request didn't look right.")
			return
		}
		params = in.Params
	}
	a := current(r)
	var targets []Node
	for _, id := range in.Nodes {
		if n, ok := p.nodeByID(id); ok {
			targets = append(targets, n)
		}
	}
	results := make([]bulkResult, len(targets))
	var wg sync.WaitGroup
	for i, n := range targets {
		wg.Add(1)
		go func(i int, n Node) {
			defer wg.Done()
			res := bulkResult{NodeID: n.ID, Name: n.Name}
			c, err := p.client(n)
			if err != nil {
				res.Error = "stored key could not be read"
				results[i] = res
				return
			}
			ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
			defer cancel()
			hres, err := c.request(ctx, http.MethodPost, act.path, params, true)
			if err != nil {
				res.Error = shortNetErr(err)
				results[i] = res
				return
			}
			defer hres.Body.Close()
			res.Status = hres.StatusCode
			var out map[string]any
			_ = json.NewDecoder(io.LimitReader(hres.Body, maxNodeBody)).Decode(&out)
			res.OK = hres.StatusCode >= 200 && hres.StatusCode < 300
			if res.OK {
				res.Data = out
				p.audit(a.User.Username, act.audit, n.Name, "bulk")
			} else if msg, ok := out["error"].(string); ok {
				res.Error = msg
			}
			results[i] = res
		}(i, n)
	}
	wg.Wait()
	web.JSON(w, http.StatusOK, map[string]any{"results": results})
}
