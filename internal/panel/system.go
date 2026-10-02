package panel

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/veylvpn/backend/internal/agentapi"
	"github.com/veylvpn/backend/internal/app"
	"github.com/veylvpn/backend/internal/backup"
	"github.com/veylvpn/backend/internal/panelkey"
	"github.com/veylvpn/backend/internal/web"
)

const ReleaseAPI = "https://api.github.com/repos/VeylVPN/backend/releases/latest"

func agentRequest(op string) agentapi.Request {
	return agentapi.Request{Op: op}
}

func GitHubRelease(client *http.Client) func(ctx context.Context) (string, error) {
	return func(ctx context.Context) (string, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, ReleaseAPI, nil)
		if err != nil {
			return "", err
		}
		req.Header.Set("Accept", "application/vnd.github+json")
		req.Header.Set("User-Agent", "VeylControl/"+app.Version)
		res, err := client.Do(req)
		if err != nil {
			return "", err
		}
		defer res.Body.Close()
		if res.StatusCode != http.StatusOK {
			return "", errors.New("no release")
		}
		var out struct {
			Tag string `json:"tag_name"`
		}
		if err := json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&out); err != nil {
			return "", err
		}
		return out.Tag, nil
	}
}

func (p *Panel) auditEntries(r *http.Request) []AuditEntry {
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	before, _ := strconv.ParseInt(q.Get("before"), 10, 64)
	user := q.Get("user")
	action := q.Get("action")
	out := []AuditEntry{}
	p.db.View(func(d *data) {
		for i := len(d.Audit) - 1; i >= 0 && len(out) < limit; i-- {
			e := d.Audit[i]
			if before > 0 && e.Time >= before {
				continue
			}
			if user != "" && e.User != user {
				continue
			}
			if action != "" && !strings.HasPrefix(e.Action, action) {
				continue
			}
			out = append(out, e)
		}
	})
	return out
}

func (p *Panel) auditList(w http.ResponseWriter, r *http.Request) {
	web.JSON(w, http.StatusOK, map[string]any{"entries": p.auditEntries(r), "retention_days": int(Retention / (24 * time.Hour))})
}

func csvSafe(s string) string {
	if s != "" && strings.ContainsAny(s[:1], "=+-@\t\r") {
		return "'" + s
	}
	return s
}

func (p *Panel) auditExport(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	q.Set("limit", "1000000")
	var all []AuditEntry
	p.db.View(func(d *data) { all = append(all, d.Audit...) })
	h := w.Header()
	h.Set("Content-Disposition", `attachment; filename="veyl-control-audit-`+p.now().UTC().Format("2006-01-02")+`.csv"`)
	h.Set("Content-Type", "text/csv; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"time", "user", "action", "target", "detail"})
	for _, e := range all {
		_ = cw.Write([]string{time.Unix(e.Time, 0).UTC().Format(time.RFC3339), csvSafe(e.User), csvSafe(e.Action), csvSafe(e.Target), csvSafe(e.Detail)})
	}
	cw.Flush()
	p.audit(current(r).User.Username, "audit.export", "", "")
}

func (p *Panel) system(w http.ResponseWriter, r *http.Request) {
	st := p.agentStatus(r.Context(), r.URL.Query().Get("fresh") == "1")
	s := p.site()
	set := p.settings()
	release := p.mon.Release()
	j := map[string]any{"running": false}
	if jj := p.job("update"); jj != nil {
		_, done, o := jj.State()
		j = map[string]any{"running": !done, "ok": o.OK, "error": o.Error}
	}
	web.JSON(w, http.StatusOK, map[string]any{
		"version":  app.Version,
		"release":  release,
		"update":   release != "" && Newer(release, app.Version),
		"platform": p.opt.Platform,
		"domain":   s.Domain,
		"mode":     s.Mode,
		"uptime":   int64(p.now().Sub(p.started) / time.Second),
		"agent":    st,
		"settings": set,
		"job":      j,
	})
}

type settingsIn struct {
	Name         string `json:"name"`
	CheckUpdates bool   `json:"check_updates"`
	AutoHeal     bool   `json:"auto_heal"`
}

func (p *Panel) putSettings(w http.ResponseWriter, r *http.Request) {
	var in settingsIn
	if !web.Decode(w, r, &in, bodyLimit) {
		return
	}
	name := panelkey.CleanName(in.Name)
	if name == "" || len([]rune(name)) > 40 {
		web.Error(w, http.StatusBadRequest, "BAD_REQUEST", "Pick a name with 1 to 40 characters.")
		return
	}
	_ = p.db.Update(func(d *data) error {
		d.Settings = Settings{Name: name, CheckUpdates: in.CheckUpdates, AutoHeal: in.AutoHeal}
		return nil
	})
	p.audit(current(r).User.Username, "panel.settings", "", "")
	web.JSON(w, http.StatusOK, map[string]any{"settings": p.settings()})
}

func (p *Panel) selfUpdate(w http.ResponseWriter, r *http.Request) {
	if _, err := p.startJob("update", agentRequest(agentapi.OpUpdate), nil); err != nil {
		web.Error(w, http.StatusConflict, "BUSY", "Another task is running. Try again in a moment.")
		return
	}
	p.audit(current(r).User.Username, "panel.update", "", app.Version)
	web.JSON(w, http.StatusAccepted, map[string]bool{"ok": true})
}

type backupIn struct {
	Passphrase string `json:"passphrase"`
}

func (p *Panel) backup(w http.ResponseWriter, r *http.Request) {
	var in backupIn
	if !web.Decode(w, r, &in, bodyLimit) {
		return
	}
	data, err := CreateBackup(p.opt.Paths, p.db, in.Passphrase)
	if errors.Is(err, backup.ErrWeak) {
		web.Error(w, http.StatusBadRequest, "WEAK_PASSPHRASE", "Use a passphrase with at least 10 characters.")
		return
	}
	if err != nil {
		web.Error(w, http.StatusInternalServerError, "INTERNAL", "Could not create the backup.")
		return
	}
	p.audit(current(r).User.Username, "panel.backup", "", "")
	h := w.Header()
	h.Set("Content-Type", "application/octet-stream")
	h.Set("Content-Disposition", `attachment; filename="veyl-control-`+p.now().UTC().Format("2006-01-02")+`.vbk"`)
	h.Set("Content-Length", strconv.Itoa(len(data)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}
