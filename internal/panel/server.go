package panel

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/veylvpn/backend/internal/agentapi"
	"github.com/veylvpn/backend/internal/panelcfg"
	"github.com/veylvpn/backend/internal/records"
	"github.com/veylvpn/backend/internal/store"
	"github.com/veylvpn/backend/internal/web"
)

type Options struct {
	Paths     panelcfg.Paths
	Agent     agentapi.Client
	Now       func() time.Time
	Checker   *records.Checker
	Releases  func(ctx context.Context) (string, error)
	Dial      func(ctx context.Context, network, addr string) (net.Conn, error)
	RootCAs   *x509.CertPool
	Platform  string
	Interval  time.Duration
	JobTime   time.Duration
	AlertHTTP *http.Client
	SMTPTLS   *x509.CertPool
	Insecure  bool
}

type Panel struct {
	opt      Options
	db       *DB
	seal     *Sealer
	throttle *store.Throttle
	ipKey    []byte
	started  time.Time

	mu      sync.Mutex
	enrolls map[string]*enrollment
	clients map[string]*nodeClient
	wiz     wizardState

	jobMu sync.Mutex
	jobs  map[string]*web.Job

	statMu sync.Mutex
	stat   map[string]string
	statAt time.Time

	recMu    sync.Mutex
	recCache map[string]cachedReport

	mon    *Monitor
	alerts *Alerter
	acme   *ACMEHub
}

func New(o Options) (*Panel, error) {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Checker == nil {
		o.Checker = &records.Checker{Client: &records.Client{Timeout: 3 * time.Second}}
	}
	if o.Platform == "" {
		o.Platform = runtime.GOOS
	}
	if o.Interval == 0 {
		o.Interval = 30 * time.Second
	}
	if o.JobTime == 0 {
		o.JobTime = 55 * time.Minute
	}
	db, err := OpenDB(o.Paths.DB())
	if err != nil {
		return nil, err
	}
	key, err := LoadOrCreateKey(o.Paths.Secret())
	if err != nil {
		return nil, err
	}
	seal, err := NewSealer(key)
	if err != nil {
		return nil, err
	}
	ipKey := make([]byte, 32)
	if _, err := rand.Read(ipKey); err != nil {
		return nil, err
	}
	p := &Panel{opt: o, db: db, seal: seal, throttle: store.NewThrottle(), ipKey: ipKey, started: o.Now(), enrolls: map[string]*enrollment{}, jobs: map[string]*web.Job{}, recCache: map[string]cachedReport{}}
	p.alerts = newAlerter(p)
	p.mon = newMonitor(p)
	p.acme = newACMEHub(p)
	return p, nil
}

func (p *Panel) now() time.Time { return p.opt.Now() }

func (p *Panel) site() panelcfg.Site {
	s, _ := panelcfg.LoadSite(p.opt.Paths.Site())
	return s
}

func (p *Panel) saveSite(s panelcfg.Site) error {
	return panelcfg.SaveSite(p.opt.Paths.Site(), s)
}

func (p *Panel) settings() Settings {
	var s Settings
	p.db.View(func(d *data) { s = d.Settings })
	return s
}

func (p *Panel) audit(user, action, target, detail string) {
	clean := func(s string, n int) string {
		s = strings.Map(func(r rune) rune {
			if r < 0x20 || r == 0x7f {
				return ' '
			}
			return r
		}, s)
		if len(s) > n {
			s = s[:n]
		}
		return s
	}
	e := AuditEntry{Time: p.now().Unix(), User: clean(user, 64), Action: clean(action, 64), Target: clean(target, 160), Detail: clean(detail, 300)}
	_ = p.db.Update(func(d *data) error {
		d.Audit = append(d.Audit, e)
		if len(d.Audit) > maxAudit {
			d.Audit = d.Audit[len(d.Audit)-maxAudit:]
		}
		return nil
	})
}

func (p *Panel) agentStatus(ctx context.Context, fresh bool) map[string]string {
	p.statMu.Lock()
	defer p.statMu.Unlock()
	if !fresh && p.stat != nil && p.now().Sub(p.statAt) < 30*time.Second {
		return p.stat
	}
	out := map[string]string{}
	if p.opt.Agent != nil {
		c, cancel := context.WithTimeout(ctx, 20*time.Second)
		_ = p.opt.Agent.Do(c, agentapi.Request{Op: agentapi.OpStatus}, func(ev agentapi.Event) {
			for k, v := range ev.Data {
				if len(k) <= 64 && len(v) <= 256 {
					out[k] = v
				}
			}
		})
		cancel()
	}
	p.stat = out
	p.statAt = p.now()
	return out
}

var errBusy = errors.New("busy")

func (p *Panel) startJob(kind string, req agentapi.Request, after func(error)) (*web.Job, error) {
	p.jobMu.Lock()
	defer p.jobMu.Unlock()
	for _, j := range p.jobs {
		if j.Running() {
			return nil, errBusy
		}
	}
	j := web.NewJob(kind)
	p.jobs[kind] = j
	go func() {
		if p.opt.Agent == nil {
			j.Finish(nil, errors.New("the Veyl Control agent is not running"))
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), p.opt.JobTime)
		defer cancel()
		last := ""
		var data map[string]string
		err := p.opt.Agent.Do(ctx, req, func(ev agentapi.Event) {
			if ev.Done {
				last = ev.Error
				data = ev.Data
			}
			j.Event(ev)
		})
		if err != nil && last != "" {
			err = errors.New(last)
		}
		p.statMu.Lock()
		p.stat = nil
		p.statMu.Unlock()
		if after != nil {
			after(err)
		}
		j.Finish(data, err)
	}()
	return j, nil
}

func (p *Panel) job(kind string) *web.Job {
	p.jobMu.Lock()
	defer p.jobMu.Unlock()
	return p.jobs[kind]
}

func (p *Panel) jobProgress(w http.ResponseWriter, r *http.Request) {
	j := p.job(r.PathValue("kind"))
	if j == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	j.ServeSSE(w, r)
}

func health(w http.ResponseWriter, r *http.Request) {
	web.JSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (p *Panel) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/health", health)
	st := newStatic()
	mux.Handle("GET /", st)
	mux.Handle("GET "+web.FontRoute, web.Fonts(p.opt.Paths.Data))

	mux.HandleFunc("GET /api/session", p.sessionInfo)
	mux.HandleFunc("POST /api/login", p.login)
	mux.HandleFunc("POST /api/enroll/info", p.enrollInfo)
	mux.HandleFunc("POST /api/enroll/finish", p.enrollFinish)
	mux.HandleFunc("POST /api/join/info", p.joinInfo)
	mux.HandleFunc("POST /api/join/start", p.joinStart)
	mux.HandleFunc("POST /api/logout", p.authed(RoleViewer, p.logout))
	mux.HandleFunc("GET /api/me", p.authed(RoleViewer, p.me))
	mux.HandleFunc("GET /api/me/sessions", p.authed(RoleViewer, p.mySessions))
	mux.HandleFunc("DELETE /api/me/sessions/{id}", p.authed(RoleViewer, p.revokeSession))
	mux.HandleFunc("POST /api/me/password", p.authed(RoleViewer, p.changePassword))
	mux.HandleFunc("POST /api/me/recovery", p.authed(RoleViewer, p.newRecovery))

	mux.HandleFunc("GET /api/team", p.authed(RoleOwner, p.team))
	mux.HandleFunc("POST /api/team/invites", p.authed(RoleOwner, p.createInvite))
	mux.HandleFunc("DELETE /api/team/invites/{id}", p.authed(RoleOwner, p.deleteInvite))
	mux.HandleFunc("PATCH /api/team/users/{id}", p.authed(RoleOwner, p.patchUser))
	mux.HandleFunc("DELETE /api/team/users/{id}", p.authed(RoleOwner, p.deleteUser))
	mux.HandleFunc("POST /api/team/users/{id}/reset-2fa", p.authed(RoleOwner, p.reset2FA))

	mux.HandleFunc("GET /api/fleet", p.authed(RoleViewer, p.fleet))
	mux.HandleFunc("POST /api/nodes", p.authed(RoleAdmin, p.addNode))
	mux.HandleFunc("GET /api/nodes/{id}", p.authed(RoleViewer, p.nodeDetail))
	mux.HandleFunc("PATCH /api/nodes/{id}", p.authed(RoleAdmin, p.patchNode))
	mux.HandleFunc("DELETE /api/nodes/{id}", p.authed(RoleAdmin, p.deleteNode))
	for _, m := range []string{"GET", "POST", "PATCH", "PUT", "DELETE"} {
		mux.HandleFunc(m+" /api/nodes/{id}/admin/{rest...}", p.authed(RoleViewer, p.proxy))
	}
	mux.HandleFunc("POST /api/bulk", p.authed(RoleAdmin, p.bulk))
	mux.HandleFunc("GET /api/incidents", p.authed(RoleViewer, p.incidents))

	mux.HandleFunc("GET /api/alerts", p.authed(RoleAdmin, p.getAlerts))
	mux.HandleFunc("PUT /api/alerts", p.authed(RoleAdmin, p.putAlerts))
	mux.HandleFunc("POST /api/alerts/test", p.authed(RoleAdmin, p.testAlert))

	mux.HandleFunc("GET /api/domains", p.authed(RoleViewer, p.domains))
	mux.HandleFunc("GET /api/records", p.authed(RoleViewer, p.recordCheck))
	mux.HandleFunc("POST /api/domains/renew", p.authed(RoleAdmin, p.renew))
	mux.HandleFunc("GET /api/jobs/{kind}", p.authed(RoleViewer, p.jobProgress))

	mux.HandleFunc("GET /api/audit", p.authed(RoleAdmin, p.auditList))
	mux.HandleFunc("GET /api/audit/export", p.authed(RoleAdmin, p.auditExport))
	mux.HandleFunc("GET /api/system", p.authed(RoleViewer, p.system))
	mux.HandleFunc("PUT /api/system/settings", p.authed(RoleOwner, p.putSettings))
	mux.HandleFunc("POST /api/system/update", p.authed(RoleOwner, p.selfUpdate))
	mux.HandleFunc("POST /api/system/backup", p.authed(RoleOwner, p.backup))

	p.setupRoutes(mux)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		web.Headers(w, r)
		if strings.HasPrefix(r.URL.Path, "/api/") && !p.site().Configured && !strings.HasPrefix(r.URL.Path, "/api/setup/") && !p.ownerExists() {
			web.Error(w, http.StatusConflict, "NOT_SET_UP", "Finish setup first.")
			return
		}
		mux.ServeHTTP(w, r)
	})
}

func (p *Panel) ownerExists() bool {
	ok := false
	p.db.View(func(d *data) { ok = d.owners() > 0 })
	return ok
}

func (p *Panel) Run(ctx context.Context) {
	go p.mon.Run(ctx)
	go p.alerts.Run(ctx)
	go func() {
		t := time.NewTicker(time.Hour)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				_ = p.db.Update(func(d *data) error { d.prune(p.now()); return nil })
			}
		}
	}()
}
