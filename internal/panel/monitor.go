package panel

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/veylvpn/backend/internal/admin"
	"github.com/veylvpn/backend/internal/panelkey"
	"github.com/veylvpn/backend/internal/web"
)

const (
	downAfter     = 2
	healMax       = 3
	healWindow    = time.Hour
	healBase      = time.Minute
	certWarn      = 14 * 24 * time.Hour
	diskWarnRatio = 0.90
)

type Service struct {
	Name  string `json:"name"`
	State string `json:"state"`
}

type Blocklist struct {
	Category string `json:"category"`
	Entries  int    `json:"entries"`
	Updated  string `json:"updated,omitempty"`
}

type Overview struct {
	Version    string            `json:"version"`
	Name       string            `json:"name"`
	Host       string            `json:"host"`
	Uptime     int64             `json:"uptime"`
	Connected  int               `json:"connected"`
	Accounts   int               `json:"accounts"`
	Devices    int               `json:"devices"`
	System     map[string]string `json:"system"`
	Services   []Service         `json:"services"`
	Blocklists []Blocklist       `json:"blocklists"`
	CertExpiry string            `json:"cert_expiry"`
	Stealth    bool              `json:"stealth"`
	UDPPort    int               `json:"udp_port"`
	Job        struct {
		Running bool   `json:"running"`
		Kind    string `json:"kind"`
	} `json:"job"`
}

type jobState struct {
	ID      string `json:"id"`
	Kind    string `json:"kind"`
	Running bool   `json:"running"`
	Outcome struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	} `json:"outcome"`
}

type healState struct {
	attempts []time.Time
	next     time.Time
	gaveUp   bool
	tried    bool
}

type nodeState struct {
	Known     bool
	Up        bool
	Down      bool
	Fails     int
	LastProbe time.Time
	LastUp    time.Time
	Error     string
	Overview  *Overview
	Platform  string
	jobSeen   bool
	lastJob   string
	heal      map[string]*healState
}

type probeResult struct {
	up       bool
	err      string
	ov       *Overview
	job      *jobState
	platform string
}

type Monitor struct {
	p        *Panel
	mu       sync.Mutex
	state    map[string]*nodeState
	release  string
	relAt    time.Time
	lastTick time.Time
}

func newMonitor(p *Panel) *Monitor {
	return &Monitor{p: p, state: map[string]*nodeState{}}
}

func (m *Monitor) forget(id string) {
	m.mu.Lock()
	delete(m.state, id)
	m.mu.Unlock()
}

func (m *Monitor) LastTick() time.Time {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lastTick
}

func (m *Monitor) Run(ctx context.Context) {
	m.Tick(ctx)
	t := time.NewTicker(m.p.opt.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			m.Tick(ctx)
		}
	}
}

func (m *Monitor) probe(ctx context.Context, n Node) probeResult {
	c, err := m.p.client(n)
	if err != nil {
		return probeResult{err: "stored key could not be read"}
	}
	if err := c.health(ctx); err != nil {
		return probeResult{err: shortNetErr(err)}
	}
	res := probeResult{up: true}
	var ov Overview
	if err := c.getJSON(ctx, "/v1/admin/overview", true, &ov); err == nil {
		res.ov = &ov
	} else {
		res.err = shortNetErr(err)
	}
	var js jobState
	if err := c.getJSON(ctx, "/v1/admin/job", true, &js); err == nil {
		res.job = &js
	}
	var info map[string]any
	if err := c.getJSON(ctx, "/v1/info", false, &info); err == nil {
		if pl, ok := info["platform"].(string); ok && len(pl) <= 16 {
			res.platform = pl
		}
	}
	return res
}

func shortNetErr(err error) string {
	s := err.Error()
	switch {
	case err == errNodeAuth:
		return "the node rejected the panel key"
	case strings.Contains(s, "certificate"):
		return "certificate problem"
	case strings.Contains(s, "connection refused"):
		return "connection refused"
	case strings.Contains(s, "no such host"):
		return "address does not resolve"
	case strings.Contains(s, "timeout") || strings.Contains(s, "deadline"):
		return "timed out"
	}
	if len(s) > 120 {
		s = s[:120]
	}
	return s
}

func (m *Monitor) probeOne(ctx context.Context, n Node) {
	res := m.probe(ctx, n)
	m.apply(ctx, map[string]probeResult{n.ID: res}, false)
}

func (m *Monitor) Tick(ctx context.Context) {
	nodes := m.p.nodes()
	results := map[string]probeResult{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 16)
	for _, n := range nodes {
		wg.Add(1)
		go func(n Node) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			pctx, cancel := context.WithTimeout(ctx, 25*time.Second)
			r := m.probe(pctx, n)
			cancel()
			mu.Lock()
			results[n.ID] = r
			mu.Unlock()
		}(n)
	}
	wg.Wait()
	m.checkRelease(ctx)
	m.apply(ctx, results, true)
}

func (m *Monitor) checkRelease(ctx context.Context) {
	if m.p.opt.Releases == nil || !m.p.settings().CheckUpdates {
		return
	}
	m.mu.Lock()
	due := m.p.now().Sub(m.relAt) > 6*time.Hour
	m.mu.Unlock()
	if !due {
		return
	}
	rctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	v, err := m.p.opt.Releases(rctx)
	m.mu.Lock()
	m.relAt = m.p.now()
	if err == nil && validVersion(v) {
		m.release = v
	}
	m.mu.Unlock()
}

func (m *Monitor) Release() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.release
}

func validVersion(v string) bool {
	if v == "" || len(v) > 64 {
		return false
	}
	for _, r := range v {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r == '.' || r == '-' || r == '+' || r == '_') {
			return false
		}
	}
	return true
}

func parseSemver(v string) ([3]int, bool) {
	var out [3]int
	v = strings.TrimPrefix(v, "v")
	core, _, _ := strings.Cut(v, "-")
	core, _, _ = strings.Cut(core, "+")
	parts := strings.Split(core, ".")
	if len(parts) != 3 {
		return out, false
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return out, false
		}
		out[i] = n
	}
	return out, true
}

func Newer(latest, current string) bool {
	a, ok1 := parseSemver(latest)
	b, ok2 := parseSemver(current)
	if !ok1 || !ok2 {
		return false
	}
	for i := 0; i < 3; i++ {
		if a[i] != b[i] {
			return a[i] > b[i]
		}
	}
	return strings.Contains(current, "-") && !strings.Contains(latest, "-")
}

func hourStart(t time.Time) int64 {
	u := t.Unix()
	return u - u%3600
}

func addUptime(hours []Hour, at time.Time, up bool, secs int64) []Hour {
	start := hourStart(at)
	if n := len(hours); n > 0 && hours[n-1].Start == start {
		hours[n-1].Total += secs
		if up {
			hours[n-1].Up += secs
		}
		return hours
	}
	h := Hour{Start: start, Total: secs}
	if up {
		h.Up = secs
	}
	return append(hours, h)
}

func openIncident(d *data, nodeID, kind, subject string) *Incident {
	for i := len(d.Incidents) - 1; i >= 0; i-- {
		in := &d.Incidents[i]
		if in.NodeID == nodeID && in.Kind == kind && in.Subject == subject && in.End == 0 {
			return in
		}
	}
	return nil
}

func addNote(in *Incident, now time.Time, text string) {
	if len(in.Notes) >= 50 {
		return
	}
	in.Notes = append(in.Notes, Note{Time: now.Unix(), Text: text})
}

type healTask struct {
	node    Node
	service string
	attempt int
}

func (m *Monitor) apply(ctx context.Context, results map[string]probeResult, tick bool) {
	now := m.p.now()
	secs := int64(m.p.opt.Interval / time.Second)
	set := m.p.settings()
	release := m.Release()
	var events []Event
	var heals []healTask
	m.mu.Lock()
	if tick {
		m.lastTick = now
	}
	_ = m.p.db.Update(func(d *data) error {
		for id, res := range results {
			n := d.node(id)
			if n == nil {
				continue
			}
			st := m.state[id]
			if st == nil {
				st = &nodeState{heal: map[string]*healState{}}
				m.state[id] = st
			}
			wasDown := st.Down
			st.Known = true
			st.LastProbe = now
			st.Up = res.up
			st.Error = res.err
			if res.platform != "" {
				st.Platform = res.platform
				n.Platform = res.platform
			}
			if res.up {
				st.Fails = 0
				st.LastUp = now
				st.Down = false
				if res.ov != nil {
					st.Overview = res.ov
				}
			} else {
				st.Fails++
				if st.Fails >= downAfter {
					st.Down = true
				}
			}
			if tick {
				d.Uptime[id] = addUptime(d.Uptime[id], now, res.up, secs)
			}
			if st.Down && !wasDown {
				in := Incident{ID: randID(), NodeID: id, Kind: "down", Start: now.Add(-time.Duration(st.Fails-1) * m.p.opt.Interval).Unix()}
				addNote(&in, now, "Node stopped answering: "+orDefault(res.err, "no response"))
				d.Incidents = append(d.Incidents, in)
				events = append(events, Event{Kind: EventNodeDown, NodeID: id, Node: n.Name, Title: n.Name + " is down", Message: n.Name + " (" + n.Host + ") stopped answering health checks: " + orDefault(res.err, "no response") + "."})
			}
			if !st.Down && wasDown {
				if in := openIncident(d, id, "down", ""); in != nil {
					in.End = now.Unix()
					addNote(in, now, "Node is answering again")
				}
				events = append(events, Event{Kind: EventNodeUp, NodeID: id, Node: n.Name, Title: n.Name + " is back up", Message: n.Name + " (" + n.Host + ") answers health checks again."})
			}
			if !res.up || res.ov == nil {
				continue
			}
			events = append(events, m.serviceChecks(d, st, *n, res.ov, now, set, &heals)...)
			events = append(events, m.resourceChecks(st, *n, res.ov, now, release)...)
			if res.job != nil {
				if st.jobSeen && res.job.ID != "" && res.job.ID != st.lastJob && !res.job.Running && res.job.Kind == "apply" && !res.job.Outcome.OK {
					events = append(events, Event{Kind: EventApplyFailed, NodeID: id, Node: n.Name, Subject: res.job.ID, Title: "Applying settings failed on " + n.Name, Message: "The node could not apply its settings: " + orDefault(res.job.Outcome.Error, "unknown error") + "."})
				}
				if !res.job.Running {
					st.lastJob = res.job.ID
				}
				st.jobSeen = true
			}
		}
		if tick {
			d.prune(now)
		}
		return nil
	})
	m.mu.Unlock()
	for _, e := range events {
		m.p.alerts.Emit(e)
	}
	for _, h := range heals {
		m.heal(ctx, h)
	}
}

func orDefault(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

func (m *Monitor) serviceChecks(d *data, st *nodeState, n Node, ov *Overview, now time.Time, set Settings, heals *[]healTask) []Event {
	var events []Event
	failed := map[string]bool{}
	for _, s := range ov.Services {
		if s.State == "failed" {
			failed[s.Name] = true
		}
	}
	for name := range failed {
		in := openIncident(d, n.ID, "service", name)
		if in == nil {
			d.Incidents = append(d.Incidents, Incident{ID: randID(), NodeID: n.ID, Kind: "service", Subject: name, Start: now.Unix(), Notes: []Note{{Time: now.Unix(), Text: name + " failed"}}})
			in = &d.Incidents[len(d.Incidents)-1]
			events = append(events, Event{Kind: EventServiceFailed, NodeID: n.ID, Node: n.Name, Subject: name, Title: name + " failed on " + n.Name, Message: "The " + name + " service on " + n.Name + " is in a failed state."})
		}
		if !set.AutoHeal || !n.Heal || n.Scope != panelkey.ScopeManage || !restartable(name) {
			continue
		}
		hs := st.heal[name]
		if hs == nil {
			hs = &healState{}
			st.heal[name] = hs
		}
		keep := hs.attempts[:0]
		for _, t := range hs.attempts {
			if now.Sub(t) < healWindow {
				keep = append(keep, t)
			}
		}
		hs.attempts = keep
		if len(hs.attempts) >= healMax {
			if !hs.gaveUp {
				hs.gaveUp = true
				addNote(in, now, fmt.Sprintf("No more automatic restarts this hour after %d attempts", healMax))
				events = append(events, Event{Kind: EventServiceFailed, NodeID: n.ID, Node: n.Name, Subject: name + ":gave-up", Title: name + " keeps failing on " + n.Name, Message: fmt.Sprintf("Automatic restarts of %s on %s did not help after %d attempts. Have a look at the server.", name, n.Name, healMax)})
			}
			continue
		}
		if now.Before(hs.next) {
			continue
		}
		hs.attempts = append(hs.attempts, now)
		hs.next = now.Add(healBase << (len(hs.attempts) - 1))
		hs.tried = true
		hs.gaveUp = false
		addNote(in, now, fmt.Sprintf("Automatic restart requested (attempt %d of %d)", len(hs.attempts), healMax))
		*heals = append(*heals, healTask{node: n, service: name, attempt: len(hs.attempts)})
	}
	for i := range d.Incidents {
		in := &d.Incidents[i]
		if in.NodeID != n.ID || in.Kind != "service" || in.End != 0 || failed[in.Subject] {
			continue
		}
		in.End = now.Unix()
		hs := st.heal[in.Subject]
		if hs != nil && hs.tried {
			addNote(in, now, "Healed by automatic restart")
			events = append(events, Event{Kind: EventServiceHealed, NodeID: n.ID, Node: n.Name, Subject: in.Subject, Title: in.Subject + " recovered on " + n.Name, Message: "An automatic restart brought " + in.Subject + " on " + n.Name + " back."})
		} else {
			addNote(in, now, "Recovered")
		}
		delete(st.heal, in.Subject)
	}
	return events
}

func restartable(name string) bool {
	for _, s := range admin.RestartableServices {
		if s == name {
			return true
		}
	}
	return false
}

func diskUsed(sys map[string]string) (float64, bool) {
	t, err1 := strconv.ParseFloat(sys["disk_total"], 64)
	f, err2 := strconv.ParseFloat(sys["disk_free"], 64)
	if err1 != nil || err2 != nil || t <= 0 || f < 0 || f > t {
		return 0, false
	}
	return (t - f) / t, true
}

func (m *Monitor) resourceChecks(st *nodeState, n Node, ov *Overview, now time.Time, release string) []Event {
	var events []Event
	if exp, err := time.Parse(time.RFC3339, ov.CertExpiry); err == nil && exp.Sub(now) < certWarn {
		days := int(exp.Sub(now).Hours() / 24)
		events = append(events, Event{Kind: EventCertExpiring, NodeID: n.ID, Node: n.Name, Subject: now.UTC().Format("2006-01-02"), Title: "Certificate for " + ov.Host + " expires soon", Message: fmt.Sprintf("The certificate for %s on %s expires in %d days (%s). Caddy renews it automatically; if this keeps showing, check DNS and port 80.", ov.Host, n.Name, days, exp.UTC().Format("2006-01-02"))})
	}
	if used, ok := diskUsed(ov.System); ok && used > diskWarnRatio {
		events = append(events, Event{Kind: EventDiskFull, NodeID: n.ID, Node: n.Name, Subject: now.UTC().Format("2006-01-02"), Title: "Disk almost full on " + n.Name, Message: fmt.Sprintf("%s has used %.0f%% of its disk.", n.Name, used*100)})
	}
	if release != "" && Newer(release, ov.Version) {
		events = append(events, Event{Kind: EventUpdate, NodeID: n.ID, Node: n.Name, Subject: release, Title: "Update available for " + n.Name, Message: fmt.Sprintf("%s runs %s. Version %s is available. Update it from the node page.", n.Name, ov.Version, release)})
	}
	return events
}

func (m *Monitor) heal(ctx context.Context, h healTask) {
	c, err := m.p.client(h.node)
	if err != nil {
		return
	}
	hctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	status, err := c.postJSON(hctx, "/v1/admin/services/restart", map[string]string{"service": h.service}, nil)
	note := "Restart accepted by the node"
	if err != nil {
		note = "Restart request failed: " + shortNetErr(err)
	} else if status != http.StatusAccepted {
		note = fmt.Sprintf("Node declined the restart (%d)", status)
	}
	now := m.p.now()
	_ = m.p.db.Update(func(d *data) error {
		if in := openIncident(d, h.node.ID, "service", h.service); in != nil {
			addNote(in, now, note)
		}
		return nil
	})
	m.p.audit("auto-heal", "node.service.restart", h.node.Name, h.service)
}

func (m *Monitor) snapshot(id string) nodeState {
	m.mu.Lock()
	defer m.mu.Unlock()
	if st := m.state[id]; st != nil {
		c := *st
		return c
	}
	return nodeState{}
}

func uptimeRatio(hours []Hour, since int64) (float64, bool) {
	var up, total int64
	for _, h := range hours {
		if h.Start >= since {
			up += h.Up
			total += h.Total
		}
	}
	if total == 0 {
		return 0, false
	}
	return float64(up) / float64(total), true
}

type fleetNode struct {
	ID         string      `json:"id"`
	Name       string      `json:"name"`
	Host       string      `json:"host"`
	Platform   string      `json:"platform"`
	Status     string      `json:"status"`
	Error      string      `json:"error,omitempty"`
	LastProbe  int64       `json:"last_probe"`
	Version    string      `json:"version"`
	Update     string      `json:"update,omitempty"`
	Connected  int         `json:"connected"`
	Accounts   int         `json:"accounts"`
	Devices    int         `json:"devices"`
	Services   []Service   `json:"services"`
	CertExpiry string      `json:"cert_expiry"`
	Disk       float64     `json:"disk"`
	Mem        string      `json:"mem"`
	Load       string      `json:"load"`
	Blocklists []Blocklist `json:"blocklists"`
	Blocklist  string      `json:"blocklist_updated"`
	Up24       *float64    `json:"uptime_24h"`
	Up30       *float64    `json:"uptime_30d"`
	Up90       *float64    `json:"uptime_90d"`
	Hours      []int       `json:"hours"`
	Incidents  int         `json:"open_incidents"`
	Heal       bool        `json:"heal"`
	Scope      string      `json:"scope"`
	Local      bool        `json:"local"`
	Stealth    bool        `json:"stealth"`
}

func ratioPtr(hours []Hour, since int64) *float64 {
	if r, ok := uptimeRatio(hours, since); ok {
		return &r
	}
	return nil
}

func hourGrid(hours []Hour, now time.Time, n int) []int {
	out := make([]int, n)
	idx := map[int64]Hour{}
	for _, h := range hours {
		idx[h.Start] = h
	}
	start := hourStart(now) - int64(n-1)*3600
	for i := 0; i < n; i++ {
		h, ok := idx[start+int64(i)*3600]
		if !ok || h.Total == 0 {
			out[i] = -1
			continue
		}
		out[i] = int(h.Up * 1000 / h.Total)
	}
	return out
}

func (p *Panel) fleetNode(d *data, n Node, st nodeState, now time.Time, release string) fleetNode {
	f := fleetNode{ID: n.ID, Name: n.Name, Host: n.Host, Platform: orDefault(n.Platform, "linux"), Status: "unknown", Error: st.Error, Heal: n.Heal, Scope: n.Scope, Local: n.Local, Services: []Service{}, Blocklists: []Blocklist{}}
	if !st.LastProbe.IsZero() {
		f.LastProbe = st.LastProbe.Unix()
	}
	switch {
	case st.Down:
		f.Status = "down"
	case st.Known && st.Up:
		f.Status = "up"
	case st.Known:
		f.Status = "checking"
	}
	if ov := st.Overview; ov != nil {
		f.Version, f.Connected, f.Accounts, f.Devices = ov.Version, ov.Connected, ov.Accounts, ov.Devices
		f.Services = append(f.Services, ov.Services...)
		f.CertExpiry, f.Stealth = ov.CertExpiry, ov.Stealth
		f.Blocklists = append(f.Blocklists, ov.Blocklists...)
		if used, ok := diskUsed(ov.System); ok {
			f.Disk = used
		}
		f.Mem, f.Load = ov.System["mem"], ov.System["load"]
		for _, b := range ov.Blocklists {
			if b.Updated != "" && (f.Blocklist == "" || b.Updated < f.Blocklist) {
				f.Blocklist = b.Updated
			}
		}
		if f.Status == "up" {
			for _, s := range ov.Services {
				if s.State == "failed" {
					f.Status = "degraded"
				}
			}
		}
		if release != "" && Newer(release, ov.Version) {
			f.Update = release
		}
	}
	hours := d.Uptime[n.ID]
	f.Up24 = ratioPtr(hours, now.Add(-24*time.Hour).Unix())
	f.Up30 = ratioPtr(hours, now.Add(-30*24*time.Hour).Unix())
	f.Up90 = ratioPtr(hours, now.Add(-90*24*time.Hour).Unix())
	f.Hours = hourGrid(hours, now, 48)
	for _, in := range d.Incidents {
		if in.NodeID == n.ID && in.End == 0 {
			f.Incidents++
		}
	}
	return f
}

func (p *Panel) fleet(w http.ResponseWriter, r *http.Request) {
	now := p.now()
	release := p.mon.Release()
	out := []fleetNode{}
	nodes := p.nodes()
	states := make([]nodeState, len(nodes))
	for i, n := range nodes {
		states[i] = p.mon.snapshot(n.ID)
	}
	totals := map[string]int{}
	p.db.View(func(d *data) {
		for i, n := range nodes {
			f := p.fleetNode(d, n, states[i], now, release)
			totals[f.Status]++
			totals["connected"] += f.Connected
			totals["accounts"] += f.Accounts
			totals["devices"] += f.Devices
			totals["incidents"] += f.Incidents
			out = append(out, f)
		}
	})
	totals["nodes"] = len(out)
	last := p.mon.LastTick()
	web.JSON(w, http.StatusOK, map[string]any{"nodes": out, "totals": totals, "release": release, "interval": int(p.opt.Interval / time.Second), "last_tick": last.Unix()})
}

func (p *Panel) nodeDetail(w http.ResponseWriter, r *http.Request) {
	n, ok := p.nodeByID(r.PathValue("id"))
	if !ok {
		web.Error(w, http.StatusNotFound, "NOT_FOUND", "That node is no longer in your fleet.")
		return
	}
	now := p.now()
	var f fleetNode
	incidents := []Incident{}
	var grid []int
	st := p.mon.snapshot(n.ID)
	release := p.mon.Release()
	p.db.View(func(d *data) {
		f = p.fleetNode(d, n, st, now, release)
		grid = hourGrid(d.Uptime[n.ID], now, 90*24)
		for i := len(d.Incidents) - 1; i >= 0 && len(incidents) < 100; i-- {
			if d.Incidents[i].NodeID == n.ID {
				incidents = append(incidents, d.Incidents[i])
			}
		}
	})
	days := make([]int, 90)
	for i := range days {
		var up, tot int
		for _, v := range grid[i*24 : i*24+24] {
			if v >= 0 {
				up += v
				tot += 1000
			}
		}
		if tot == 0 {
			days[i] = -1
		} else {
			days[i] = up * 1000 / tot
		}
	}
	web.JSON(w, http.StatusOK, map[string]any{"node": f, "days": days, "incidents": incidents, "url": n.URL, "added": n.Added, "pinned": n.Pin != ""})
}

type incidentOut struct {
	Incident
	NodeName string `json:"node_name"`
}

func (p *Panel) incidents(w http.ResponseWriter, r *http.Request) {
	nodeID := r.URL.Query().Get("node")
	open := r.URL.Query().Get("open") == "1"
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	out := []incidentOut{}
	p.db.View(func(d *data) {
		names := map[string]string{}
		for _, n := range d.Nodes {
			names[n.ID] = n.Name
		}
		for i := len(d.Incidents) - 1; i >= 0 && len(out) < limit; i-- {
			in := d.Incidents[i]
			if (nodeID != "" && in.NodeID != nodeID) || (open && in.End != 0) {
				continue
			}
			out = append(out, incidentOut{Incident: in, NodeName: orDefault(names[in.NodeID], "removed node")})
		}
	})
	sort.SliceStable(out, func(i, j int) bool {
		if (out[i].End == 0) != (out[j].End == 0) {
			return out[i].End == 0
		}
		return out[i].Start > out[j].Start
	})
	web.JSON(w, http.StatusOK, map[string]any{"incidents": out})
}
