package panel

import (
	"encoding/json"
	"errors"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/veylvpn/backend/internal/panelcfg"
)

const (
	RoleOwner  = "owner"
	RoleAdmin  = "admin"
	RoleViewer = "viewer"

	Retention   = 90 * 24 * time.Hour
	maxAudit    = 50000
	maxIncident = 5000
	schema      = 1
)

type User struct {
	ID         string   `json:"id"`
	Username   string   `json:"username"`
	Role       string   `json:"role"`
	Password   string   `json:"password"`
	TOTP       string   `json:"totp,omitempty"`
	TOTPLast   int64    `json:"totp_last,omitempty"`
	Recovery   []string `json:"recovery,omitempty"`
	Created    int64    `json:"created"`
	LastLogin  int64    `json:"last_login,omitempty"`
	Epoch      string   `json:"epoch"`
	MustEnroll bool     `json:"must_enroll,omitempty"`
}

type Session struct {
	Hash    string `json:"hash"`
	UserID  string `json:"user_id"`
	CSRF    string `json:"csrf"`
	Created int64  `json:"created"`
	Last    int64  `json:"last"`
	Agent   string `json:"agent"`
	Epoch   string `json:"epoch"`
}

type TeamInvite struct {
	ID      string `json:"id"`
	Hash    string `json:"hash"`
	Role    string `json:"role"`
	Note    string `json:"note,omitempty"`
	By      string `json:"by"`
	Created int64  `json:"created"`
	Expires int64  `json:"expires"`
}

type Node struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	URL      string `json:"url"`
	Host     string `json:"host"`
	Key      string `json:"key"`
	KeyID    string `json:"key_id"`
	Scope    string `json:"scope"`
	Pin      string `json:"pin,omitempty"`
	Local    bool   `json:"local,omitempty"`
	Added    int64  `json:"added"`
	Platform string `json:"platform,omitempty"`
	Heal     bool   `json:"heal"`
}

type Hour struct {
	Start int64 `json:"t"`
	Up    int64 `json:"up"`
	Total int64 `json:"total"`
}

type Note struct {
	Time int64  `json:"time"`
	Text string `json:"text"`
}

type Incident struct {
	ID      string `json:"id"`
	NodeID  string `json:"node_id"`
	Kind    string `json:"kind"`
	Subject string `json:"subject,omitempty"`
	Start   int64  `json:"start"`
	End     int64  `json:"end,omitempty"`
	Notes   []Note `json:"notes,omitempty"`
}

type AuditEntry struct {
	Time   int64  `json:"time"`
	User   string `json:"user"`
	Action string `json:"action"`
	Target string `json:"target,omitempty"`
	Detail string `json:"detail,omitempty"`
}

type SMTPConfig struct {
	Enabled  bool     `json:"enabled"`
	Host     string   `json:"host"`
	Port     int      `json:"port"`
	Security string   `json:"security"`
	Username string   `json:"username"`
	Password string   `json:"password"`
	From     string   `json:"from"`
	To       []string `json:"to"`
}

type WebhookConfig struct {
	ID      string `json:"id"`
	Enabled bool   `json:"enabled"`
	Name    string `json:"name"`
	URL     string `json:"url"`
	Format  string `json:"format"`
	Secret  string `json:"secret"`
}

type NtfyConfig struct {
	Enabled bool   `json:"enabled"`
	Server  string `json:"server"`
	Topic   string `json:"topic"`
	Token   string `json:"token"`
}

type AlertConfig struct {
	Events   map[string]bool `json:"events"`
	SMTP     SMTPConfig      `json:"smtp"`
	Webhooks []WebhookConfig `json:"webhooks"`
	Ntfy     NtfyConfig      `json:"ntfy"`
}

type Settings struct {
	Name         string `json:"name"`
	CheckUpdates bool   `json:"check_updates"`
	AutoHeal     bool   `json:"auto_heal"`
}

type data struct {
	Schema    int               `json:"schema"`
	Settings  Settings          `json:"settings"`
	Users     []User            `json:"users"`
	Sessions  []Session         `json:"sessions"`
	Invites   []TeamInvite      `json:"invites"`
	Nodes     []Node            `json:"nodes"`
	Uptime    map[string][]Hour `json:"uptime"`
	Incidents []Incident        `json:"incidents"`
	Alerts    AlertConfig       `json:"alerts"`
	Dedupe    map[string]int64  `json:"dedupe"`
	Audit     []AuditEntry      `json:"audit"`
}

type DB struct {
	path string
	mu   sync.Mutex
	d    data
}

func defaults() data {
	return data{
		Schema:   schema,
		Settings: Settings{Name: "Veyl Control", CheckUpdates: true, AutoHeal: true},
		Uptime:   map[string][]Hour{},
		Dedupe:   map[string]int64{},
		Alerts:   AlertConfig{Events: defaultEvents(), SMTP: SMTPConfig{Port: 587, Security: "starttls"}, Ntfy: NtfyConfig{Server: "https://ntfy.sh"}},
	}
}

func OpenDB(path string) (*DB, error) {
	db := &DB{path: path, d: defaults()}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return db, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, &db.d); err != nil {
		return nil, err
	}
	if db.d.Uptime == nil {
		db.d.Uptime = map[string][]Hour{}
	}
	if db.d.Dedupe == nil {
		db.d.Dedupe = map[string]int64{}
	}
	if db.d.Alerts.Events == nil {
		db.d.Alerts.Events = defaultEvents()
	}
	return db, nil
}

func (db *DB) saveLocked() error {
	b, err := json.Marshal(db.d)
	if err != nil {
		return err
	}
	return panelcfg.WriteFile(db.path, b, 0o600)
}

func (db *DB) Update(fn func(*data) error) error {
	db.mu.Lock()
	defer db.mu.Unlock()
	if err := fn(&db.d); err != nil {
		return err
	}
	return db.saveLocked()
}

func (db *DB) View(fn func(*data)) {
	db.mu.Lock()
	defer db.mu.Unlock()
	fn(&db.d)
}

func (db *DB) Raw() ([]byte, error) {
	db.mu.Lock()
	defer db.mu.Unlock()
	return json.Marshal(db.d)
}

func (d *data) prune(now time.Time) {
	cut := now.Add(-Retention).Unix()
	for id, hours := range d.Uptime {
		keep := hours[:0]
		for _, h := range hours {
			if h.Start >= cut-3600 {
				keep = append(keep, h)
			}
		}
		d.Uptime[id] = keep
	}
	inc := d.Incidents[:0]
	for _, i := range d.Incidents {
		if i.End == 0 || i.End >= cut {
			inc = append(inc, i)
		}
	}
	d.Incidents = inc
	if over := len(d.Incidents) - maxIncident; over > 0 {
		d.Incidents = d.Incidents[over:]
	}
	aud := d.Audit[:0]
	for _, a := range d.Audit {
		if a.Time >= cut {
			aud = append(aud, a)
		}
	}
	d.Audit = aud
	if over := len(d.Audit) - maxAudit; over > 0 {
		d.Audit = d.Audit[over:]
	}
	for k, t := range d.Dedupe {
		if t < now.Add(-48*time.Hour).Unix() {
			delete(d.Dedupe, k)
		}
	}
	sessions := d.Sessions[:0]
	for _, s := range d.Sessions {
		if now.Unix()-s.Last <= int64(IdleTimeout/time.Second) && now.Unix()-s.Created <= int64(MaxLifetime/time.Second) {
			sessions = append(sessions, s)
		}
	}
	d.Sessions = sessions
	invites := d.Invites[:0]
	for _, i := range d.Invites {
		if i.Expires > now.Unix() {
			invites = append(invites, i)
		}
	}
	d.Invites = invites
}

func (d *data) user(id string) *User {
	for i := range d.Users {
		if d.Users[i].ID == id {
			return &d.Users[i]
		}
	}
	return nil
}

func (d *data) userByName(name string) *User {
	for i := range d.Users {
		if d.Users[i].Username == name {
			return &d.Users[i]
		}
	}
	return nil
}

func (d *data) node(id string) *Node {
	for i := range d.Nodes {
		if d.Nodes[i].ID == id {
			return &d.Nodes[i]
		}
	}
	return nil
}

func (d *data) owners() int {
	n := 0
	for _, u := range d.Users {
		if u.Role == RoleOwner {
			n++
		}
	}
	return n
}

func (d *data) sortIncidents() {
	sort.SliceStable(d.Incidents, func(i, j int) bool { return d.Incidents[i].Start < d.Incidents[j].Start })
}
