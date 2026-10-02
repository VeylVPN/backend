package panel

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/mail"
	"net/smtp"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/veylvpn/backend/internal/app"
	"github.com/veylvpn/backend/internal/config"
	"github.com/veylvpn/backend/internal/panelkey"
	"github.com/veylvpn/backend/internal/web"
)

const (
	EventNodeDown      = "node_down"
	EventNodeUp        = "node_up"
	EventCertExpiring  = "cert_expiring"
	EventDiskFull      = "disk_full"
	EventServiceFailed = "service_failed"
	EventServiceHealed = "service_healed"
	EventUpdate        = "update_available"
	EventApplyFailed   = "apply_failed"
	EventTest          = "test"

	alertsPerHour = 30
	maxWebhooks   = 8
	maxRecipients = 10
	SignatureHdr  = "X-Veyl-Signature"
	TimestampHdr  = "X-Veyl-Timestamp"
)

var eventKinds = []struct {
	Kind  string `json:"kind"`
	Label string `json:"label"`
}{
	{EventNodeDown, "Node goes down"},
	{EventNodeUp, "Node comes back"},
	{EventServiceFailed, "A service fails"},
	{EventServiceHealed, "A service is healed"},
	{EventCertExpiring, "Certificate expires within 14 days"},
	{EventDiskFull, "Disk more than 90% full"},
	{EventUpdate, "Update available"},
	{EventApplyFailed, "Applying settings failed"},
}

var dedupeWindow = map[string]time.Duration{
	EventNodeDown:      5 * time.Minute,
	EventNodeUp:        5 * time.Minute,
	EventServiceFailed: 6 * time.Hour,
	EventServiceHealed: time.Hour,
	EventCertExpiring:  24 * time.Hour,
	EventDiskFull:      24 * time.Hour,
	EventUpdate:        7 * 24 * time.Hour,
	EventApplyFailed:   time.Hour,
}

func defaultEvents() map[string]bool {
	m := map[string]bool{}
	for _, k := range eventKinds {
		m[k.Kind] = true
	}
	return m
}

type Event struct {
	Kind    string
	NodeID  string
	Node    string
	Subject string
	Title   string
	Message string
	Time    time.Time
}

func (e Event) severity() string {
	switch e.Kind {
	case EventNodeDown, EventServiceFailed, EventApplyFailed:
		return "critical"
	case EventCertExpiring, EventDiskFull:
		return "warning"
	}
	return "info"
}

type Result struct {
	Time  int64  `json:"time"`
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

type Alerter struct {
	p       *Panel
	queue   chan Event
	mu      sync.Mutex
	sent    []time.Time
	dropped int
	status  map[string]Result
	Retry   []time.Duration
}

func newAlerter(p *Panel) *Alerter {
	return &Alerter{p: p, queue: make(chan Event, 256), status: map[string]Result{}, Retry: []time.Duration{0, 5 * time.Second, 30 * time.Second}}
}

func (a *Alerter) Emit(e Event) {
	if e.Time.IsZero() {
		e.Time = a.p.now()
	}
	enabled := false
	key := e.Kind + "|" + e.NodeID + "|" + e.Subject
	now := e.Time
	suppress := false
	_ = a.p.db.Update(func(d *data) error {
		enabled = d.Alerts.Events[e.Kind]
		if !enabled {
			return nil
		}
		if last, ok := d.Dedupe[key]; ok && now.Unix()-last < int64(dedupeWindow[e.Kind]/time.Second) {
			suppress = true
			return nil
		}
		d.Dedupe[key] = now.Unix()
		if e.Kind == EventNodeUp {
			delete(d.Dedupe, EventNodeDown+"|"+e.NodeID+"|")
		}
		if e.Kind == EventNodeDown {
			delete(d.Dedupe, EventNodeUp+"|"+e.NodeID+"|")
		}
		return nil
	})
	if !enabled || suppress {
		return
	}
	a.mu.Lock()
	keep := a.sent[:0]
	for _, t := range a.sent {
		if now.Sub(t) < time.Hour {
			keep = append(keep, t)
		}
	}
	a.sent = keep
	if len(a.sent) >= alertsPerHour {
		a.dropped++
		a.mu.Unlock()
		return
	}
	a.sent = append(a.sent, now)
	a.mu.Unlock()
	select {
	case a.queue <- e:
	default:
		a.mu.Lock()
		a.dropped++
		a.mu.Unlock()
	}
}

func (a *Alerter) Run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case e := <-a.queue:
			a.deliver(ctx, e)
		}
	}
}

func (a *Alerter) Drain(ctx context.Context) {
	for {
		select {
		case e := <-a.queue:
			a.deliver(ctx, e)
		default:
			return
		}
	}
}

type channel struct {
	id   string
	send func(ctx context.Context, e Event) error
}

func (a *Alerter) channels() []channel {
	var cfg AlertConfig
	a.p.db.View(func(d *data) { cfg = d.Alerts })
	var out []channel
	if cfg.SMTP.Enabled {
		s := cfg.SMTP
		out = append(out, channel{"smtp", func(ctx context.Context, e Event) error { return a.sendSMTP(ctx, s, e) }})
	}
	for _, w := range cfg.Webhooks {
		if w.Enabled {
			w := w
			out = append(out, channel{"webhook:" + w.ID, func(ctx context.Context, e Event) error { return a.sendWebhook(ctx, w, e) }})
		}
	}
	if cfg.Ntfy.Enabled {
		n := cfg.Ntfy
		out = append(out, channel{"ntfy", func(ctx context.Context, e Event) error { return a.sendNtfy(ctx, n, e) }})
	}
	return out
}

func (a *Alerter) deliver(ctx context.Context, e Event) {
	for _, ch := range a.channels() {
		var err error
		for _, wait := range a.Retry {
			if wait > 0 {
				t := time.NewTimer(wait)
				select {
				case <-ctx.Done():
					t.Stop()
					return
				case <-t.C:
				}
			}
			sctx, cancel := context.WithTimeout(ctx, 30*time.Second)
			err = ch.send(sctx, e)
			cancel()
			if err == nil {
				break
			}
		}
		a.record(ch.id, err)
	}
}

func (a *Alerter) record(id string, err error) {
	r := Result{Time: a.p.now().Unix(), OK: err == nil}
	if err != nil {
		r.Error = trimErr(err)
	}
	a.mu.Lock()
	a.status[id] = r
	a.mu.Unlock()
}

func trimErr(err error) string {
	s := err.Error()
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}

func (a *Alerter) httpClient() *http.Client {
	if a.p.opt.AlertHTTP != nil {
		return a.p.opt.AlertHTTP
	}
	return &http.Client{
		Timeout:       20 * time.Second,
		Transport:     &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: a.p.opt.RootCAs}, Proxy: http.ProxyFromEnvironment},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

func (a *Alerter) text(e Event) string {
	b := e.Message
	if e.Node != "" && !strings.Contains(b, e.Node) {
		b += " Node: " + e.Node + "."
	}
	return b
}

func Sign(secret string, ts int64, body []byte) string {
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte(strconv.FormatInt(ts, 10)))
	m.Write([]byte("."))
	m.Write(body)
	return "sha256=" + hex.EncodeToString(m.Sum(nil))
}

func (a *Alerter) sendWebhook(ctx context.Context, w WebhookConfig, e Event) error {
	var payload any
	switch w.Format {
	case "discord":
		payload = map[string]any{"username": "Veyl Control", "content": "**" + e.Title + "**\n" + a.text(e), "allowed_mentions": map[string]any{"parse": []string{}}}
	case "slack":
		payload = map[string]any{"text": "*" + e.Title + "*\n" + a.text(e)}
	default:
		payload = map[string]any{"event": e.Kind, "severity": e.severity(), "title": e.Title, "message": a.text(e), "node": e.Node, "node_id": e.NodeID, "time": e.Time.UTC().Format(time.RFC3339), "source": "veyl-control", "version": app.Version}
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "VeylControl/"+app.Version)
	if w.Secret != "" {
		secret, err := a.p.seal.Open(w.Secret, "webhook:"+w.ID)
		if err != nil {
			return err
		}
		ts := a.p.now().Unix()
		req.Header.Set(TimestampHdr, strconv.FormatInt(ts, 10))
		req.Header.Set(SignatureHdr, Sign(secret, ts, body))
	}
	res, err := a.httpClient().Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 64<<10))
	if res.StatusCode < 200 || res.StatusCode > 299 {
		return fmt.Errorf("webhook answered %d", res.StatusCode)
	}
	return nil
}

func asciiHeader(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r > 0x7e {
			return ' '
		}
		return r
	}, s)
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}

func (a *Alerter) sendNtfy(ctx context.Context, n NtfyConfig, e Event) error {
	u := strings.TrimSuffix(n.Server, "/") + "/" + n.Topic
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, strings.NewReader(a.text(e)))
	if err != nil {
		return err
	}
	req.Header.Set("Title", asciiHeader(e.Title))
	switch e.severity() {
	case "critical":
		req.Header.Set("Priority", "high")
		req.Header.Set("Tags", "rotating_light")
	case "warning":
		req.Header.Set("Priority", "default")
		req.Header.Set("Tags", "warning")
	default:
		req.Header.Set("Priority", "default")
		req.Header.Set("Tags", "white_check_mark")
	}
	if n.Token != "" {
		tok, err := a.p.seal.Open(n.Token, "ntfy")
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	res, err := a.httpClient().Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 64<<10))
	if res.StatusCode < 200 || res.StatusCode > 299 {
		return fmt.Errorf("ntfy answered %d", res.StatusCode)
	}
	return nil
}

func headerSafe(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\r' || r == '\n' {
			return ' '
		}
		return r
	}, s)
}

func (a *Alerter) sendSMTP(ctx context.Context, s SMTPConfig, e Event) error {
	pass, err := a.p.seal.Open(s.Password, "smtp")
	if err != nil {
		return err
	}
	addr := net.JoinHostPort(s.Host, strconv.Itoa(s.Port))
	tcfg := &tls.Config{ServerName: s.Host, MinVersion: tls.VersionTLS12, RootCAs: a.p.opt.SMTPTLS}
	if tcfg.RootCAs == nil {
		tcfg.RootCAs = a.p.opt.RootCAs
	}
	var d net.Dialer
	deadline := time.Now().Add(30 * time.Second)
	if dl, ok := ctx.Deadline(); ok {
		deadline = dl
	}
	var conn net.Conn
	if s.Security == "tls" {
		raw, err := d.DialContext(ctx, "tcp", addr)
		if err != nil {
			return err
		}
		tc := tls.Client(raw, tcfg)
		_ = tc.SetDeadline(deadline)
		if err := tc.HandshakeContext(ctx); err != nil {
			raw.Close()
			return err
		}
		conn = tc
	} else {
		raw, err := d.DialContext(ctx, "tcp", addr)
		if err != nil {
			return err
		}
		conn = raw
	}
	_ = conn.SetDeadline(deadline)
	c, err := smtp.NewClient(conn, s.Host)
	if err != nil {
		conn.Close()
		return err
	}
	defer c.Close()
	helo := "veyl-control"
	if dom := a.p.site().Domain; dom != "" {
		helo = dom
	}
	if err := c.Hello(helo); err != nil {
		return err
	}
	if s.Security != "tls" {
		if ok, _ := c.Extension("STARTTLS"); !ok {
			return errors.New("the mail server does not offer STARTTLS, refusing to send without encryption")
		}
		if err := c.StartTLS(tcfg); err != nil {
			return err
		}
	}
	if s.Username != "" {
		if err := c.Auth(smtp.PlainAuth("", s.Username, pass, s.Host)); err != nil {
			return err
		}
	}
	if err := c.Mail(s.From); err != nil {
		return err
	}
	for _, to := range s.To {
		if err := c.Rcpt(to); err != nil {
			return err
		}
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	var b strings.Builder
	b.WriteString("From: Veyl Control <" + s.From + ">\r\n")
	b.WriteString("To: " + strings.Join(s.To, ", ") + "\r\n")
	b.WriteString("Subject: " + mime(headerSafe("[Veyl] "+e.Title)) + "\r\n")
	b.WriteString("Date: " + e.Time.UTC().Format(time.RFC1123Z) + "\r\n")
	b.WriteString("Message-ID: <" + randID() + "@" + helo + ">\r\n")
	b.WriteString("MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n")
	for _, line := range strings.Split(a.text(e), "\n") {
		b.WriteString(line + "\r\n")
	}
	b.WriteString("\r\nSent by Veyl Control. Change alerts under Alerts in the panel.\r\n")
	if _, err := io.WriteString(w, b.String()); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}

func mime(s string) string {
	for _, r := range s {
		if r > 0x7e {
			return "=?utf-8?q?" + qEncode(s) + "?="
		}
	}
	return s
}

func qEncode(s string) string {
	var b strings.Builder
	for _, c := range []byte(s) {
		switch {
		case c == ' ':
			b.WriteByte('_')
		case c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z':
			b.WriteByte(c)
		default:
			fmt.Fprintf(&b, "=%02X", c)
		}
	}
	return b.String()
}

type smtpOut struct {
	Enabled     bool     `json:"enabled"`
	Host        string   `json:"host"`
	Port        int      `json:"port"`
	Security    string   `json:"security"`
	Username    string   `json:"username"`
	PasswordSet bool     `json:"password_set"`
	From        string   `json:"from"`
	To          []string `json:"to"`
}

type webhookOut struct {
	ID        string `json:"id"`
	Enabled   bool   `json:"enabled"`
	Name      string `json:"name"`
	URL       string `json:"url"`
	Format    string `json:"format"`
	SecretSet bool   `json:"secret_set"`
}

type ntfyOut struct {
	Enabled  bool   `json:"enabled"`
	Server   string `json:"server"`
	Topic    string `json:"topic"`
	TokenSet bool   `json:"token_set"`
}

func (p *Panel) getAlerts(w http.ResponseWriter, r *http.Request) {
	var cfg AlertConfig
	p.db.View(func(d *data) { cfg = d.Alerts })
	hooks := []webhookOut{}
	for _, h := range cfg.Webhooks {
		hooks = append(hooks, webhookOut{ID: h.ID, Enabled: h.Enabled, Name: h.Name, URL: h.URL, Format: h.Format, SecretSet: h.Secret != ""})
	}
	to := cfg.SMTP.To
	if to == nil {
		to = []string{}
	}
	p.alerts.mu.Lock()
	status := map[string]Result{}
	for k, v := range p.alerts.status {
		status[k] = v
	}
	dropped := p.alerts.dropped
	p.alerts.mu.Unlock()
	web.JSON(w, http.StatusOK, map[string]any{
		"events":   cfg.Events,
		"kinds":    eventKinds,
		"smtp":     smtpOut{Enabled: cfg.SMTP.Enabled, Host: cfg.SMTP.Host, Port: cfg.SMTP.Port, Security: cfg.SMTP.Security, Username: cfg.SMTP.Username, PasswordSet: cfg.SMTP.Password != "", From: cfg.SMTP.From, To: to},
		"webhooks": hooks,
		"ntfy":     ntfyOut{Enabled: cfg.Ntfy.Enabled, Server: cfg.Ntfy.Server, Topic: cfg.Ntfy.Topic, TokenSet: cfg.Ntfy.Token != ""},
		"status":   status,
		"dropped":  dropped,
	})
}

type smtpIn struct {
	Enabled       bool     `json:"enabled"`
	Host          string   `json:"host"`
	Port          int      `json:"port"`
	Security      string   `json:"security"`
	Username      string   `json:"username"`
	Password      string   `json:"password"`
	ClearPassword bool     `json:"clear_password"`
	From          string   `json:"from"`
	To            []string `json:"to"`
}

type webhookIn struct {
	ID          string `json:"id"`
	Enabled     bool   `json:"enabled"`
	Name        string `json:"name"`
	URL         string `json:"url"`
	Format      string `json:"format"`
	Secret      string `json:"secret"`
	ClearSecret bool   `json:"clear_secret"`
}

type ntfyIn struct {
	Enabled    bool   `json:"enabled"`
	Server     string `json:"server"`
	Topic      string `json:"topic"`
	Token      string `json:"token"`
	ClearToken bool   `json:"clear_token"`
}

type alertsIn struct {
	Events   map[string]bool `json:"events"`
	SMTP     smtpIn          `json:"smtp"`
	Webhooks []webhookIn     `json:"webhooks"`
	Ntfy     ntfyIn          `json:"ntfy"`
}

var (
	hostRE  = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$`)
	topicRE = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
)

func validHTTPS(raw string) bool {
	if len(raw) > 512 {
		return false
	}
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "https" && u.Host != "" && u.User == nil && u.Fragment == ""
}

func validMail(s string) bool {
	if s == "" || !config.ValidEmail(s) {
		return false
	}
	_, err := mail.ParseAddress(s)
	return err == nil
}

func (p *Panel) putAlerts(w http.ResponseWriter, r *http.Request) {
	var in alertsIn
	if !web.Decode(w, r, &in, bodyLimit) {
		return
	}
	bad := func(msg string) {
		web.Error(w, http.StatusBadRequest, "BAD_REQUEST", msg)
	}
	s := in.SMTP
	s.Host = strings.TrimSpace(s.Host)
	if s.Enabled || s.Host != "" {
		if !hostRE.MatchString(s.Host) {
			bad("Enter the mail server host name, like smtp.example.com.")
			return
		}
		if s.Port < 1 || s.Port > 65535 {
			bad("The mail server port must be between 1 and 65535.")
			return
		}
		if s.Security != "tls" && s.Security != "starttls" {
			bad("Mail must be encrypted. Pick TLS or STARTTLS.")
			return
		}
		if !validMail(s.From) {
			bad("Enter a valid sender address.")
			return
		}
		if len(s.To) == 0 || len(s.To) > maxRecipients {
			bad("Add between 1 and 10 recipients.")
			return
		}
		for _, t := range s.To {
			if !validMail(t) {
				bad("One of the recipients does not look like an email address.")
				return
			}
		}
		if len(s.Username) > 256 || len(s.Password) > 512 {
			bad("Those mail credentials are too long.")
			return
		}
	}
	if len(in.Webhooks) > maxWebhooks {
		bad("Add up to 8 webhooks.")
		return
	}
	for _, h := range in.Webhooks {
		if !validHTTPS(h.URL) {
			bad("Webhook addresses must start with https://.")
			return
		}
		if h.Format != "json" && h.Format != "discord" && h.Format != "slack" {
			bad("Pick a webhook format: JSON, Discord or Slack.")
			return
		}
		if len(h.Secret) > 256 {
			bad("That signing secret is too long.")
			return
		}
	}
	n := in.Ntfy
	if n.Server == "" {
		n.Server = "https://ntfy.sh"
	}
	if n.Enabled || n.Topic != "" {
		if !validHTTPS(n.Server) {
			bad("The ntfy server must start with https://.")
			return
		}
		if !topicRE.MatchString(n.Topic) {
			bad("ntfy topics use letters, digits, dashes and underscores.")
			return
		}
		if len(n.Token) > 256 {
			bad("That ntfy token is too long.")
			return
		}
	}
	err := p.db.Update(func(d *data) error {
		ev := defaultEvents()
		for k := range ev {
			if v, ok := in.Events[k]; ok {
				ev[k] = v
			}
		}
		old := d.Alerts
		cfg := AlertConfig{Events: ev}
		cfg.SMTP = SMTPConfig{Enabled: s.Enabled, Host: s.Host, Port: s.Port, Security: s.Security, Username: s.Username, Password: old.SMTP.Password, From: s.From, To: s.To}
		if s.ClearPassword {
			cfg.SMTP.Password = ""
		}
		if s.Password != "" {
			sealed, err := p.seal.Seal(s.Password, "smtp")
			if err != nil {
				return err
			}
			cfg.SMTP.Password = sealed
		}
		for _, h := range in.Webhooks {
			wc := WebhookConfig{ID: h.ID, Enabled: h.Enabled, Name: panelkey.CleanName(h.Name), URL: h.URL, Format: h.Format}
			found := false
			for _, o := range old.Webhooks {
				if o.ID == h.ID && h.ID != "" {
					wc.Secret = o.Secret
					found = true
				}
			}
			if !found {
				wc.ID = randID()
			}
			if h.ClearSecret {
				wc.Secret = ""
			}
			if h.Secret != "" {
				sealed, err := p.seal.Seal(h.Secret, "webhook:"+wc.ID)
				if err != nil {
					return err
				}
				wc.Secret = sealed
			}
			cfg.Webhooks = append(cfg.Webhooks, wc)
		}
		cfg.Ntfy = NtfyConfig{Enabled: n.Enabled, Server: strings.TrimSuffix(n.Server, "/"), Topic: n.Topic, Token: old.Ntfy.Token}
		if n.ClearToken {
			cfg.Ntfy.Token = ""
		}
		if n.Token != "" {
			sealed, err := p.seal.Seal(n.Token, "ntfy")
			if err != nil {
				return err
			}
			cfg.Ntfy.Token = sealed
		}
		d.Alerts = cfg
		return nil
	})
	if err != nil {
		web.Error(w, http.StatusInternalServerError, "INTERNAL", "Could not save alert settings.")
		return
	}
	p.audit(current(r).User.Username, "alerts.update", "", "")
	p.getAlerts(w, r)
}

type testIn struct {
	Channel string `json:"channel"`
}

func (p *Panel) testAlert(w http.ResponseWriter, r *http.Request) {
	var in testIn
	if !web.Decode(w, r, &in, bodyLimit) {
		return
	}
	var target *channel
	for _, ch := range p.alerts.allChannels() {
		if ch.id == in.Channel {
			c := ch
			target = &c
		}
	}
	if target == nil {
		web.Error(w, http.StatusNotFound, "NOT_FOUND", "Save this channel first, then send a test.")
		return
	}
	e := Event{Kind: EventTest, Title: "Test alert", Message: "This is a test from Veyl Control. Alerts reach you here.", Time: p.now()}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	err := target.send(ctx, e)
	p.alerts.record(target.id, err)
	p.audit(current(r).User.Username, "alerts.test", in.Channel, "")
	if err != nil {
		web.JSON(w, http.StatusOK, map[string]any{"ok": false, "error": trimErr(err)})
		return
	}
	web.JSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (a *Alerter) allChannels() []channel {
	var cfg AlertConfig
	a.p.db.View(func(d *data) { cfg = d.Alerts })
	var out []channel
	if cfg.SMTP.Host != "" {
		s := cfg.SMTP
		out = append(out, channel{"smtp", func(ctx context.Context, e Event) error { return a.sendSMTP(ctx, s, e) }})
	}
	for _, w := range cfg.Webhooks {
		w := w
		out = append(out, channel{"webhook:" + w.ID, func(ctx context.Context, e Event) error { return a.sendWebhook(ctx, w, e) }})
	}
	if cfg.Ntfy.Topic != "" {
		n := cfg.Ntfy
		out = append(out, channel{"ntfy", func(ctx context.Context, e Event) error { return a.sendNtfy(ctx, n, e) }})
	}
	return out
}
