package panel

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

type webhook struct {
	url    string
	client *http.Client
	mu     sync.Mutex
	reqs   []*http.Request
	bodies [][]byte
}

func newWebhook(t *testing.T, fn func(map[string]any)) *webhook {
	w := &webhook{}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		w.mu.Lock()
		w.reqs = append(w.reqs, r)
		w.bodies = append(w.bodies, b)
		w.mu.Unlock()
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		if fn != nil && m != nil {
			fn(m)
		}
		rw.WriteHeader(204)
	}))
	t.Cleanup(srv.Close)
	w.url = srv.URL + "/hook"
	w.client = srv.Client()
	return w
}

func configureWebhook(t *testing.T, o *client, url, format string) {
	t.Helper()
	if format == "" {
		format = "json"
	}
	code, out := o.do("PUT", "/api/alerts", map[string]any{"events": map[string]bool{}, "webhooks": []map[string]any{{"enabled": true, "name": "ops", "url": url, "format": format, "secret": "s3cret-signing-key"}}})
	if code != 200 {
		t.Fatal(code, out)
	}
}

func TestWebhookSignatureAndFormats(t *testing.T) {
	hook := newWebhook(t, nil)
	h := newHarness(t, func(o *Options) {})
	configure(h)
	h.p.opt.AlertHTTP = hook.client
	o := h.owner()
	configureWebhook(t, o, hook.url, "json")
	raw, _ := os.ReadFile(h.paths.DB())
	if strings.Contains(string(raw), "s3cret-signing-key") {
		t.Fatal("webhook secret stored in clear")
	}
	_, out := o.do("GET", "/api/alerts", nil)
	wh := out["webhooks"].([]any)[0].(map[string]any)
	if wh["secret_set"] != true || wh["secret"] != nil {
		t.Fatal(wh)
	}
	code, out := o.do("POST", "/api/alerts/test", map[string]string{"channel": "webhook:" + wh["id"].(string)})
	if code != 200 || out["ok"] != true {
		t.Fatal(code, out)
	}
	r, body := hook.reqs[0], hook.bodies[0]
	ts, _ := strconv.ParseInt(r.Header.Get(TimestampHdr), 10, 64)
	m := hmac.New(sha256.New, []byte("s3cret-signing-key"))
	m.Write([]byte(strconv.FormatInt(ts, 10) + "."))
	m.Write(body)
	if r.Header.Get(SignatureHdr) != "sha256="+hex.EncodeToString(m.Sum(nil)) {
		t.Fatal("bad signature")
	}
	var j map[string]any
	_ = json.Unmarshal(body, &j)
	if j["event"] != "test" || j["title"] != "Test alert" {
		t.Fatal(j)
	}
	for _, f := range []string{"discord", "slack"} {
		code, out = o.do("PUT", "/api/alerts", map[string]any{"webhooks": []map[string]any{{"id": wh["id"], "enabled": true, "name": "ops", "url": hook.url, "format": f}}})
		if code != 200 {
			t.Fatal(code, out)
		}
		o.do("POST", "/api/alerts/test", map[string]string{"channel": "webhook:" + wh["id"].(string)})
		var b map[string]any
		_ = json.Unmarshal(hook.bodies[len(hook.bodies)-1], &b)
		if f == "discord" && !strings.HasPrefix(b["content"].(string), "**Test alert**") {
			t.Fatal(b)
		}
		if f == "slack" && !strings.HasPrefix(b["text"].(string), "*Test alert*") {
			t.Fatal(b)
		}
		if hook.reqs[len(hook.reqs)-1].Header.Get(SignatureHdr) == "" {
			t.Fatal("kept secret not used")
		}
	}
	if code, _ := o.do("PUT", "/api/alerts", map[string]any{"webhooks": []map[string]any{{"enabled": true, "url": "http://example.com/x", "format": "json"}}}); code != 400 {
		t.Fatal("plain http webhook accepted", code)
	}
}

func TestNtfy(t *testing.T) {
	hook := newWebhook(t, nil)
	h := newHarness(t, nil)
	configure(h)
	h.p.opt.AlertHTTP = hook.client
	o := h.owner()
	server := strings.TrimSuffix(hook.url, "/hook")
	if code, out := o.do("PUT", "/api/alerts", map[string]any{"ntfy": map[string]any{"enabled": true, "server": server, "topic": "veyl-alerts", "token": "tk_secret"}}); code != 200 {
		t.Fatal(code, out)
	}
	if code, out := o.do("POST", "/api/alerts/test", map[string]string{"channel": "ntfy"}); code != 200 || out["ok"] != true {
		t.Fatal(code, out)
	}
	r := hook.reqs[0]
	if r.URL.Path != "/veyl-alerts" || r.Header.Get("Title") != "Test alert" || r.Header.Get("Authorization") != "Bearer tk_secret" {
		t.Fatal(r.URL.Path, r.Header)
	}
	if code, _ := o.do("PUT", "/api/alerts", map[string]any{"ntfy": map[string]any{"enabled": true, "topic": "bad topic/../x"}}); code != 400 {
		t.Fatal(code)
	}
}

func TestDedupeAndRateLimit(t *testing.T) {
	h := newHarness(t, nil)
	configure(h)
	a := h.p.alerts
	e := Event{Kind: EventServiceFailed, NodeID: "n1", Subject: "caddy", Title: "x", Message: "y"}
	a.Emit(e)
	a.Emit(e)
	if len(a.queue) != 1 {
		t.Fatal(len(a.queue))
	}
	h.clk.Add(7 * time.Hour)
	a.Emit(e)
	if len(a.queue) != 2 {
		t.Fatal("dedupe window not expiring")
	}
	_ = h.p.db.Update(func(d *data) error { d.Alerts.Events[EventDiskFull] = false; return nil })
	a.Emit(Event{Kind: EventDiskFull, NodeID: "n1"})
	if len(a.queue) != 2 {
		t.Fatal("disabled event sent")
	}
	for i := 0; i < 50; i++ {
		a.Emit(Event{Kind: EventServiceFailed, NodeID: "n1", Subject: strconv.Itoa(i)})
	}
	if len(a.queue) != alertsPerHour+1 || a.dropped == 0 {
		t.Fatal(len(a.queue), a.dropped)
	}
	a.Emit(Event{Kind: EventNodeDown, NodeID: "n2"})
	h.clk.Add(time.Hour)
	a.Emit(Event{Kind: EventNodeDown, NodeID: "n2"})
}

func testCert(t *testing.T) (tls.Certificate, *x509.CertPool) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "mail"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(c)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}, pool
}

type smtpServer struct {
	addr     string
	mu       sync.Mutex
	msgs     []string
	authed   bool
	tlsUsed  bool
	starttls bool
}

func fakeSMTP(t *testing.T, implicit, offerTLS bool, cert tls.Certificate) *smtpServer {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	s := &smtpServer{addr: ln.Addr().String()}
	cfg := &tls.Config{Certificates: []tls.Certificate{cert}}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go s.serve(c, implicit, offerTLS, cfg)
		}
	}()
	return s
}

func (s *smtpServer) serve(c net.Conn, implicit, offer bool, cfg *tls.Config) {
	defer c.Close()
	secure := false
	if implicit {
		c = tls.Server(c, cfg)
		secure = true
	}
	rd := bufio.NewReader(c)
	say := func(l string) { _, _ = io.WriteString(c, l+"\r\n") }
	say("220 fake ESMTP")
	for {
		line, err := rd.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		up := strings.ToUpper(line)
		switch {
		case strings.HasPrefix(up, "EHLO"):
			say("250-fake")
			if offer && !secure {
				say("250-STARTTLS")
			}
			say("250 AUTH PLAIN")
		case up == "STARTTLS":
			say("220 go ahead")
			c = tls.Server(c, cfg)
			rd = bufio.NewReader(c)
			secure = true
			s.mu.Lock()
			s.starttls = true
			s.mu.Unlock()
		case strings.HasPrefix(up, "AUTH PLAIN"):
			b, _ := base64.StdEncoding.DecodeString(strings.TrimSpace(line[10:]))
			if string(b) == "\x00mailer\x00mail-pass" && secure {
				s.mu.Lock()
				s.authed = true
				s.mu.Unlock()
				say("235 ok")
			} else {
				say("535 no")
			}
		case strings.HasPrefix(up, "MAIL"), strings.HasPrefix(up, "RCPT"):
			say("250 ok")
		case up == "DATA":
			say("354 go")
			var b strings.Builder
			for {
				l, err := rd.ReadString('\n')
				if err != nil {
					return
				}
				if l == ".\r\n" {
					break
				}
				b.WriteString(l)
			}
			s.mu.Lock()
			s.msgs = append(s.msgs, b.String())
			s.tlsUsed = secure
			s.mu.Unlock()
			say("250 queued")
		case up == "QUIT":
			say("221 bye")
			return
		default:
			say("250 ok")
		}
	}
}

func smtpConfig(o *client, t *testing.T, addr, security string) {
	host, port, _ := net.SplitHostPort(addr)
	p, _ := strconv.Atoi(port)
	code, out := o.do("PUT", "/api/alerts", map[string]any{"smtp": map[string]any{"enabled": true, "host": host, "port": p, "security": security, "username": "mailer", "password": "mail-pass", "from": "alerts@example.com", "to": []string{"ops@example.com"}}})
	if code != 200 {
		t.Fatal(code, out)
	}
}

func TestSMTP(t *testing.T) {
	cert, pool := testCert(t)
	h := newHarness(t, func(o *Options) { o.SMTPTLS = pool })
	configure(h)
	o := h.owner()
	for _, mode := range []string{"starttls", "tls"} {
		srv := fakeSMTP(t, mode == "tls", true, cert)
		smtpConfig(o, t, srv.addr, mode)
		code, out := o.do("POST", "/api/alerts/test", map[string]string{"channel": "smtp"})
		if code != 200 || out["ok"] != true {
			t.Fatal(mode, code, out)
		}
		if len(srv.msgs) != 1 || !srv.authed || !srv.tlsUsed || !strings.Contains(srv.msgs[0], "Subject: [Veyl] Test alert") {
			t.Fatal(mode, srv.msgs, srv.authed)
		}
		if mode == "starttls" && !srv.starttls {
			t.Fatal("starttls not used")
		}
	}
	raw, _ := os.ReadFile(h.paths.DB())
	if strings.Contains(string(raw), "mail-pass") {
		t.Fatal("smtp password stored in clear")
	}
	plain := fakeSMTP(t, false, false, cert)
	host, port, _ := net.SplitHostPort(plain.addr)
	p, _ := strconv.Atoi(port)
	if code, _ := o.do("PUT", "/api/alerts", map[string]any{"smtp": map[string]any{"enabled": true, "host": host, "port": p, "security": "starttls", "username": "mailer", "from": "alerts@example.com", "to": []string{"ops@example.com"}}}); code != 200 {
		t.Fatal(code)
	}
	code, out := o.do("POST", "/api/alerts/test", map[string]string{"channel": "smtp"})
	if code != 200 || out["ok"] != false || !strings.Contains(out["error"].(string), "STARTTLS") || len(plain.msgs) != 0 {
		t.Fatal("sent without encryption", out)
	}
	if code, _ := o.do("PUT", "/api/alerts", map[string]any{"smtp": map[string]any{"enabled": true, "host": host, "port": p, "security": "none", "from": "a@example.com", "to": []string{"b@example.com"}}}); code != 400 {
		t.Fatal("unencrypted mode accepted", code)
	}
}

func TestDeliverRecordsStatus(t *testing.T) {
	h := newHarness(t, nil)
	configure(h)
	hook := newWebhook(t, nil)
	h.p.opt.AlertHTTP = hook.client
	o := h.owner()
	configureWebhook(t, o, hook.url, "slack")
	h.p.alerts.Emit(Event{Kind: EventNodeDown, NodeID: "n", Node: "Lisbon", Title: "Lisbon is down", Message: "down"})
	h.p.alerts.Drain(context.Background())
	if len(hook.bodies) != 1 || !strings.Contains(string(hook.bodies[0]), "Lisbon is down") {
		t.Fatal(len(hook.bodies))
	}
	_, out := o.do("GET", "/api/alerts", nil)
	st := out["status"].(map[string]any)
	if len(st) != 1 {
		t.Fatal(st)
	}
}
