package panel

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/veylvpn/backend/internal/panelkey"
	"github.com/veylvpn/backend/internal/web"
)

const (
	maxNodes     = 200
	maxNodeBody  = 2 << 20
	nodeTimeout  = 15 * time.Second
	keyPurpose   = "node-key:"
	pinHexLength = 64
)

var (
	ErrUntrusted = errors.New("untrusted certificate")
	errNodeAuth  = errors.New("the node rejected the panel key")
)

type UntrustedError struct {
	Fingerprint string
}

func (e *UntrustedError) Error() string { return "untrusted certificate " + e.Fingerprint }

func spkiPin(c *x509.Certificate) string {
	s := sha256.Sum256(c.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(s[:])
}

func (p *Panel) transport(n Node) *http.Transport {
	host := ""
	if u, err := url.Parse(n.URL); err == nil {
		host = u.Hostname()
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: host, RootCAs: p.opt.RootCAs}
	if n.Pin != "" {
		pin := n.Pin
		cfg.InsecureSkipVerify = true
		cfg.VerifyPeerCertificate = func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) == 0 {
				return ErrUntrusted
			}
			c, err := x509.ParseCertificate(raw[0])
			if err != nil || spkiPin(c) != pin {
				return ErrUntrusted
			}
			return nil
		}
	}
	dial := p.opt.Dial
	if dial == nil {
		var d net.Dialer
		dial = d.DialContext
	}
	tr := &http.Transport{
		TLSClientConfig:       cfg,
		DisableKeepAlives:     false,
		MaxIdleConnsPerHost:   2,
		IdleConnTimeout:       90 * time.Second,
		ResponseHeaderTimeout: nodeTimeout,
		TLSHandshakeTimeout:   10 * time.Second,
		ForceAttemptHTTP2:     true,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if n.Local {
				_, port, _ := net.SplitHostPort(addr)
				addr = net.JoinHostPort("127.0.0.1", port)
			}
			return dial(ctx, network, addr)
		},
	}
	return tr
}

type nodeClient struct {
	p    *Panel
	n    Node
	key  string
	http *http.Client
}

func (p *Panel) client(n Node) (*nodeClient, error) {
	key, err := p.seal.Open(n.Key, keyPurpose+n.ID)
	if err != nil {
		return nil, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.clients == nil {
		p.clients = map[string]*nodeClient{}
	}
	if c := p.clients[n.ID]; c != nil && c.n.URL == n.URL && c.n.Pin == n.Pin && c.key == key {
		return c, nil
	}
	c := &nodeClient{p: p, n: n, key: key, http: &http.Client{Transport: p.transport(n), CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
	p.clients[n.ID] = c
	return c, nil
}

func (c *nodeClient) request(ctx context.Context, method, path string, body []byte, auth bool) (*http.Response, error) {
	var r io.Reader
	if body != nil {
		r = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimSuffix(c.n.URL, "/")+path, r)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("User-Agent", "VeylControl")
	if auth {
		req.Header.Set("Authorization", "Bearer "+c.key)
	}
	return c.http.Do(req)
}

func (c *nodeClient) getJSON(ctx context.Context, path string, auth bool, out any) error {
	ctx, cancel := context.WithTimeout(ctx, nodeTimeout)
	defer cancel()
	res, err := c.request(ctx, http.MethodGet, path, nil, auth)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode == http.StatusUnauthorized && auth {
		return errNodeAuth
	}
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("node answered %d", res.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(res.Body, maxNodeBody)).Decode(out)
}

func (c *nodeClient) postJSON(ctx context.Context, path string, in, out any) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, nodeTimeout)
	defer cancel()
	b, _ := json.Marshal(in)
	res, err := c.request(ctx, http.MethodPost, path, b, true)
	if err != nil {
		return 0, err
	}
	defer res.Body.Close()
	if out != nil {
		_ = json.NewDecoder(io.LimitReader(res.Body, maxNodeBody)).Decode(out)
	}
	return res.StatusCode, nil
}

func (c *nodeClient) health(ctx context.Context) error {
	var out map[string]string
	if err := c.getJSON(ctx, "/v1/health", false, &out); err != nil {
		return err
	}
	if out["status"] != "ok" {
		return errors.New("unhealthy")
	}
	return nil
}

func normalizePin(s string) string {
	s = strings.ToLower(strings.NewReplacer(":", "", " ", "").Replace(strings.TrimSpace(s)))
	if len(s) != pinHexLength {
		return ""
	}
	if _, err := hex.DecodeString(s); err != nil {
		return ""
	}
	return s
}

func (p *Panel) probeFingerprint(ctx context.Context, n Node) string {
	dial := p.opt.Dial
	if dial == nil {
		var d net.Dialer
		dial = d.DialContext
	}
	u, err := url.Parse(n.URL)
	if err != nil {
		return ""
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	addr := net.JoinHostPort(u.Hostname(), port)
	if n.Local {
		addr = net.JoinHostPort("127.0.0.1", port)
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	raw, err := dial(ctx, "tcp", addr)
	if err != nil {
		return ""
	}
	defer raw.Close()
	tc := tls.Client(raw, &tls.Config{ServerName: u.Hostname(), InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
	if err := tc.HandshakeContext(ctx); err != nil {
		return ""
	}
	certs := tc.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return ""
	}
	return spkiPin(certs[0])
}

type pairOut struct {
	Key      string `json:"key"`
	ID       string `json:"id"`
	Scope    string `json:"scope"`
	Name     string `json:"name"`
	Host     string `json:"host"`
	Version  string `json:"version"`
	Platform string `json:"platform"`
	Error    string `json:"error"`
}

func (p *Panel) pairNode(ctx context.Context, code, name, pin string, local bool) (Node, error) {
	nodeURL, err := panelkey.Decode(code)
	if err != nil {
		return Node{}, err
	}
	u, _ := url.Parse(nodeURL)
	n := Node{ID: randID(), URL: nodeURL, Host: u.Hostname(), Local: local, Added: p.now().Unix(), Heal: true}
	if pin != "" {
		n.Pin = normalizePin(pin)
		if n.Pin == "" {
			return Node{}, errors.New("fingerprint")
		}
	}
	dup := false
	count := 0
	p.db.View(func(d *data) {
		count = len(d.Nodes)
		for _, x := range d.Nodes {
			if x.URL == nodeURL {
				dup = true
			}
		}
	})
	if dup {
		return Node{}, errDuplicate
	}
	if count >= maxNodes {
		return Node{}, errors.New("too many nodes")
	}
	label := p.settings().Name
	if s := p.site(); s.Domain != "" {
		label += " (" + s.Domain + ")"
	}
	c := &nodeClient{p: p, n: n, http: &http.Client{Transport: p.transport(n), Timeout: 20 * time.Second}}
	var out pairOut
	status, err := c.postJSON(ctx, "/v1/admin/pair", map[string]string{"code": strings.TrimSpace(code), "name": label}, &out)
	if err != nil {
		var ce *tls.CertificateVerificationError
		if errors.As(err, &ce) || errors.Is(err, ErrUntrusted) || strings.Contains(err.Error(), "certificate") {
			fp := p.probeFingerprint(ctx, n)
			return Node{}, &UntrustedError{Fingerprint: fp}
		}
		return Node{}, fmt.Errorf("%w: %v", errUnreachable, err)
	}
	if status != http.StatusCreated || !panelkey.ValidSecret(out.Key) {
		if status == http.StatusTooManyRequests {
			return Node{}, errNodeBusy
		}
		return Node{}, panelkey.ErrCode
	}
	sealed, err := p.seal.Seal(out.Key, keyPurpose+n.ID)
	if err != nil {
		return Node{}, err
	}
	n.Key, n.KeyID, n.Scope, n.Platform = sealed, out.ID, out.Scope, out.Platform
	n.Name = panelkey.CleanName(name)
	if n.Name == "" {
		n.Name = panelkey.CleanName(out.Name)
	}
	if n.Name == "" {
		n.Name = n.Host
	}
	err = p.db.Update(func(d *data) error {
		d.Nodes = append(d.Nodes, n)
		return nil
	})
	if err == nil {
		go p.mon.probeOne(context.Background(), n)
	}
	return n, err
}

var (
	errDuplicate   = errors.New("node already paired")
	errUnreachable = errors.New("node unreachable")
	errNodeBusy    = errors.New("node throttled")
)

func (p *Panel) pairErr(w http.ResponseWriter, err error) bool {
	var ue *UntrustedError
	switch {
	case err == nil:
		return true
	case errors.As(err, &ue):
		web.JSON(w, http.StatusConflict, map[string]string{"code": "UNTRUSTED_CERT", "fingerprint": ue.Fingerprint, "error": "This node does not have a publicly trusted certificate. Check the fingerprint below against the node and confirm to pin it."})
	case errors.Is(err, errDuplicate):
		web.Error(w, http.StatusConflict, "DUPLICATE", "That node is already in your fleet.")
	case errors.Is(err, errUnreachable):
		web.Error(w, http.StatusBadGateway, "UNREACHABLE", "We could not reach that node. Check that its address works over https.")
	case errors.Is(err, errNodeBusy):
		web.Error(w, http.StatusTooManyRequests, "TOO_MANY_REQUESTS", "The node is limiting pairing attempts. Wait a few minutes.")
	case errors.Is(err, panelkey.ErrCode):
		web.Error(w, http.StatusBadRequest, "INVALID_CODE", "That pairing code is not valid or has expired. Create a new one on the node.")
	default:
		web.Error(w, http.StatusBadRequest, "BAD_REQUEST", "That did not work. Check the pairing code and try again.")
	}
	return false
}

func (p *Panel) addNode(w http.ResponseWriter, r *http.Request) {
	var in pairIn
	if !web.Decode(w, r, &in, bodyLimit) {
		return
	}
	n, err := p.pairNode(r.Context(), in.Code, in.Name, in.Pin, false)
	if !p.pairErr(w, err) {
		return
	}
	p.audit(current(r).User.Username, "node.pair", n.Name, n.Host)
	web.JSON(w, http.StatusCreated, map[string]any{"node": map[string]string{"id": n.ID, "name": n.Name, "host": n.Host}})
}

type nodePatch struct {
	Name *string `json:"name"`
	Heal *bool   `json:"heal"`
}

func (p *Panel) patchNode(w http.ResponseWriter, r *http.Request) {
	var in nodePatch
	if !web.Decode(w, r, &in, bodyLimit) {
		return
	}
	id := r.PathValue("id")
	name := ""
	err := p.db.Update(func(d *data) error {
		n := d.node(id)
		if n == nil {
			return errNoNode
		}
		if in.Name != nil {
			if v := panelkey.CleanName(*in.Name); v != "" {
				n.Name = v
			}
		}
		if in.Heal != nil {
			n.Heal = *in.Heal
		}
		name = n.Name
		return nil
	})
	if err != nil {
		web.Error(w, http.StatusNotFound, "NOT_FOUND", "That node is no longer in your fleet.")
		return
	}
	p.audit(current(r).User.Username, "node.update", name, "")
	web.JSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (p *Panel) deleteNode(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var n Node
	err := p.db.Update(func(d *data) error {
		x := d.node(id)
		if x == nil {
			return errNoNode
		}
		n = *x
		keep := d.Nodes[:0]
		for _, y := range d.Nodes {
			if y.ID != id {
				keep = append(keep, y)
			}
		}
		d.Nodes = keep
		delete(d.Uptime, id)
		return nil
	})
	if err != nil {
		web.Error(w, http.StatusNotFound, "NOT_FOUND", "That node is no longer in your fleet.")
		return
	}
	revoked := false
	if c, err := p.client(n); err == nil {
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		if res, err := c.request(ctx, http.MethodDelete, "/v1/admin/panel/key", nil, true); err == nil {
			revoked = res.StatusCode == http.StatusOK
			res.Body.Close()
		}
		cancel()
	}
	p.mu.Lock()
	delete(p.clients, id)
	p.mu.Unlock()
	p.mon.forget(id)
	p.audit(current(r).User.Username, "node.remove", n.Name, n.Host)
	web.JSON(w, http.StatusOK, map[string]bool{"ok": true, "key_revoked": revoked})
}

func (p *Panel) nodes() []Node {
	var out []Node
	p.db.View(func(d *data) { out = append(out, d.Nodes...) })
	sort.SliceStable(out, func(i, j int) bool { return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name) })
	return out
}

func (p *Panel) nodeByID(id string) (Node, bool) {
	var n Node
	ok := false
	p.db.View(func(d *data) {
		if x := d.node(id); x != nil {
			n, ok = *x, true
		}
	})
	return n, ok
}
