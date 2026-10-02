package records

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

var DefaultResolvers = []string{"1.1.1.1:53", "8.8.8.8:53", "9.9.9.9:53"}

const (
	RoleNode  = "node"
	RolePanel = "panel"

	StatusOK          = "ok"
	StatusPropagating = "propagating"
	StatusMissing     = "missing"
	StatusWrong       = "wrong"
	StatusProxied     = "proxied"
	StatusError       = "error"

	LetsEncrypt  = "letsencrypt.org"
	SuggestedTTL = 300
	maxNS        = 8
)

type Checker struct {
	Client    *Client
	Resolvers []string
	AuthPort  string
}

func (c *Checker) resolvers() []string {
	if len(c.Resolvers) == 0 {
		return DefaultResolvers
	}
	return c.Resolvers
}

func (c *Checker) authPort() string {
	if c.AuthPort == "" {
		return "53"
	}
	return c.AuthPort
}

type Target struct {
	Host string   `json:"host"`
	Role string   `json:"role"`
	IPv4 []string `json:"ipv4"`
	IPv6 []string `json:"ipv6"`
}

type View struct {
	Server string   `json:"server"`
	Label  string   `json:"label"`
	Auth   bool     `json:"authoritative"`
	A      []string `json:"a"`
	AAAA   []string `json:"aaaa"`
	CNAME  []string `json:"cname,omitempty"`
	TTL    uint32   `json:"ttl"`
	Status string   `json:"status"`
	Error  string   `json:"error,omitempty"`
}

type Record struct {
	Name   string `json:"name"`
	Host   string `json:"host"`
	Type   string `json:"type"`
	Value  string `json:"value"`
	TTL    int    `json:"ttl"`
	Line   string `json:"line"`
	Action string `json:"action"`
}

type Finding struct {
	Level string `json:"level"`
	Text  string `json:"text"`
}

type CAAResult struct {
	Domain   string   `json:"domain,omitempty"`
	Records  []string `json:"records"`
	AllowsLE bool     `json:"allows_letsencrypt"`
	Checked  bool     `json:"checked"`
}

type Report struct {
	Host       string    `json:"host"`
	Role       string    `json:"role"`
	Zone       string    `json:"zone,omitempty"`
	Status     string    `json:"status"`
	Summary    string    `json:"summary"`
	Expected4  []string  `json:"expected_ipv4"`
	Expected6  []string  `json:"expected_ipv6"`
	Public     []View    `json:"public"`
	Auth       []View    `json:"authoritative"`
	CAA        CAAResult `json:"caa"`
	Cloudflare bool      `json:"cloudflare"`
	TTL        uint32    `json:"ttl"`
	Findings   []Finding `json:"findings"`
	Records    []Record  `json:"records"`
	Checked    time.Time `json:"checked"`
}

func normIPs(in []string, v4 bool) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		ip := net.ParseIP(strings.TrimSpace(s))
		if ip == nil || (ip.To4() != nil) != v4 {
			continue
		}
		k := ip.String()
		if !seen[k] {
			seen[k] = true
			out = append(out, k)
		}
	}
	sort.Strings(out)
	if out == nil {
		out = []string{}
	}
	return out
}

func ipStrings(rrs []RR) []string {
	var out []string
	for _, rr := range rrs {
		out = append(out, rr.IP.String())
	}
	sort.Strings(out)
	if out == nil {
		out = []string{}
	}
	return out
}

func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func (c *Checker) view(ctx context.Context, server, label, host string, auth bool, t Target) View {
	v := View{Server: server, Label: label, Auth: auth, A: []string{}, AAAA: []string{}}
	a, errA := c.Client.Lookup(ctx, server, host, TypeA, !auth)
	q, err6 := c.Client.Lookup(ctx, server, host, TypeAAAA, !auth)
	v.A = ipStrings(a.Records)
	v.AAAA = ipStrings(q.Records)
	v.CNAME = a.CNAMEs
	v.TTL = a.TTL
	if q.TTL > 0 && (v.TTL == 0 || q.TTL < v.TTL) {
		v.TTL = q.TTL
	}
	switch {
	case errA != nil && !errors.Is(errA, ErrNXDomain):
		v.Status = StatusError
		v.Error = shortErr(errA)
		return v
	case errors.Is(errA, ErrNXDomain) || len(v.A) == 0 && len(v.AAAA) == 0:
		v.Status = StatusMissing
		_ = err6
		return v
	}
	for _, ip := range append(append([]string{}, v.A...), v.AAAA...) {
		if IsCloudflare(ip) {
			v.Status = StatusProxied
			return v
		}
	}
	ok4 := sameSet(v.A, t.IPv4) || len(t.IPv4) == 0 && len(v.A) == 0
	ok6 := len(v.AAAA) == 0 || sameSet(v.AAAA, t.IPv6)
	if ok4 && ok6 {
		v.Status = StatusOK
	} else {
		v.Status = StatusWrong
	}
	return v
}

func shortErr(err error) string {
	var ne net.Error
	switch {
	case errors.As(err, &ne) && ne.Timeout():
		return "no answer (timeout)"
	case errors.Is(err, ErrServer):
		return "server refused or failed"
	case errors.Is(err, ErrFormat):
		return "malformed answer"
	}
	s := err.Error()
	if len(s) > 120 {
		s = s[:120]
	}
	return s
}

type nameserver struct {
	host string
	addr string
}

func (c *Checker) firstAnswer(ctx context.Context, name string, qtype uint16) (Answer, error) {
	var last error = ErrServer
	for _, r := range c.resolvers() {
		a, err := c.Client.Lookup(ctx, r, name, qtype, true)
		if err == nil || errors.Is(err, ErrNXDomain) {
			return a, err
		}
		last = err
	}
	return Answer{}, last
}

func (c *Checker) Zone(ctx context.Context, host string) (string, []string, error) {
	n, err := CanonicalName(host)
	if err != nil {
		return "", nil, err
	}
	for cur := n; cur != "" && strings.Contains(cur, "."); cur = Parent(cur) {
		a, err := c.firstAnswer(ctx, cur, TypeNS)
		if err != nil && !errors.Is(err, ErrNXDomain) {
			return "", nil, err
		}
		var hosts []string
		for _, rr := range a.Records {
			if rr.Name == cur && len(a.CNAMEs) == 0 {
				hosts = append(hosts, rr.Target)
			}
		}
		if len(hosts) > 0 {
			sort.Strings(hosts)
			if len(hosts) > maxNS {
				hosts = hosts[:maxNS]
			}
			return cur, hosts, nil
		}
	}
	return "", nil, errors.New("no nameservers found")
}

func (c *Checker) nameservers(ctx context.Context, hosts []string) []nameserver {
	var mu sync.Mutex
	var wg sync.WaitGroup
	var out []nameserver
	for _, h := range hosts {
		wg.Add(1)
		go func(h string) {
			defer wg.Done()
			a, err := c.firstAnswer(ctx, h, TypeA)
			if err != nil || len(a.Records) == 0 {
				a, err = c.firstAnswer(ctx, h, TypeAAAA)
				if err != nil || len(a.Records) == 0 {
					return
				}
			}
			mu.Lock()
			out = append(out, nameserver{host: h, addr: net.JoinHostPort(a.Records[0].IP.String(), c.authPort())})
			mu.Unlock()
		}(h)
	}
	wg.Wait()
	sort.Slice(out, func(i, j int) bool { return out[i].host < out[j].host })
	return out
}

func relative(name, zone string) string {
	if name == zone || zone == "" {
		return "@"
	}
	return strings.TrimSuffix(name, "."+zone)
}

func record(name, zone, typ, value, action string) Record {
	v := value
	if typ == "TXT" {
		v = strconv.Quote(value)
	}
	return Record{Name: name, Host: relative(name, zone), Type: typ, Value: value, TTL: SuggestedTTL, Action: action,
		Line: fmt.Sprintf("%s. %d IN %s %s", name, SuggestedTTL, typ, v)}
}

func (c *Checker) Check(ctx context.Context, t Target) Report {
	host, err := CanonicalName(t.Host)
	r := Report{Host: host, Role: t.Role, Expected4: normIPs(t.IPv4, true), Expected6: normIPs(t.IPv6, false), Public: []View{}, Auth: []View{}, Findings: []Finding{}, Records: []Record{}, Checked: time.Now().UTC()}
	if err != nil || host == "." || !strings.Contains(host, ".") {
		r.Status = StatusError
		r.Summary = "That does not look like a domain name."
		return r
	}
	r.Host = host
	t.IPv4, t.IPv6 = r.Expected4, r.Expected6
	var wg sync.WaitGroup
	var mu sync.Mutex
	for i, srv := range c.resolvers() {
		wg.Add(1)
		go func(i int, srv string) {
			defer wg.Done()
			v := c.view(ctx, srv, resolverLabel(srv), host, false, t)
			mu.Lock()
			r.Public = append(r.Public, v)
			mu.Unlock()
		}(i, srv)
	}
	var caa CAAResult
	wg.Add(1)
	go func() {
		defer wg.Done()
		caa = c.CAA(ctx, host)
	}()
	zone, hosts, zerr := c.Zone(ctx, host)
	r.Zone = zone
	if zerr == nil {
		for _, ns := range c.nameservers(ctx, hosts) {
			wg.Add(1)
			go func(ns nameserver) {
				defer wg.Done()
				v := c.view(ctx, ns.addr, ns.host, host, true, t)
				mu.Lock()
				r.Auth = append(r.Auth, v)
				mu.Unlock()
			}(ns)
		}
	}
	wg.Wait()
	sort.Slice(r.Public, func(i, j int) bool { return r.Public[i].Server < r.Public[j].Server })
	sort.Slice(r.Auth, func(i, j int) bool { return r.Auth[i].Label < r.Auth[j].Label })
	r.CAA = caa
	evaluate(&r, zerr)
	return r
}

func resolverLabel(s string) string {
	switch s {
	case "1.1.1.1:53":
		return "Cloudflare 1.1.1.1"
	case "8.8.8.8:53":
		return "Google 8.8.8.8"
	case "9.9.9.9:53":
		return "Quad9 9.9.9.9"
	}
	return s
}

func count(vs []View, status string) int {
	n := 0
	for _, v := range vs {
		if v.Status == status {
			n++
		}
	}
	return n
}

func evaluate(r *Report, zerr error) {
	add := func(level, format string, a ...any) {
		r.Findings = append(r.Findings, Finding{Level: level, Text: fmt.Sprintf(format, a...)})
	}
	all := append(append([]View{}, r.Auth...), r.Public...)
	for _, v := range all {
		if v.Status == StatusProxied {
			r.Cloudflare = true
		}
		if v.TTL > r.TTL {
			r.TTL = v.TTL
		}
	}
	authOK := len(r.Auth) > 0 && count(r.Auth, StatusOK) == len(r.Auth)
	pubOK := len(r.Public) > 0 && count(r.Public, StatusOK) == len(r.Public)
	authAnswered := len(r.Auth) - count(r.Auth, StatusError)
	switch {
	case r.Cloudflare:
		r.Status = StatusProxied
		if r.Role == RoleNode {
			r.Summary = "This name goes through the Cloudflare proxy (orange cloud). VPN traffic is UDP and cannot pass through it."
			add("error", "In Cloudflare, switch the record for %s to DNS only (grey cloud).", r.Host)
		} else {
			r.Summary = "This name goes through the Cloudflare proxy (orange cloud), so we cannot confirm it reaches this server."
			add("warn", "Switch the record for %s to DNS only (grey cloud) while certificates are issued.", r.Host)
		}
	case authOK && pubOK:
		r.Status = StatusOK
		r.Summary = "Every nameserver and public resolver points this name at this server."
	case authOK:
		r.Status = StatusPropagating
		r.Summary = "Your nameservers have the right records. Public resolvers still have an old answer cached."
		add("info", "Caches expire within %s. Nothing else to do.", ttlText(r.TTL))
	case authAnswered == 0 && len(r.Public) > 0 && pubOK:
		r.Status = StatusOK
		r.Summary = "Public resolvers point this name at this server."
		if zerr != nil || len(r.Auth) == 0 {
			add("info", "We could not ask your nameservers directly, so propagation is based on public resolvers.")
		} else {
			add("warn", "Your nameservers did not answer us directly. Public resolvers look right.")
		}
	case authAnswered == 0 && count(r.Public, StatusError) == len(r.Public):
		r.Status = StatusError
		r.Summary = "We could not reach any DNS server. Check again in a moment."
	default:
		views := r.Auth
		if authAnswered == 0 {
			views = r.Public
		}
		if count(views, StatusMissing) == len(views)-count(views, StatusError) {
			r.Status = StatusMissing
			r.Summary = "This name has no address records yet."
		} else {
			r.Status = StatusWrong
			r.Summary = "This name points somewhere else."
			seen := map[string]bool{}
			for _, v := range views {
				for _, ip := range append(append([]string{}, v.A...), v.AAAA...) {
					if !contains(r.Expected4, ip) && !contains(r.Expected6, ip) && !seen[ip] {
						seen[ip] = true
						typ := "A"
						if strings.Contains(ip, ":") {
							typ = "AAAA"
						}
						r.Records = append(r.Records, record(r.Host, r.Zone, typ, ip, "remove"))
					}
				}
			}
		}
	}
	for _, v := range r.Auth {
		if v.Status == StatusError {
			add("warn", "Nameserver %s did not answer: %s.", v.Label, v.Error)
		}
	}
	if r.Status != StatusOK && r.Status != StatusPropagating {
		for _, ip := range r.Expected4 {
			r.Records = append(r.Records, record(r.Host, r.Zone, "A", ip, "add"))
		}
		for _, ip := range r.Expected6 {
			r.Records = append(r.Records, record(r.Host, r.Zone, "AAAA", ip, "add"))
		}
		if len(r.Expected4) == 0 && len(r.Expected6) == 0 {
			add("warn", "We do not know this server's public address yet, so we cannot say which records to add.")
		}
	}
	if r.TTL > 3600 {
		add("warn", "The TTL is %s. Lower it to %d seconds while you set things up so fixes show up fast.", ttlText(r.TTL), SuggestedTTL)
	}
	if r.CAA.Checked && !r.CAA.AllowsLE {
		add("error", "The CAA records on %s do not allow Let's Encrypt. Add the CAA record below.", r.CAA.Domain)
		r.Records = append(r.Records, record(r.CAA.Domain, r.Zone, "CAA", `0 issue "`+LetsEncrypt+`"`, "add"))
	}
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func ttlText(ttl uint32) string {
	switch {
	case ttl == 0:
		return "a few minutes"
	case ttl < 120:
		return strconv.Itoa(int(ttl)) + " seconds"
	case ttl < 7200:
		return strconv.Itoa(int(ttl/60)) + " minutes"
	}
	return strconv.Itoa(int(ttl/3600)) + " hours"
}

func caaAllows(rrs []RR, ca string) bool {
	hasIssue := false
	for _, rr := range rrs {
		if rr.CAA == nil {
			continue
		}
		if rr.CAA.Flags&0x80 != 0 && rr.CAA.Tag != "issue" && rr.CAA.Tag != "issuewild" && rr.CAA.Tag != "iodef" {
			return false
		}
		if rr.CAA.Tag != "issue" {
			continue
		}
		hasIssue = true
		dom, _, _ := strings.Cut(rr.CAA.Value, ";")
		if strings.EqualFold(strings.TrimSpace(dom), ca) {
			return true
		}
	}
	return !hasIssue
}

func (c *Checker) CAA(ctx context.Context, host string) CAAResult {
	res := CAAResult{AllowsLE: true, Records: []string{}}
	n, err := CanonicalName(host)
	if err != nil {
		return res
	}
	for cur := n; cur != "" && strings.Contains(cur, "."); cur = Parent(cur) {
		a, err := c.firstAnswer(ctx, cur, TypeCAA)
		if err != nil && !errors.Is(err, ErrNXDomain) {
			return res
		}
		if len(a.Records) == 0 {
			continue
		}
		res.Checked = true
		res.Domain = cur
		for _, rr := range a.Records {
			res.Records = append(res.Records, fmt.Sprintf("%d %s %q", rr.CAA.Flags, rr.CAA.Tag, rr.CAA.Value))
		}
		res.AllowsLE = caaAllows(a.Records, LetsEncrypt)
		return res
	}
	res.Checked = true
	return res
}

type TXTServer struct {
	Label   string `json:"label"`
	Visible bool   `json:"visible"`
	Error   string `json:"error,omitempty"`
}

type TXTReport struct {
	Name    string      `json:"name"`
	Value   string      `json:"value"`
	Zone    string      `json:"zone,omitempty"`
	Servers []TXTServer `json:"servers"`
	Visible bool        `json:"visible"`
	Record  Record      `json:"record"`
}

func (c *Checker) TXT(ctx context.Context, name, value string) TXTReport {
	n, err := CanonicalName(name)
	rep := TXTReport{Name: n, Value: value, Servers: []TXTServer{}}
	if err != nil {
		return rep
	}
	zone, hosts, zerr := c.Zone(ctx, n)
	rep.Zone = zone
	rep.Record = record(n, zone, "TXT", value, "add")
	if zerr != nil {
		return rep
	}
	nss := c.nameservers(ctx, hosts)
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, ns := range nss {
		wg.Add(1)
		go func(ns nameserver) {
			defer wg.Done()
			s := TXTServer{Label: ns.host}
			a, err := c.Client.Lookup(ctx, ns.addr, n, TypeTXT, false)
			if err != nil && !errors.Is(err, ErrNXDomain) {
				s.Error = shortErr(err)
			}
			for _, rr := range a.Records {
				if strings.Join(rr.TXT, "") == value {
					s.Visible = true
				}
			}
			mu.Lock()
			rep.Servers = append(rep.Servers, s)
			mu.Unlock()
		}(ns)
	}
	wg.Wait()
	sort.Slice(rep.Servers, func(i, j int) bool { return rep.Servers[i].Label < rep.Servers[j].Label })
	rep.Visible = len(rep.Servers) > 0
	for _, s := range rep.Servers {
		if !s.Visible {
			rep.Visible = false
		}
	}
	return rep
}

func (c *Checker) WaitTXT(ctx context.Context, name, value string, every time.Duration, progress func(TXTReport)) error {
	for {
		rep := c.TXT(ctx, name, value)
		if progress != nil {
			progress(rep)
		}
		if rep.Visible {
			return nil
		}
		t := time.NewTimer(every)
		select {
		case <-ctx.Done():
			t.Stop()
			return ctx.Err()
		case <-t.C:
		}
	}
}

var cloudflareNets = func() []*net.IPNet {
	var out []*net.IPNet
	for _, c := range []string{
		"173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
		"141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
		"197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
		"104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
		"2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32",
		"2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
	} {
		_, n, err := net.ParseCIDR(c)
		if err == nil {
			out = append(out, n)
		}
	}
	return out
}()

func IsCloudflare(s string) bool {
	ip := net.ParseIP(s)
	if ip == nil {
		return false
	}
	for _, n := range cloudflareNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}
