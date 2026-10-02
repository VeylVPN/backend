package panel

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/veylvpn/backend/internal/panelcfg"
	"github.com/veylvpn/backend/internal/records"
	"github.com/veylvpn/backend/internal/web"
)

type cachedReport struct {
	at  time.Time
	rep records.Report
}

func (p *Panel) check(ctx context.Context, t records.Target, maxAge time.Duration) records.Report {
	key := t.Role + "|" + t.Host + "|" + strings.Join(t.IPv4, ",") + "|" + strings.Join(t.IPv6, ",")
	p.recMu.Lock()
	c, ok := p.recCache[key]
	p.recMu.Unlock()
	if ok && p.now().Sub(c.at) < maxAge {
		return c.rep
	}
	cctx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	rep := p.opt.Checker.Check(cctx, t)
	p.recMu.Lock()
	if len(p.recCache) > 256 {
		p.recCache = map[string]cachedReport{}
	}
	p.recCache[key] = cachedReport{at: p.now(), rep: rep}
	p.recMu.Unlock()
	return rep
}

func (p *Panel) serveRecords(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	host := strings.ToLower(strings.TrimSpace(q.Get("host")))
	role := q.Get("role")
	if role != records.RoleNode {
		role = records.RolePanel
	}
	if !panelcfg.ValidDomain(host) {
		web.Error(w, http.StatusBadRequest, "BAD_DOMAIN", "Use a domain name like control.example.com.")
		return
	}
	t := records.Target{Host: host, Role: role}
	if role == records.RolePanel {
		t.IPv4, t.IPv6 = p.publicIPs(r)
	} else {
		t.IPv4, t.IPv6 = p.nodeIPs(host)
	}
	web.JSON(w, http.StatusOK, p.check(r.Context(), t, 4*time.Second))
}

func (p *Panel) recordCheck(w http.ResponseWriter, r *http.Request) {
	p.serveRecords(w, r)
}

func (p *Panel) nodeIPs(host string) ([]string, []string) {
	for _, n := range p.nodes() {
		if !strings.EqualFold(n.Host, host) {
			continue
		}
		st := p.mon.snapshot(n.ID)
		if st.Overview == nil {
			continue
		}
		var v4, v6 []string
		if ip := st.Overview.System["public_ip"]; panelcfg.ValidPublicIP(ip) {
			v4 = append(v4, ip)
		}
		if ip := st.Overview.System["public_ipv6"]; panelcfg.ValidPublicIP(ip) {
			v6 = append(v6, ip)
		}
		return v4, v6
	}
	return nil, nil
}

type domainOut struct {
	Host       string          `json:"host"`
	Role       string          `json:"role"`
	NodeID     string          `json:"node_id,omitempty"`
	NodeName   string          `json:"node_name,omitempty"`
	CertExpiry string          `json:"cert_expiry,omitempty"`
	Issuer     string          `json:"issuer"`
	Report     *records.Report `json:"report,omitempty"`
}

func (p *Panel) domains(w http.ResponseWriter, r *http.Request) {
	s := p.site()
	st := p.agentStatus(r.Context(), false)
	var out []domainOut
	if s.Domain != "" {
		v4, v6 := p.publicIPs(r)
		rep := p.check(r.Context(), records.Target{Host: s.Domain, Role: records.RolePanel, IPv4: v4, IPv6: v6}, 60*time.Second)
		issuer := "Let's Encrypt through certbot"
		if s.Mode == panelcfg.ModeCaddy {
			issuer = "Let's Encrypt through Caddy"
		}
		out = append(out, domainOut{Host: s.Domain, Role: records.RolePanel, CertExpiry: st["cert_expiry"], Issuer: issuer, Report: &rep})
	}
	for _, n := range p.nodes() {
		if !panelcfg.ValidDomain(n.Host) {
			out = append(out, domainOut{Host: n.Host, Role: records.RoleNode, NodeID: n.ID, NodeName: n.Name, Issuer: "Self-signed by the node"})
			continue
		}
		d := domainOut{Host: n.Host, Role: records.RoleNode, NodeID: n.ID, NodeName: n.Name, Issuer: "Let's Encrypt through Caddy"}
		if snap := p.mon.snapshot(n.ID); snap.Overview != nil {
			d.CertExpiry = snap.Overview.CertExpiry
		}
		v4, v6 := p.nodeIPs(n.Host)
		rep := p.check(r.Context(), records.Target{Host: n.Host, Role: records.RoleNode, IPv4: v4, IPv6: v6}, 5*time.Minute)
		d.Report = &rep
		out = append(out, d)
	}
	if out == nil {
		out = []domainOut{}
	}
	j := map[string]any{"running": false}
	if jj := p.job("renew"); jj != nil {
		_, done, o := jj.State()
		j = map[string]any{"running": !done, "ok": o.OK, "error": o.Error}
	}
	web.JSON(w, http.StatusOK, map[string]any{"domains": out, "mode": s.Mode, "certbot": st["certbot"], "renew": j, "challenge": p.acme.Current()})
}

func (p *Panel) renew(w http.ResponseWriter, r *http.Request) {
	s := p.site()
	if s.Mode == panelcfg.ModeCaddy {
		web.Error(w, http.StatusConflict, "AUTOMATIC", "Caddy renews this certificate on its own.")
		return
	}
	if _, err := p.startJob("renew", agentRequest(panelcfg.OpRenew), nil); err != nil {
		web.Error(w, http.StatusConflict, "BUSY", "Another task is running. Try again in a moment.")
		return
	}
	p.audit(current(r).User.Username, "cert.renew", s.Domain, "")
	web.JSON(w, http.StatusAccepted, map[string]bool{"ok": true})
}
