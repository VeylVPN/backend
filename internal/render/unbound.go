package render

import (
	"github.com/veylvpn/backend/internal/config"
)

type dotServer struct {
	addr string
	name string
	v6   bool
}

var upstreams = map[string][]dotServer{
	config.UpQuad9: {
		{"9.9.9.9", "dns.quad9.net", false},
		{"149.112.112.112", "dns.quad9.net", false},
		{"2620:fe::fe", "dns.quad9.net", true},
		{"2620:fe::9", "dns.quad9.net", true},
	},
	config.UpCloudflare: {
		{"1.1.1.1", "cloudflare-dns.com", false},
		{"1.0.0.1", "cloudflare-dns.com", false},
		{"2606:4700:4700::1111", "cloudflare-dns.com", true},
		{"2606:4700:4700::1001", "cloudflare-dns.com", true},
	},
	config.UpMullvad: {
		{"194.242.2.2", "dns.mullvad.net", false},
		{"2a07:e340::2", "dns.mullvad.net", true},
	},
}

var privateRanges = []string{
	"10.0.0.0/8", "100.64.0.0/10", "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16",
	"fc00::/7", "fe80::/10", "::ffff:0:0/96",
}

func Unbound(s config.Settings, f Facts) (string, error) {
	return unbound(s, f.HasIPv6, nil)
}

func unbound(s config.Settings, v6 bool, win *winUnbound) (string, error) {
	if err := checkSettings(s); err != nil {
		return "", err
	}
	yes := func(b bool) string {
		if b {
			return "yes"
		}
		return "no"
	}
	var l lines
	l.add("server:")
	l.indent = "\t"
	if win != nil {
		win.head(&l)
	}
	l.add("interface: %s", "127.0.0.1@5335")
	l.add("access-control: 127.0.0.0/8 allow")
	l.add("do-ip4: yes")
	l.add("do-ip6: %s", yes(v6))
	l.add("prefer-ip6: no")
	l.add("do-udp: yes")
	l.add("do-tcp: yes")
	l.add("verbosity: 0")
	l.add("use-syslog: no")
	l.add("logfile: \"\"")
	l.add("log-queries: no")
	l.add("log-replies: no")
	l.add("log-servfail: no")
	l.add("log-local-actions: no")
	l.add("statistics-interval: 0")
	l.add("statistics-cumulative: no")
	l.add("extended-statistics: no")
	l.add("hide-identity: yes")
	l.add("hide-version: yes")
	l.add("hide-trustanchor: yes")
	l.add("qname-minimisation: yes")
	l.add("harden-glue: yes")
	l.add("harden-dnssec-stripped: yes")
	l.add("harden-below-nxdomain: yes")
	l.add("harden-large-queries: yes")
	l.add("harden-short-bufsize: yes")
	l.add("harden-algo-downgrade: no")
	l.add("use-caps-for-id: no")
	l.add("prefetch: yes")
	l.add("prefetch-key: yes")
	l.add("aggressive-nsec: yes")
	l.add("num-threads: 1")
	l.add("msg-cache-size: 16m")
	l.add("rrset-cache-size: 32m")
	l.add("key-cache-size: 8m")
	l.add("neg-cache-size: 4m")
	l.add("edns-buffer-size: 1232")
	l.add("minimal-responses: yes")
	l.add("rrset-roundrobin: yes")
	for _, r := range privateRanges {
		l.add("private-address: %s", r)
	}
	servers, dot := upstreams[s.DNS.Upstream]
	if dot && win == nil {
		l.add("tls-cert-bundle: \"%s\"", CertBundle)
	}
	if dot && win != nil {
		l.add("tls-win-cert: yes")
	}
	if dot {
		l.indent = ""
		l.blank()
		l.add("forward-zone:")
		l.indent = "\t"
		l.add("name: \".\"")
		l.add("forward-tls-upstream: yes")
		for _, sv := range servers {
			if sv.v6 && !v6 {
				continue
			}
			l.add("forward-addr: %s@853#%s", sv.addr, sv.name)
		}
	}
	return l.String(), nil
}
