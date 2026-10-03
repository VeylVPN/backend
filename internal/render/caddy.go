package render

import (
	"fmt"

	"github.com/veylvpn/backend/internal/config"
	"github.com/veylvpn/backend/internal/panelcfg"
)

func Caddyfile(s config.Settings, stealth bool) (string, error) {
	return caddyfile(s, stealth, panelcfg.ImportGlob)
}

func caddyfile(s config.Settings, stealth bool, glob string) (string, error) {
	if err := checkSettings(s); err != nil {
		return "", err
	}
	if s.Host == "" {
		return caddySetup(glob), nil
	}
	if !config.ValidHost(s.Host) {
		return "", fmt.Errorf("%w: host", ErrSettings)
	}
	if s.TLS == config.TLSACME && config.IsIP(s.Host) {
		return "", fmt.Errorf("%w: acme needs a domain", ErrSettings)
	}
	var l lines
	l.add("{")
	l.indent = "\t"
	l.add("admin off")
	if s.ACMEEmail != "" {
		l.add("email %s", s.ACMEEmail)
	}
	if stealth {
		l.add("https_port %d", config.CaddyTLSPort)
		l.add("default_bind 127.0.0.1")
	}
	l.add("auto_https disable_redirects")
	caddyGlobalTail(&l)
	l.indent = ""
	l.add("}")
	l.blank()
	{
		l.add("http:// {")
		l.indent = "\t"
		if stealth {
			l.add("bind 0.0.0.0 [::]")
		}
		if s.Configured {
			l.add("@setup path /setup /setup/* /v1/setup/* /assets/fonts/*")
			l.add("handle @setup {")
			l.indent = "\t\t"
			l.add("reverse_proxy %s", config.WebListen)
			l.indent = "\t"
			l.add("}")
			l.add("handle {")
			l.indent = "\t\t"
			l.add("redir https://{host}{uri} 308")
			l.indent = "\t"
			l.add("}")
		} else {
			l.add("reverse_proxy %s", config.WebListen)
		}
		l.indent = ""
		l.add("}")
		l.blank()
	}
	l.add("%s {", hostLiteral(s.Host))
	l.indent = "\t"
	if s.TLS == config.TLSInternal {
		l.add("tls internal")
	}
	l.add("encode zstd gzip")
	l.add("reverse_proxy %s {", config.WebListen)
	l.indent = "\t\t"
	l.add("header_up X-Forwarded-Proto https")
	l.indent = "\t"
	l.add("}")
	l.indent = ""
	l.add("}")
	caddyImport(&l, glob)
	return l.String(), nil
}

func caddyGlobalTail(l *lines) {
	l.add("log default {")
	l.indent = "\t\t"
	l.add("output discard")
	l.indent = "\t"
	l.add("}")
	l.add("servers {")
	l.indent = "\t\t"
	l.add("protocols h1 h2")
	l.indent = "\t"
	l.add("}")
}

func caddySetup(glob string) string {
	var l lines
	l.add("{")
	l.indent = "\t"
	l.add("admin off")
	l.add("auto_https off")
	caddyGlobalTail(&l)
	l.indent = ""
	l.add("}")
	l.blank()
	l.add(":80 {")
	l.indent = "\t"
	l.add("reverse_proxy %s", config.WebListen)
	l.indent = ""
	l.add("}")
	caddyImport(&l, glob)
	return l.String()
}
