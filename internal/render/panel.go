package render

import (
	"fmt"
	"path/filepath"

	"github.com/veylvpn/backend/internal/config"
	"github.com/veylvpn/backend/internal/panelcfg"
)

type PanelContext struct {
	NodePresent bool
	NodeSetup   bool
	Stealth     bool
	Issued      bool
}

const WinImportGlob = "C:/ProgramData/Veyl/caddy/veyl.d/*.caddy"

func caddyImport(l *lines, glob string) {
	l.blank()
	l.add("import %s", glob)
}

func PanelCaddyfile(email string) (string, error) {
	if !config.ValidEmail(email) {
		return "", fmt.Errorf("%w: email", ErrSettings)
	}
	var l lines
	l.add("{")
	l.indent = "\t"
	l.add("admin off")
	if email != "" {
		l.add("email %s", email)
	}
	caddyGlobalTail(&l)
	l.indent = ""
	l.add("}")
	caddyImport(&l, panelcfg.ImportGlob)
	return l.String(), nil
}

func panelProxy(l *lines, base string, https bool) {
	l.add("%sreverse_proxy %s {", base, panelcfg.Listen)
	if https {
		l.add("%s\theader_up X-Forwarded-Proto https", base)
	} else {
		l.add("%s\theader_up X-Forwarded-Proto http", base)
	}
	l.add("%s}", base)
}

func PanelSite(s panelcfg.Site, c PanelContext) (string, error) {
	if err := s.Validate(); err != nil {
		return "", fmt.Errorf("%w: %v", ErrSettings, err)
	}
	var l lines
	bind := func(base string) {
		if c.Stealth {
			l.add("%sbind 0.0.0.0 [::]", base)
		}
	}
	if !s.Configured && s.PublicIP != "" {
		ip := hostLiteral(s.PublicIP)
		for _, scheme := range []string{"http", "https"} {
			if l.b.Len() > 0 {
				l.blank()
			}
			l.add("%s://%s {", scheme, ip)
			if scheme == "http" {
				bind("\t")
			} else {
				l.add("\ttls internal")
			}
			l.add("\thandle %s/* {", panelcfg.SetupPrefix)
			l.add("\t\turi strip_prefix %s", panelcfg.SetupPrefix)
			panelProxy(&l, "\t\t", scheme == "https")
			l.add("\t}")
			l.add("\thandle {")
			if c.NodePresent && c.NodeSetup {
				l.add("\t\treverse_proxy %s", config.WebListen)
			} else {
				l.add("\t\tredir %s/setup 302", panelcfg.SetupPrefix)
			}
			l.add("\t}")
			l.add("}")
		}
	}
	if s.Domain != "" {
		if l.b.Len() > 0 {
			l.blank()
		}
		if s.Mode == panelcfg.ModeCaddy {
			l.add("%s {", s.Domain)
			if s.Email != "" {
				l.add("\ttls %s", s.Email)
			}
			l.add("\tencode zstd gzip")
			panelProxy(&l, "\t", true)
			l.add("}")
			return l.String(), nil
		}
		l.add("http://%s {", s.Domain)
		bind("\t")
		l.add("\thandle /.well-known/acme-challenge/* {")
		l.add("\t\troot * %s", panelcfg.Webroot)
		l.add("\t\tfile_server")
		l.add("\t}")
		l.add("\thandle {")
		if c.Issued {
			l.add("\t\tredir https://{host}{uri} 308")
		} else {
			panelProxy(&l, "\t\t", false)
		}
		l.add("\t}")
		l.add("}")
		if c.Issued {
			crt, key := panelcfg.CertPaths(s.Domain)
			l.blank()
			l.add("%s {", s.Domain)
			l.add("\ttls %s %s", crt, key)
			l.add("\tencode zstd gzip")
			panelProxy(&l, "\t", true)
			l.add("}")
		}
	}
	return l.String(), nil
}

const (
	PanelUnit      = panelcfg.UnitPanel
	PanelAgentUnit = panelcfg.UnitPanelAgent
)

func PanelUnits() []File {
	bin := config.BinPath
	data := panelcfg.DataDir
	run := panelcfg.RunDir
	files := []File{
		{Path: filepath.Join(UnitDir, PanelUnit), Data: unit(
			[]string{"[Unit]", "Description=Veyl Control", "After=network-online.target " + PanelAgentUnit, "Wants=network-online.target " + PanelAgentUnit, "StartLimitIntervalSec=0"},
			withSandbox("[Service]", "Type=notify", "NotifyAccess=main", "User="+panelcfg.User, "Group="+panelcfg.User,
				"ExecStart="+bin+" panel serve", "Restart=always", "RestartSec=2", "WatchdogSec=30", "TimeoutStartSec=60", "UMask=0007",
				"CapabilityBoundingSet=", "ReadWritePaths="+data+" "+run),
			[]string{"[Install]", "WantedBy=multi-user.target"},
		)},
		{Path: filepath.Join(UnitDir, PanelAgentUnit), Data: unit(
			[]string{"[Unit]", "Description=Veyl Control root agent", "After=network-online.target", "Wants=network-online.target", "StartLimitIntervalSec=0"},
			[]string{"[Service]", "Type=simple", "ExecStart=" + bin + " panel agent", "Restart=always", "RestartSec=2", "UMask=0022", "PrivateTmp=yes", "ProtectHome=yes"},
			[]string{"[Install]", "WantedBy=multi-user.target"},
		)},
		{Path: panelcfg.TmpfilesFile, Data: "d " + run + " 0770 root " + panelcfg.User + " -\n"},
	}
	for i := range files {
		files[i].Mode = 0o644
	}
	return files
}

const WinServicePanel = "VeylPanel"

func WinPanelService() WinService {
	return WinService{Name: WinServicePanel, Display: "Veyl Control", Desc: "Optional Veyl Control fleet panel on 127.0.0.1:8090.", Key: "veyl-panel", Args: []string{"panel", "serve"}, Virtual: true, Optional: true}
}
