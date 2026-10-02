package render

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/veylvpn/backend/internal/panelcfg"
)

func panelSite() panelcfg.Site {
	return panelcfg.Site{Domain: "control.example.com", Email: "ops@example.com", Mode: panelcfg.ModeHTTP, PublicIP: "203.0.113.7"}
}

func TestPanelSiteGolden(t *testing.T) {
	cases := []struct {
		name string
		site func(*panelcfg.Site)
		ctx  PanelContext
	}{
		{"panel-setup-only", func(s *panelcfg.Site) { s.Domain = ""; s.Mode = "" }, PanelContext{}},
		{"panel-setup-combined", func(s *panelcfg.Site) {}, PanelContext{NodePresent: true, NodeSetup: true, Stealth: true}},
		{"panel-issued", func(s *panelcfg.Site) { s.Configured = true }, PanelContext{Issued: true}},
		{"panel-issued-stealth", func(s *panelcfg.Site) { s.Configured = true; s.Mode = panelcfg.ModeDNS }, PanelContext{Issued: true, Stealth: true, NodePresent: true}},
		{"panel-caddy", func(s *panelcfg.Site) { s.Configured = true; s.Mode = panelcfg.ModeCaddy }, PanelContext{}},
	}
	for _, c := range cases {
		s := panelSite()
		c.site(&s)
		got, err := PanelSite(s, c.ctx)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		golden(t, c.name+".caddy", got)
	}
	main, err := PanelCaddyfile("ops@example.com")
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "Caddyfile-panel", main)
}

func TestPanelSiteRejects(t *testing.T) {
	bad := []panelcfg.Site{
		{Domain: "control.example.com\n}", Mode: panelcfg.ModeHTTP},
		{Domain: "control.example.com", Mode: "shell"},
		{Domain: "control.example.com", Email: "a b@example.com", Mode: panelcfg.ModeHTTP},
		{PublicIP: "10.0.0.1"},
		{PublicIP: "203.0.113.7 { }"},
		{Domain: "203.0.113.7", Mode: panelcfg.ModeHTTP},
	}
	for i, s := range bad {
		if _, err := PanelSite(s, PanelContext{}); err == nil {
			t.Errorf("case %d accepted", i)
		}
	}
	if _, err := PanelCaddyfile("x\n}"); err == nil {
		t.Error("email accepted")
	}
}

func TestPanelUnits(t *testing.T) {
	files := PanelUnits()
	if len(files) != 3 {
		t.Fatal(len(files))
	}
	for _, f := range files {
		golden(t, filepath.Base(f.Path), f.Data)
	}
	svc := files[0].Data
	for _, want := range []string{"Type=notify", "WatchdogSec=30", "Restart=always", "User=veyl-panel", "ExecStart=/usr/local/bin/veyl panel serve", "StartLimitIntervalSec=0", "NoNewPrivileges=yes"} {
		if !strings.Contains(svc, want) {
			t.Errorf("missing %q", want)
		}
	}
}

func TestPanelCaddyAdapts(t *testing.T) {
	caddy, err := exec.LookPath("caddy")
	if err != nil {
		t.Skip("caddy not installed")
	}
	dir := t.TempDir()
	certs := filepath.Join(dir, "certs")
	if err := os.MkdirAll(filepath.Join(dir, "veyl.d"), 0o755); err != nil {
		t.Fatal(err)
	}
	node, err := Caddyfile(settings(), true)
	if err != nil {
		t.Fatal(err)
	}
	s := panelSite()
	site, err := PanelSite(s, PanelContext{NodePresent: true, Stealth: true})
	if err != nil {
		t.Fatal(err)
	}
	s.Configured = true
	issued, err := PanelSite(s, PanelContext{NodePresent: true, Stealth: true, Issued: true})
	if err != nil {
		t.Fatal(err)
	}
	only, err := PanelCaddyfile("ops@example.com")
	if err != nil {
		t.Fatal(err)
	}
	fix := func(s string) string {
		s = strings.ReplaceAll(s, panelcfg.ImportGlob, filepath.Join(dir, "veyl.d", "*.caddy"))
		return strings.ReplaceAll(s, panelcfg.CertDir, certs)
	}
	for name, pair := range map[string][2]string{
		"node-empty":    {node, ""},
		"node-setup":    {node, site},
		"node-issued":   {node, issued},
		"panel-only":    {only, site},
		"panel-only-ok": {only, issued},
	} {
		main := filepath.Join(dir, "Caddyfile")
		if err := os.WriteFile(main, []byte(fix(pair[0])), 0o644); err != nil {
			t.Fatal(err)
		}
		_ = os.Remove(filepath.Join(dir, "veyl.d", "panel.caddy"))
		if pair[1] != "" {
			if err := os.WriteFile(filepath.Join(dir, "veyl.d", "panel.caddy"), []byte(fix(pair[1])), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		out, err := exec.Command(caddy, "adapt", "--config", main, "--adapter", "caddyfile").CombinedOutput()
		if err != nil {
			t.Errorf("%s: %v\n%s", name, err, out)
		}
	}
}
