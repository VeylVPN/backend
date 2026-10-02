package api

import (
	"testing"

	"github.com/veylvpn/backend/internal/config"
)

func TestInfoReportsPlatformAndStealthPort(t *testing.T) {
	e := setup(t, func(s *config.Settings) { s.Stealth = true })
	b := e.req(t, "GET", "/v1/info", nil).body
	if b["platform"] != "linux" || b["stealth_port"] != float64(443) {
		t.Fatal(b)
	}
	config.Platform = config.PlatformWindows
	defer func() { config.Platform = config.PlatformLinux }()
	b = e.req(t, "GET", "/v1/info", nil).body
	if b["platform"] != "windows" || b["stealth_port"] != float64(993) {
		t.Fatal(b)
	}
	off := setup(t, func(s *config.Settings) { s.Stealth = false })
	b = off.req(t, "GET", "/v1/info", nil).body
	if _, ok := b["stealth_port"]; ok || b["platform"] != "windows" {
		t.Fatal(b)
	}
}
