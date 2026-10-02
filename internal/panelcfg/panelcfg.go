package panelcfg

import (
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/veylvpn/backend/internal/config"
)

const (
	User        = "veyl-panel"
	Listen      = "127.0.0.1:8090"
	SetupPrefix = "/control"

	OpSite  = "site"
	OpCert  = "cert"
	OpRenew = "renew"

	ModeHTTP  = "http"
	ModeDNS   = "dns"
	ModeCaddy = "caddy"

	UnitPanel      = "veyl-panel.service"
	UnitPanelAgent = "veyl-panel-agent.service"
	UpdateUnit     = "veyl-panel-update"
	ImportGlob     = "/etc/caddy/veyl.d/*.caddy"
	SiteDir        = "/etc/caddy/veyl.d"
	SiteFile       = "/etc/caddy/veyl.d/panel.caddy"
	CertDir        = "/etc/caddy/veyl-panel"
	Webroot        = "/var/www/veyl-panel-acme"
	LetsEncryptDir = "/etc/letsencrypt"
	TmpfilesFile   = "/etc/tmpfiles.d/veyl-panel.conf"
)

var (
	ErrDomain = errors.New("invalid panel domain")
	ErrEmail  = errors.New("invalid email")
	ErrMode   = errors.New("invalid certificate mode")
	ErrIP     = errors.New("invalid public ip")
)

type Paths struct {
	Data string
	Run  string
}

func (p Paths) DB() string         { return filepath.Join(p.Data, "panel.json") }
func (p Paths) Secret() string     { return filepath.Join(p.Data, "secret.key") }
func (p Paths) Site() string       { return filepath.Join(p.Data, "site.json") }
func (p Paths) SetupToken() string { return filepath.Join(p.Data, "setup-token") }
func (p Paths) LocalPair() string  { return filepath.Join(p.Data, "local-pair") }
func (p Paths) AgentSock() string  { return filepath.Join(p.Run, "agent.sock") }
func (p Paths) ACMESock() string   { return filepath.Join(p.Run, "acme.sock") }

type Site struct {
	Domain     string `json:"domain"`
	Email      string `json:"email"`
	Mode       string `json:"mode"`
	PublicIP   string `json:"public_ip"`
	Configured bool   `json:"configured"`
	Staging    bool   `json:"staging,omitempty"`
}

var domainRE = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]([a-z0-9-]{0,61}[a-z0-9])?$`)

func ValidDomain(d string) bool {
	return len(d) <= 253 && domainRE.MatchString(d) && net.ParseIP(d) == nil
}

func ValidPublicIP(s string) bool {
	ip := net.ParseIP(s)
	return ip != nil && ip.String() == s && ip.IsGlobalUnicast() && !ip.IsPrivate()
}

func (s Site) Validate() error {
	if s.Domain != "" && !ValidDomain(s.Domain) {
		return ErrDomain
	}
	if !config.ValidEmail(s.Email) {
		return ErrEmail
	}
	switch s.Mode {
	case "", ModeHTTP, ModeDNS, ModeCaddy:
	default:
		return ErrMode
	}
	if s.PublicIP != "" && !ValidPublicIP(s.PublicIP) {
		return ErrIP
	}
	if s.Configured && (s.Domain == "" || s.Mode == "") {
		return ErrDomain
	}
	return nil
}

func LoadSite(path string) (Site, error) {
	var s Site
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return s, err
	}
	if len(b) > 16<<10 {
		return s, errors.New("site file too large")
	}
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil {
		return Site{}, err
	}
	return s, s.Validate()
}

func SaveSite(path string, s Site) error {
	if err := s.Validate(); err != nil {
		return err
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return WriteFile(path, b, 0o640)
}

func WriteFile(path string, b []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, mode); err != nil {
		return err
	}
	if err := os.Chmod(tmp, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func CertPaths(domain string) (string, string) {
	return filepath.Join(CertDir, domain+".crt"), filepath.Join(CertDir, domain+".key")
}

func ChallengeName(domain string) string {
	return "_acme-challenge." + strings.TrimPrefix(domain, "*.")
}

func DefaultPaths() Paths {
	return Paths{Data: DataDir, Run: RunDir}
}
