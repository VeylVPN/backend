package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/mail"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

const SchemaVersion = 1

const (
	TLSACME     = "acme"
	TLSInternal = "internal"

	RegClosed = "closed"
	RegInvite = "invite"
	RegOpen   = "open"

	UpRecursive  = "recursive"
	UpQuad9      = "quad9"
	UpCloudflare = "cloudflare"
	UpMullvad    = "mullvad"
)

type DNS struct {
	Default  []string `json:"default"`
	Upstream string   `json:"upstream"`
}

type Settings struct {
	Version      int    `json:"version"`
	Configured   bool   `json:"configured"`
	Name         string `json:"name"`
	Host         string `json:"host"`
	TLS          string `json:"tls"`
	ACMEEmail    string `json:"acme_email"`
	UDPPort      int    `json:"udp_port"`
	Stealth      bool   `json:"stealth"`
	IPv6         bool   `json:"ipv6"`
	PostQuantum  bool   `json:"post_quantum"`
	Registration string `json:"registration"`
	DeviceLimit  int    `json:"device_limit"`
	DNS          DNS    `json:"dns"`
	AdminVPNOnly bool   `json:"admin_vpn_only"`
	AutoUpdates  bool   `json:"auto_updates"`
	AppURL       string `json:"app_url"`
}

func Defaults() Settings {
	return Settings{
		Version:      SchemaVersion,
		Name:         "Veyl",
		TLS:          TLSACME,
		UDPPort:      1194,
		Stealth:      true,
		IPv6:         true,
		PostQuantum:  true,
		Registration: RegInvite,
		DeviceLimit:  5,
		DNS:          DNS{Default: []string{CatAds, CatTrackers, CatMalware}, Upstream: UpRecursive},
		AutoUpdates:  true,
		AppURL:       "https://github.com/VeylVPN/frontend/releases/latest",
	}
}

var (
	ErrHost     = errors.New("host must be a domain name or a public IP address")
	ErrName     = errors.New("name must be 1 to 40 printable characters")
	ErrPort     = errors.New("udp port must be between 1024 and 65535 and not 8080 or 8443")
	ErrTLS      = errors.New("tls must be acme or internal")
	ErrEmail    = errors.New("invalid email address")
	ErrReg      = errors.New("registration must be closed, invite or open")
	ErrLimit    = errors.New("device limit must be between 1 and 20")
	ErrCategory = errors.New("unknown dns blocking category")
	ErrUpstream = errors.New("unknown dns upstream")
	ErrAppURL   = errors.New("app url must be an https url")
)

var domainRE = regexp.MustCompile(`^(?i)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*\.[a-z]{2,63}$`)

var appURLRE = regexp.MustCompile(`^https://[A-Za-z0-9.-]+(?::[0-9]{1,5})?(?:/[A-Za-z0-9._~%/+-]*)?$`)

func ValidHost(h string) bool {
	if h == "" || len(h) > 253 || strings.ContainsAny(h, " \t\r\n\"'\\#;") {
		return false
	}
	if ip := net.ParseIP(h); ip != nil {
		return ip.IsGlobalUnicast() && !ip.IsPrivate()
	}
	return domainRE.MatchString(h)
}

func IsIP(h string) bool {
	return net.ParseIP(h) != nil
}

func ValidName(n string) bool {
	c := utf8.RuneCountInString(n)
	if c < 1 || c > 40 || !utf8.ValidString(n) || strings.TrimSpace(n) != n {
		return false
	}
	for _, r := range n {
		if unicode.IsControl(r) || r == '<' || r == '>' {
			return false
		}
	}
	return true
}

func ValidEmail(e string) bool {
	if e == "" {
		return true
	}
	if len(e) > 254 || strings.ContainsAny(e, " \t\r\n\"'\\;{}<>") {
		return false
	}
	a, err := mail.ParseAddress(e)
	return err == nil && a.Address == e
}

func ValidPort(p int) bool {
	return p >= 1024 && p <= 65535 && p != 8080 && p != 8443
}

func (s Settings) Validate() error {
	if !ValidName(s.Name) {
		return ErrName
	}
	if s.Host != "" && !ValidHost(s.Host) {
		return ErrHost
	}
	if s.Configured && s.Host == "" {
		return ErrHost
	}
	if s.TLS != TLSACME && s.TLS != TLSInternal {
		return ErrTLS
	}
	if s.TLS == TLSACME && s.Host != "" && IsIP(s.Host) {
		return fmt.Errorf("%w: automatic certificates need a domain", ErrTLS)
	}
	if !ValidEmail(s.ACMEEmail) {
		return ErrEmail
	}
	if !ValidPort(s.UDPPort) {
		return ErrPort
	}
	switch s.Registration {
	case RegClosed, RegInvite, RegOpen:
	default:
		return ErrReg
	}
	if s.DeviceLimit < 1 || s.DeviceLimit > 20 {
		return ErrLimit
	}
	if !ValidCategories(s.DNS.Default) {
		return ErrCategory
	}
	switch s.DNS.Upstream {
	case UpRecursive, UpQuad9, UpCloudflare, UpMullvad:
	default:
		return ErrUpstream
	}
	if s.AppURL != "" && !appURLRE.MatchString(s.AppURL) {
		return ErrAppURL
	}
	return nil
}

func Load(path string) (Settings, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return Defaults(), nil
	}
	if err != nil {
		return Settings{}, err
	}
	s := Defaults()
	if err := json.Unmarshal(b, &s); err != nil {
		return Settings{}, err
	}
	if s.Version == 0 {
		s.Version = SchemaVersion
	}
	if err := s.Validate(); err != nil {
		return Settings{}, err
	}
	return s, nil
}

func Save(path string, s Settings) error {
	s.Version = SchemaVersion
	if err := s.Validate(); err != nil {
		return err
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
