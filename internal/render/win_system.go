package render

import (
	"fmt"
	"strings"

	"github.com/veylvpn/backend/internal/config"
	"github.com/veylvpn/backend/internal/winacl"
	"github.com/veylvpn/backend/internal/winps"
)

const LocalSystem = "LocalSystem"

type WinService struct {
	Name     string
	Display  string
	Desc     string
	Key      string
	Args     []string
	Virtual  bool
	Optional bool
}

func (w WinService) Account() string {
	if !w.Virtual {
		return LocalSystem
	}
	return `NT SERVICE\` + w.Name
}

func (w WinService) SID() (string, error) {
	if !w.Virtual {
		return winacl.SIDSystem, nil
	}
	return winacl.ServiceSID(w.Name)
}

func winArg(a string) (string, error) {
	if a == "" || strings.ContainsAny(a, "\"\r\n\x00") {
		return "", fmt.Errorf("%w: unsafe service argument", ErrSettings)
	}
	if strings.ContainsAny(a, " \t") {
		if strings.HasSuffix(a, `\`) {
			return "", fmt.Errorf("%w: unsafe service argument", ErrSettings)
		}
		return "\"" + a + "\"", nil
	}
	return a, nil
}

func (w WinService) BinPath() (string, error) {
	parts := []string{"\"" + config.WinBinPath + "\"", "service"}
	for _, a := range w.Args {
		q, err := winArg(a)
		if err != nil {
			return "", err
		}
		parts = append(parts, q)
	}
	return strings.Join(parts, " "), nil
}

func WinServices() []WinService {
	p := config.WindowsPaths()
	return []WinService{
		{Name: config.WinServiceVeyl, Display: "Veyl server", Desc: "Veyl API, admin panel, setup page and connection hook.", Key: "veyl", Args: []string{"serve"}, Virtual: true},
		{Name: config.WinServiceAgent, Display: "Veyl agent", Desc: "Applies fixed, validated Veyl system changes.", Key: "veyl-agent", Args: []string{"agent"}},
		{Name: config.WinServiceDNS, Display: "Veyl DNS filter", Desc: "Content blocking DNS for VPN clients.", Key: "veyl-dns", Args: []string{"dns", "-blocklists", p.Blocklists(), "-upstream", config.UnboundAddr}, Virtual: true},
		{Name: config.WinServiceUDP, Display: "Veyl VPN (UDP)", Desc: "Runs OpenVPN for Veyl over UDP.", Key: "openvpn-server@veyl-udp", Args: []string{"supervise", "openvpn-udp"}},
		{Name: config.WinServiceTCP, Display: "Veyl VPN (TCP fallback)", Desc: "Runs OpenVPN for Veyl over TCP for networks that block UDP.", Key: "openvpn-server@veyl-tcp", Args: []string{"supervise", "openvpn-tcp"}, Optional: true},
		{Name: config.WinServiceUnbnd, Display: "Veyl resolver", Desc: "Unbound DNS resolver for Veyl on 127.0.0.1:5335.", Key: "unbound", Args: []string{"supervise", "unbound"}, Virtual: true},
		{Name: config.WinServiceCaddy, Display: "Veyl web", Desc: "Caddy HTTPS front for Veyl.", Key: "caddy", Args: []string{"supervise", "caddy"}, Virtual: true},
	}
}

func FindWinService(name string) (WinService, bool) {
	for _, s := range WinServices() {
		if s.Name == name {
			return s, true
		}
	}
	return WinService{}, false
}

func WinFirewallScript(s config.Settings) (string, error) {
	if err := checkSettings(s); err != nil {
		return "", err
	}
	if !config.ValidStealthPort(config.PlatformWindows, s.StealthPort) {
		return "", fmt.Errorf("%w: stealth port", ErrSettings)
	}
	g := winps.S(config.FirewallGroup)
	var sc winps.Script
	sc.Add("Get-NetFirewallRule -Group %s -ErrorAction SilentlyContinue | Remove-NetFirewallRule", g)
	rule := func(name, display, proto string, port int, extra string) {
		sc.Add("New-NetFirewallRule -Group %s -Name %s -DisplayName %s -Direction Inbound -Action Allow -Profile Any -Protocol %s -LocalPort %s"+extra+" | Out-Null",
			g, winps.S(name), winps.S(display), winps.S(proto), winps.I(port))
	}
	rule("Veyl-VPN-UDP", "Veyl VPN (UDP)", "UDP", s.UDPPort, "")
	if s.Stealth {
		rule("Veyl-VPN-TCP", "Veyl VPN (TCP fallback)", "TCP", s.StealthTCPPortFor(config.PlatformWindows), "")
	}
	rule("Veyl-HTTP", "Veyl web (HTTP)", "TCP", 80, "")
	rule("Veyl-HTTPS", "Veyl web (HTTPS)", "TCP", 443, "")
	tunnel := winps.Line(" -RemoteAddress %s -LocalAddress %s", winps.S(config.TunnelPrefix), winps.S(config.DNSPrefix+".0/24"))
	rule("Veyl-DNS-UDP", "Veyl DNS (VPN clients)", "UDP", 53, tunnel)
	rule("Veyl-DNS-TCP", "Veyl DNS (VPN clients)", "TCP", 53, tunnel)
	if s.AdminVPNOnly {
		rule("Veyl-Admin-VPN", "Veyl admin (VPN only)", "TCP", AdminVPNPort, winps.Line(" -RemoteAddress %s -LocalAddress %s", winps.S(config.TunnelPrefix), winps.List(config.UDPGW4, config.TCPGW4)))
	}
	sc.Add("Set-NetFirewallProfile -All -LogAllowed False -LogBlocked False -LogIgnored False")
	return sc.String(), nil
}

func WinNetworkScript(f WinFacts) (string, error) {
	if f.WANIndex < 1 || f.WANIndex > 1<<24 {
		return "", fmt.Errorf("%w: wan interface", ErrFacts)
	}
	var sc winps.Script
	sc.Add("Set-NetIPInterface -InterfaceIndex %s -AddressFamily IPv4 -Forwarding Enabled", winps.I(f.WANIndex))
	sc.Add("foreach ($n in %s) {", winps.List(config.TapUDP, config.TapTCP))
	sc.Add("  if (Get-NetIPInterface -InterfaceAlias $n -AddressFamily IPv4 -ErrorAction SilentlyContinue) {")
	sc.Add("    Set-NetIPInterface -InterfaceAlias $n -AddressFamily IPv4 -Forwarding Enabled -WeakHostReceive Enabled -WeakHostSend Enabled")
	sc.Add("  }")
	sc.Add("}")
	sc.Add("$nat = Get-NetNat -Name %s -ErrorAction SilentlyContinue", winps.S(config.NATName))
	sc.Add("if ($nat -and $nat.InternalIPInterfaceAddressPrefix -ne %s) {", winps.S(config.NATPrefix))
	sc.Add("  Remove-NetNat -Name %s -Confirm:$false", winps.S(config.NATName))
	sc.Add("  $nat = $null")
	sc.Add("}")
	sc.Add("if (-not $nat) {")
	sc.Add("  New-NetNat -Name %s -InternalIPInterfaceAddressPrefix %s | Out-Null", winps.S(config.NATName), winps.S(config.NATPrefix))
	sc.Add("  'nat created'")
	sc.Add("} else {")
	sc.Add("  'nat present'")
	sc.Add("}")
	return sc.String(), nil
}

func WinTapScript(instance string) (string, error) {
	if instance != config.InstanceUDP && instance != config.InstanceTCP {
		return "", ErrInstance
	}
	name := winps.S(config.TapName(instance))
	var sc winps.Script
	sc.Add("Set-NetIPInterface -InterfaceAlias %s -AddressFamily IPv4 -Forwarding Enabled -WeakHostReceive Enabled -WeakHostSend Enabled", name)
	if instance == config.InstanceUDP {
		sc.Add("$have = @(Get-NetIPAddress -InterfaceAlias %s -AddressFamily IPv4 -ErrorAction SilentlyContinue | ForEach-Object { $_.IPAddress })", name)
		sc.Add("$added = 0")
		sc.Add("foreach ($i in 1..%s) {", winps.I(config.MaxMask()+1))
		sc.Add("  $ip = %s + $i", winps.S(config.DNSPrefix+"."))
		sc.Add("  if ($have -notcontains $ip) {")
		sc.Add("    New-NetIPAddress -InterfaceAlias %s -IPAddress $ip -PrefixLength 32 -SkipAsSource $true | Out-Null", name)
		sc.Add("    $added++")
		sc.Add("  }")
		sc.Add("}")
		sc.Add("if ($added -gt 0) {")
		sc.Add("  Restart-Service -Name %s -Force -ErrorAction SilentlyContinue", winps.S(config.WinServiceDNS))
		sc.Add("} else {")
		sc.Add("  Start-Service -Name %s -ErrorAction SilentlyContinue", winps.S(config.WinServiceDNS))
		sc.Add("}")
		sc.Add("'dns addresses ' + $added")
	}
	return sc.String(), nil
}

func WinAdapterScript(instance string) (string, error) {
	if instance != config.InstanceUDP && instance != config.InstanceTCP {
		return "", ErrInstance
	}
	var sc winps.Script
	sc.Add("$a = Get-NetAdapter -Name %s -ErrorAction SilentlyContinue", winps.S(config.TapName(instance)))
	sc.Add("if ($a) { 'adapter=' + $a.InterfaceDescription }")
	return sc.String(), nil
}

func WinFactsScript() string {
	var sc winps.Script
	sc.Add("$r = Get-NetRoute -AddressFamily IPv4 -DestinationPrefix %s -ErrorAction SilentlyContinue | Sort-Object -Property RouteMetric | Select-Object -First 1", winps.S("0.0.0.0/0"))
	sc.Add("if ($r) { 'wan=' + $r.ifIndex }")
	sc.Add("$o = Get-CimInstance -ClassName Win32_OperatingSystem")
	sc.Add("'os=' + $o.Caption")
	return sc.String()
}

func WinStatusScript() string {
	var sc winps.Script
	sc.Add("$o = Get-CimInstance -ClassName Win32_OperatingSystem")
	sc.Add("'os=' + $o.Caption + ' ' + $o.Version")
	sc.Add("'uptime=' + [int64]((Get-Date) - $o.LastBootUpTime).TotalSeconds")
	sc.Add("'mem_total=' + ([int64]$o.TotalVisibleMemorySize * 1024)")
	sc.Add("'mem_avail=' + ([int64]$o.FreePhysicalMemory * 1024)")
	sc.Add("$d = Get-PSDrive -Name $env:SystemDrive.TrimEnd(':')")
	sc.Add("'disk_total=' + ([int64]$d.Used + [int64]$d.Free)")
	sc.Add("'disk_free=' + [int64]$d.Free")
	sc.Add("$fw = @(Get-NetFirewallRule -Group %s -ErrorAction SilentlyContinue | Where-Object { $_.Enabled -eq 'True' })", winps.S(config.FirewallGroup))
	sc.Add("'firewall=' + $fw.Count")
	return sc.String()
}

func WinListenersScript() string {
	var sc winps.Script
	sc.Add("Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | ForEach-Object { 'tcp ' + $_.LocalAddress + ' ' + $_.LocalPort }")
	sc.Add("Get-NetUDPEndpoint -ErrorAction SilentlyContinue | ForEach-Object { 'udp ' + $_.LocalAddress + ' ' + $_.LocalPort }")
	return sc.String()
}

func WinUninstallScript() string {
	var sc winps.Script
	sc.Add("Get-NetFirewallRule -Group %s -ErrorAction SilentlyContinue | Remove-NetFirewallRule", winps.S(config.FirewallGroup))
	sc.Add("Get-NetNat -Name %s -ErrorAction SilentlyContinue | Remove-NetNat -Confirm:$false", winps.S(config.NATName))
	sc.Add("foreach ($n in %s) {", winps.List(config.TapUDP))
	sc.Add("  Get-NetIPAddress -InterfaceAlias $n -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -like %s } | Remove-NetIPAddress -Confirm:$false", winps.S(config.DNSPrefix+".*"))
	sc.Add("}")
	return sc.String()
}

func WinGrants(dir string) ([]winacl.Grant, error) {
	sid := func(name string) string {
		s, err := winacl.ServiceSID(name)
		if err != nil {
			panic(err)
		}
		return s
	}
	base := []winacl.Grant{{SID: winacl.SIDSystem, Rights: winacl.Full}, {SID: winacl.SIDAdmins, Rights: winacl.Full}}
	p := config.WindowsPaths()
	switch dir {
	case config.WinRoot, config.WinConfDir:
		return base, nil
	case p.Data, p.Run:
		return append(base, winacl.Grant{SID: sid(config.WinServiceVeyl), Rights: winacl.Modify}), nil
	case p.Blocklists():
		return append(base, winacl.Grant{SID: sid(config.WinServiceVeyl), Rights: winacl.Read}, winacl.Grant{SID: sid(config.WinServiceDNS), Rights: winacl.Read}), nil
	case config.WinUnboundData:
		return append(base, winacl.Grant{SID: sid(config.WinServiceUnbnd), Rights: winacl.Modify}), nil
	case config.WinCaddyData:
		return append(base, winacl.Grant{SID: sid(config.WinServiceCaddy), Rights: winacl.Modify}), nil
	}
	return nil, fmt.Errorf("%w: no access rules for %s", ErrSettings, dir)
}

func WinDirs() []string {
	p := config.WindowsPaths()
	return []string{config.WinRoot, p.Data, p.Run, config.WinConfDir, p.Blocklists(), config.WinUnboundData, config.WinCaddyData}
}

func WinMgmtGrants() []winacl.Grant {
	s, _ := winacl.ServiceSID(config.WinServiceVeyl)
	return []winacl.Grant{{SID: winacl.SIDSystem, Rights: winacl.Full}, {SID: winacl.SIDAdmins, Rights: winacl.Full}, {SID: s, Rights: winacl.Read}}
}
