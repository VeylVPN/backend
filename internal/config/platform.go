package config

import (
	"errors"
	"runtime"
)

const (
	PlatformLinux   = "linux"
	PlatformWindows = "windows"
)

var Platform = hostPlatform()

func hostPlatform() string {
	if runtime.GOOS == "windows" {
		return PlatformWindows
	}
	return PlatformLinux
}

const (
	WinInstallDir   = `C:\Program Files\Veyl`
	WinBinPath      = `C:\Program Files\Veyl\veyl.exe`
	WinInstaller    = `C:\Program Files\Veyl\install.ps1`
	WinRoot         = `C:\ProgramData\Veyl`
	WinDataDir      = `C:\ProgramData\Veyl\data`
	WinRunDir       = `C:\ProgramData\Veyl\run`
	WinConfDir      = `C:\ProgramData\Veyl\config`
	WinUnboundData  = `C:\ProgramData\Veyl\unbound`
	WinCaddyData    = `C:\ProgramData\Veyl\caddy`
	WinOpenVPNBin   = `C:\Program Files\OpenVPN\bin\openvpn.exe`
	WinTapctl       = `C:\Program Files\OpenVPN\bin\tapctl.exe`
	WinUnboundDir   = `C:\Program Files\Veyl\unbound`
	WinCaddyBin     = `C:\Program Files\Veyl\caddy\caddy.exe`
	WinPowerShell   = `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
	WinSC           = `C:\Windows\System32\sc.exe`
	WinIcacls       = `C:\Windows\System32\icacls.exe`
	TapUDP          = "Veyl UDP"
	TapTCP          = "Veyl TCP"
	TapHWID         = `root\tap0901`
	MgmtHost        = "127.0.0.1"
	MgmtPortUDP     = 7505
	MgmtPortTCP     = 7506
	WinStealthPort  = 993
	NATName         = "Veyl"
	NATPrefix       = "10.8.0.0/15"
	TunnelPrefix    = "10.8.0.0/15"
	FirewallGroup   = "Veyl"
	WinServiceVeyl  = "Veyl"
	WinServiceAgent = "VeylAgent"
	WinServiceDNS   = "VeylDNS"
	WinServiceUDP   = "VeylOpenVPNUDP"
	WinServiceTCP   = "VeylOpenVPNTCP"
	WinServiceUnbnd = "VeylUnbound"
	WinServiceCaddy = "VeylCaddy"
)

var ErrStealthPort = errors.New("stealth port must be 443 on Linux, or a free TCP port other than 53, 80, 443, 5335, 7505, 7506, 8080, 8081 and 8443 on Windows")

func DefaultStealthPort(platform string) int {
	if platform == PlatformWindows {
		return WinStealthPort
	}
	return StealthPort
}

func ValidStealthPort(platform string, p int) bool {
	if p == 0 {
		return true
	}
	if platform != PlatformWindows {
		return p == StealthPort
	}
	if p < 1 || p > 65535 {
		return false
	}
	switch p {
	case 53, 80, 443, 5335, MgmtPortUDP, MgmtPortTCP, 8080, 8081, CaddyTLSPort:
		return false
	}
	return true
}

func (s Settings) StealthTCPPort() int {
	return s.StealthTCPPortFor(Platform)
}

func (s Settings) StealthTCPPortFor(platform string) int {
	if platform != PlatformWindows || s.StealthPort == 0 {
		return DefaultStealthPort(platform)
	}
	return s.StealthPort
}

func MgmtPort(instance string) int {
	if instance == InstanceTCP {
		return MgmtPortTCP
	}
	return MgmtPortUDP
}

func TapName(instance string) string {
	if instance == InstanceTCP {
		return TapTCP
	}
	return TapUDP
}
