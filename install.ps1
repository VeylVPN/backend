[CmdletBinding()]
param(
	[string]$Domain = '',
	[string]$Email = '',
	[string]$Branch = 'main',
	[string]$Version = '',
	[switch]$Build,
	[switch]$Yes,
	[switch]$Force,
	[switch]$Uninstall,
	[switch]$Purge
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$Script:Repo = 'VeylVPN/backend'
$Script:Module = 'github.com/veylvpn/backend'
$Script:ProgramFiles = 'C:\Program Files'
if ($env:ProgramFiles) {
	$Script:ProgramFiles = $env:ProgramFiles
}
$Script:ProgramData = 'C:\ProgramData'
if ($env:ProgramData) {
	$Script:ProgramData = $env:ProgramData
}
$Script:Temp = [IO.Path]::GetTempPath()
$Script:InstallDir = [IO.Path]::Combine($Script:ProgramFiles, 'Veyl')
$Script:Bin = [IO.Path]::Combine($Script:InstallDir, 'veyl.exe')
$Script:Root = [IO.Path]::Combine($Script:ProgramData, 'Veyl')
$Script:DataDir = [IO.Path]::Combine($Script:Root, 'data')
$Script:Work = [IO.Path]::Combine($Script:Temp, ('veyl-install-' + [guid]::NewGuid().ToString('N')))
$Script:Services = @('Veyl', 'VeylDNS', 'VeylOpenVPNUDP', 'VeylOpenVPNTCP', 'VeylUnbound', 'VeylCaddy', 'VeylAgent')

$Script:OpenVPN = @{
	Version = '2.7.7'
	Url     = 'https://swupdate.openvpn.org/community/releases/OpenVPN-2.7.7-I001-amd64.msi'
	Sha256  = '9069a48397c4fd4135fb9c9baea4863c74a465651f67e55a423a433e503100bb'
	Signer  = 'OpenVPN Inc.'
}
$Script:Unbound = @{
	Version = '1.26.1'
	Url     = 'https://nlnetlabs.nl/downloads/unbound/unbound-1.26.1.zip'
	Sha256  = 'ce48b56232b4ceeb36e0087e23b4facdb31202fd0b12cfc75be6fc7c8bd74d3b'
}
$Script:Caddy = @{
	Version = '2.11.6'
	Url     = 'https://github.com/caddyserver/caddy/releases/download/v2.11.6/caddy_2.11.6_windows_amd64.zip'
	Sha256  = '07429393375227eb669e449764c5245eaac8fc69fc68b2f867717af794cc1153'
}
$Script:Go = @{
	File   = 'go1.27.1.windows-amd64.zip'
	Url    = 'https://go.dev/dl/go1.27.1.windows-amd64.zip'
	Sha256 = 'a3911b5e0e1b1053f25ed0675f4c1c6aad1e2bfcf253df2b9be4caabd2edd95d'
}

function Say([string]$Text) {
	Write-Host $Text
}

function Step([string]$Text) {
	Write-Host ('==> ' + $Text) -ForegroundColor White
}

function Fail([string]$Text) {
	throw $Text
}

function Confirm-Step([string]$Question) {
	if ($Yes) {
		return
	}
	if (-not [Environment]::UserInteractive) {
		return
	}
	$answer = Read-Host ($Question + ' [Y/n]')
	if ($answer -and $answer -notmatch '^(y|yes)$') {
		Fail 'aborted'
	}
}

function Test-Admin {
	$id = [Security.Principal.WindowsIdentity]::GetCurrent()
	$p = New-Object Security.Principal.WindowsPrincipal($id)
	return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-Inputs {
	if ($Domain -and $Domain -notmatch '^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$') {
		Fail ('invalid domain: ' + $Domain)
	}
	if ($Email -and $Email -notmatch '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}$') {
		Fail ('invalid email: ' + $Email)
	}
	if ($Branch -notmatch '^[A-Za-z0-9._/-]{1,100}$' -or $Branch.StartsWith('-')) {
		Fail ('invalid branch: ' + $Branch)
	}
	if ($Version -and $Version -notmatch '^v[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]{1,32})?$') {
		Fail ('invalid version: ' + $Version)
	}
}

function Test-System {
	if (-not [Environment]::Is64BitOperatingSystem -or $env:PROCESSOR_ARCHITECTURE -ne 'AMD64') {
		Fail 'Veyl for Windows needs a 64-bit x86 (amd64) system'
	}
	$os = Get-CimInstance -ClassName Win32_OperatingSystem
	$build = [int]$os.BuildNumber
	$ok = $build -ge 17763 -and $os.Caption -notmatch 'Home'
	if (-not $ok) {
		if ($Force) {
			Say ('Warning: ' + $os.Caption + ' (build ' + $build + ') is not supported, continuing because of -Force')
		} else {
			Fail ('unsupported system ' + $os.Caption + ' build ' + $build + ' (supported: Windows Server 2019, 2022, 2025 and Windows 10/11 Pro; use -Force to try anyway)')
		}
	}
	Say ('    ' + $os.Caption + ' build ' + $build)
}

function Get-PortOwners {
	$found = @()
	foreach ($p in 80, 443) {
		foreach ($c in @(Get-NetTCPConnection -State Listen -LocalPort $p -ErrorAction SilentlyContinue)) {
			$found += [pscustomobject]@{ Port = [string]$p + '/tcp'; Pid = $c.OwningProcess }
		}
	}
	foreach ($c in @(Get-NetUDPEndpoint -LocalPort 1194 -ErrorAction SilentlyContinue)) {
		$found += [pscustomobject]@{ Port = '1194/udp'; Pid = $c.OwningProcess }
	}
	$conflicts = @()
	foreach ($f in $found) {
		$name = 'pid ' + $f.Pid
		$proc = Get-Process -Id $f.Pid -ErrorAction SilentlyContinue
		if ($proc) {
			$name = $proc.ProcessName
		}
		if ($name -notin @('caddy', 'openvpn', 'veyl')) {
			$conflicts += ($f.Port + ' (' + $name + ')')
		}
	}
	return $conflicts | Select-Object -Unique
}

function Test-Ports {
	$conflicts = @(Get-PortOwners)
	if ($conflicts.Count -eq 0) {
		return
	}
	$text = 'ports in use: ' + ($conflicts -join ', ') + '. Stop those services (IIS uses port 80 as System) or rerun with -Force'
	if ($Force) {
		Say ('Warning: ' + $text)
	} else {
		Fail $text
	}
}

function Get-Sha256([string]$Path) {
	return (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant()
}

function Get-Verified([string]$Url, [string]$Sha256, [string]$OutFile) {
	if ($Url -notmatch '^https://') {
		Fail ('refusing to download over plain http: ' + $Url)
	}
	Invoke-WebRequest -UseBasicParsing -Uri $Url -OutFile $OutFile
	$got = Get-Sha256 $OutFile
	if ($got -ne $Sha256.ToLowerInvariant()) {
		Remove-Item -LiteralPath $OutFile -Force -ErrorAction SilentlyContinue
		Fail ('checksum mismatch for ' + $Url + ': got ' + $got + ', want ' + $Sha256)
	}
}

function Get-OpenVPNVersion {
	$exe = [IO.Path]::Combine($Script:ProgramFiles, 'OpenVPN\bin\openvpn.exe')
	if (-not (Test-Path -LiteralPath $exe)) {
		return ''
	}
	$out = (& $exe --version 2>$null | Select-Object -First 1)
	if ($out -match '^OpenVPN ([0-9]+\.[0-9]+\.[0-9]+)') {
		return $Matches[1]
	}
	return ''
}

function Install-OpenVPN {
	Step 'Installing OpenVPN with the TAP-Windows6 driver'
	$have = Get-OpenVPNVersion
	$tap = [IO.Path]::Combine($Script:ProgramFiles, 'OpenVPN\bin\tapctl.exe')
	if ($have -eq $Script:OpenVPN.Version -and (Test-Path -LiteralPath $tap)) {
		Say ('    OpenVPN ' + $have + ' already installed')
		return
	}
	$msi = [IO.Path]::Combine($Script:Work, 'openvpn.msi')
	Get-Verified $Script:OpenVPN.Url $Script:OpenVPN.Sha256 $msi
	$sig = Get-AuthenticodeSignature -FilePath $msi
	if ($sig.Status -ne 'Valid' -or -not $sig.SignerCertificate -or $sig.SignerCertificate.GetNameInfo('SimpleName', $false) -ne $Script:OpenVPN.Signer) {
		Fail ('the OpenVPN installer is not signed by ' + $Script:OpenVPN.Signer)
	}
	$msiArgs = @('/i', ('"' + $msi + '"'), '/qn', '/norestart', 'ADDLOCAL=OpenVPN,Drivers,Drivers.TAPWindows6')
	$p = Start-Process -FilePath 'msiexec.exe' -ArgumentList $msiArgs -Wait -PassThru
	if ($p.ExitCode -notin @(0, 3010, 1641)) {
		Fail ('OpenVPN installer failed with exit code ' + $p.ExitCode)
	}
	if ($p.ExitCode -ne 0) {
		Say '    Windows asks for a restart to finish the driver installation. Restart, then run this installer again.'
	}
	Say ('    OpenVPN ' + (Get-OpenVPNVersion))
}

function Install-Zip([hashtable]$Pkg, [string]$Name, [string]$Dest) {
	$marker = [IO.Path]::Combine($Dest, '.veyl-sha256')
	if ((Test-Path -LiteralPath $marker) -and ((Get-Content -LiteralPath $marker -Raw).Trim() -eq $Pkg.Sha256)) {
		Say ('    ' + $Name + ' ' + $Pkg.Version + ' already installed')
		return
	}
	$zip = [IO.Path]::Combine($Script:Work, ($Name + '.zip'))
	Get-Verified $Pkg.Url $Pkg.Sha256 $zip
	$tmp = [IO.Path]::Combine($Script:Work, $Name)
	Expand-Archive -LiteralPath $zip -DestinationPath $tmp -Force
	Stop-VeylServices
	if (Test-Path -LiteralPath $Dest) {
		Remove-Item -LiteralPath $Dest -Recurse -Force
	}
	New-Item -ItemType Directory -Path $Dest -Force | Out-Null
	Copy-Item -Path ([IO.Path]::Combine($tmp, '*')) -Destination $Dest -Recurse -Force
	Set-Content -LiteralPath $marker -Value $Pkg.Sha256 -Encoding ASCII
	Say ('    ' + $Name + ' ' + $Pkg.Version)
}

function Stop-VeylServices {
	foreach ($s in $Script:Services) {
		$svc = Get-Service -Name $s -ErrorAction SilentlyContinue
		if ($svc -and $svc.Status -ne 'Stopped') {
			Stop-Service -Name $s -Force -ErrorAction SilentlyContinue
		}
	}
}

function Get-LatestRelease {
	if ($Version) {
		return $Version
	}
	try {
		$rel = Invoke-RestMethod -UseBasicParsing -Uri ('https://api.github.com/repos/' + $Script:Repo + '/releases/latest') -Headers @{ 'User-Agent' = 'veyl-installer' }
	} catch {
		return ''
	}
	$tag = ''
	if ($rel -and $rel.PSObject.Properties['tag_name']) {
		$tag = [string]$rel.tag_name
	}
	if ($tag -notmatch '^v[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]{1,32})?$') {
		return ''
	}
	return $tag
}

function Get-ReleaseBinary([string]$Tag) {
	$ver = $Tag.TrimStart('v')
	$file = 'veyl_' + $ver + '_windows_amd64.zip'
	$base = 'https://github.com/' + $Script:Repo + '/releases/download/' + $Tag + '/'
	$sums = [IO.Path]::Combine($Script:Work, 'SHA256SUMS')
	try {
		Invoke-WebRequest -UseBasicParsing -Uri ($base + 'SHA256SUMS') -OutFile $sums
	} catch {
		return $null
	}
	$want = ''
	foreach ($line in Get-Content -LiteralPath $sums) {
		$parts = $line -split '\s+'
		if ($parts.Count -ge 2 -and $parts[1].TrimStart('*') -eq $file -and $parts[0] -match '^[0-9a-fA-F]{64}$') {
			$want = $parts[0]
		}
	}
	if (-not $want) {
		return $null
	}
	$zip = [IO.Path]::Combine($Script:Work, $file)
	Get-Verified ($base + $file) $want $zip
	$out = [IO.Path]::Combine($Script:Work, 'release')
	Expand-Archive -LiteralPath $zip -DestinationPath $out -Force
	if (-not (Test-Path -LiteralPath ([IO.Path]::Combine($out, 'veyl.exe')))) {
		Fail ('release archive ' + $file + ' has no veyl.exe')
	}
	Say ('    release ' + $Tag + ' verified with SHA256SUMS')
	return $out
}

function Test-GoChecksum {
	try {
		$all = Invoke-RestMethod -UseBasicParsing -Uri 'https://go.dev/dl/?mode=json&include=all'
	} catch {
		Fail 'cannot reach go.dev to cross-check the Go toolchain checksum'
	}
	foreach ($r in $all) {
		foreach ($f in $r.files) {
			if ($f.filename -eq $Script:Go.File) {
				if ($f.sha256 -ne $Script:Go.Sha256) {
					Fail 'the pinned Go toolchain checksum does not match go.dev'
				}
				return
			}
		}
	}
	Fail ('go.dev does not list ' + $Script:Go.File)
}

function Build-FromSource {
	Step ('Building veyl from source (' + $Branch + ')')
	Test-GoChecksum
	$gozip = [IO.Path]::Combine($Script:Work, $Script:Go.File)
	Get-Verified $Script:Go.Url $Script:Go.Sha256 $gozip
	Expand-Archive -LiteralPath $gozip -DestinationPath $Script:Work -Force
	$src = [IO.Path]::Combine($Script:Work, 'src.zip')
	Invoke-WebRequest -UseBasicParsing -Uri ('https://codeload.github.com/' + $Script:Repo + '/zip/refs/heads/' + $Branch) -OutFile $src
	$srcDir = [IO.Path]::Combine($Script:Work, 'src')
	Expand-Archive -LiteralPath $src -DestinationPath $srcDir -Force
	$top = Get-ChildItem -LiteralPath $srcDir -Directory | Select-Object -First 1
	if (-not $top -or -not (Test-Path -LiteralPath ([IO.Path]::Combine($top.FullName, 'go.mod')))) {
		Fail 'unexpected source archive'
	}
	$mod = Get-Content -LiteralPath ([IO.Path]::Combine($top.FullName, 'go.mod')) -TotalCount 1
	if ($mod -ne ('module ' + $Script:Module)) {
		Fail 'unexpected source checkout'
	}
	$ver = 'src-' + ($Branch -replace '[^A-Za-z0-9._-]', '-')
	$out = [IO.Path]::Combine($Script:Work, 'build')
	New-Item -ItemType Directory -Path $out -Force | Out-Null
	$env:GOROOT = [IO.Path]::Combine($Script:Work, 'go')
	$env:GOPATH = [IO.Path]::Combine($Script:Work, 'gopath')
	$env:GOCACHE = [IO.Path]::Combine($Script:Work, 'cache')
	$env:GOMODCACHE = [IO.Path]::Combine($Script:Work, 'modcache')
	$env:GOTOOLCHAIN = 'local'
	$env:GOPROXY = 'off'
	$env:CGO_ENABLED = '0'
	Push-Location $top.FullName
	try {
		& ([IO.Path]::Combine($env:GOROOT, 'bin\go.exe')) build -trimpath -ldflags ('-s -w -X ' + $Script:Module + '/internal/app.Version=' + $ver) -o ([IO.Path]::Combine($out, 'veyl.exe')) ./cmd/veyl
		if ($LASTEXITCODE -ne 0) {
			Fail 'go build failed'
		}
	} finally {
		Pop-Location
	}
	Copy-Item -LiteralPath ([IO.Path]::Combine($top.FullName, 'install.ps1')) -Destination ([IO.Path]::Combine($out, 'install.ps1')) -Force
	Say ('    veyl ' + $ver)
	return $out
}

function Get-Veyl {
	$dir = $null
	if (-not $Build) {
		Step 'Downloading the veyl release'
		$tag = Get-LatestRelease
		if ($tag) {
			$dir = Get-ReleaseBinary $tag
		}
		if (-not $dir) {
			if ($Version) {
				Fail ('release ' + $Version + ' was not found')
			}
			Say '    no release found, building from source instead'
		}
	}
	if (-not $dir) {
		$dir = Build-FromSource
	}
	Stop-VeylServices
	New-Item -ItemType Directory -Path $Script:InstallDir -Force | Out-Null
	$old = $Script:Bin + '.old'
	if (Test-Path -LiteralPath $old) {
		Remove-Item -LiteralPath $old -Force -ErrorAction SilentlyContinue
	}
	if (Test-Path -LiteralPath $Script:Bin) {
		Move-Item -LiteralPath $Script:Bin -Destination $old -Force
	}
	Copy-Item -LiteralPath ([IO.Path]::Combine($dir, 'veyl.exe')) -Destination $Script:Bin -Force
	$ps1 = [IO.Path]::Combine($dir, 'install.ps1')
	$target = [IO.Path]::Combine($Script:InstallDir, 'install.ps1')
	if (Test-Path -LiteralPath $ps1) {
		Copy-Item -LiteralPath $ps1 -Destination $target -Force
	} elseif ($PSCommandPath -and ($PSCommandPath -ne $target)) {
		Copy-Item -LiteralPath $PSCommandPath -Destination $target -Force
	}
	Say ('    ' + (& $Script:Bin version))
}

function Protect-Root {
	New-Item -ItemType Directory -Path $Script:DataDir -Force | Out-Null
	& icacls.exe $Script:Root /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)(F)' '*S-1-5-32-544:(OI)(CI)(F)' /C /Q | Out-Null
	if ($LASTEXITCODE -ne 0) {
		Fail ('could not lock down ' + $Script:Root)
	}
}

function Initialize-Keys {
	Step 'Preparing keys'
	if (Test-Path -LiteralPath ([IO.Path]::Combine($Script:DataDir, 'ca.key'))) {
		Say '    existing keys kept'
	}
	& $Script:Bin init $Script:DataDir
	if ($LASTEXITCODE -ne 0) {
		Fail 'key generation failed'
	}
}

function Invoke-Bootstrap {
	Step 'Configuring the system'
	$a = @('agent', 'bootstrap')
	if ($Domain) {
		$a += @('-domain', $Domain)
	}
	if ($Email) {
		$a += @('-email', $Email)
	}
	& $Script:Bin @a | ForEach-Object { Say ('    ' + $_) }
	if ($LASTEXITCODE -ne 0) {
		Fail 'system configuration failed'
	}
}

function Test-Configured {
	$f = [IO.Path]::Combine($Script:DataDir, 'settings.json')
	if (-not (Test-Path -LiteralPath $f)) {
		return $false
	}
	return ((Get-Content -LiteralPath $f -Raw) -match '"configured":\s*true')
}

function New-SetupToken {
	$bytes = New-Object byte[] 32
	$rng = [Security.Cryptography.RandomNumberGenerator]::Create()
	$rng.GetBytes($bytes)
	$token = [Convert]::ToBase64String($bytes).Replace('+', '-').Replace('/', '_').TrimEnd('=')
	$path = [IO.Path]::Combine($Script:DataDir, 'setup-token')
	[IO.File]::WriteAllText($path, $token)
	return $token
}

function Get-PublicIP {
	foreach ($u in 'https://api.ipify.org', 'https://ifconfig.co/ip') {
		try {
			$ip = (Invoke-RestMethod -UseBasicParsing -Uri $u -TimeoutSec 8).ToString().Trim()
			if ($ip -match '^[0-9]{1,3}(\.[0-9]{1,3}){3}$') {
				return $ip
			}
		} catch {
		}
	}
	$addr = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -notmatch '^(127\.|169\.254\.|10\.8\.|10\.9\.|10\.64\.)' } | Select-Object -First 1
	if ($addr) {
		return $addr.IPAddress
	}
	return '<server-ip>'
}

function Test-HttpsReady {
	if (-not $Domain) {
		return $false
	}
	try {
		$r = Invoke-WebRequest -UseBasicParsing -Uri ('https://' + $Domain + '/v1/health') -TimeoutSec 10
		return $r.StatusCode -eq 200
	} catch {
		return $false
	}
}

function Show-Banner([string]$Url) {
	$line = '=================================================================='
	Write-Host ''
	Write-Host $line -ForegroundColor Green
	Write-Host ''
	Write-Host '  Veyl is installed.'
	Write-Host ''
	Write-Host '  Open this link to finish setup:'
	Write-Host ''
	Write-Host ('    ' + $Url) -ForegroundColor White
	Write-Host ''
	Write-Host '  If you have no domain, setup can give you one automatically.'
	Write-Host '  The link works once. Lost it? Run as Administrator: veyl setup-link'
	Write-Host ''
	Write-Host $line -ForegroundColor Green
	Write-Host ''
}

function Complete-Install {
	if (Test-Configured) {
		Write-Host ''
		Write-Host 'Veyl is up to date and running. Check it with: veyl status' -ForegroundColor Green
		Write-Host ''
		return
	}
	$token = New-SetupToken
	if (Test-HttpsReady) {
		$url = 'https://' + $Domain + '/setup#' + $token
	} else {
		$url = 'http://' + (Get-PublicIP) + '/setup#' + $token
	}
	Show-Banner $url
}

function Add-ToPath {
	$machine = [Environment]::GetEnvironmentVariable('Path', 'Machine')
	if (($machine -split ';') -notcontains $Script:InstallDir) {
		[Environment]::SetEnvironmentVariable('Path', ($machine.TrimEnd(';') + ';' + $Script:InstallDir), 'Machine')
	}
}

function Remove-Veyl {
	Step 'Removing Veyl'
	if (Test-Path -LiteralPath $Script:Bin) {
		$a = @('uninstall')
		if ($Purge) {
			$a += '-purge'
		}
		& $Script:Bin @a | ForEach-Object { Say ('    ' + $_) }
	}
	Stop-VeylServices
	foreach ($s in $Script:Services) {
		if (Get-Service -Name $s -ErrorAction SilentlyContinue) {
			& sc.exe delete $s | Out-Null
		}
	}
	Remove-Item -LiteralPath $Script:InstallDir -Recurse -Force -ErrorAction SilentlyContinue
	$machine = [Environment]::GetEnvironmentVariable('Path', 'Machine')
	$kept = ($machine -split ';') | Where-Object { $_ -and $_ -ne $Script:InstallDir }
	[Environment]::SetEnvironmentVariable('Path', ($kept -join ';'), 'Machine')
	if ($Purge) {
		Remove-Item -LiteralPath $Script:Root -Recurse -Force -ErrorAction SilentlyContinue
		Say 'Veyl and its data were removed. OpenVPN stays installed, remove it in Settings > Apps if you no longer need it.'
	} else {
		Say ('Veyl was removed. Keys and accounts are kept in ' + $Script:DataDir + ' (use -Uninstall -Purge to delete them).')
	}
}

function Install-Veyl {
	Test-Inputs
	if (-not (Test-Admin)) {
		Fail 'run PowerShell as Administrator, for example: irm https://raw.githubusercontent.com/VeylVPN/backend/main/install.ps1 | iex'
	}
	[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
	if ($Uninstall) {
		Confirm-Step 'Remove Veyl from this server?'
		Remove-Veyl
		return
	}
	New-Item -ItemType Directory -Path $Script:Work -Force | Out-Null
	try {
		Step 'Checking the system'
		Test-System
		if ((Test-Path -LiteralPath $Script:Bin) -and (Test-Path -LiteralPath ([IO.Path]::Combine($Script:DataDir, 'ca.key')))) {
			Step 'Existing installation found, updating and repairing'
		} else {
			Test-Ports
			Confirm-Step 'Install Veyl on this server?'
		}
		Install-OpenVPN
		Step 'Installing Unbound and Caddy'
		Install-Zip $Script:Unbound 'unbound' ([IO.Path]::Combine($Script:InstallDir, 'unbound'))
		Install-Zip $Script:Caddy 'caddy' ([IO.Path]::Combine($Script:InstallDir, 'caddy'))
		Get-Veyl
		Protect-Root
		Add-ToPath
		Initialize-Keys
		Invoke-Bootstrap
		Complete-Install
	} finally {
		Remove-Item -LiteralPath $Script:Work -Recurse -Force -ErrorAction SilentlyContinue
	}
}

try {
	Install-Veyl
} catch {
	Write-Host ('Error: ' + $_.Exception.Message) -ForegroundColor Red
	if ($PSCommandPath) {
		exit 1
	}
}
