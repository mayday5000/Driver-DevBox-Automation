#Requires -RunAsAdministrator
# ================================================
# Configure-Target-KDNet.ps1
# TARGET-machine script.
#
# 1. Enables test signing (bcdedit /set testsigning on)
# 2. Enables kernel debugging over the network (KDNET)
# 3. Writes dbgsettings hostip / port / key
# 4. Reads the live BCD store and prints the port and key
#
# Defaults match the previous host-side hardcoded values:
#   port=50008
#   key=1.2.3.4
#
# A reboot is required after first-time debug / testsigning
# changes. Run this script again after reboot with -ShowOnly
# to confirm the active port and key.
#
# Usage:
#   .\Configure-Target-KDNet.ps1 -HostIp 192.168.1.10
#   .\Configure-Target-KDNet.ps1 -HostIp 192.168.1.10 -Port 50008 -Key 1.2.3.4
#   .\Configure-Target-KDNet.ps1 -ShowOnly
# ================================================

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$HostIp = "",

    [Parameter(Mandatory = $false)]
    [string]$Port = "50008",

    [Parameter(Mandatory = $false)]
    [string]$Key = "1.2.3.4",

    [Parameter(Mandatory = $false)]
    [string]$DriverName = "InspectorDrv",

    [switch]$ShowOnly,

    [switch]$SkipTestSigning,

    [switch]$NoRebootPrompt
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Continue"

function Write-Step { param([string]$Message) Write-Host "[+] $Message" -ForegroundColor Green }
function Write-Info { param([string]$Message) Write-Host "[i] $Message" -ForegroundColor Yellow }
function Write-Err  { param([string]$Message) Write-Host "[-] $Message" -ForegroundColor Red }

function Test-IsAdministrator {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-IPv4Address {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
    return [bool]($Value -match '^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$')
}

function Test-KdnetPort {
    param([string]$Value)
    if ($Value -notmatch '^\d+$') { return $false }
    $n = [int]$Value
    return ($n -ge 1 -and $n -le 65535)
}

function Test-KdnetKey {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
    # KDNET accepts dotted-decimal style keys (e.g. 1.2.3.4) or longer strings.
    if ($Value.Length -lt 3) { return $false }
    if ($Value -match '\s') { return $false }
    return $true
}

function Get-BcdeditOutput {
    param([string[]]$BcdArgs)
    $raw = & bcdedit.exe @BcdArgs 2>&1 | Out-String
    return $raw
}

function Parse-BcdeditKeyValues {
    param([string]$Text)

    $map = @{}
    if ([string]::IsNullOrWhiteSpace($Text)) {
        return $map
    }

    foreach ($line in ($Text -split "`r?`n")) {
        $trim = $line.Trim()
        if ([string]::IsNullOrWhiteSpace($trim)) { continue }
        if ($trim -match '^(The boot configuration|An error has occurred|Access is denied)') { continue }

        # bcdedit prints: <identifier><spaces><value>
        if ($trim -match '^(\S+)\s+(\S.*)$') {
            $k = $Matches[1].ToLowerInvariant()
            $v = $Matches[2].Trim()
            $map[$k] = $v
        }
    }
    return $map
}

function Get-KdnetSettings {
    $dbgText = Get-BcdeditOutput -BcdArgs @("/dbgsettings")
    $enumText = Get-BcdeditOutput -BcdArgs @("/enum", "{current}")

    $dbg  = Parse-BcdeditKeyValues -Text $dbgText
    $enum = Parse-BcdeditKeyValues -Text $enumText

    $testsigning = $null
    if ($enum.ContainsKey("testsigning")) { $testsigning = $enum["testsigning"] }

    $debug = $null
    if ($enum.ContainsKey("debug")) { $debug = $enum["debug"] }

    $nointegrity = $null
    if ($enum.ContainsKey("nointegritychecks")) { $nointegrity = $enum["nointegritychecks"] }

    return [pscustomobject]@{
        RawDbgsettings      = $dbgText
        RawEnum             = $enumText
        DebugType           = $(if ($dbg.ContainsKey("debugtype")) { $dbg["debugtype"] } else { $null })
        HostIp              = $(if ($dbg.ContainsKey("hostip")) { $dbg["hostip"] } else { $null })
        Port                = $(if ($dbg.ContainsKey("port")) { $dbg["port"] } else { $null })
        Key                 = $(if ($dbg.ContainsKey("key")) { $dbg["key"] } else { $null })
        TestSigning         = $testsigning
        KernelDebug         = $debug
        NoIntegrityChecks   = $nointegrity
        AccessDenied        = ($dbgText -match 'Access is denied' -or $enumText -match 'Access is denied')
    }
}

function Write-KdnetReport {
    param($Settings)

    Write-Host ""
    Write-Host "================================================" -ForegroundColor Cyan
    Write-Host "  Active BCD / KDNET configuration" -ForegroundColor Cyan
    Write-Host "================================================" -ForegroundColor Cyan

    if ($Settings.AccessDenied) {
        Write-Err "bcdedit could not open the BCD store (Access is denied)."
        Write-Info "Re-run this script from an elevated PowerShell prompt."
        return
    }

    $ts = if ($Settings.TestSigning) { $Settings.TestSigning } else { "(not set)" }
    $dbg = if ($Settings.KernelDebug) { $Settings.KernelDebug } else { "(not set)" }
    $dtype = if ($Settings.DebugType) { $Settings.DebugType } else { "(not set)" }
    $ip = if ($Settings.HostIp) { $Settings.HostIp } else { "(not set)" }
    $port = if ($Settings.Port) { $Settings.Port } else { "(not set)" }
    $key = if ($Settings.Key) { $Settings.Key } else { "(not set)" }

    Write-Host ("  testsigning      : {0}" -f $ts)
    Write-Host ("  debug            : {0}" -f $dbg)
    Write-Host ("  debugtype        : {0}" -f $dtype)
    Write-Host ("  hostip           : {0}" -f $ip)
    Write-Host ("  port             : {0}" -f $port) -ForegroundColor Green
    Write-Host ("  key              : {0}" -f $key) -ForegroundColor Green
    Write-Host ""
    Write-Host "  Host WinDbg listen string:" -ForegroundColor Yellow
    if ($Settings.Port -and $Settings.Key) {
        Write-Host ("    -k net:port={0},key={1}" -f $Settings.Port, $Settings.Key) -ForegroundColor Cyan
    } else {
        Write-Host "    (port/key not present in BCD — configure first)" -ForegroundColor Red
    }
    Write-Host "================================================" -ForegroundColor Cyan
    Write-Host ""
}

if (-not (Test-IsAdministrator)) {
    Write-Err "This script must run as Administrator on the TARGET machine."
    exit 1
}

Write-Host ""
Write-Host "================================================" -ForegroundColor Cyan
Write-Host "  Configure-Target-KDNet" -ForegroundColor Cyan
Write-Host "  DriverName default : $DriverName" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan

if ($ShowOnly) {
    $current = Get-KdnetSettings
    Write-KdnetReport -Settings $current
    exit 0
}

if (-not (Test-KdnetPort $Port)) {
    Write-Err "Port must be an integer in 1..65535. Got: $Port"
    exit 1
}
if (-not (Test-KdnetKey $Key)) {
    Write-Err "Key is invalid. Use a compact token such as 1.2.3.4"
    exit 1
}

if ([string]::IsNullOrWhiteSpace($HostIp)) {
    Write-Info "HostIp was not supplied. Trying default-gateway IPv4 as a hint..."
    try {
        $gw = Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue |
              Sort-Object RouteMetric |
              Select-Object -First 1 -ExpandProperty NextHop
        if (Test-IPv4Address $gw) {
            Write-Info "Detected default gateway: $gw"
            Write-Info "This is often the host / debugger NIC on a private lab network."
            $HostIp = $gw
        }
    } catch {
        Write-Info "Could not probe default gateway."
    }
}

if (-not (Test-IPv4Address $HostIp)) {
    Write-Err "HostIp is required and must be a dotted IPv4 address (the WinDbg HOST)."
    Write-Info "Example: .\\Configure-Target-KDNet.ps1 -HostIp 192.168.1.10 -Port 50008 -Key 1.2.3.4"
    exit 1
}

Write-Step "Requested KDNET: hostip=$HostIp port=$Port key=$Key"

# --- Test signing / integrity policy ----------------------------------------
if (-not $SkipTestSigning) {
    Write-Step "Enabling test signing (bcdedit /set testsigning on)"
    $out = Get-BcdeditOutput -BcdArgs @("/set", "testsigning", "on")
    Write-Host $out

    Write-Step "Enabling kernel debug (bcdedit /debug on)"
    $out = Get-BcdeditOutput -BcdArgs @("/debug", "on")
    Write-Host $out
} else {
    Write-Info "Skipping testsigning / debug enable (-SkipTestSigning)"
}

# --- KDNET transport --------------------------------------------------------
Write-Step "Writing dbgsettings net hostip:$HostIp port:$Port key:$Key"
$out = Get-BcdeditOutput -BcdArgs @("/dbgsettings", "net", "hostip:$HostIp", "port:$Port", "key:$Key")
Write-Host $out

# Persist a small sidecar so host scripts can be kept in sync by hand.
$sidecar = Join-Path $PSScriptRoot "kdnet-target-settings.json"
$payload = @{
    generatedUtc = [DateTime]::UtcNow.ToString("o")
    driverName   = $DriverName
    hostIp       = $HostIp
    port         = $Port
    key          = $Key
} | ConvertTo-Json
Set-Content -Path $sidecar -Value $payload -Encoding UTF8
Write-Step "Wrote $sidecar"

$current = Get-KdnetSettings
Write-KdnetReport -Settings $current

if ($current.Port -ne $Port -or $current.Key -ne $Key) {
    Write-Info "Reported port/key differ from the values just written."
    Write-Info "That is normal until the TARGET reboots into the edited BCD entry."
}

if (-not $NoRebootPrompt) {
    Write-Info "A reboot is required for testsigning / kernel-debug / dbgsettings to take effect."
    $r = Read-Host "Reboot TARGET now? (y/n)"
    if ($r -in 'y', 'Y') {
        Restart-Computer -Force
    }
}
