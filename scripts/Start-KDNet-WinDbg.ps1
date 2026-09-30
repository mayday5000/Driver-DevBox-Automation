# ================================================
# Start-KDNet-WinDbg.ps1
# WinDbg Preview KDNET launcher (host / debugger machine)
#
# Defaults match the previous hardcoded values:
#   port=50008
#   key=1.2.3.4
#   driver / service = InspectorDrv
#
# After WinDbg connects, load the generated debug.wds:
#   $< <path-to-debug.wds>
# ================================================

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$Port = "50008",

    [Parameter(Mandatory = $false)]
    [string]$Key = "1.2.3.4",

    [Parameter(Mandatory = $false)]
    [string]$DriverName = "InspectorDrv",

    [Parameter(Mandatory = $false)]
    [string]$WdsPath = "",

    [Parameter(Mandatory = $false)]
    [string]$WorkspacePath = "C:\Development\Damian\Drivers\WinDbgWorkspace.xml",

    [Parameter(Mandatory = $false)]
    [string]$SymbolPath = ""
)

if ($Port -notmatch '^\d+$' -or [int]$Port -lt 1 -or [int]$Port -gt 65535) {
    Write-Error "Port must be an integer in 1..65535. Got: $Port"
    exit 1
}
if ([string]::IsNullOrWhiteSpace($Key)) {
    Write-Error "Key cannot be empty."
    exit 1
}

$winDbgPath = "$env:LOCALAPPDATA\Microsoft\WindowsApps\WinDbgX.exe"
if (-not (Test-Path $winDbgPath)) {
    $alt = @(
        "$env:LOCALAPPDATA\Microsoft\WinDbg\WinDbgX.exe",
        "C:\Program Files\WindowsApps\Microsoft.WinDbg_*\WinDbgX.exe",
        "C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\windbg.exe"
    )
    foreach ($pattern in $alt) {
        $found = Get-Item $pattern -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($found) {
            $winDbgPath = $found.FullName
            break
        }
    }
}

if (-not (Test-Path $winDbgPath)) {
    Write-Error "WinDbg Preview not found! Please install it from the Microsoft Store."
    exit 1
}

if ([string]::IsNullOrWhiteSpace($WdsPath)) {
    $candidate = Join-Path $PSScriptRoot "debug.wds"
    if (Test-Path $candidate) {
        $WdsPath = $candidate
    }
}

if ([string]::IsNullOrWhiteSpace($SymbolPath)) {
    $SymbolPath = "srv*C:\Symbols*https://msdl.microsoft.com/download/symbols"
}

Write-Host "=== Launching WinDbg KDNET ===" -ForegroundColor Green
Write-Host "Driver : $DriverName" -ForegroundColor White
Write-Host "Listen : net:port=$Port,key=$Key" -ForegroundColor White
if ($WdsPath) {
    Write-Host "WDS    : $WdsPath" -ForegroundColor White
    Write-Host "After WinDbg connects, type:" -ForegroundColor Yellow
    Write-Host "   `$< $WdsPath" -ForegroundColor Cyan
}

$autoCmd = @"
.echo [AUTO] KDNET session for $DriverName
.echo [INFO] Connection net:port=$Port,key=$Key
"@

if (Test-Path $WorkspacePath) {
    $autoCmd += "`n.echo [AUTO] Loading WinDbg Workspace..."
    $autoCmd += "`n.wdf `"$WorkspacePath`""
    $autoCmd += "`n.echo [READY] Workspace loaded successfully."
}

if ($WdsPath -and (Test-Path $WdsPath)) {
    $autoCmd += "`n.echo [INFO] To load Debug script type: `$< $WdsPath"
}

& $winDbgPath `
    -k "net:port=$Port,key=$Key" `
    -y $SymbolPath `
    -c $autoCmd
