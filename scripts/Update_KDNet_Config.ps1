# ================================================
# Update_KDNet_Config.ps1
# Dynamically detects .sys file and updates paths
# Run after every driver rebuild
#
# Host-side script (development / WinDbg machine).
# Pair with Configure-Target-KDNet.ps1 on the TARGET.
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
    [string]$SymbolModule = "",

    [Parameter(Mandatory = $false)]
    [ValidateSet("Debug", "Release")]
    [string]$BuildConfig = "Debug",

    [Parameter(Mandatory = $false)]
    [string]$WorkspacePath = "C:\Development\Damian\Drivers\WinDbgWorkspace.xml"
)

$projectRoot = $PSScriptRoot
$defaultBinPath = "x64\$BuildConfig\"

if ([string]::IsNullOrWhiteSpace($Port)) {
    Write-Error "Port cannot be empty. Example: -Port 50008"
    exit 1
}
if ($Port -notmatch '^\d+$' -or [int]$Port -lt 1 -or [int]$Port -gt 65535) {
    Write-Error "Port must be an integer in 1..65535. Got: $Port"
    exit 1
}
if ([string]::IsNullOrWhiteSpace($Key)) {
    Write-Error "Key cannot be empty. Example: -Key 1.2.3.4"
    exit 1
}
if ([string]::IsNullOrWhiteSpace($DriverName)) {
    Write-Error "DriverName cannot be empty. Example: -DriverName InspectorDrv"
    exit 1
}

# Detect the solution file dynamically
$slnFiles = Get-ChildItem -Path $projectRoot -Filter "*.sln" -ErrorAction SilentlyContinue
if ($slnFiles.Count -eq 0) {
    Write-Error "No .sln file found in $projectRoot"
    exit 1
}
$slnFile = $slnFiles[0].Name

Write-Host "Cleaning old build artifacts..." -ForegroundColor Cyan
if (Test-Path "$projectRoot\x64") {
    Remove-Item "$projectRoot\x64" -Recurse -Force
}
if (Test-Path "$projectRoot\.vs") {
    Remove-Item "$projectRoot\.vs" -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host "Rebuilding driver in $BuildConfig configuration..." -ForegroundColor Cyan

# Find msbuild using vswhere (more reliable)
$msbuildPath = & "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe" `
    -latest -products * -requires Microsoft.Component.MSBuild `
    -find MSBuild\**\Bin\MSBuild.exe | Select-Object -First 1

if (-not $msbuildPath) {
    Write-Error "Could not find MSBuild. Please run this script from 'Developer Command Prompt for Visual Studio'."
    exit 1
}

& $msbuildPath "$projectRoot\$slnFile" /p:Configuration=$BuildConfig /p:Platform=x64 /t:Rebuild /m /nologo

if ($LASTEXITCODE -ne 0) {
    Write-Error "Build failed! Please check the output above."
    exit 1
}

Write-Host "Build completed successfully." -ForegroundColor Green
Write-Host ""

# Detect the .sys file
$sysSearchPath = Join-Path $projectRoot $defaultBinPath
$sysFiles = Get-ChildItem -Path $sysSearchPath -Filter "*.sys" -ErrorAction SilentlyContinue

if ($sysFiles.Count -eq 0) {
    Write-Error "No .sys file found in $sysSearchPath"
    exit 1
}

$sysFile = $sysFiles[0]
$sysFullPath = $sysFile.FullName
$sysModuleName = $sysFile.Name
$pdbModuleName = $sysModuleName -replace '\.sys$', '.pdb'

if ([string]::IsNullOrWhiteSpace($SymbolModule)) {
    $SymbolModule = [System.IO.Path]::GetFileNameWithoutExtension($sysModuleName)
}

Write-Host "Found driver: $sysFullPath" -ForegroundColor Green
Write-Host "Service name : $DriverName" -ForegroundColor Green
Write-Host "Symbol module: $SymbolModule" -ForegroundColor Green
Write-Host "KDNET        : net:port=$Port,key=$Key" -ForegroundColor Green

# Paths
$wdsPath       = Join-Path $projectRoot "debug.wds"
$launcherPath  = Join-Path $projectRoot "Start-KDNet-WinDbg.ps1"

# Print full paths to stdout
Write-Host ""
Write-Host "=== Updated Paths ===" -ForegroundColor Cyan
Write-Host "debug.wds fullpath     : $wdsPath" -ForegroundColor White
Write-Host "Start-KDNet-WinDbg.ps1 : $launcherPath" -ForegroundColor White
Write-Host ".sys fullpath          : $sysFullPath" -ForegroundColor White
Write-Host ""

# ================================================
# Generate debug.wds
# Only DriverEntry is armed. IOCTL / helper BPs were removed
# so the session stops at load instead of flooding on every IOCTL.
# ================================================
$wdsContent = @"
!sym noisy
.sympath $projectRoot\x64\$BuildConfig;srv*C:\Symbols*https://msdl.microsoft.com/download/symbols
.reload /f /i $sysModuleName

.echo [READY] Symbol path and reload complete.

bp ${SymbolModule}!DriverEntry "echo [BP] === DriverEntry ===; kv"
bl

.echo [READY] Breakpoint is set on DriverEntry. Load or reload the driver to hit it.
"@
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($wdsPath, $wdsContent, $utf8NoBom)
Write-Host "Updated debug.wds (no BOM)" -ForegroundColor Green

# ================================================
# Generate Start-KDNet-WinDbg.ps1
# ================================================
$launcherContent = @"
# ================================================
# WinDbg KDNET Launcher - $DriverName
# Loads Workspace + Debug Script and stops at prompt
# Generated by Update_KDNet_Config.ps1
# ================================================

`$winDbgPath     = "`$env:LOCALAPPDATA\Microsoft\WindowsApps\WinDbgX.exe"
`$workspacePath  = `"$WorkspacePath`"
`$wdsPath        = `"$wdsPath`"
`$kdnetPort      = `"$Port`"
`$kdnetKey       = `"$Key`"

if (-not (Test-Path `$winDbgPath)) {
    Write-Error "WinDbg Preview not found! Please install it from the Microsoft Store."
    exit 1
}

Write-Host "=== Launching WinDbg KDNET (port `$kdnetPort) ===" -ForegroundColor Green
Write-Host "After WinDbg connects, type this command manually:" -ForegroundColor Yellow
Write-Host "   `$$< `$wdsPath" -ForegroundColor Cyan

# Build the command that will run after WinDbg connects
`$autoCmd = @`"
.echo [AUTO] Loading WinDbg Workspace...
.wdf ``"$WorkspacePath``"
.echo [READY] Workspace loaded successfully.
.echo [INFO] To load Debug script type: `$`$< $wdsPath
`"@

& `$winDbgPath ``
    -k "net:port=`$kdnetPort,key=`$kdnetKey" ``
    -y "srv*C:\Symbols*https://msdl.microsoft.com/download/symbols;$projectRoot\x64\$BuildConfig" ``
    -c `$autoCmd
"@

$launcherContent | Out-File -FilePath $launcherPath -Encoding utf8 -Force
Write-Host "Updated Start-KDNet-WinDbg.ps1" -ForegroundColor Green

# ================================================
# Generate install.bat
# ================================================
$installBatPath = Join-Path $projectRoot "install.bat"
$installBatContent = @"
@echo off
setlocal enableddelayedexpansion

:: ================================================
:: install.bat
:: Copies the driver + PDB and installs it on the target machine
:: ================================================

set "driverName=$DriverName"
set "sysModuleName=$sysModuleName"
set "pdbModuleName=$pdbModuleName"
set "relativeDriverPath=x64\$BuildConfig"

set "sourceSys=%relativeDriverPath%\%sysModuleName%"
set "sourcePdb=%relativeDriverPath%\%pdbModuleName%"
set "targetSys=C:\Windows\System32\drivers\%sysModuleName%"
set "targetPdb=C:\Windows\System32\drivers\%pdbModuleName%"

echo.
echo ================================================
echo   Driver Installation Helper
echo ================================================
echo.

:: Check if the .sys file exists
if not exist "%sourceSys%" (
    echo [ERROR] %sysModuleName% not found in %relativeDriverPath%
    echo Please build the driver first.
    pause
    exit /b 1
)

echo Found driver: %sourceSys%
echo.

:: Copy the driver
echo Copying %sysModuleName% to %targetSys%...
copy /Y "%sourceSys%" "%targetSys%" >nul 2>&1

if %errorlevel% neq 0 (
    echo [ERROR] Failed to copy driver file to %targetSys%
    echo Make sure you are running this as Administrator.
    pause
    exit /b 1
)

echo [SUCCESS] Driver copied successfully.

:: Copy the PDB (important for source-level debugging)
if exist "%sourcePdb%" (
    echo Copying %pdbModuleName% to %targetPdb%...
    copy /Y "%sourcePdb%" "%targetPdb%" >nul 2>&1
    if %errorlevel% equ 0 (
        echo [SUCCESS] PDB copied successfully.
    ) else (
        echo [WARNING] Failed to copy PDB file.
    )
) else (
    echo [WARNING] PDB file not found - source debugging may be limited.
)

echo.

:: Execute installation commands
echo Stopping existing driver (if running)...
sc.exe stop %driverName% >nul 2>&1

echo Deleting existing driver (if exists)...
sc.exe delete %driverName% >nul 2>&1

echo Creating new driver service...
sc.exe create %driverName% type= kernel binPath= "%targetSys%"

if %errorlevel% neq 0 (
    echo [ERROR] Failed to create driver service.
    pause
    exit /b 1
)

echo Starting driver...
sc.exe start %driverName%

if %errorlevel% neq 0 (
    echo [ERROR] Failed to start driver. Check Event Viewer for details.
    pause
    exit /b 1
)

echo.
echo [SUCCESS] Driver installed and started successfully!
echo.
pause
"@
$installBatContent | Out-File -FilePath $installBatPath -Encoding ascii -Force
Write-Host "Generated install.bat (with PDB copy)" -ForegroundColor Green

# Create / Update Desktop Shortcut
$desktop = [Environment]::GetFolderPath("Desktop")
$shortcutPath = Join-Path $desktop "WinDbg Start KDNET.lnk"

$WScriptShell = New-Object -ComObject WScript.Shell
$shortcut = $WScriptShell.CreateShortcut($shortcutPath)
$shortcut.TargetPath = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
$shortcut.Arguments = "-NoExit -ExecutionPolicy Bypass -File `"$launcherPath`""
$shortcut.WorkingDirectory = $projectRoot
$shortcut.Save()

Write-Host "Desktop shortcut created/updated: $shortcutPath" -ForegroundColor Green

# Important message
Write-Host ""
Write-Host "==================================================" -ForegroundColor Yellow
Write-Host "IMPORTANT: Update the driver on the TARGET machine" -ForegroundColor Yellow
Write-Host ""
Write-Host "1. Run install.bat on the target (recommended for WDM)" -ForegroundColor Cyan
Write-Host "2. For minifilters run Install-Minifilter.ps1 instead" -ForegroundColor Cyan
Write-Host "3. Or manually:" -ForegroundColor Cyan
Write-Host "   sc.exe stop $DriverName" -ForegroundColor White
Write-Host "   sc.exe delete $DriverName" -ForegroundColor White
Write-Host "   sc.exe create $DriverName type= kernel binPath= C:\Windows\System32\drivers\$sysModuleName" -ForegroundColor White
Write-Host "   sc.exe start $DriverName" -ForegroundColor White
Write-Host ""
Write-Host "KDNET listen string (host WinDbg): net:port=$Port,key=$Key" -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Yellow

Write-Host "`nConfiguration updated successfully!" -ForegroundColor Green
Read-Host -Prompt "Press Enter to continue"
