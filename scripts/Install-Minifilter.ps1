#Requires -RunAsAdministrator
# ================================================
# Install-Minifilter.ps1
# Minifilter_Automation
#
# Installs / reinstalls a file-system minifilter on the TARGET
# machine: catalog signing, Driver Store cleanup, service +
# Instances\Altitude registry, fltmc verification, optional
# Driver Verifier handling.
#
# Usage:
#   .\Install-Minifilter.ps1 -DriverName FsMonDrv -DriverPath C:\build\fsmon
#   .\Install-Minifilter.ps1 -DriverName FsMonDrv -DriverPath . -ForceRename
# ================================================

param (
    [Parameter(Mandatory = $true)]
    [string]$DriverName,

    [Parameter(Mandatory = $true)]
    [string]$DriverPath,

    [switch]$ForceRename
)

Set-Location $DriverPath -ErrorAction Stop

# ──────────────────────────────────────────────────────────────────────────────
# Output Helpers
# ──────────────────────────────────────────────────────────────────────────────

function Write-Step      { param([string]$Message) Write-Host "[+] $Message" -ForegroundColor Green  }
function Write-Info      { param([string]$Message) Write-Host "[i] $Message" -ForegroundColor Yellow }
function Write-ErrorStep { param([string]$Message) Write-Host "[-] $Message" -ForegroundColor Red    }

# ──────────────────────────────────────────────────────────────────────────────
# NEW: Driver Verifier handling for development reload cycles
# ──────────────────────────────────────────────────────────────────────────────

function Disable-DriverVerifierForDriver {
    param([string]$DriverName)

    Write-Step "Checking Driver Verifier status for $DriverName.sys ..."

    $verifierStatus = & verifier /querysettings 2>$null
    if ($verifierStatus -match [regex]::Escape($DriverName) + "\.sys") {
        Write-Warning "Driver Verifier is currently ENABLED on $DriverName.sys"
        Write-Step "Temporarily disabling Driver Verifier to allow safe unload/replace ..."

        & verifier /reset $DriverName.sys 2>$null
        if ($LASTEXITCODE -eq 0) {
            Write-Step "Verifier settings for $DriverName.sys successfully reset"
        } else {
            Write-ErrorStep "verifier /reset $DriverName.sys failed (exit code $LASTEXITCODE)"
        }
    } else {
        Write-Info "Driver Verifier not active on $DriverName.sys"
    }

    # Also reset global / other drivers to be extra safe (especially kdnic)
    $globalState = & verifier /querysettings | Select-String "Verification flags"
    if ($globalState -match "0x[1-9a-fA-F]+") {
        Write-Warning "Global or other-driver Verifier flags detected → performing full reset"
        & verifier /reset 2>$null
        if ($LASTEXITCODE -eq 0) {
            Write-Step "Global Driver Verifier fully reset"
        } else {
            Write-ErrorStep "Global verifier /reset failed"
        }
    }

    $global:VerifierWasEnabled = $true
}

function ReEnable-DriverVerifierIfNeeded {
    if (-not $global:VerifierWasEnabled) { return }

    Write-Step "Re-enabling Driver Verifier **only** on $DriverName.sys (standard mode) ..."
    & verifier /reset 2>$null                  # clean slate
    & verifier /standard /driver $DriverName.sys

    if ($LASTEXITCODE -eq 0) {
        Write-Step "Driver Verifier re-enabled in standard mode for $DriverName.sys only"
        Write-Info "Settings take effect after next driver load / reboot"
    } else {
        Write-ErrorStep "Failed to re-enable verifier (exit code $LASTEXITCODE)"
    }
}

# ──────────────────────────────────────────────────────────────────────────────
# Driver Verifier status function
# ──────────────────────────────────────────────────────────────────────────────

function Get-DriverVerifierLoadStatus {
    param([string]$DriverName)

    $output = & verifier /query 2>$null
    if (-not $output) { return @{ Loaded = $false; LoadCount = 0; UnloadCount = 0; Verified = $false } }

    $verified = $output -match [regex]::Escape($DriverName) + "\.sys"
    $loadLine = $output | Where-Object { $_ -match [regex]::Escape($DriverName) + "\.sys\s*\(load:\s*(\d+)\s*/\s*unload:\s*(\d+)\)" }

    if ($loadLine -match "\(load:\s*(\d+)\s*/\s*unload:\s*(\d+)\)") {
        return @{
            Verified    = $true
            LoadCount   = [int]$Matches[1]
            UnloadCount = [int]$Matches[2]
            Loaded      = ([int]$Matches[1] -gt [int]$Matches[2])
        }
    }

    return @{ Verified = $verified; Loaded = $false; LoadCount = 0; UnloadCount = 0 }
}

# ──────────────────────────────────────────────────────────────────────────────
# Environment Checks
# ──────────────────────────────────────────────────────────────────────────────

function Check-TestMode {
    if (bcdedit | Select-String "testsigning\s+Yes") {
        Write-Info "Test Mode is ENABLED"
    } else {
        Write-Info "Test Mode is DISABLED - unsigned drivers will NOT load"
        Write-Host "Run: bcdedit /set testsigning on   then reboot" -ForegroundColor Yellow
    }
}

function Check-DriverSignatureEnforcement {
    $lua = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -EA SilentlyContinue
    if ($lua -and $lua.EnableLUA -eq 1) {
        Write-Info "Driver Signature Enforcement is ENABLED"
        return $true
    }
    Write-Info "Driver Signature Enforcement is DISABLED"
    return $false
}

function Check-WDKTools {
    $inf2cat  = "C:\Program Files (x86)\Windows Kits\10\bin\*\x86\Inf2Cat.exe"
    $signtool = "C:\Program Files (x86)\Windows Kits\10\bin\*\x64\signtool.exe"

    if ((Test-Path $inf2cat) -and (Test-Path $signtool)) {
        Write-Info "WDK tools (Inf2Cat & SignTool) detected"
        return $true
    }

    Write-Info "WDK / SDK tools missing (Inf2Cat or SignTool not found)"
    Write-Host "  --> Install WDK to sign catalog files" -ForegroundColor Yellow
    Write-Host "  --> https://learn.microsoft.com/en-us/windows-hardware/drivers/other-wdk-downloads" -ForegroundColor Yellow
    return $false
}

# ──────────────────────────────────────────────────────────────────────────────
# Check if registry already contains valid minifilter configuration
# ──────────────────────────────────────────────────────────────────────────────

function Test-MinifilterRegistryExists {
    param([string]$ServiceName)

    $baseKey = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"
    if (-not (Test-Path $baseKey)) { return $false }

    $props = Get-ItemProperty -Path $baseKey -ErrorAction SilentlyContinue
    if (-not $props) { return $false }

    if ($props.Type -ne 2)                          { return $false }
    if ($props.Group -notlike "FSFilter*")          { return $false }
    if ($props.DependOnService -notcontains "FltMgr") { return $false }

    $instKey = "$baseKey\Instances"
    if (-not (Test-Path $instKey)) { return $false }

    $defaultInst = Get-ItemProperty -Path $instKey -Name DefaultInstance -EA SilentlyContinue
    if (-not $defaultInst -or [string]::IsNullOrWhiteSpace($defaultInst.DefaultInstance)) {
        return $false
    }

    $instanceSubkeys = Get-ChildItem -Path $instKey -ErrorAction SilentlyContinue
    if ($instanceSubkeys.Count -eq 0) { return $false }

    $hasAltitude = $false
    foreach ($sub in $instanceSubkeys) {
        $alt = Get-ItemProperty -Path $sub.PSPath -Name Altitude -EA SilentlyContinue
        if ($alt -and $alt.Altitude -match '^\d{5,6}$') {
            $hasAltitude = $true
            break
        }
    }

    return $hasAltitude
}

# ──────────────────────────────────────────────────────────────────────────────
# Catalog Signature Functions
# ──────────────────────────────────────────────────────────────────────────────

function Validate-CatSignature {
    param([string]$CatPath)

    $signtoolPattern = "C:\Program Files (x86)\Windows Kits\10\bin\*\x64\signtool.exe"
    $signtool = Get-ChildItem $signtoolPattern -EA SilentlyContinue | Select-Object -First 1 -Expand FullName

    if (-not $signtool) {
        Write-Info "Skipping .cat signature check (signtool not found)"
        return $false
    }

    Write-Step "Verifying catalog signature..."
    $result = & $signtool verify /pa /v "$CatPath" 2>&1
    if ($result -match "Successfully verified") {
        Write-Step "Catalog signature is valid"
        return $true
    }

    Write-ErrorStep "Catalog signature verification FAILED"
    Write-Host $result -ForegroundColor Yellow
    return $false
}

function Should-SignCatalog {
    param([string]$CatFile)

    if (-not (Test-Path $CatFile)) {
        Write-Info "No catalog file found --> signing required"
        return $true
    }

    Write-Step "Existing catalog found --> checking signature..."
    $valid = Validate-CatSignature $CatFile

    if (-not $valid) {
        Write-ErrorStep "Existing catalog signature invalid --> will re-sign"
        return $true
    }

    Write-Step "Existing catalog signature is valid"
    return $false
}

function Remove-OldCatalogFile {
    param([string]$CatFile = ".\$using:DriverName.cat")

    if (Test-Path $CatFile) {
        Write-Step "Removing old/invalid catalog: $CatFile"
        Remove-Item $CatFile -Force -EA SilentlyContinue
    }
}

function Create-SelfSignedCodeSigningCert {
    $ts = Get-Date -Format "yyyyMMdd-HHmmss"
    $certName = "TestDriverCert_$ts"

    Write-Step "Creating temporary self-signed code-signing certificate..."

    try {
        $cert = New-SelfSignedCertificate `
            -Subject           "CN=$certName" `
            -Type              CodeSigningCert `
            -CertStoreLocation Cert:\CurrentUser\My `
            -Provider          "Microsoft Enhanced RSA and AES Cryptographic Provider" `
            -KeyLength         2048 `
            -KeyExportPolicy   Exportable `
            -NotAfter          (Get-Date).AddYears(3) `
            -ErrorAction       Stop

        $cerPath = ".\$certName.cer"
        Export-Certificate -Cert $cert -FilePath $cerPath -EA Stop | Out-Null

        Write-Step "Certificate exported to: $cerPath"
        return $cerPath
    }
    catch {
        Write-ErrorStep "Failed to create self-signed certificate"
        Write-Host $_.Exception.Message -ForegroundColor Yellow
        return $null
    }
}

function Generate-CatalogFile {
    param([string]$InfFile)

    $inf2catPattern = "C:\Program Files (x86)\Windows Kits\10\bin\*\x86\Inf2Cat.exe"
    $inf2cat = (Get-ChildItem $inf2catPattern -EA SilentlyContinue | Select-Object -First 1).FullName

    if (-not $inf2cat) {
        Write-ErrorStep "Inf2Cat.exe not found - cannot generate catalog"
        return $false
    }

    Write-Step "Running Inf2Cat to generate catalog..."
    & $inf2cat /driver:. /os:10_X64 /verbose

    $catFile = ".\$DriverName.cat"
    if (Test-Path $catFile) {
        Write-Step "Catalog created: $catFile"
        return $true
    }

    Write-ErrorStep "Catalog file was not generated"
    return $false
}

function Sign-CatalogFile {
    param(
        [string]$CatFile,
        [string]$CerPath
    )

    if (-not (Test-Path $CerPath)) {
        Write-ErrorStep "Certificate file not found: $CerPath"
        return $false
    }

    $signtoolPattern = "C:\Program Files (x86)\Windows Kits\10\bin\*\x64\signtool.exe"
    $signtool = (Get-ChildItem $signtoolPattern -EA SilentlyContinue | Select-Object -First 1).FullName

    if (-not $signtool) {
        Write-ErrorStep "signtool.exe not found - cannot sign catalog"
        return $false
    }

    Write-Step "Signing catalog with certificate..."
    & $signtool sign /v /f "$CerPath" /t http://timestamp.digicert.com /fd sha256 "$CatFile"

    return $true
}

# ──────────────────────────────────────────────────────────────────────────────
# INF & Driver Store Helpers
# ──────────────────────────────────────────────────────────────────────────────

function Find-InfFile {
    param([string]$Path, [string]$PreferredName)

    $inf = Join-Path $Path "$PreferredName.inf"
    if (Test-Path $inf) { return $inf }

    $found = Get-ChildItem -Path $Path -Filter "*.inf" | Select-Object -First 1
    if ($found) {
        Write-Step "Using $($found.Name) (no $PreferredName.inf found)"
        return $found.FullName
    }

    Write-ErrorStep "No .inf file found in $Path"
    exit 1
}

function Patch-DriverVerDate {
    param([string]$InfPath)

    $content = Get-Content $InfPath -Raw -EA Stop
    $today = Get-Date -Format "MM/dd/yyyy"

    if ($content -match 'DriverVer\s*=\s*\d{2}/\d{2}/\d{4},') {
        $new = $content -replace 'DriverVer\s*=\s*\d{2}/\d{2}/\d{4},', "DriverVer   = $today,"
        Set-Content $InfPath $new -NoNewline
        Write-Step "DriverVer updated to $today"
    } else {
        Write-ErrorStep "DriverVer line not found"
    }
}

function Rename-InfWithTimestamp {
    param([string]$InfPath)

    $dir  = Split-Path $InfPath
    $ts   = Get-Date -Format "yyyyMMddHHmmss"
    $new  = "${DriverName}_${ts}.inf"
    $newPath = Join-Path $dir $new

    Rename-Item $InfPath $new -Force
    Write-Step "Renamed INF -> $new (new Driver Store entry)"
    return $newPath
}

function Get-OemFiles {
    param (
        [Parameter(Mandatory = $true)]
        [string]$DriverName
    )

    Write-Host "Searching for previous driver versions in Driver Store for $DriverName..." -ForegroundColor Cyan

    $output = pnputil /enum-drivers
    $lines = $output -split "`r`n"

    $oemList = @()
    $currentOem = $null
    $inMatchingBlock = $false

    for ($i = 0; $i -lt $lines.Count; $i++) {
        $line = $lines[$i].Trim()

        if ($line -match "^Published Name:\s+(oem\d+\.inf)") {
            if ($currentOem -and $inMatchingBlock) {
                $oemList += $currentOem
            }
            $currentOem = $Matches[1]
            $inMatchingBlock = $false
            continue
        }

        if ($currentOem -and $line -match "$([regex]::Escape($DriverName)).*\.inf") {
            $inMatchingBlock = $true
            Write-Host "  Published Name: " -NoNewline -ForegroundColor Gray
            Write-Host "$currentOem" -ForegroundColor Green
        }

        if ($inMatchingBlock -and $line -and $line -notmatch "^$") {
            if ($line -match "^\s*(Original Name:|Provider Name:|Class Name:|Class GUID:|Driver Version:|Signer Name:)") {
                Write-Host "  $line" -ForegroundColor Gray
                if ($line -match "^\s*Signer Name:") {
                    Write-Host ""
                }
            }
        }
    }
    
    if ($currentOem -and $inMatchingBlock) {
        $oemList += $currentOem
    }

    return $oemList | Sort-Object -Unique
}

function Clean-PreviousVersions {
    param([string]$DriverName)

    Write-Step "Searching for previous versions in Driver Store..."

    $oems = Get-OemFiles $DriverName
    if ($oems.Count -eq 0) {
        Write-Step "No previous versions found"
        return
    }

    Write-Host "Found $($oems.Count) oem packages to remove:" -ForegroundColor Yellow
    $oems | ForEach-Object { Write-Host "  $_" }

    $ans = Read-Host "Delete them? (y/n)"
    if ($ans -notin 'y','Y') { Write-Step "Skipped"; return }

    foreach ($oem in $oems) {
        for ($i = 1; $i -le 3; $i++) {
            Write-Step "Deleting $oem (attempt $i)"
            $r = pnputil /delete-driver $oem /uninstall /force 2>&1
            if ($r -match "successfully deleted|Driver package deleted") {
                Write-Step "Success"
                break
            }
            Write-ErrorStep "Attempt $i failed"
            Start-Sleep -Milliseconds 1200
        }
    }
}

# ──────────────────────────────────────────────────────────────────────────────
# Get expected GUID for a given class name (from devguid.h)
# ──────────────────────────────────────────────────────────────────────────────

function Get-ExpectedClassGuid {
    param([string]$ClassName)

    $guidTable = @{
        "1394"                  = "{6bdd1fc1-810f-11d0-bec7-08002be2092f}"
        "1394DEBUG"             = "{66f250d6-7801-4a64-b139-eea80a450b24}"
        "61883"                 = "{7ebefbc0-3200-11d2-b4c2-00a0c9697d07}"
        "ADAPTER"               = "{4d36e964-e325-11ce-bfc1-08002be10318}"
        "APMSUPPORT"            = "{d45b1c18-c8fa-11d1-9f77-0000f805f530}"
        "AVC"                   = "{c06ff265-ae09-48f0-812c-16753d7cba83}"
        "BATTERY"               = "{72631e54-78a4-11d0-bcf7-00aa00b7b32a}"
        "BIOMETRIC"             = "{53d29ef7-377c-4d14-864b-eb3a85769359}"
        "BLUETOOTH"             = "{e0cbf06c-cd8b-4647-bb8a-263b43f0f974}"
        "CAMERA"                = "{ca3e7ab9-b4c3-4ae6-8251-579ef933890f}"
        "CDROM"                 = "{4d36e965-e325-11ce-bfc1-08002be10318}"
        "COMPUTEACCELERATOR"    = "{f01a9d53-3ff6-48d2-9f97-c8a7004be10c}"
        "COMPUTER"              = "{4d36e966-e325-11ce-bfc1-08002be10318}"
        "DECODER"               = "{6bdd1fc2-810f-11d0-bec7-08002be2092f}"
        "DISKDRIVE"             = "{4d36e967-e325-11ce-bfc1-08002be10318}"
        "DISPLAY"               = "{4d36e968-e325-11ce-bfc1-08002be10318}"
        "DOT4"                  = "{48721b56-6795-11d2-b1a8-0080c72e74a2}"
        "DOT4PRINT"             = "{49ce6ac8-6f86-11d2-b1e5-0080c72e74a2}"
        "EHSTORAGESILO"         = "{9da2b80f-f89f-4a49-a5c2-511b085b9e8a}"
        "ENUM1394"              = "{c459df55-db08-11d1-b009-00a0c9081ff6}"
        "EXTENSION"             = "{e2f84ce7-8efa-411c-aa69-97454ca4cb57}"
        "FDC"                   = "{4d36e969-e325-11ce-bfc1-08002be10318}"
        "FIRMWARE"              = "{f2e7dd72-6468-4e36-b6f1-6488f42c1b52}"
        "FLOPPYDISK"            = "{4d36e980-e325-11ce-bfc1-08002be10318}"
        "GPS"                   = "{6bdd1fc3-810f-11d0-bec7-08002be2092f}"
        "HDC"                   = "{4d36e96a-e325-11ce-bfc1-08002be10318}"
        "HIDCLASS"              = "{745a17a0-74d3-11d0-b6fe-00a0c90f57da}"
        "HOLOGRAPHIC"           = "{d612553d-06b1-49ca-8938-e39ef80eb16f}"
        "IMAGE"                 = "{6bdd1fc6-810f-11d0-bec7-08002be2092f}"
        "INFINIBAND"            = "{30ef7132-d858-4a0c-ac24-b9028a5cca3f}"
        "INFRARED"              = "{6bdd1fc5-810f-11d0-bec7-08002be2092f}"
        "KEYBOARD"              = "{4d36e96b-e325-11ce-bfc1-08002be10318}"
        "LEGACYDRIVER"          = "{8ecc055d-047f-11d1-a537-0000f8753ed1}"
        "MEDIA"                 = "{4d36e96c-e325-11ce-bfc1-08002be10318}"
        "MEDIUM_CHANGER"        = "{ce5939ae-ebde-11d0-b181-0000f8753ec4}"
        "MEMORY"                = "{5099944a-f6b9-4057-a056-8c550228544c}"
        "MODEM"                 = "{4d36e96d-e325-11ce-bfc1-08002be10318}"
        "MONITOR"               = "{4d36e96e-e325-11ce-bfc1-08002be10318}"
        "MOUSE"                 = "{4d36e96f-e325-11ce-bfc1-08002be10318}"
        "MTD"                   = "{4d36e970-e325-11ce-bfc1-08002be10318}"
        "MULTIFUNCTION"         = "{4d36e971-e325-11ce-bfc1-08002be10318}"
        "MULTIPORTSERIAL"       = "{50906cb8-ba12-11d1-bf5d-0000f805f530}"
        "NET"                   = "{4d36e972-e325-11ce-bfc1-08002be10318}"
        "NETCLIENT"             = "{4d36e973-e325-11ce-bfc1-08002be10318}"
        "NETDRIVER"             = "{87ef9ad1-8f70-49ee-b215-ab1fcadcbe3c}"
        "NETSERVICE"            = "{4d36e974-e325-11ce-bfc1-08002be10318}"
        "NETTRANS"              = "{4d36e975-e325-11ce-bfc1-08002be10318}"
        "NETUIO"                = "{78912bc1-cb8e-4b28-a329-f322ebadbe0f}"
        "NODRIVER"              = "{4d36e976-e325-11ce-bfc1-08002be10318}"
        "PCMCIA"                = "{4d36e977-e325-11ce-bfc1-08002be10318}"
        "PNPPRINTERS"           = "{4658ee7e-f050-11d1-b6bd-00c04fa372a7}"
        "PORTS"                 = "{4d36e978-e325-11ce-bfc1-08002be10318}"
        "PRINTER"               = "{4d36e979-e325-11ce-bfc1-08002be10318}"
        "PRINTERUPGRADE"        = "{4d36e97a-e325-11ce-bfc1-08002be10318}"
        "PRINTQUEUE"            = "{1ed2bbf9-11f0-4084-b21f-ad83a8e6dcdc}"
        "PROCESSOR"             = "{50127dc3-0f36-415e-a6cc-4cb3be910b65}"
        "SBP2"                  = "{d48179be-ec20-11d1-b6b8-00c04fa372a7}"
        "SCMDISK"               = "{53966cb1-4d46-4166-bf23-c522403cd495}"
        "SCMVOLUME"             = "{53b3cf03-8f5a-4788-91b6-d19e9fccbfbf}"
        "SCSIADAPTER"           = "{4d36e97b-e325-11ce-bfc1-08002be10318}"
        "SECURITYACCELERATOR"   = "{268c95a1-edfe-11d3-95c3-0010dc4050a5}"
        "SENSOR"                = "{5175d334-c371-4806-b3ba-71fd53c9258d}"
        "SIDESHOW"              = "{997b5d8d-c442-4f2e-baf3-9c8e671e9e21}"
        "SMARTCARDREADER"       = "{50dd5230-ba8a-11d1-bf5d-0000f805f530}"
        "SMRDISK"               = "{53487c23-680f-4585-acc3-1f10d6777e82}"
        "SMRVOLUME"             = "{53b3cf03-8f5a-4788-91b6-d19e9fccbfbf}"
        "SOFTWARECOMPONENT"     = "{5c4c3332-344d-483c-8739-259e934c9cc8}"
        "SOUND"                 = "{4d36e97c-e325-11ce-bfc1-08002be10318}"
        "SYSTEM"                = "{4d36e97d-e325-11ce-bfc1-08002be10318}"
        "TAPEDRIVE"             = "{6d807884-7d21-11cf-801c-08002be10318}"
        "UNKNOWN"               = "{4d36e97e-e325-11ce-bfc1-08002be10318}"
        "UCM"                   = "{e6f1aa1c-7f3b-4473-b2e8-c97d8ac71d53}"
        "USB"                   = "{36fc9e60-c465-11cf-8056-444553540000}"
        "VOLUME"                = "{71a27cdd-812a-11d0-bec7-08002be2092f}"
        "VOLUMESNAPSHOT"        = "{533c5b84-ec70-11d2-9505-00c04f79deaf}"
        "WCEUSBS"               = "{25dbce51-6c8f-4a72-8a6d-b54c2b4fc835}"
        "WPD"                   = "{eec5ad98-8080-425f-922a-dabf3de3f69a}"

        # Filesystem filter classes
        "FSFILTER_TOP"                  = "{b369baf4-5568-4e82-a87e-a93eb16bca87}"
        "FSFILTER_ACTIVITYMONITOR"      = "{b86dff51-a31e-4bac-b3cf-e8cfe75c9fc2}"
        "FSFILTER_UNDELETE"             = "{fe8f1572-c67a-48c0-bbac-0b5c6d66cafb}"
        "FSFILTER_ANTIVIRUS"            = "{b1d1a169-c54f-4379-81db-bee7d88d7454}"
        "FSFILTER_REPLICATION"          = "{48d3ebc4-4cf8-48ff-b869-9c68ad42eb9f}"
        "FSFILTER_CONTINUOUSBACKUP"     = "{71aa14f8-6fad-4622-ad77-92bb9d7e6947}"
        "FSFILTER_CONTENTSCREENER"      = "{3e3f0674-c83c-4558-bb26-9820e1eba5c5}"
        "FSFILTER_QUOTAMANAGEMENT"      = "{8503c911-a6c7-4919-8f79-5028f5866b0c}"
        "FSFILTER_SYSTEMRECOVERY"       = "{2db15374-706e-4131-a0c7-d7c78eb0289a}"
        "FSFILTER_CFSMETADATASERVER"    = "{cdcf0939-b75b-4630-bf76-80f7ba655884}"
        "FSFILTER_HSM"                  = "{d546500a-2aeb-45f6-9482-f4b1799c3177}"
        "FSFILTER_COMPRESSION"          = "{f3586baf-b5aa-49b5-8d6c-0569284c639f}"
        "FSFILTER_ENCRYPTION"           = "{a0a701c0-a511-42ff-aa6c-06dc0395576f}"
        "FSFILTER_VIRTUALIZATION"       = "{f75a86c0-10d8-4c3a-b233-ed60e4cdfaac}"
        "FSFILTER_PHYSICALQUOTAMANAGEMENT" = "{6a0a8e78-bba6-4fc4-a709-1e33cd09d67e}"
        "FSFILTER_OPENFILEBACKUP"       = "{f8ecafa6-66d1-41a5-899b-66585d7216b7}"
        "FSFILTER_SECURITYENHANCER"     = "{d02bc3da-0c8e-4945-9bd5-f1883c22c8c8}"
        "FSFILTER_COPYPROTECTION"       = "{89786ff1-9c12-402f-9c9e-17753c7f4375}"
        "FSFILTER_BOTTOM"               = "{37765ea0-5958-4fc9-b04b-2fdfeff97e59e}"
        "FSFILTER_SYSTEM"               = "{5d1b9aaa-01e2-46af-849f-272b3f324c46}"
        "FSFILTER_INFRASTRUCTURE"       = "{e55fa6f9-128c-4d04-abab-630c74b1453a}"
    }

    if ($guidTable.ContainsKey($ClassName)) {
        return $guidTable[$ClassName]
    }

    return $null  # Unknown class -> no validation possible
}

# ──────────────────────────────────────────────────────────────────────────────
# Validate altitude range based on LoadOrderGroup
# ──────────────────────────────────────────────────────────────────────────────

function Validate-AltitudeRange {
    param(
        [Parameter(Mandatory = $true)]
        [int64]$Altitude,

        [Parameter(Mandatory = $true)]
        [string]$LoadOrderGroup
    )

    $rangeValid = $false
    $expectedRange = ""
    $category = ""

    switch -Wildcard ($LoadOrderGroup) {
        "*Bottom*"              { $rangeValid = ($Altitude -ge 0 -and $Altitude -le 49999);   $expectedRange = "0-49999";      $category = "Bottom" }
        "*System*"              { $rangeValid = ($Altitude -ge 50000 -and $Altitude -le 99999);  $expectedRange = "50000-99999";   $category = "System" }
        "*Infrastructure*"      { $rangeValid = ($Altitude -ge 100000 -and $Altitude -le 109999); $expectedRange = "100000-109999"; $category = "Infrastructure" }
        "*Encryption*"          { $rangeValid = ($Altitude -ge 140000 -and $Altitude -le 149999); $expectedRange = "140000-149999"; $category = "Encryption" }
        "*Compression*"         { $rangeValid = ($Altitude -ge 160000 -and $Altitude -le 169999); $expectedRange = "160000-169999"; $category = "Compression" }
        "*HSM*"                 { $rangeValid = ($Altitude -ge 180000 -and $Altitude -le 189999); $expectedRange = "180000-189999"; $category = "HSM" }
        "*Virtualisation*"      { $rangeValid = ($Altitude -ge 200000 -and $Altitude -le 209999); $expectedRange = "200000-209999"; $category = "Virtualisation" }
        "*Physical Quota*"      { $rangeValid = ($Altitude -ge 210000 -and $Altitude -le 219999); $expectedRange = "210000-219999"; $category = "Physical Quota" }
        "*Open File*"           { $rangeValid = ($Altitude -ge 220000 -and $Altitude -le 229999); $expectedRange = "220000-229999"; $category = "Open File" }
        "*Security*"            { $rangeValid = ($Altitude -ge 250000 -and $Altitude -le 259999); $expectedRange = "250000-259999"; $category = "Security" }
        "*Content Screener*"    { $rangeValid = ($Altitude -ge 260000 -and $Altitude -le 269999); $expectedRange = "260000-269999"; $category = "Content Screener" }
        "*Continuous Backup*"   { $rangeValid = ($Altitude -ge 270000 -and $Altitude -le 279999); $expectedRange = "270000-279999"; $category = "Continuous Backup" }
        "*Replication*"         { $rangeValid = ($Altitude -ge 280000 -and $Altitude -le 289999); $expectedRange = "280000-289999"; $category = "Replication" }
        "*Top*"                 { $rangeValid = ($Altitude -ge 320000 -and $Altitude -le 329999); $expectedRange = "320000-329999"; $category = "Top" }
        "*Anti-Virus*"          { $rangeValid = ($Altitude -ge 330000 -and $Altitude -le 339999); $expectedRange = "330000-339999"; $category = "Anti-Virus" }
        "*Undelete*"            { $rangeValid = ($Altitude -ge 340000 -and $Altitude -le 349999); $expectedRange = "340000-349999"; $category = "Undelete" }
        "*Activity Monitor*"    { $rangeValid = ($Altitude -ge 360000 -and $Altitude -le 389999); $expectedRange = "360000-389999"; $category = "Activity Monitor" }
        default                 { 
            Write-ErrorStep "Unrecognized LoadOrderGroup category '$LoadOrderGroup' - cannot validate altitude range"
            return $false 
        }
    }

    if (-not $rangeValid) {
        Write-ErrorStep "Altitude $Altitude is OUTSIDE recommended range for '$LoadOrderGroup' (should be $expectedRange)"
        Write-Info "  Category: $category"
        return $false
    }

    return $true
}

# ──────────────────────────────────────────────────────────────────────────────
# Validate INF content
# ──────────────────────────────────────────────────────────────────────────────

function Validate-InfContent {
    param([string]$InfPath)

    $content = Get-Content $InfPath -Raw -ErrorAction SilentlyContinue
    if (-not $content) {
        Write-ErrorStep "Cannot read INF file"
        return $null
    }

    $valid = $true
    $altitude = $null
    $loadGroup = $null

    if ($content -notmatch '\[DefaultInstall\.NTamd64\]') {
        Write-ErrorStep "[DefaultInstall.NTamd64] section missing (required for x64)"
        $valid = $false
    }

    if ($content -notmatch 'CopyFiles\s*=\s*DriverFiles' -or $content -notmatch '\[DriverFiles\]') {
        Write-ErrorStep "Missing CopyFiles=DriverFiles + [DriverFiles] section"
        $valid = $false
    }

    $class = if ($content -match 'Class\s*=\s*"([^"]+)"') { $Matches[1].Trim() } else { "" }
    $guid  = if ($content -match 'ClassGuid\s*=\s*{([^}]+)}') { $Matches[1].Trim() } else { "" }

    if ($class) {
        $expectedGuid = Get-ExpectedClassGuid -ClassName $class
        if ($expectedGuid -and $guid -and $guid -ne $expectedGuid) {
            Write-ErrorStep "Class='$class' has incorrect GUID (expected $expectedGuid, got $guid)"
            $valid = $false
        } elseif (-not $expectedGuid -and $guid) {
            Write-Info "Class='$class' is unknown - GUID validation skipped (got $guid)"
        }
    }

    if ($content -match '(?im)^\s*LoadOrderGroup\s*=\s*([^;\r\n]+)') {
        $loadGroup = $Matches[1].Trim()
    }

    if ([string]::IsNullOrWhiteSpace($loadGroup)) {
        Write-ErrorStep "LoadOrderGroup is missing or could not be parsed from INF"
        $valid = $false
    }
    elseif ($loadGroup -notlike "FSFilter*") {
        Write-ErrorStep "Invalid LoadOrderGroup '$loadGroup' - must start with 'FSFilter'"
        $valid = $false
    }

    if ($content -match '(?im)Altitude["\s,]*0x00000000[,\s]*[""]?(\d+)[""]?') {
        $altitude = $Matches[1].Trim()
    }
    elseif ($content -match '(?im)Altitude.*?(\d{5,6})') {
        $altitude = $Matches[1].Trim()
    }

    if ([string]::IsNullOrWhiteSpace($altitude)) {
        Write-ErrorStep "Altitude value could not be found or parsed"
        $valid = $false
    }

    if ($valid -and $altitude) {
        $altNum = [int64]$altitude
        if (-not (Validate-AltitudeRange -Altitude $altNum -LoadOrderGroup $loadGroup)) {
            $valid = $false
        }
    }

    if (-not $valid) {
        return $null
    }

    return @{ Altitude = $altitude; LoadOrderGroup = $loadGroup }
}

# ──────────────────────────────────────────────────────────────────────────────
# .sys file comparison function
# ──────────────────────────────────────────────────────────────────────────────

function Test-DriverFileMatch {
    param(
        [string]$SourcePath,
        [string]$DestPath
    )

    if (-not (Test-Path $SourcePath)) {
        Write-ErrorStep "Source .sys not found: $SourcePath"
        exit 1
    }

    $srcHash = (Get-FileHash $SourcePath -Algorithm SHA256).Hash
    Write-Info "Source file hash: $srcHash"

    if (-not (Test-Path $DestPath)) {
        Write-Step "Destination .sys does not exist in System32"
        return "not_present"
    }

    $dstHash = (Get-FileHash $DestPath -Algorithm SHA256).Hash
    Write-Info "Destination file hash: $dstHash"

    if ($srcHash -eq $dstHash) {
        Write-Step "Destination .sys is identical (hash match)"
        return $true
    } else {
        Write-Step "Destination .sys differs (hash mismatch) - will replace"
        return $false
    }
}

# ──────────────────────────────────────────────────────────────────────────────
# Detect zombie lock (kernel reference)
# ──────────────────────────────────────────────────────────────────────────────

function Test-ZombieLock {
    param(
        [string]$DriverName,
        [string]$DestPath
    )

    $zombie = $false

    if (Test-Path $DestPath) {
        try {
            $fs = [System.IO.File]::Open($DestPath, 'Open', 'ReadWrite', 'None')
            $fs.Close()
        }
        catch [System.UnauthorizedAccessException], [System.IO.IOException] {
            if ($_.Exception.Message -match "used by another process|access denied|sharing violation") {
                Write-Warning "File locked (sharing violation) -> likely zombie"
                $zombie = $true
            }
        }
    }

    $verif = Get-DriverVerifierLoadStatus $DriverName
    if ($verif.Verified -and $verif.LoadCount -gt ($verif.UnloadCount + 1)) {
        Write-Warning "Verifier shows load > unload -> possible zombie"
        $zombie = $true
    }

    if (Test-Path $DestPath) {
        $testRename = $DestPath -replace '\.sys$', '_testrename.sys'
        try {
            Rename-Item $DestPath $testRename -EA Stop
            Rename-Item $testRename $DestPath -EA Stop
        }
        catch {
            Write-Warning "Rename test failed -> likely kernel lock (zombie)"
            $zombie = $true
        }
    }

    return $zombie
}

# ──────────────────────────────────────────────────────────────────────────────
# Replace .sys file (takeown + delete + rename if locked)
# ──────────────────────────────────────────────────────────────────────────────

function Replace-DriverFile {
    param(
        [string]$SourcePath,
        [string]$DestPath,
        [string]$DriverName
    )

    $result = [PSCustomObject]@{
        Success = $false
        Zombie  = $false
    }

    if (Test-Path $DestPath) {
        Write-Step "Force removing old $DriverName.sys (takeown + icacls + delete)..."
        & takeown /F $DestPath >$null 2>&1
        & icacls $DestPath /grant Administrators:F >$null 2>&1
        $deleted = $false
        for ($i = 1; $i -le 3; $i++) {
            try {
                Remove-Item $DestPath -Force -EA Stop
                Start-Sleep -Seconds 2
                if (-not (Test-Path $DestPath)) {
                    Write-Step "Old .sys deleted successfully"
                    $deleted = $true
                    break
                }
            } catch {
                Write-ErrorStep "Delete attempt $i failed - file still locked"
            }
        }
        if (-not $deleted) {
            Write-Step "Could not delete old .sys file - attempting rename to break lock"
            $zombiePath = $DestPath -replace '\.sys$', "_zombie_$(Get-Date -Format HHmmss).sys"
            try {
                Rename-Item $DestPath $zombiePath -Force -EA Stop
                Write-Step "Renamed old .sys to $zombiePath (lock broken)"
                $result.Zombie = $true
            } catch {
                Write-ErrorStep "Rename also failed - file is zombie-locked by kernel"
                $result.Zombie = $true
            }
        }
    }

    Write-Step "Force copying fresh $DriverName.sys to System32\drivers..."
    $copyOk = $false
    $srcSize = (Get-Item $SourcePath).Length
    for ($i = 1; $i -le 3; $i++) {
        try {
            Copy-Item $SourcePath $DestPath -Force -EA Stop
            Start-Sleep -Seconds 2
            if (Test-Path $DestPath) {
                $dstSize = (Get-Item $DestPath).Length
                if ($dstSize -eq $srcSize) {
                    Write-Step "Copy verified OK (size matches)"
                    $copyOk = $true
                    break
                } else {
                    Write-ErrorStep "Copy size mismatch on attempt $i"
                }
            }
        } catch {
            Write-ErrorStep "Copy attempt $i failed"
        }
    }
    if ($copyOk) {
        $result.Success = $true
    } else {
        Write-ErrorStep "Could not copy driver after retries - file may still be locked"
    }

    return $result
}

# ──────────────────────────────────────────────────────────────────────────────
# NEW: Generate unique service name + .sys path + binPath
# ──────────────────────────────────────────────────────────────────────────────

function Get-UniqueDriverPaths {
    param(
        [Parameter(Mandatory = $true)]
        [string]$BaseDriverName
    )

    $uniqueSuffix = Get-Date -Format HHmmss
    $destSysFinal = "C:\Windows\System32\drivers\$BaseDriverName`_$uniqueSuffix.sys"
    $binPathFinal = "\??\$destSysFinal"

    return @{
        ServiceNameSuffix = "_V$uniqueSuffix"
        DestSysPath       = $destSysFinal
        BinPath           = $binPathFinal
    }
}

# ──────────────────────────────────────────────────────────────────────────────
# NEW: Get next valid altitude within the same category range
# ──────────────────────────────────────────────────────────────────────────────

function Get-NextAltitude {
    param(
        [Parameter(Mandatory = $true)]
        [int64]$CurrentAltitude,

        [Parameter(Mandatory = $true)]
        [string]$LoadOrderGroup
    )

    $step = 100
    $candidate = $CurrentAltitude + $step

    $ranges = @{
        "*Bottom*"               = @{ Min = 0;      Max = 49999  }
        "*System*"               = @{ Min = 50000;  Max = 99999  }
        "*Infrastructure*"       = @{ Min = 100000; Max = 109999 }
        "*Encryption*"           = @{ Min = 140000; Max = 149999 }
        "*Compression*"          = @{ Min = 160000; Max = 169999 }
        "*HSM*"                  = @{ Min = 180000; Max = 189999 }
        "*Virtualisation*"       = @{ Min = 200000; Max = 209999 }
        "*Physical Quota*"       = @{ Min = 210000; Max = 219999 }
        "*Open File*"            = @{ Min = 220000; Max = 229999 }
        "*Security*"             = @{ Min = 250000; Max = 259999 }
        "*Content Screener*"     = @{ Min = 260000; Max = 269999 }
        "*Continuous Backup*"    = @{ Min = 270000; Max = 279999 }
        "*Replication*"          = @{ Min = 280000; Max = 289999 }
        "*Top*"                  = @{ Min = 320000; Max = 329999 }
        "*Anti-Virus*"           = @{ Min = 330000; Max = 339999 }
        "*Undelete*"             = @{ Min = 340000; Max = 349999 }
        "*Activity Monitor*"     = @{ Min = 360000; Max = 389999 }
    }

    $range = $null
    foreach ($key in $ranges.Keys) {
        if ($LoadOrderGroup -like $key) {
            $range = $ranges[$key]
            break
        }
    }

    if (-not $range) {
        Write-Warning "No known range for LoadOrderGroup '$LoadOrderGroup'. Incrementing anyway."
        return $candidate
    }

    if ($candidate -le $range.Max) {
        Write-Info "Next altitude: $candidate (within $($range.Min)-$($range.Max))"
        return $candidate
    }

    Write-Warning "Would exceed max altitude $($range.Max) - restarting at beginning of range"
    return $range.Min + $step
}

# ──────────────────────────────────────────────────────────────────────────────
# Main Execution
# ──────────────────────────────────────────────────────────────────────────────

Check-TestMode
$enforce = Check-DriverSignatureEnforcement
$hasWdk  = Check-WDKTools

# NEW - prepare safe driver replacement by disabling verifier early
Disable-DriverVerifierForDriver -DriverName $DriverName

$sourceSys = Join-Path $DriverPath "$DriverName.sys"
$defaultDestSys = "C:\Windows\System32\drivers\$DriverName.sys"

$zombieDetected = $false
$forceUniqueMode = $ForceRename.IsPresent

if (-not $forceUniqueMode) {
    Write-Step "Early zombie lock detection..."
    $zombieDetected = Test-ZombieLock -DriverName $DriverName -DestPath $defaultDestSys
    if ($zombieDetected) {
        Write-Warning "Zombie lock detected -> will use unique service name and next altitude"
    }
} else {
    Write-Step "ForceRename mode enabled -> always using unique service name and next altitude (skipping zombie & file checks)"
}

$fileMatchStatus = Test-DriverFileMatch -SourcePath $sourceSys -DestPath $defaultDestSys

$service = $null
try {
    $service = Get-Service -Name $DriverName -ErrorAction Stop
    Write-Info "Service '$DriverName' exists. Current status: $($service.Status)"
}
catch {
    Write-Info "No SCM service named '$DriverName' found."
}

if ($service) {
    if ($service.Status -eq 'Running') {
        if ($fileMatchStatus -eq $true -and -not $zombieDetected -and -not $forceUniqueMode) {
            Write-Info "Service is already RUNNING (same version, no zombie lock)."
        } else {
            Write-Info "Service is already RUNNING but different version, zombie lock, or ForceRename requested."
        }
        $reinstall = Read-Host "Reinstall anyway? (y/n)"
        if ($reinstall -notin 'y','Y') {
            Write-Step "Exiting as requested."
            exit 0
        }
        Write-Step "Proceeding with reinstall..."

        # Force unique name + altitude when user explicitly wants to reinstall a running driver
        if (-not $forceUniqueMode) {
            $forceUniqueMode = $true
            Write-Warning "User requested reinstall of running driver -> forcing unique service name + next altitude"
        }
    }
    elseif ($service.Status -eq 'Stopped') {
        if ($fileMatchStatus -eq $true -and -not $zombieDetected -and -not $forceUniqueMode) {
            Write-Info "Service is STOPPED (same version, no zombie lock)."
            try {
                Write-Info "Attempting to start existing version..."
                Start-Service -Name $DriverName -ErrorAction Stop
                Start-Sleep -Seconds 4
                $service.Refresh()
                if ($service.Status -eq 'Running') {
                    Write-Step "Service successfully started."
                    $fltmcOut = fltmc instances | Where-Object { $_ -match [regex]::Escape($DriverName) }
                    if ($fltmcOut) {
                        Write-Step "Driver is active (fltmc shows instances)."
                        Write-Host "`nInstances:"
                        $fltmcOut | ForEach-Object { Write-Host "  $_" }

                        $currentService = Get-Service -Name $DriverName
                        if ($currentService.StartType -ne 'Automatic') {
                            Write-Info "Driver is currently set to $($currentService.StartType) start (not auto-start)."
                            $setAuto = Read-Host "Do you want to set it to Automatic startup? (y/n)"
                            if ($setAuto -in 'y','Y') {
                                try {
                                    Set-Service -Name $DriverName -StartupType Automatic -ErrorAction Stop
                                    Write-Step "Successfully set $DriverName to Automatic startup."
                                }
                                catch {
                                    Write-ErrorStep "Failed to set auto-start: $($_.Exception.Message)"
                                }
                            }
                        } else {
                            Write-Info "Driver is already set to Automatic startup."
                        }

                        exit 0
                    } else {
                        Write-Info "Service started but no fltmc instances visible yet."
                    }
                }
            }
            catch {
                Write-ErrorStep "Failed to start service: $($_.Exception.Message)"
            }
        } else {
            Write-Info "Service is STOPPED and different version / zombie / ForceRename -> full reinstall required."
        }
    }
    else {
        Write-Info "Service exists but in unexpected state ($($service.Status)) -> proceeding to reinstall"
    }
}
else {
    Write-Step "No SCM service found. Checking fltmc instances..."

    $fltmcInstances = fltmc instances | Where-Object { $_ -match [regex]::Escape($DriverName) }
    if ($fltmcInstances) {
        Write-Info "Driver '$DriverName' appears loaded via fltmc (no SCM service)."
        Write-Host "`nInstances:"
        $fltmcInstances | ForEach-Object { Write-Host "  $_" }

        $reinstall = Read-Host "Reinstall anyway? (y/n)"
        if ($reinstall -notin 'y','Y') {
            Write-Step "Exiting as requested."
            exit 0
        }
        Write-Step "Proceeding with reinstall..."
    }
    else {
        Write-Info "No active instance found in fltmc nor in SCM -> full installation required."
    }
}

# ─── Proceed with full installation ─────────────────────────────────────────

Write-Step "Checking for existing minifilter registry configuration..."

$registryOk = Test-MinifilterRegistryExists -ServiceName $DriverName

if ($registryOk -and -not $forceUniqueMode -and -not $zombieDetected) {
    Write-Step "Valid registry configuration found -> attempting quick load via fltmc..."

    $loadOutput = fltmc load $DriverName 2>&1
    Start-Sleep -Milliseconds 1200

    $filtersLine   = fltmc filters   | Where-Object { $_ -match [regex]::Escape($DriverName) }
    $instancesLine = fltmc instances | Where-Object { $_ -match [regex]::Escape($DriverName) }

    if ($filtersLine -and $instancesLine) {
        Write-Step "Quick load succeeded - driver is running"
        Write-Host "`nFilters:"
        $filtersLine | ForEach-Object { Write-Host "  $_" }
        Write-Host "`nInstances:"
        $instancesLine | ForEach-Object { Write-Host "  $_" }

        if ($fileMatchStatus -eq "not_present" -or $fileMatchStatus -eq $false) {
            $replaceResult = Replace-DriverFile -SourcePath $sourceSys -DestPath $defaultDestSys -DriverName $DriverName
            if ($replaceResult.Zombie) {
                $zombieDetected = $true
            }
        }

        $currentService = Get-Service -Name $DriverName
        if ($currentService.StartType -ne 'Automatic') {
            Write-Info "Driver is currently set to $($currentService.StartType) start (not auto-start)."
            $setAuto = Read-Host "Do you want to set it to Automatic startup? (y/n)"
            if ($setAuto -in 'y','Y') {
                try {
                    Set-Service -Name $DriverName -StartupType Automatic -ErrorAction Stop
                    Write-Step "Successfully set $DriverName to Automatic startup."
                }
                catch {
                    Write-ErrorStep "Failed to set auto-start: $($_.Exception.Message)"
                }
            }
        } else {
            Write-Info "Driver is already set to Automatic startup."
        }

        if ($zombieDetected) {
            Write-Warning "Zombie lock detected - new service name and altitude will be used"
        }

        Write-Host "`nFinished (quick path)." -ForegroundColor Cyan
        exit 0
    }
    else {
        Write-Info "fltmc load did not succeed or instances/filters not visible"
        Write-Step "Falling back to full installation procedure..."
    }
}
else {
    Write-Info "No complete minifilter registry configuration found -> full install required"
}

# ─── Full installation ──────────────────────────────────────────────────────

$infFile = Find-InfFile -Path . -PreferredName $DriverName

Write-Step "Validating INF <$($infFile | Split-Path -Leaf)> ..."

$infInfo = Validate-InfContent $infFile
if (-not $infInfo) {
    Write-ErrorStep "INF validation issues detected"
    $c = Read-Host "Continue anyway? (y/n)"
    if ($c -notin 'y','Y') { exit 1 }
}

$baseAltitude   = $infInfo.Altitude
$loadOrderGroup = $infInfo.LoadOrderGroup

Patch-DriverVerDate $infFile

$catFile = ".\$DriverName.cat"

if ($enforce) {
    $needsSigning = Should-SignCatalog $catFile

    if ($needsSigning) {
        if (-not $hasWdk) {
            Write-ErrorStep "Cannot sign catalog - WDK tools missing"
            $choice = Read-Host "Continue without signing? (y/n)"
            if ($choice -notin 'y','Y') { exit 1 }
        }
        else {
            Remove-OldCatalogFile $catFile

            $cerPath = Create-SelfSignedCodeSigningCert
            if (-not $cerPath) {
                Write-ErrorStep "Certificate creation failed - skipping signing"
            }
            else {
                $catGenerated = Generate-CatalogFile $infFile
                if ($catGenerated) {
                    $signed = Sign-CatalogFile -CatFile $catFile -CerPath $cerPath
                    if ($signed) {
                        $finalValid = Validate-CatSignature $catFile
                        if ($finalValid) {
                            Write-Step "Catalog successfully re-generated and signed"
                        } else {
                            Write-ErrorStep "Signed catalog failed final validation"
                        }
                    } else {
                        Write-ErrorStep "Signing step failed"
                    }
                } else {
                    Write-ErrorStep "Catalog generation failed"
                }
            }
        }
    }
}

Clean-PreviousVersions $DriverName

$renamedInf = Rename-InfWithTimestamp $infFile

Write-Info "Current driver status (last 3 logs):"
Get-WinEvent -LogName System -MaxEvents 3 | 
    Where-Object { $_.Message -like "*Verifier*" -or $_.Message -like "*$DriverName*" } | 
    Format-List TimeCreated, Id, Message

$verifStatus = Get-DriverVerifierLoadStatus $DriverName
if ($verifStatus.Verified) {
    Write-Info "Verifier is ACTIVE on $DriverName.sys"
    Write-Info "Load/Unload counts: $($verifStatus.LoadCount) / $($verifStatus.UnloadCount)"
    if ($verifStatus.LoadCount -gt ($verifStatus.UnloadCount + 1)) {
        Write-Warning "Driver appears loaded but possibly zombie (more loads than unloads)"
    }
}

# ─── Decide final service name, paths and altitude ──────────────────────────

$finalServiceName = $DriverName
$finalDestSys     = $defaultDestSys
$finalBinPath     = "\??\$defaultDestSys"
$finalAltitude    = $baseAltitude

if ($forceUniqueMode -or $zombieDetected) {
    $paths = Get-UniqueDriverPaths -BaseDriverName $DriverName
    $finalServiceName = $DriverName + $paths.ServiceNameSuffix
    $finalDestSys     = $paths.DestSysPath
    $finalBinPath     = $paths.BinPath
    $finalAltitude    = Get-NextAltitude -CurrentAltitude $baseAltitude -LoadOrderGroup $loadOrderGroup
    Write-Warning "Using unique service: $finalServiceName @ altitude $finalAltitude"
}

# ─── SCM install ────────────────────────────────────────────────────────────

Write-Step "Attempting SCM-based installation..."

# Clean original service name if it exists
if (Get-Service -Name $DriverName -ErrorAction SilentlyContinue) {
    Write-Step "Stopping and deleting existing service '$DriverName'..."
    Stop-Service -Name $DriverName -Force -EA SilentlyContinue
    Start-Sleep -Seconds 2
    sc.exe delete $DriverName | Out-Null
    Start-Sleep -Seconds 1
}

# Only attempt file replacement if not forcing unique name
if (-not $forceUniqueMode) {
    $replaceResult = Replace-DriverFile -SourcePath $sourceSys -DestPath $finalDestSys -DriverName $DriverName
    if ($replaceResult.Zombie -and -not $zombieDetected) {
        $zombieDetected = $true
        $paths = Get-UniqueDriverPaths -BaseDriverName $DriverName
        $finalServiceName = $DriverName + $paths.ServiceNameSuffix
        $finalDestSys     = $paths.DestSysPath
        $finalBinPath     = $paths.BinPath
        $finalAltitude    = Get-NextAltitude -CurrentAltitude $baseAltitude -LoadOrderGroup $loadOrderGroup
        Write-Warning "Zombie detected during replacement -> switched to $finalServiceName @ $finalAltitude"
        
        # Try to copy again with new destination
        Copy-Item $sourceSys $finalDestSys -Force -EA Stop
    }
} else {
    # In ForceRename mode we always copy to new unique path
    Write-Step "ForceRename: Copying driver to unique location $finalDestSys"
    Copy-Item $sourceSys $finalDestSys -Force -EA Stop
}

Write-Step "Creating service '$finalServiceName' ..."
& sc.exe create $finalServiceName binPath= "$finalBinPath" type= filesys start= demand error= normal depend= FltMgr DisplayName= "$DriverName Minifilter" group= "$loadOrderGroup"

if ($LASTEXITCODE -ne 0) {
    Write-Info "sc create failed - retrying after short delay..."
    Start-Sleep -Seconds 2
    & sc.exe create $finalServiceName binPath= "$finalBinPath" type= filesys start= demand error= normal depend= FltMgr DisplayName= "$DriverName Minifilter" group= "$loadOrderGroup"
}

# ─── Register minifilter instance ───────────────────────────────────────────

Write-Step "Adding Instances configuration for $finalServiceName..."
reg add "HKLM\SYSTEM\CurrentControlSet\Services\$finalServiceName\Instances" /v DefaultInstance /t REG_SZ /d "$finalServiceName Instance" /f | Out-Null
reg add "HKLM\SYSTEM\CurrentControlSet\Services\$finalServiceName\Instances\$finalServiceName Instance" /v Altitude /t REG_SZ /d $finalAltitude /f | Out-Null
reg add "HKLM\SYSTEM\CurrentControlSet\Services\$finalServiceName\Instances\$finalServiceName Instance" /v Flags /t REG_DWORD /d 0x0 /f | Out-Null

# ─── Start and verify ───────────────────────────────────────────────────────

Write-Step "Starting service '$finalServiceName' ..."
& sc.exe start $finalServiceName | Out-Null
Start-Sleep -Seconds 5

Write-Host "`nStatus:" -ForegroundColor Cyan
Write-Host "`nInstances:"
$instances = fltmc instances | Where-Object { $_ -match [regex]::Escape($finalServiceName) }
$instances | ForEach-Object { Write-Host "  $_" }

Write-Host "`nFilters:"
$filters = fltmc filters | Where-Object { $_ -match [regex]::Escape($finalServiceName) }
$filters | ForEach-Object { Write-Host "  $_" }

if ($instances.Count -gt 0) {
    Write-Step "Installation appears successful - setting service to auto-start"
    & sc.exe config $finalServiceName start= auto | Out-Null
    if ($LASTEXITCODE -eq 0) {
        Write-Step "Auto-start configured successfully"
    } else {
        Write-ErrorStep "Failed to set auto-start (exit code $LASTEXITCODE)"
    }
} else {
    Write-ErrorStep "No instances visible - installation may have failed"

    if (-not $verifStatus.Verified) {
        $enableVerifier = Read-Host "Enable Driver Verifier on $DriverName.sys for debugging? (y/n)"
        if ($enableVerifier -in 'y','Y') {
            Write-Step "Enabling standard Verifier on $DriverName.sys ..."
            & verifier /reset 2>$null
            & verifier /standard /driver $DriverName.sys
            Write-Info "Verifier enabled. Reboot or reload required."
        }
    }

    $crashDumpKey = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl" -Name "CrashDumpEnabled" -EA SilentlyContinue
    if (-not ($crashDumpKey -and $crashDumpKey.CrashDumpEnabled -eq 3)) {
        $enableDumps = Read-Host "Enable small minidumps for crash debugging? (y/n)"
        if ($enableDumps -in 'y','Y') {
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl" -Name "CrashDumpEnabled" -Value 3 -Type DWord -Force
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl" -Name "MinidumpsCount" -Value 10 -Type DWord -Force
            Write-Info "Minidumps enabled. Reboot required."
        }
    }

    Write-Info "Reboot may be required to clear zombie state or complete first-time load."
    $r = Read-Host "Reboot now? (y/n)"
    if ($r -in 'y','Y') { Restart-Computer -Force }
}

ReEnable-DriverVerifierIfNeeded

Write-Host "`nFinished." -ForegroundColor Cyan