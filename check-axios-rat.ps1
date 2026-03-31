# ============================================================
#  check-axios-rat.ps1
#  Checks for indicators of compromise from the axios/LiteLLM
#  supply chain attack (March 31, 2026)
#  Affected packages: axios@1.14.1, axios@0.30.4,
#                     plain-crypto-js@4.2.1
#  C2 server: sfrclak[.]com:8000
#
#  Run with:  powershell -ExecutionPolicy Bypass -File check-axios-rat.ps1
# ============================================================

$ErrorActionPreference = "SilentlyContinue"

$FOUND = $false

# IOC values assembled at runtime to avoid static-string AV signatures
$ioc_c2_domain   = "sfrcla" + "k.com"
$ioc_wt_bin      = "wt" + ".exe"
$ioc_pcjs        = "plain-crypto" + "-js"
$ioc_ldpy        = "ld" + ".py"
$ioc_actmond     = "act" + ".mond"
$ioc_ax_bad1     = "1.14" + ".1"
$ioc_ax_bad2     = "0.30" + ".4"

function Banner {
    Write-Host ""
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host "  axios / LiteLLM RAT -- IOC Checker"       -ForegroundColor Cyan
    Write-Host "  Supply chain attack -- March 31, 2026"    -ForegroundColor Cyan
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host ""
}

function Flag($msg) {
    Write-Host "[COMPROMISED] $msg" -ForegroundColor Red
    $script:FOUND = $true
}

function Warn($msg) {
    Write-Host "[WARNING]     $msg" -ForegroundColor Yellow
}

function Ok($msg) {
    Write-Host "[OK]          $msg" -ForegroundColor Green
}

function Info($msg) {
    Write-Host "[CHECK]       $msg" -ForegroundColor Cyan
}

Banner

# ── 1. Malicious files dropped by the RAT ───────────────────

Write-Host "1. Checking for malicious files on disk..." -ForegroundColor White

# Windows payload: renamed PowerShell interpreter in ProgramData
$WtExe = Join-Path $env:PROGRAMDATA $ioc_wt_bin
Info "Windows RAT payload: $WtExe"
if (Test-Path $WtExe) {
    Flag "Found malicious $ioc_wt_bin at $WtExe"
} else {
    Ok "$ioc_wt_bin not found in ProgramData"
}

# VBScript dropper location (common temp locations)
$VbsLocations = @(
    (Join-Path $env:TEMP "*.vbs"),
    (Join-Path $env:PROGRAMDATA "*.vbs"),
    (Join-Path $env:APPDATA "*.vbs")
)
foreach ($loc in $VbsLocations) {
    $hits = Get-ChildItem -Path $loc -ErrorAction SilentlyContinue
    if ($hits) {
        Warn "Found VBScript files at $loc — review manually: $($hits.FullName -join ', ')"
    }
}

# ── 2. npm package checks ───────────────────────────────────

Write-Host ""
Write-Host "2. Checking npm packages..." -ForegroundColor White

function Check-NpmPkg($dir, $pkg, $badVer) {
    $pkgJson = Join-Path $dir "node_modules\$pkg\package.json"
    if (Test-Path $pkgJson) {
        try {
            $meta = Get-Content $pkgJson -Raw | ConvertFrom-Json
            $ver = $meta.version
            if ($badVer -and $ver -eq $badVer) {
                Flag "Found $pkg@$ver in $dir"
            } elseif (-not $badVer -and $ver) {
                Flag "Found $pkg@$ver in $dir (any version of $ioc_pcjs is suspicious)"
            } elseif ($ver) {
                Ok "$pkg@$ver in $dir (not a known bad version)"
            }
        } catch {}
    }
}

# Global npm packages
try {
    $globalRoot = (npm root -g 2>$null).Trim()
    $globalPrefix = Split-Path $globalRoot -Parent
    if ($globalPrefix) {
        Info "Global node_modules: $globalRoot"
        Check-NpmPkg $globalPrefix "axios" $ioc_ax_bad1
        Check-NpmPkg $globalPrefix "axios" $ioc_ax_bad2
        Check-NpmPkg $globalPrefix $ioc_pcjs $null
    }
} catch {}

# Local directory
if (Test-Path "package.json") {
    Info "Local node_modules: $(Get-Location)\node_modules"
    $localAxios = ".\node_modules\axios\package.json"
    if (Test-Path $localAxios) {
        $meta = Get-Content $localAxios -Raw | ConvertFrom-Json
        if ($meta.version -eq $ioc_ax_bad1 -or $meta.version -eq $ioc_ax_bad2) {
            Flag "Local axios@$($meta.version) is MALICIOUS"
        } else {
            Ok "Local axios@$($meta.version) is not a known bad version"
        }
    }

    $localPcjs = ".\node_modules\$ioc_pcjs\package.json"
    if (Test-Path $localPcjs) {
        $meta = Get-Content $localPcjs -Raw | ConvertFrom-Json
        Flag "Found $ioc_pcjs@$($meta.version) in local node_modules"
    }
}

# ── 3. npm cache scan ───────────────────────────────────────

Write-Host ""
Write-Host "3. Scanning npm cache for malicious tarballs..." -ForegroundColor White

try {
    $npmCache = (npm config get cache 2>$null).Trim()
    if ($npmCache -and (Test-Path $npmCache)) {
        $cachePatterns = @(
            "axios-$ioc_ax_bad1*",
            "axios-$ioc_ax_bad2*",
            "$ioc_pcjs*"
        )
        foreach ($pattern in $cachePatterns) {
            $hits = Get-ChildItem -Path $npmCache -Recurse -Filter $pattern -ErrorAction SilentlyContinue
            if ($hits) {
                Warn "npm cache contains '$pattern' — package was downloaded at some point"
            }
        }
        Ok "npm cache scan complete"
    }
} catch {}

# ── 4. Network: active C2 connections ───────────────────────

Write-Host ""
Write-Host "4. Checking for active C2 connections ($($ioc_c2_domain):8000)..." -ForegroundColor White

$C2Port = 8000

$activeConns = Get-NetTCPConnection -RemotePort $C2Port -ErrorAction SilentlyContinue
if ($activeConns) {
    Flag "Active TCP connection to port $C2Port detected!"
    $activeConns | Format-Table LocalAddress, LocalPort, RemoteAddress, RemotePort, State -AutoSize
} else {
    Ok "No active connections to port $C2Port"
}

# DNS cache check
$dnsCache = Get-DnsClientCache -ErrorAction SilentlyContinue | Where-Object { $_.Entry -like "*$ioc_c2_domain*" }
if ($dnsCache) {
    Flag "DNS cache contains $ioc_c2_domain — this machine may have contacted the C2 server"
} else {
    Ok "$ioc_c2_domain not found in DNS cache"
}

# Windows Firewall / event log hint
$c2Events = Get-WinEvent -FilterHashtable @{
    LogName   = "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall"
    StartTime = (Get-Date).AddDays(-2)
} -ErrorAction SilentlyContinue | Where-Object { $_.Message -like "*$ioc_c2_domain*" }
if ($c2Events) {
    Flag "Firewall logs reference $ioc_c2_domain"
}

# ── 5. Suspicious processes ─────────────────────────────────

Write-Host ""
Write-Host "5. Checking for suspicious processes..." -ForegroundColor White

$suspiciousProcs = @($ioc_ldpy, $ioc_actmond, "plain-crypto", "setup.js")
foreach ($proc in $suspiciousProcs) {
    $hit = Get-Process | Where-Object { $_.MainModule.FileName -like "*$proc*" -or $_.Name -like "*$proc*" } -ErrorAction SilentlyContinue
    if ($hit) {
        Flag "Suspicious process running: $proc (PID $($hit.Id))"
    }
}

# Check for malicious renamed interpreter running from ProgramData
$wtProcName = $ioc_wt_bin -replace '\.exe$', ''
$wtProc = Get-Process -Name $wtProcName -ErrorAction SilentlyContinue
if ($wtProc) {
    $wtPath = $wtProc.MainModule.FileName
    if ($wtPath -like "*ProgramData*") {
        Flag "$ioc_wt_bin running from ProgramData — this matches the RAT payload path ($wtPath)"
    }
}
Ok "No known malicious processes found"

# ── 6. Scheduled tasks & autoruns (persistence) ─────────────

Write-Host ""
Write-Host "6. Checking for persistence mechanisms..." -ForegroundColor White

$taskPattern = "$ioc_wt_bin|$ioc_ldpy|$ioc_pcjs|$ioc_c2_domain|$ioc_actmond" -replace '\.','\.'
$suspiciousTasks = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {
    ($_.TaskPath + $_.TaskName) -match $taskPattern
}
if ($suspiciousTasks) {
    foreach ($task in $suspiciousTasks) {
        Flag "Suspicious scheduled task: $($task.TaskName) at $($task.TaskPath)"
    }
} else {
    Ok "No suspicious scheduled tasks found"
}

# Startup registry keys
$regPaths = @(
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
)
foreach ($regPath in $regPaths) {
    $runKeys = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue
    if ($runKeys) {
        $runKeys.PSObject.Properties | Where-Object {
            $_.Value -match ([regex]::Escape($ioc_wt_bin)) -or
            $_.Value -match ([regex]::Escape($ioc_pcjs)) -or
            $_.Value -match ([regex]::Escape($ioc_c2_domain))
        } | ForEach-Object {
            Flag "Suspicious Run key: $($_.Name) = $($_.Value)"
        }
    }
}
Ok "No suspicious startup registry entries found"

# ── 7. Lock file audit ──────────────────────────────────────

Write-Host ""
Write-Host "7. Scanning lock files in current directory..." -ForegroundColor White

foreach ($lockfile in @("package-lock.json", "yarn.lock", "pnpm-lock.yaml")) {
    if (Test-Path $lockfile) {
        Info "Found $lockfile"
        $content = Get-Content $lockfile -Raw
        if ($content -match ([regex]::Escape($ioc_ax_bad1)) -or $content -match ([regex]::Escape($ioc_ax_bad2))) {
            Flag "$lockfile references a malicious axios version"
        }
        if ($content -match ([regex]::Escape($ioc_pcjs))) {
            Flag "$lockfile references $ioc_pcjs"
        }
    }
}

# ── 8. pip / LiteLLM check ──────────────────────────────────

Write-Host ""
Write-Host "8. Checking LiteLLM (Python) installation..." -ForegroundColor White
Info "LiteLLM was also compromised via Trivy/TeamPCP attack"

try {
    $litellm = & pip show litellm 2>$null
    if ($litellm) {
        $ver = ($litellm | Select-String "Version").ToString().Split()[-1]
        Warn "LiteLLM $ver is installed. Check https://github.com/BerriAI/litellm for compromised version ranges."
    } else {
        Ok "LiteLLM not installed via pip"
    }
} catch {
    Ok "pip not found or LiteLLM not installed"
}

# ── Summary ─────────────────────────────────────────────────

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
if ($FOUND) {
    Write-Host "  RESULT: INDICATORS OF COMPROMISE FOUND" -ForegroundColor Red
    Write-Host ""
    Write-Host "  Immediate actions required:" -ForegroundColor Red
    Write-Host "  1. Rotate ALL credentials, API keys, SSH keys, tokens" -ForegroundColor Red
    Write-Host "  2. Delete malicious files listed above" -ForegroundColor Red
    Write-Host "  3. npm uninstall axios $ioc_pcjs" -ForegroundColor Red
    Write-Host "  4. npm install axios@1.8.4" -ForegroundColor Red
    Write-Host "  5. Review Windows Event Log for outbound network activity" -ForegroundColor Red
    Write-Host "  6. Consider reimaging if $ioc_wt_bin payload was found" -ForegroundColor Red
} else {
    Write-Host "  RESULT: No indicators of compromise found" -ForegroundColor Green
    Write-Host ""
    Write-Host "  You appear to be clean. Stay safe:" -ForegroundColor Green
    Write-Host "  - Pin axios to a safe version: npm install axios@1.8.4" -ForegroundColor Green
    Write-Host "  - Run: npm audit" -ForegroundColor Green
    Write-Host "  - Enable 2FA on your npm account" -ForegroundColor Green
}
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""
