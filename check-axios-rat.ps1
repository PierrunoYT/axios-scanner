# ============================================================
#  check-axios-rat.ps1
#  Checks for indicators of compromise from the axios/LiteLLM
#  supply chain attack (March 31, 2026).
#
#  IOC values are fetched from GitHub first; falls back to the
#  local ioc.json if the network is unreachable.
#
#  Run with:  powershell -ExecutionPolicy Bypass -File check-axios-rat.ps1
# ============================================================

$ErrorActionPreference = "SilentlyContinue"

$script:FOUND = $false

# Ensure the window always stays open when launched via Start-Process -Verb RunAs
trap {
    Write-Host ""
    Write-Host "[ERROR] Unexpected error: $_" -ForegroundColor Red
    Read-Host "Press Enter to close"
    break
}

$IOC_URL = "https://raw.githubusercontent.com/PierrunoYT/axios-scanner/main/ioc.json"

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

# ── Load IOC data (web first, local fallback) ────────────────
Write-Host "Fetching latest IOC data..." -ForegroundColor White

$ioc = $null

try {
    $response = Invoke-WebRequest -Uri $IOC_URL -UseBasicParsing -TimeoutSec 10 -ErrorAction Stop
    $ioc = $response.Content | ConvertFrom-Json
    Ok "IOC data loaded from GitHub (up to date)"
} catch {
    Warn "Could not reach GitHub ($($_.Exception.Message)). Falling back to local ioc.json."
}

if (-not $ioc) {
    $iocFile = Join-Path $PSScriptRoot "ioc.json"
    if (-not (Test-Path $iocFile)) {
        Write-Host "[ERROR] ioc.json not found locally and web fetch failed. Cannot continue." -ForegroundColor Red
        Read-Host "Press Enter to close"
        exit 1
    }
    $ioc = Get-Content $iocFile -Raw | ConvertFrom-Json
    Ok "IOC data loaded from local ioc.json"
}

$c2Domain  = $ioc.c2_domain
$c2Port    = [int]$ioc.c2_port
$wtBin     = $ioc.wt_bin
$pcjsPkg   = $ioc.pcjs_pkg
$ldPy      = $ioc.ld_py
$actMond   = $ioc.act_mond
$axBadVers = $ioc.ax_bad

# ── 1. Malicious files dropped by the RAT ───────────────────

Write-Host ""
Write-Host "1. Checking for malicious files on disk..." -ForegroundColor White

$WtExe = Join-Path $env:PROGRAMDATA $wtBin
Info "Windows RAT payload: $WtExe"
if (Test-Path $WtExe) {
    Flag "Found malicious $wtBin at $WtExe"
} else {
    Ok "$wtBin not found in ProgramData"
}

$VbsLocations = @(
    (Join-Path $env:TEMP "*.vbs"),
    (Join-Path $env:PROGRAMDATA "*.vbs"),
    (Join-Path $env:APPDATA "*.vbs")
)
foreach ($loc in $VbsLocations) {
    $hits = Get-ChildItem -Path $loc -ErrorAction SilentlyContinue
    if ($hits) {
        if ($hits -is [System.Array]) {
            Warn "Found VBScript files at $loc — review manually: $($hits | Select-Object -ExpandProperty FullName -Unique -join ', ')"
        } else {
            Warn "Found VBScript file at $loc — review manually: $($hits.FullName)"
        }
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
            $ver  = $meta.version
            if ($badVer -and $ver -eq $badVer) {
                Flag "Found $pkg@$ver in $dir"
            } elseif ((-not $badVer) -and $ver) {
                Flag "Found $pkg@$ver in $dir (any version of $pkg is suspicious)"
            } elseif ($ver) {
                Ok "$pkg@$ver in $dir (not a known bad version)"
            }
        } catch {}
    }
}

try {
    $globalRoot   = (npm root -g 2>$null).Trim()
    $globalPrefix = Split-Path $globalRoot -Parent
    if ($globalRoot -and $globalPrefix) {
        Info "Global node_modules: $globalRoot"
        foreach ($badVer in $axBadVers) {
            Check-NpmPkg $globalPrefix "axios" $badVer
        }
        if ($pcjsPkg) { Check-NpmPkg $globalPrefix $pcjsPkg $null }
    }
} catch {}

if (Test-Path "package.json") {
    Info "Local node_modules: $(Join-Path (Get-Location) 'node_modules')"
    $localAxios = ".\node_modules\axios\package.json"
    if (Test-Path $localAxios) {
        $meta = Get-Content $localAxios -Raw | ConvertFrom-Json
        if ($axBadVers -contains $meta.version) {
            Flag "Local axios@$($meta.version) is MALICIOUS"
        } else {
            Ok "Local axios@$($meta.version) is not a known bad version"
        }
    }

    $localPcjs = ".\node_modules\$pcjsPkg\package.json"
    if ($pcjsPkg -and (Test-Path $localPcjs)) {
        $meta = Get-Content $localPcjs -Raw | ConvertFrom-Json
        Flag "Found $pcjsPkg@$($meta.version) in local node_modules"
    }
}

# ── 3. Package manager cache scans ──────────────────────────

Write-Host ""
Write-Host "3. Scanning package manager caches (npm, yarn, pnpm, pip)..." -ForegroundColor White

# npm
try {
    $npmCache = (npm config get cache 2>$null).Trim()
    if ($npmCache -and (Test-Path $npmCache)) {
        Info "npm cache: $npmCache"
        $cachePatterns = @()
        if ($pcjsPkg) { $cachePatterns += "$pcjsPkg*" }
        foreach ($badVer in $axBadVers) { $cachePatterns += "axios-$badVer*" }
        foreach ($pattern in $cachePatterns) {
            $hits = Get-ChildItem -Path $npmCache -Recurse -Filter $pattern -ErrorAction SilentlyContinue
            if ($hits) { Warn "npm cache contains '$pattern' — package was downloaded at some point" }
        }
        Ok "npm cache scan complete"
    }
} catch {}

# yarn (classic v1 and berry v2/v3)
try {
    $yarnCache = (yarn cache dir 2>$null).Trim()
    if ($yarnCache -and (Test-Path $yarnCache)) {
        Info "yarn cache: $yarnCache"
        foreach ($badVer in $axBadVers) {
            $hits = Get-ChildItem -Path $yarnCache -Recurse -Filter "*axios*$badVer*" -ErrorAction SilentlyContinue
            if ($hits) { Warn "yarn cache contains 'axios-$badVer' — package was downloaded" }
        }
        if ($pcjsPkg) {
            $hits = Get-ChildItem -Path $yarnCache -Recurse -Filter "$pcjsPkg*" -ErrorAction SilentlyContinue
            if ($hits) { Warn "yarn cache contains '$pcjsPkg' — package was downloaded" }
        }
        Ok "yarn cache scan complete"
    }
} catch {}

# pnpm
try {
    $pnpmStore = (pnpm store path 2>$null).Trim()
    if ($pnpmStore -and (Test-Path $pnpmStore)) {
        Info "pnpm store: $pnpmStore"
        foreach ($badVer in $axBadVers) {
            $hits = Get-ChildItem -Path $pnpmStore -Recurse -Filter "*axios*$badVer*" -ErrorAction SilentlyContinue
            if ($hits) { Warn "pnpm store contains 'axios@$badVer' — package was downloaded" }
        }
        if ($pcjsPkg) {
            $hits = Get-ChildItem -Path $pnpmStore -Recurse -Filter "$pcjsPkg*" -ErrorAction SilentlyContinue
            if ($hits) { Warn "pnpm store contains '$pcjsPkg' — package was downloaded" }
        }
        Ok "pnpm store scan complete"
    }
} catch {}

# pip
try {
    $pipCacheDir = (pip cache dir 2>$null).Trim()
    if ($pipCacheDir -and (Test-Path $pipCacheDir)) {
        Info "pip cache: $pipCacheDir"
        $hits = Get-ChildItem -Path $pipCacheDir -Recurse -Filter "litellm*" -ErrorAction SilentlyContinue
        if ($hits) { Warn "pip cache contains litellm package(s) — review for compromised version" }
        Ok "pip cache scan complete"
    }
} catch {}

# ── 4. Network: active C2 connections ───────────────────────

Write-Host ""
Write-Host "4. Checking for active C2 connections ($($c2Domain):$c2Port)..." -ForegroundColor White

$activeConns = Get-NetTCPConnection -RemotePort $c2Port -ErrorAction SilentlyContinue
if ($activeConns) {
    Flag "Active TCP connection to port $c2Port detected!"
    $activeConns | Format-Table LocalAddress, LocalPort, RemoteAddress, RemotePort, State -AutoSize
} else {
    Ok "No active connections to port $c2Port"
}

$dnsCache = Get-DnsClientCache -ErrorAction SilentlyContinue | Where-Object { $_.Entry -like "*$c2Domain*" }
if ($dnsCache) {
    Flag "DNS cache contains $c2Domain — this machine may have contacted the C2 server"
} else {
    Ok "$c2Domain not found in DNS cache"
}

$c2Events = Get-WinEvent -FilterHashtable @{
    LogName   = "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall"
    StartTime = (Get-Date).AddDays(-2)
} -ErrorAction SilentlyContinue | Where-Object { $_.Message -like "*$c2Domain*" }
if ($c2Events) {
    Flag "Firewall logs reference $c2Domain"
}

# ── 5. Suspicious processes ─────────────────────────────────

Write-Host ""
Write-Host "5. Checking for suspicious processes..." -ForegroundColor White

foreach ($proc in @($ldPy, $actMond, $pcjsPkg, "setup.js")) {
    try {
        $hits = Get-Process -ErrorAction SilentlyContinue | Where-Object {
            ($_ | Get-Member -Name MainModule -ErrorAction SilentlyContinue) -and
            (
                ($_.MainModule.FileName -like "*$proc*") -or
                ($_.Name -like "*$proc*")
            )
        }
        if ($hits) {
            foreach ($hit in @($hits)) {
                Flag "Suspicious process running: $proc (PID $($hit.Id))"
            }
        }
    } catch {}
}

$wtProcName = [System.IO.Path]::GetFileNameWithoutExtension($wtBin)
try {
    $wtProcList = Get-Process -Name $wtProcName -ErrorAction SilentlyContinue
    if ($wtProcList) {
        foreach ($wtProc in @($wtProcList)) {
            try {
                $wtPath = $wtProc.MainModule.FileName
                if ($wtPath -like "*ProgramData*") {
                    Flag "$wtBin running from ProgramData — this matches the RAT payload path ($wtPath)"
                }
            } catch {}
        }
    }
} catch {}
Ok "No known malicious processes found"

# ── 6. Scheduled tasks & autoruns (persistence) ─────────────

Write-Host ""
Write-Host "6. Checking for persistence mechanisms..." -ForegroundColor White

try {
    $suspiciousTasks = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {
        $fullName = $_.TaskPath + $_.TaskName
        $fullName -match [regex]::Escape($wtBin)    -or
        $fullName -match [regex]::Escape($ldPy)     -or
        $fullName -match [regex]::Escape($pcjsPkg)  -or
        $fullName -match [regex]::Escape($c2Domain) -or
        $fullName -match [regex]::Escape($actMond)
    }
    if ($suspiciousTasks) {
        foreach ($task in @($suspiciousTasks)) {
            Flag "Suspicious scheduled task: $($task.TaskName) at $($task.TaskPath)"
        }
    } else {
        Ok "No suspicious scheduled tasks found"
    }
} catch {
    Ok "Unable to scan scheduled tasks"
}

$regPaths = @(
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
)
foreach ($regPath in $regPaths) {
    try {
        $runKeys = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue
        if ($runKeys) {
            $runKeys.PSObject.Properties | Where-Object {
                ($_.Value -match [regex]::Escape($wtBin))   -or
                ($_.Value -match [regex]::Escape($pcjsPkg)) -or
                ($_.Value -match [regex]::Escape($c2Domain))
            } | ForEach-Object {
                Flag "Suspicious Run key: $($_.Name) = $($_.Value)"
            }
        }
    } catch {}
}
Ok "No suspicious startup registry entries found"

# ── 7. Lock file audit ──────────────────────────────────────

Write-Host ""
Write-Host "7. Scanning lock files in current directory..." -ForegroundColor White

foreach ($lockfile in @("package-lock.json", "yarn.lock", "pnpm-lock.yaml")) {
    if (Test-Path $lockfile) {
        Info "Found $lockfile"
        try {
            $content = Get-Content $lockfile -Raw
            $badAxios = $false
            foreach ($badVer in $axBadVers) {
                if ($content -match [regex]::Escape($badVer)) { $badAxios = $true }
            }
            if ($badAxios) {
                Flag "$lockfile references a malicious axios version"
            }
            if ($content -match [regex]::Escape($pcjsPkg)) {
                Flag "$lockfile references $pcjsPkg"
            }
        } catch {}
    }
}

# ── 8. pip / LiteLLM check ──────────────────────────────────

Write-Host ""
Write-Host "8. Checking LiteLLM (Python) installation..." -ForegroundColor White
Info "LiteLLM was also compromised via Trivy/TeamPCP attack"

try {
    $litellm = & pip show litellm 2>$null
    if ($litellm) {
        $verLine = $litellm | Select-String "^Version\s*:" | Select-Object -First 1
        if (-not $verLine) {
            $verLine = $litellm | Select-String "Version" | Select-Object -First 1
        }
        if ($verLine) {
            $ver = ($verLine.ToString() -replace '.*:\s*', '').Trim()
            Warn "LiteLLM $ver is installed. Check https://github.com/BerriAI/litellm for compromised version ranges."
        } else {
            Warn "LiteLLM is installed but version could not be detected. Review manually."
        }
    } else {
        Ok "LiteLLM not installed via pip"
    }
} catch {
    Ok "pip not found or LiteLLM not installed"
}

# ── Summary ─────────────────────────────────────────────────

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
if ($script:FOUND) {
    Write-Host "  RESULT: INDICATORS OF COMPROMISE FOUND" -ForegroundColor Red
    Write-Host ""
    Write-Host "  Immediate actions required:" -ForegroundColor Red
    Write-Host "  1. Rotate ALL credentials, API keys, SSH keys, tokens" -ForegroundColor Red
    Write-Host "  2. Delete malicious files listed above" -ForegroundColor Red
    Write-Host "  3. npm uninstall axios $pcjsPkg" -ForegroundColor Red
    Write-Host "  4. npm install axios@1.8.4" -ForegroundColor Red
    Write-Host "  5. Review Windows Event Log for outbound network activity" -ForegroundColor Red
    Write-Host "  6. Consider reimaging if $wtBin payload was found" -ForegroundColor Red
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
Read-Host "Press Enter to close"
