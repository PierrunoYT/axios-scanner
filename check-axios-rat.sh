#!/usr/bin/env bash
# ============================================================
#  check-axios-rat.sh
#  Checks for indicators of compromise from the axios/LiteLLM
#  supply chain attack (March 31, 2026).
#
#  IOC values are fetched from GitHub first; falls back to the
#  local ioc.json if the network is unreachable.
# ============================================================

RED='\033[0;31m'
YEL='\033[0;33m'
GRN='\033[0;32m'
CYN='\033[0;36m'
BLD='\033[1m'
RST='\033[0m'

FOUND=0

IOC_URL="https://raw.githubusercontent.com/PierrunoYT/axios-scanner/main/ioc.json"

banner() {
  echo ""
  echo -e "${BLD}${CYN}============================================${RST}"
  echo -e "${BLD}${CYN}  axios / LiteLLM RAT — IOC Checker${RST}"
  echo -e "${BLD}${CYN}  Supply chain attack — March 31, 2026${RST}"
  echo -e "${BLD}${CYN}============================================${RST}"
  echo ""
}

flag() {
  echo -e "${RED}[COMPROMISED]${RST} $1"
  FOUND=1
}

warn() {
  echo -e "${YEL}[WARNING]${RST}     $1"
}

ok() {
  echo -e "${GRN}[OK]${RST}          $1"
}

info() {
  echo -e "${CYN}[CHECK]${RST}       $1"
}

# ── Load IOC data (web first, local fallback) ────────────────
load_ioc_json() {
  local raw=""

  echo -e "${BLD}Fetching latest IOC data...${RST}"

  if command -v curl &>/dev/null; then
    raw=$(curl -fsSL --max-time 10 "$IOC_URL" 2>/dev/null)
  elif command -v wget &>/dev/null; then
    raw=$(wget -qO- --timeout=10 "$IOC_URL" 2>/dev/null)
  fi

  if [[ -n "$raw" ]]; then
    ok "IOC data loaded from GitHub (up to date)"
    echo "$raw"
    return 0
  fi

  warn "Could not reach GitHub. Falling back to local ioc.json."
  local script_dir
  script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  local local_ioc="$script_dir/ioc.json"

  if [[ ! -f "$local_ioc" ]]; then
    echo -e "${RED}[ERROR]${RST} ioc.json not found locally and web fetch failed. Cannot continue." >&2
    exit 1
  fi

  ok "IOC data loaded from local ioc.json"
  cat "$local_ioc"
}

parse_ioc() {
  local json="$1"
  local key="$2"
  echo "$json" | grep -oP "\"${key}\"\s*:\s*\K(\"[^\"]*\"|\[[^\]]*\])" | tr -d '"'
}

parse_ioc_array() {
  local json="$1"
  local key="$2"
  echo "$json" | grep -oP "\"${key}\"\s*:\s*\[\K[^\]]+" | grep -oP '"[^"]+"' | tr -d '"'
}

banner

IOC_JSON="$(load_ioc_json)"

C2_DOMAIN="$(parse_ioc "$IOC_JSON" "c2_domain")"
C2_PORT="$(parse_ioc "$IOC_JSON" "c2_port" | tr -d ' ')"
WT_BIN="$(parse_ioc "$IOC_JSON" "wt_bin")"
PCJS_PKG="$(parse_ioc "$IOC_JSON" "pcjs_pkg")"
LD_PY="$(parse_ioc "$IOC_JSON" "ld_py")"
ACT_MOND="$(parse_ioc "$IOC_JSON" "act_mond")"

mapfile -t AX_BAD < <(parse_ioc_array "$IOC_JSON" "ax_bad")

# ── 1. Malicious files on disk ───────────────────────────────
echo ""
echo -e "${BLD}1. Checking for malicious files on disk...${RST}"

if [[ "$OSTYPE" == "darwin"* ]]; then
  RAT_PATH="/Library/Caches/com.apple.$ACT_MOND"
  info "macOS RAT payload: $RAT_PATH"
  if [[ -f "$RAT_PATH" ]]; then
    flag "Found macOS RAT payload: $RAT_PATH"
  else
    ok "macOS RAT payload not found"
  fi
elif [[ "$OSTYPE" == "linux"* ]]; then
  LINUX_RAT="/tmp/$LD_PY"
  info "Linux RAT payload: $LINUX_RAT"
  if [[ -f "$LINUX_RAT" ]]; then
    flag "Found Linux RAT payload: $LINUX_RAT"
  else
    ok "Linux RAT payload not found"
  fi
elif [[ "$OSTYPE" == "msys"* || "$OSTYPE" == "cygwin"* || "$OSTYPE" == "win32" || "$OSTYPE" == "windows"* ]]; then
  WT_EXE_LOC=""
  if command -v cygpath &>/dev/null; then
    WT_EXE_LOC="$(cygpath "$PROGRAMDATA")/$WT_BIN"
  elif [[ -n "$PROGRAMDATA" ]]; then
    WT_EXE_LOC="$PROGRAMDATA/$WT_BIN"
  else
    WT_EXE_LOC="/c/ProgramData/$WT_BIN"
  fi
  info "Windows RAT payload: $WT_EXE_LOC"
  if [[ -f "$WT_EXE_LOC" ]]; then
    flag "Found Windows RAT payload: $WT_EXE_LOC"
  else
    ok "Windows RAT payload not found"
  fi
else
  ok "Unknown OS type: $OSTYPE (skipping RAT payload check)"
fi

# ── 2. npm package checks ───────────────────────────────────
echo ""
echo -e "${BLD}2. Checking npm packages...${RST}"

check_npm_pkg() {
  local pkg="$1"
  local bad_ver="$2"
  local dir="$3"
  local pkg_json="$dir/node_modules/$pkg/package.json"

  if [[ -f "$pkg_json" ]]; then
    local ver=""
    ver=$(node -e "try{process.stdout.write(require('$pkg_json').version)}catch(e){}" 2>/dev/null)
    if [[ -n "$bad_ver" && "$ver" == "$bad_ver" ]]; then
      flag "Found $pkg@$ver in $dir"
    elif [[ -z "$bad_ver" && -n "$ver" ]]; then
      flag "Found $pkg@$ver in $dir (any version is suspicious)"
    elif [[ -n "$ver" ]]; then
      ok "$pkg@$ver in $dir (not a known bad version)"
    fi
  fi
}

GLOBAL_NM="$(npm root -g 2>/dev/null)"
if [[ -n "$GLOBAL_NM" ]]; then
  info "Global node_modules: $GLOBAL_NM"
  for bad_ver in "${AX_BAD[@]}"; do
    check_npm_pkg "axios" "$bad_ver" "$(dirname "$GLOBAL_NM")"
  done
  [[ -n "$PCJS_PKG" ]] && check_npm_pkg "$PCJS_PKG" "" "$(dirname "$GLOBAL_NM")"
fi

if [[ -f "package.json" && -d "./node_modules" ]]; then
  info "Local node_modules: $(pwd)/node_modules"
  local_axios_ver=$(node -e "try{process.stdout.write(require('./node_modules/axios/package.json').version)}catch(e){}" 2>/dev/null)
  if [[ -n "$local_axios_ver" ]]; then
    is_bad=0
    for bad_ver in "${AX_BAD[@]}"; do
      [[ "$local_axios_ver" == "$bad_ver" ]] && is_bad=1 && break
    done
    if [[ "$is_bad" -eq 1 ]]; then
      flag "Local axios@$local_axios_ver is MALICIOUS"
    else
      ok "Local axios@$local_axios_ver is not a known bad version"
    fi
  fi

  if [[ -d "./node_modules/$PCJS_PKG" ]]; then
    pcjs_ver=$(node -e "try{process.stdout.write(require('./node_modules/$PCJS_PKG/package.json').version)}catch(e){}" 2>/dev/null)
    if [[ -n "$pcjs_ver" ]]; then
      flag "Found $PCJS_PKG@$pcjs_ver in local node_modules"
    else
      flag "Found $PCJS_PKG in local node_modules (version unknown)"
    fi
  fi
fi

# ── 3. npm cache scan ───────────────────────────────────────
echo ""
echo -e "${BLD}3. Scanning npm cache for malicious tarballs...${RST}"

NPM_CACHE="$(npm config get cache 2>/dev/null)"
if [[ -d "$NPM_CACHE" ]]; then
  for bad_ver in "${AX_BAD[@]}"; do
    if find "$NPM_CACHE" -name "axios-${bad_ver}*" 2>/dev/null | grep -q .; then
      warn "Found cached tarball matching 'axios-${bad_ver}' in $NPM_CACHE — package was downloaded"
    fi
  done
  if find "$NPM_CACHE" -name "${PCJS_PKG}*" 2>/dev/null | grep -q .; then
    warn "Found cached tarball matching '$PCJS_PKG' in $NPM_CACHE — package was downloaded"
  fi
  ok "npm cache scan complete"
else
  warn "npm cache path '$NPM_CACHE' does not exist or is not a directory"
fi

# ── 4. Active C2 connections ─────────────────────────────────
echo ""
echo -e "${BLD}4. Checking for active C2 connections ($C2_DOMAIN:$C2_PORT)...${RST}"

C2_CONN=""
if command -v ss &>/dev/null; then
  C2_CONN=$(ss -tnp 2>/dev/null | grep -E ":$C2_PORT(\s|$)")
elif command -v netstat &>/dev/null; then
  C2_CONN=$(netstat -an 2>/dev/null | grep -E ":$C2_PORT(\s|$)")
fi

if [[ -n "$C2_CONN" ]]; then
  flag "Active connection to port $C2_PORT detected:\n$C2_CONN"
else
  ok "No active connection to :$C2_PORT"
fi

if command -v host &>/dev/null; then
  if host "$C2_DOMAIN" 2>&1 | grep -q -i "$C2_DOMAIN"; then
    warn "DNS resolved $C2_DOMAIN — this is the known C2 server. If you did NOT look this up intentionally, your machine may have contacted it."
  fi
fi

# ── 5. Suspicious processes ──────────────────────────────────
echo ""
echo -e "${BLD}5. Checking for suspicious processes...${RST}"

SUSPICIOUS_PROCS=("$LD_PY" "$WT_BIN" "$ACT_MOND" "$PCJS_PKG" "setup.js")
FOUND_PROC=0
for proc in "${SUSPICIOUS_PROCS[@]}"; do
  [[ -z "$proc" ]] && continue
  if pgrep -f "$proc" &>/dev/null; then
    flag "Suspicious process running: $proc"
    FOUND_PROC=1
  fi
done
if [[ "$FOUND_PROC" -eq 0 ]]; then
  ok "No known malicious processes found"
fi

# ── 6. LiteLLM (Python) ──────────────────────────────────────
echo ""
echo -e "${BLD}6. Checking LiteLLM (Python) installation...${RST}"
info "LiteLLM was also compromised via Trivy/TeamPCP attack"

PIP_BIN=""
if command -v pip3 &>/dev/null; then
  PIP_BIN=$(command -v pip3)
elif command -v pip &>/dev/null; then
  PIP_BIN=$(command -v pip)
fi

if [[ -n "$PIP_BIN" ]]; then
  LITELLM_VER=$("$PIP_BIN" show litellm 2>/dev/null | grep "^Version:" | awk '{print $2}')
  if [[ -n "$LITELLM_VER" ]]; then
    warn "LiteLLM $LITELLM_VER is installed. Check https://github.com/BerriAI/litellm for compromised version ranges."
  else
    ok "LiteLLM not installed via pip"
  fi
else
  ok "pip is not installed"
fi

# ── 7. Lock file audit ───────────────────────────────────────
echo ""
echo -e "${BLD}7. Scanning lock files in current directory...${RST}"

for lockfile in package-lock.json yarn.lock pnpm-lock.yaml; do
  if [[ -f "$lockfile" ]]; then
    info "Found $lockfile"
    is_bad=0
    for bad_ver in "${AX_BAD[@]}"; do
      if grep -qF "$bad_ver" "$lockfile" 2>/dev/null; then
        is_bad=1
        break
      fi
    done
    if [[ "$is_bad" -eq 1 ]]; then
      flag "$lockfile references a malicious axios version"
    fi
    if grep -qF "$PCJS_PKG" "$lockfile" 2>/dev/null; then
      flag "$lockfile references $PCJS_PKG"
    fi
  fi
done

# ── Summary ──────────────────────────────────────────────────
echo ""
echo -e "${BLD}${CYN}============================================${RST}"
if [[ $FOUND -eq 1 ]]; then
  echo -e "${RED}${BLD}  RESULT: INDICATORS OF COMPROMISE FOUND${RST}"
  echo -e "${RED}${BLD}  Immediate actions required:${RST}"
  echo -e "${RED}  1. Rotate ALL credentials, API keys, SSH keys${RST}"
  echo -e "${RED}  2. Remove malicious files listed above${RST}"
  echo -e "${RED}  3. npm uninstall axios $PCJS_PKG${RST}"
  echo -e "${RED}  4. Reinstall safe axios: npm install axios@1.8.4${RST}"
  echo -e "${RED}  5. Review outbound connections in your firewall logs${RST}"
  echo -e "${RED}  6. Consider reimaging if RAT payload was found${RST}"
else
  echo -e "${GRN}${BLD}  RESULT: No indicators of compromise found${RST}"
  echo -e "${GRN}  You appear to be clean. Stay safe:${RST}"
  echo -e "${GRN}  - Pin axios to a safe version (e.g. 1.8.4)${RST}"
  echo -e "${GRN}  - Run: npm audit${RST}"
  echo -e "${GRN}  - Consider enabling 2FA on your npm account${RST}"
fi
echo -e "${BLD}${CYN}============================================${RST}"
echo ""
