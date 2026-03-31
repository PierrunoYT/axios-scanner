#!/usr/bin/env bash
# ============================================================
#  check-axios-rat.sh
#  Checks for indicators of compromise from the axios/LiteLLM
#  supply chain attack (March 31, 2026)
#  Affected packages: axios@1.14.1, axios@0.30.4,
#                     plain-crypto-js@4.2.1
#  C2 server: sfrclak[.]com:8000
# ============================================================

RED='\033[0;31m'
YEL='\033[0;33m'
GRN='\033[0;32m'
CYN='\033[0;36m'
BLD='\033[1m'
RST='\033[0m'

FOUND=0

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

# ── 1. Malicious files dropped by the RAT ───────────────────

banner
echo -e "${BLD}1. Checking for malicious files on disk...${RST}"

if [[ "$OSTYPE" == "darwin"* ]]; then
  # macOS payload: Mach-O RAT disguised as a system cache file
  RAT_PATH="/Library/Caches/com.apple.act.mond"
  info "macOS RAT payload: $RAT_PATH"
  if [[ -f "$RAT_PATH" ]]; then
    flag "Found macOS RAT payload: $RAT_PATH"
  else
    ok "macOS RAT payload not found"
  fi
else
  # Linux payload: Python backdoor
  LINUX_RAT="/tmp/ld.py"
  info "Linux RAT payload: $LINUX_RAT"
  if [[ -f "$LINUX_RAT" ]]; then
    flag "Found Linux RAT payload: $LINUX_RAT"
  else
    ok "Linux RAT payload not found"
  fi
fi

# ── 2. Malicious npm packages in global/local node_modules ──

echo ""
echo -e "${BLD}2. Checking npm packages...${RST}"

check_npm_pkg() {
  local pkg="$1"
  local bad_ver="$2"
  local dir="$3"
  local pkg_json="$dir/node_modules/$pkg/package.json"

  if [[ -f "$pkg_json" ]]; then
    local ver
    ver=$(node -e "try{process.stdout.write(require('$pkg_json').version)}catch(e){}" 2>/dev/null)
    if [[ -n "$bad_ver" && "$ver" == "$bad_ver" ]]; then
      flag "Found $pkg@$ver in $dir"
    elif [[ -z "$bad_ver" && -n "$ver" ]]; then
      # any version of plain-crypto-js is suspicious
      flag "Found $pkg@$ver in $dir (any version is suspicious)"
    elif [[ -n "$ver" ]]; then
      ok "$pkg@$ver in $dir (not a known bad version)"
    fi
  fi
}

# Global npm prefix
GLOBAL_NM="$(npm root -g 2>/dev/null)"
if [[ -n "$GLOBAL_NM" ]]; then
  info "Global node_modules: $GLOBAL_NM"
  check_npm_pkg "axios" "1.14.1" "$(dirname "$GLOBAL_NM")"
  check_npm_pkg "axios" "0.30.4" "$(dirname "$GLOBAL_NM")"
  check_npm_pkg "plain-crypto-js" "" "$(dirname "$GLOBAL_NM")"
fi

# Current directory
if [[ -f "package.json" ]]; then
  info "Local node_modules: $(pwd)/node_modules"
  local_axios_ver=$(node -e "try{process.stdout.write(require('./node_modules/axios/package.json').version)}catch(e){}" 2>/dev/null)
  if [[ "$local_axios_ver" == "1.14.1" || "$local_axios_ver" == "0.30.4" ]]; then
    flag "Local axios@$local_axios_ver is MALICIOUS"
  elif [[ -n "$local_axios_ver" ]]; then
    ok "Local axios@$local_axios_ver is not a known bad version"
  fi

  if [[ -d "./node_modules/plain-crypto-js" ]]; then
    pcjs_ver=$(node -e "try{process.stdout.write(require('./node_modules/plain-crypto-js/package.json').version)}catch(e){}" 2>/dev/null)
    flag "Found plain-crypto-js@$pcjs_ver in local node_modules"
  fi
fi

# npm cache — check if the bad tarballs were ever downloaded
echo ""
echo -e "${BLD}3. Scanning npm cache for malicious tarballs...${RST}"
NPM_CACHE="$(npm config get cache 2>/dev/null)"
if [[ -d "$NPM_CACHE" ]]; then
  for bad in "axios-1.14.1" "axios-0.30.4" "plain-crypto-js"; do
    if find "$NPM_CACHE" -name "${bad}*" 2>/dev/null | grep -q .; then
      warn "Found cached tarball matching '$bad' in $NPM_CACHE — package was downloaded"
    fi
  done
  ok "npm cache scan complete"
fi

# ── 3. Network: active connections to C2 ────────────────────

echo ""
echo -e "${BLD}4. Checking for active C2 connections (sfrclak.com:8000)...${RST}"

C2_DOMAIN="sfrclak.com"
C2_PORT="8000"

# Try ss first (Linux), fall back to netstat
if command -v ss &>/dev/null; then
  C2_CONN=$(ss -tnp 2>/dev/null | grep ":$C2_PORT")
elif command -v netstat &>/dev/null; then
  C2_CONN=$(netstat -an 2>/dev/null | grep ":$C2_PORT")
fi

if [[ -n "$C2_CONN" ]]; then
  flag "Active connection to port $C2_PORT detected:\n$C2_CONN"
else
  ok "No active connection to :$C2_PORT"
fi

# DNS lookup — did this host ever resolve the C2 domain?
if command -v host &>/dev/null; then
  if host "$C2_DOMAIN" &>/dev/null; then
    warn "DNS resolved $C2_DOMAIN — this domain is the known C2 server. If you did NOT look this up intentionally, your machine may have contacted it."
  fi
fi

# ── 4. Process check ────────────────────────────────────────

echo ""
echo -e "${BLD}5. Checking for suspicious processes...${RST}"

SUSPICIOUS_PROCS=("ld.py" "wt.exe" "act.mond" "plain-crypto" "setup.js")
for proc in "${SUSPICIOUS_PROCS[@]}"; do
  if pgrep -f "$proc" &>/dev/null; then
    flag "Suspicious process running: $proc"
  fi
done
ok "No known malicious processes found"

# ── 5. pip / LiteLLM check ──────────────────────────────────

echo ""
echo -e "${BLD}6. Checking LiteLLM (Python) installation...${RST}"
info "LiteLLM was also compromised via Trivy/TeamPCP attack"

if command -v pip &>/dev/null || command -v pip3 &>/dev/null; then
  PIP=$(command -v pip3 || command -v pip)
  LITELLM_VER=$("$PIP" show litellm 2>/dev/null | grep Version | awk '{print $2}')
  if [[ -n "$LITELLM_VER" ]]; then
    warn "LiteLLM $LITELLM_VER is installed. Check https://github.com/BerriAI/litellm for compromised version ranges."
  else
    ok "LiteLLM not installed via pip"
  fi
fi

# ── 6. Lock-file audit ──────────────────────────────────────

echo ""
echo -e "${BLD}7. Scanning lock files in current directory...${RST}"

for lockfile in package-lock.json yarn.lock pnpm-lock.yaml; do
  if [[ -f "$lockfile" ]]; then
    info "Found $lockfile"
    if grep -q "1\.14\.1\|0\.30\.4" "$lockfile" 2>/dev/null; then
      flag "$lockfile references a malicious axios version (1.14.1 or 0.30.4)"
    fi
    if grep -q "plain-crypto-js" "$lockfile" 2>/dev/null; then
      flag "$lockfile references plain-crypto-js"
    fi
  fi
done

# ── Summary ─────────────────────────────────────────────────

echo ""
echo -e "${BLD}${CYN}============================================${RST}"
if [[ $FOUND -eq 1 ]]; then
  echo -e "${RED}${BLD}  RESULT: INDICATORS OF COMPROMISE FOUND${RST}"
  echo -e "${RED}${BLD}  Immediate actions required:${RST}"
  echo -e "${RED}  1. Rotate ALL credentials, API keys, SSH keys${RST}"
  echo -e "${RED}  2. Remove malicious files listed above${RST}"
  echo -e "${RED}  3. npm uninstall axios plain-crypto-js${RST}"
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
