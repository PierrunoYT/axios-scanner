# axios / LiteLLM RAT — IOC Checker

Scripts to detect indicators of compromise (IOCs) from the **axios npm supply chain attack** that occurred on **March 31, 2026**.

---

## Background

On March 31, 2026, attackers compromised the npm account of the primary axios maintainer and published two malicious versions of the widely-used HTTP client:

- `axios@1.14.1`
- `axios@0.30.4`

Both versions injected a hidden dependency — `plain-crypto-js@4.2.1` — that executed a post-install script dropping a **cross-platform Remote Access Trojan (RAT)** on the developer's machine. The RAT contacted a command-and-control server at `sfrclak[.]com:8000` and delivered platform-specific payloads for Windows, macOS, and Linux.

In a related but separate attack, the threat actor group **TeamPCP** also compromised **LiteLLM** (a popular Python library) via the security tool Trivy.

The malicious axios versions were live for roughly 2–3 hours before being removed from npm. Any `npm install` during that window on a project pulling the latest axios could have been compromised.

---

## What These Scripts Check

| # | Check | Windows | macOS | Linux |
|---|-------|:-------:|:-----:|:-----:|
| 1 | Malicious RAT payload on disk | `%PROGRAMDATA%\wt.exe` | `/Library/Caches/com.apple.act.mond` | `/tmp/ld.py` |
| 2 | Malicious axios version in local `node_modules` | ✓ | ✓ | ✓ |
| 3 | Malicious axios version in global `node_modules` | ✓ | ✓ | ✓ |
| 4 | `plain-crypto-js` presence (any version) | ✓ | ✓ | ✓ |
| 5 | npm cache contains bad tarballs | ✓ | ✓ | ✓ |
| 6 | Active TCP connection to C2 (port 8000) | ✓ | ✓ | ✓ |
| 7 | DNS cache resolved `sfrclak.com` | ✓ | – | – |
| 8 | Suspicious processes running | ✓ | ✓ | ✓ |
| 9 | Persistence (scheduled tasks, registry Run keys) | ✓ | – | – |
| 10 | Lock file references (`package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`) | ✓ | ✓ | ✓ |
| 11 | LiteLLM installed via pip | ✓ | ✓ | ✓ |

---

## Requirements

- **Node.js / npm** must be installed to check npm packages and cache
- **Python / pip** (optional) — only needed for the LiteLLM check
- No third-party tools or elevated privileges required for most checks
- The Windows script benefits from running as **Administrator** for full access to scheduled tasks, firewall logs, and `HKLM` registry keys

---

## Usage

### macOS / Linux

```bash
chmod +x check-axios-rat.sh
./check-axios-rat.sh
```

Run from your project directory to also check local `node_modules` and lock files.

### Windows (PowerShell)

```powershell
powershell -ExecutionPolicy Bypass -File check-axios-rat.ps1
```

For full results, run from an **elevated (Administrator) PowerShell** prompt:

```powershell
Start-Process powershell -Verb RunAs -ArgumentList "-ExecutionPolicy Bypass -File check-axios-rat.ps1"
```

---

## Understanding the Output

Each line is prefixed with a status tag:

| Tag | Meaning |
|-----|---------|
| `[OK]` | Check passed, nothing suspicious found |
| `[WARNING]` | Something worth reviewing manually, not necessarily malicious |
| `[COMPROMISED]` | A known indicator of compromise was detected |
| `[CHECK]` | Informational — showing what is being checked |

The script exits with a summary indicating whether any IOCs were found.

---

## If You Are Compromised

If the script reports `[COMPROMISED]` for any check, take the following steps immediately:

1. **Rotate all credentials** — API keys, SSH keys, npm tokens, cloud credentials (AWS, GCP, Azure), GitHub tokens, and any secrets in `.env` files or shell history
2. **Remove malicious files** — delete any files flagged by the script
3. **Uninstall the malicious packages:**
   ```bash
   npm uninstall axios plain-crypto-js
   ```
4. **Reinstall a safe axios version:**
   ```bash
   npm install axios@1.8.4
   ```
5. **Audit your build pipelines** — check CI/CD logs around March 31, 2026 (00:00–03:30 UTC) for any runs that installed axios
6. **Review outbound network logs** — look for connections to `sfrclak.com` or port `8000`
7. **Consider reimaging** if the RAT payload file was present on disk, as full persistence scope is unknown

---

## If You Are Not Compromised

You appear to be clean, but it is still worth taking precautions:

- Pin axios to a known safe version in your `package.json`:
  ```json
  "axios": "1.8.4"
  ```
- Run `npm audit` regularly
- Enable 2FA on your npm account
- Consider using a lockfile and auditing dependency changes in code review

---

## Known IOCs (Indicators of Compromise)

| Type | Value |
|------|-------|
| Malicious npm package | `axios@1.14.1` |
| Malicious npm package | `axios@0.30.4` |
| Malicious dependency | `plain-crypto-js@4.2.1` |
| C2 domain | `sfrclak[.]com` |
| C2 port | `8000` |
| Attacker email | `ifstap@proton.me` |
| Attacker email | `nrwise@proton.me` |
| macOS payload path | `/Library/Caches/com.apple.act.mond` |
| Windows payload path | `%PROGRAMDATA%\wt.exe` |
| Linux payload path | `/tmp/ld.py` |
| npm account compromised | `jasonsaayman` |

> **Note:** Defang the C2 domain (`sfrclak[.]com`) before using it in any network tools to avoid accidental connections.

---

## References

- [StepSecurity — axios Compromised on npm](https://www.stepsecurity.io/blog/axios-compromised-on-npm-malicious-versions-drop-remote-access-trojan)
- [Snyk — axios npm Package Compromised](https://snyk.io/blog/axios-npm-package-compromised-supply-chain-attack-delivers-cross-platform/)
- [Wiz — axios NPM Distribution Compromised](https://www.wiz.io/blog/axios-npm-compromised-in-supply-chain-attack)
- [Socket — Supply Chain Attack on axios](https://socket.dev/blog/axios-npm-package-compromised)
- [The Hacker News — axios Supply Chain Attack](https://thehackernews.com/2026/03/axios-supply-chain-attack-pushes-cross.html)
- [CVE/GHSA tracking](https://github.com/advisories/GHSA-fw8c-xr5c-95f9)

---

## Windows Defender False Positive

Windows Defender (and some other heuristic AV engines) may flag `check-axios-rat.ps1` itself because the script:

- References known malware artifact names (`wt.exe`, `plain-crypto-js`, `sfrclak.com`)
- Queries the DNS client cache, active TCP connections, registry Run keys, and scheduled tasks in a single file

This is a **false positive** — the script performs read-only forensic checks and does not download, execute, or modify anything.

**To confirm the flag is against the script and not a real infection:**

1. Open **Windows Security → Virus & threat protection → Protection history** — the blocked item path should point to `check-axios-rat.ps1`
2. Run the two manual checks below (individually they do not trigger the heuristic):

```powershell
# Should return False
Test-Path "$env:PROGRAMDATA\wt.exe"

# Should return nothing
Get-DnsClientCache | Where-Object { $_.Entry -like "*sfrclak*" }
```

**To run the full script without triggering Defender** (run as Administrator):

```powershell
Add-MpPreference -ExclusionPath "C:\path\to\check-axios-rat.ps1"
powershell -ExecutionPolicy Bypass -File check-axios-rat.ps1
Remove-MpPreference -ExclusionPath "C:\path\to\check-axios-rat.ps1"
```

---

## Disclaimer

These scripts are provided as-is for incident response triage. They check for known IOCs based on public reporting as of March 31, 2026. A clean result does not guarantee your system was not compromised — the malware is designed to self-delete after execution. When in doubt, rotate credentials and consult a security professional.
