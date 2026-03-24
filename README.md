# WinPosture

**Portable Windows security posture auditor.** Runs locally, requires no cloud
connectivity, and produces a scored terminal report and/or self-contained HTML
report of your system's security configuration.

[![Tests](https://github.com/hexorcist404/winposture/actions/workflows/test.yml/badge.svg)](https://github.com/hexorcist404/winposture/actions/workflows/test.yml)
[![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

---

## Why WinPosture?

Most security auditing tools are either cloud-based (sending your data somewhere),
require expensive licenses, or are complex enterprise platforms. WinPosture is a
single executable you can drop on a USB drive and run on any Windows machine in
seconds — no installation, no internet, no surprises. Run it as Administrator for
full results — it works without admin too, but some checks (like BitLocker and
certain security policies) will be limited. It gives you an actionable security
score with plain-English remediation advice.

---

## Quick Start — Standalone Executable

No Python required.

1. Download `winposture.exe` from the [Releases](https://github.com/hexorcist404/winposture/releases) page
2. Open a terminal (Command Prompt or PowerShell) **as Administrator** for full results
3. Run:

```
winposture.exe
```

For a full HTML report:

```
winposture.exe --html report.html
```

Then open `report.html` in your browser.

---

## Terminal Output

**Standard scan (default view):**

![WinPosture scan overview](assets/screenshots/scan-overview.png)

**Verbose mode (`--verbose`) — full details and remediation steps for every check:**

![WinPosture verbose output](assets/screenshots/scan-verbose.png)

**Top issues summary (shown at the end of every scan):**

![WinPosture top issues](assets/screenshots/scan-top-issues.png)

---

## Installation via pip

Requires Python 3.12+ and Windows 10/11 or Server 2019/2022.

Install from source:

```bash
git clone https://github.com/hexorcist404/winposture.git
cd winposture
pip install -e .
winposture
```

PyPI package coming soon.

---

## Authorized Use Notice

> **WinPosture is a READ-ONLY auditing tool.**  It does not modify any system
> settings, write to the registry, or make network connections.  All data stays
> on the machine being audited.
>
> **Only run WinPosture on systems you own or have explicit written authorization
> to audit.**  Unauthorized use may violate computer fraud laws in your jurisdiction.

---

## Usage

```
winposture [OPTIONS]

Options:
  --html PATH          Save a self-contained HTML report to PATH
  --json PATH          Save a JSON report to PATH
  --baseline FILE      Save current scan as a JSON baseline for future comparisons
  --compare  FILE      Compare current scan against a saved baseline
  --profile  FILE      Load a custom check profile from a TOML file
  --category CATS      Comma-separated list of categories to audit
                       (e.g. firewall,encryption,patching)
  --dry-run            List check modules that would run without executing them
  --verbose            Show detail for every check, including PASSes
  --no-color           Disable Rich color output (for CI / log files)
  --log-level LEVEL    Logging verbosity: DEBUG, INFO, WARNING (default), ERROR
  --version            Show version and exit
  -h, --help           Show this help message and exit

Exit codes:
  0  Score >= 70 (passing)
  1  Score < 70 (failing)
  2  Fatal scan error
```

### Examples

```bash
# Full audit, terminal only
winposture

# Save HTML report
winposture --html report.html

# Save JSON for automation / SIEM integration
winposture --json report.json

# Audit only firewall and patching
winposture --category firewall,patching

# Show pass/fail details for every check
winposture --verbose

# Silent mode for scripts (exits 0 if score>=70, 1 if score<70, 2 on error)
winposture --no-color --log-level ERROR
echo Exit code: %ERRORLEVEL%

# Save a baseline, then compare on the next run
winposture --baseline baseline.json
winposture --compare  baseline.json

# Apply a custom check profile (e.g. for MSP clients)
winposture --profile myprofile.toml

# List which checks would run without executing anything
winposture --dry-run
```

### Custom Profiles (`winposture.toml`)

Create a `winposture.toml` in your working directory (or pass `--profile FILE`)
to customise scan behaviour:

```toml
[profile]
name = "MSP-Baseline"

[disabled_checks]
# Skip checks irrelevant to this environment
checks = [
    "SMBv1 Disabled",
    "Firewall — Public Default Inbound Action",
]

[severity_overrides]
# Downgrade noisy low-risk checks
"Defender Tamper Protection" = "LOW"

[thresholds]
# Allow 45 days between updates before warning (default: 30)
max_update_age_warn = 45
max_update_age_fail = 90
```

---

## Scoring System

WinPosture calculates a **0–100 security score** by starting at 100 and
deducting points for failed and warned checks, weighted by severity:

| Outcome | Severity | Deduction |
|---------|----------|-----------|
| FAIL    | CRITICAL | -15       |
| FAIL    | HIGH     | -10       |
| FAIL    | MEDIUM   | -5        |
| FAIL    | LOW      | -2        |
| WARN    | CRITICAL | -7        |
| WARN    | HIGH     | -5        |
| WARN    | MEDIUM   | -2        |
| WARN    | LOW      | -1        |

The score is clamped to [0, 100].

**Grade scale:**

| Score  | Grade | Label     |
|--------|-------|-----------|
| 90-100 | A     | Excellent |
| 80-89  | B     | Good      |
| 70-79  | C     | Fair      |
| 60-69  | D     | Poor      |
| 0-59   | F     | Critical  |

INFO and ERROR results do not affect the score.

---

## CIS Benchmark Mapping

Where applicable, findings are mapped to CIS Microsoft Windows Benchmark control
IDs (CIS Microsoft Windows 11 Enterprise Benchmark v3.0.0). These references
appear as blue badges in the HTML report's detailed findings section, making
WinPosture useful for compliance documentation and audit preparation.

---

## Checks Performed

| Category       | Check                                  | Description                                                                        |
|----------------|----------------------------------------|------------------------------------------------------------------------------------|
| Access Control | UAC Admin Consent Behavior             | Checks the UAC consent prompt behavior for administrator accounts                  |
| Access Control | UAC Enabled                            | Checks whether User Account Control (UAC) is enabled                               |
| Access Control | UAC Secure Desktop                     | Checks whether UAC prompts are shown on the isolated secure desktop                |
| Access Control | UAC Standard User Behavior             | Checks the UAC consent prompt behavior for standard user accounts                  |
| Accounts       | Built-in Administrator Account         | Checks whether the built-in Administrator account is enabled or renamed            |
| Accounts       | Guest Account                          | Checks whether the built-in Guest account is disabled                              |
| Accounts       | Local Administrators                   | Counts members of the local Administrators group (warns if > 2)                    |
| Accounts       | Password Policy — Account Lockout      | Checks whether account lockout is configured to deter brute-force attacks          |
| Accounts       | Password Policy — Complexity           | Checks whether password complexity requirements are enforced                       |
| Accounts       | Password Policy — Minimum Length       | Checks minimum password length (fail < 8 chars, warn < 12 chars)                  |
| Antivirus      | Defender Real-Time Protection          | Checks whether Windows Defender real-time protection is active                     |
| Antivirus      | Defender Signature Age                 | Checks whether virus definitions are less than 7 days old                          |
| Antivirus      | Defender Tamper Protection             | Checks whether Tamper Protection prevents unauthorised Defender changes             |
| Antivirus      | Registered AV Products                 | Lists antivirus products registered with Windows Security Center                   |
| Encryption     | BitLocker — {drive} *                  | BitLocker encryption and protection status per fixed drive (one result per drive)  |
| File Sharing   | SMB Encryption *                       | Checks whether SMB encryption (EncryptData) is enforced                            |
| File Sharing   | SMB Signing Required *                 | Checks that SMB message signing is required (mitigates NTLM relay attacks)         |
| File Sharing   | SMBv1 Disabled *                       | Checks that SMBv1 is disabled (mitigates EternalBlue/WannaCry/NotPetya)           |
| Firewall       | Firewall — Domain Default Inbound Action | Checks that the Domain profile does not explicitly allow all inbound connections  |
| Firewall       | Firewall — Domain Profile Enabled      | Checks whether Windows Firewall is enabled for domain networks                     |
| Firewall       | Firewall — Private Default Inbound Action | Checks that the Private profile does not explicitly allow all inbound connections |
| Firewall       | Firewall — Private Profile Enabled     | Checks whether Windows Firewall is enabled for private networks                    |
| Firewall       | Firewall — Public Default Inbound Action | Checks that the Public profile does not explicitly allow all inbound connections  |
| Firewall       | Firewall — Public Profile Enabled      | Checks whether Windows Firewall is enabled for public networks                     |
| Hardening      | Audit Policy                           | Checks that key subcategories (Logon, Lockout, etc.) log success/failure events    |
| Hardening      | AutoPlay Disabled                      | Checks whether AutoPlay is disabled for all drive types                            |
| Hardening      | Screen Lock Timeout                    | Checks that the screen automatically locks within 15 minutes of inactivity         |
| Hardening      | Speculative Execution Mitigations      | Checks whether Spectre/Meltdown mitigations have been explicitly disabled          |
| Hardening      | WinRM Status                           | Checks whether the Windows Remote Management (WinRM) service is running            |
| Network        | IPv6 Status                            | Reports whether IPv6 is active on any network adapter (informational)              |
| Network        | LLMNR Disabled                         | Checks whether LLMNR is disabled (susceptible to poisoning/Responder attacks)      |
| Network        | Listening Port — {port}/{service}      | Flags known-dangerous listening ports: FTP (21), Telnet (23), TFTP (69), RDP (3389) |
| Network        | Listening Ports — Summary              | Enumerates all TCP ports currently in LISTEN state (informational)                 |
| Network        | NetBIOS over TCP/IP                    | Checks whether NetBIOS over TCP/IP is disabled on all network adapters             |
| Patching       | Last Windows Update                    | Checks when the most recent update was installed (warn > 30 days, fail > 60 days) |
| Patching       | Pending Windows Updates                | Counts Windows Updates that are available but not yet installed                    |
| Patching       | Windows Update Service                 | Checks whether the Windows Update (wuauserv) service is running                   |
| Persistence    | Scheduled Tasks                        | Enumerates non-Microsoft scheduled tasks (potential persistence points)            |
| Persistence    | Startup Programs                       | Enumerates programs configured to run at startup (registry Run keys + folders)    |
| PowerShell     | PowerShell Constrained Language Mode   | Checks whether PowerShell Constrained Language Mode is active                      |
| PowerShell     | PowerShell Execution Policy            | Checks the LocalMachine execution policy (warns on Unrestricted/Bypass)            |
| PowerShell     | PowerShell Module Logging              | Checks whether PowerShell module pipeline logging is enabled                       |
| PowerShell     | PowerShell Script Block Logging        | Checks whether Script Block Logging is enabled (critical for forensics/IR)         |
| PowerShell     | PowerShell v2                          | Checks whether PowerShell v2 is installed (downgrade attack vector)                |
| Remote Access  | RDP Enabled                            | Checks whether Remote Desktop Protocol is enabled                                  |
| Remote Access  | RDP Network Level Authentication †     | Checks whether NLA is required for RDP connections                                 |
| Remote Access  | RDP Port †                             | Reports the RDP listening port (informational)                                     |
| Services       | Risky Services / Risky Service — {name} | Flags known-dangerous services if running: Remote Registry, Telnet, SNMP          |
| Services       | Unquoted Service Paths                 | Detects services with unquoted executable paths containing spaces (privilege-escalation vector) |
| System         | Domain Membership                      | Reports whether the machine is domain-joined or in a workgroup (informational)     |
| System         | OS End-of-Support Status               | Checks whether the installed Windows build is still supported by Microsoft         |
| System         | OS Version                             | Reports the installed Windows version and build number (informational)             |
| System         | Secure Boot                            | Checks whether UEFI Secure Boot is enabled                                         |
| System         | System Uptime                          | Checks system uptime (warns if > 30 days, suggesting pending patch reboots)        |
| System         | TPM Status                             | Checks whether a TPM chip is present and functional                                |

\* Requires **Administrator** privileges for full results.
† Only emitted when RDP is enabled.

---

## Building the Executable

Prerequisites: Python 3.12+, `pip install pyinstaller pillow`

```bash
python build.py
```

The exe will be at `dist/winposture.exe`. To build without the custom icon:

```bash
python build.py --no-icon
```

---

## Contributing

1. Fork the repo and create a branch: `git checkout -b feat/my-change`
2. Make your changes — each check module is self-contained in `src/winposture/checks/`
3. Add or update tests in `tests/`
4. Run `pytest tests/ -q` — all tests must pass
5. Open a pull request into `main`

### Adding a New Check Module

Create `src/winposture/checks/mycheck.py` with:

```python
from winposture.models import CheckResult, Severity, Status

CATEGORY = "MyCategory"
# REQUIRES_ADMIN = True  # uncomment if elevation is needed

def run() -> list[CheckResult]:
    # ... query the system ...
    return [CheckResult(
        category=CATEGORY,
        check_name="My Check Name",
        status=Status.PASS,       # PASS | FAIL | WARN | INFO | ERROR
        severity=Severity.HIGH,   # CRITICAL | HIGH | MEDIUM | LOW | INFO
        description="What this check verifies.",
        details="What was found.",
        remediation="",           # empty string for PASS
    )]
```

The scanner auto-discovers all modules in `checks/` — no registration needed.

---

## License

MIT — see [LICENSE](LICENSE).
