# WinPosture — Claude Code Project Context

## Project Overview

WinPosture is a portable Windows security posture auditor. It runs locally on a
Windows machine, audits common security configurations, scores the result (0–100),
and produces a terminal report (Rich) and/or HTML/JSON output.

## Language & Runtime

- Python 3.12+
- Type hints on **all** functions and methods (no bare `Any` unless unavoidable)
- Docstrings on all public functions/classes
- Logging via Python's `logging` module — never use `print()` for diagnostic output

## Architecture

```
cli.py  →  scanner.py  →  checks/*.py  →  models.CheckResult
                      ↓
                  reporter.py  (terminal via Rich, HTML via Jinja2)
                  scoring.py   (0-100 score from results list)
```

### Check Modules (`src/winposture/checks/`)

Each file is an independent audit module. Conventions:

- Expose a `run() -> list[CheckResult]` function (the scanner calls this)
- Never call `sys.exit()` or raise unhandled exceptions — return a result with
  `status=Status.ERROR` and the exception message in `details` instead
- All PowerShell / WMI / registry calls go through helpers in `utils.py`
- A single module may return multiple `CheckResult` objects

### `utils.py`

Shared helpers only. Key functions to build out:

- `run_powershell(script: str) -> str` — runs a PS snippet, returns stdout
- `read_registry(hive, key, value)` — reads a registry value safely
- `is_admin() -> bool` — checks for elevated privileges

### Data Model (`models.py`)

```python
@dataclass
class CheckResult:
    category: str       # e.g. "Firewall", "Encryption"
    check_name: str     # e.g. "Windows Firewall - Domain Profile"
    status: Status      # PASS | FAIL | WARN | INFO | ERROR
    severity: Severity  # CRITICAL | HIGH | MEDIUM | LOW | INFO
    description: str    # What is being verified
    details: str        # What was actually found
    remediation: str    # How to fix it (empty string if status is PASS)
```

## Check Categories (files in `checks/`)

| File | Category | Notes |
|------|----------|-------|
| `os_info.py` | OS | Version, build, patch level |
| `updates.py` | Updates | Windows Update status |
| `firewall.py` | Firewall | All three profiles |
| `antivirus.py` | Antivirus | Defender / third-party AV |
| `encryption.py` | Encryption | BitLocker per drive |
| `accounts.py` | Accounts | Local users, admins, guest, password policy |
| `services.py` | Services | Risky/unnecessary running services |
| `network.py` | Network | Open ports, listening services |
| `startup.py` | Startup | Startup programs, scheduled tasks |
| `smb.py` | SMB | SMBv1 disabled? Signing? |
| `rdp.py` | RDP | Enabled? NLA enforced? |
| `uac.py` | UAC | UAC level |
| `powershell.py` | PowerShell | Execution policy, logging, constrained mode |
| `misc.py` | Misc | AutoPlay, remote registry, LLMNR |

## Testing

- Framework: **pytest**
- Mock all subprocess / WMI / registry calls with `unittest.mock` so tests run on
  any OS (including Linux CI)
- Test files mirror the source: `tests/test_checks/test_firewall.py` etc.
- `tests/conftest.py` holds shared fixtures (sample `CheckResult`, mock PS output…)

## Target Platforms

- Windows 10 (21H2+) and Windows 11
- Windows Server 2019 and 2022

## Output Formats

- **Terminal**: Rich tables with color-coded status/severity
- **HTML**: Jinja2 template at `templates/report.html.j2`
- **JSON**: Serialized `AuditReport` dataclass (use `dataclasses.asdict`)

## Scoring Logic (`scoring.py`)

Start at 100. Deduct points per failed/warned check weighted by severity:

- CRITICAL FAIL: −20
- HIGH FAIL: −10
- MEDIUM FAIL: −5
- LOW FAIL / any WARN: −2
- Clamp to [0, 100]
