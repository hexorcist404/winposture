# WinPosture

A portable Windows security posture auditor. Runs locally, requires no installation
beyond Python, and produces a scored HTML or terminal report of your system's security
configuration.

## Features

- Audits Windows Firewall, BitLocker, Windows Defender/AV, Windows Update, RDP, SMB,
  UAC, PowerShell policy, local accounts, open ports, startup items, and more
- Overall security score (0–100)
- Color-coded terminal output via [Rich](https://github.com/Textualize/rich)
- Optional HTML report (Jinja2 template)
- Optional JSON export for integration with other tools
- Runs on Windows 10/11 and Windows Server 2019/2022

## Requirements

- Python 3.12+
- Windows 10/11 or Windows Server 2019/2022
- Run as **Administrator** for full results (some checks require elevated privileges)

## Installation

```bash
# Clone the repo
git clone https://github.com/yourname/winposture.git
cd winposture

# Install dependencies
pip install -r requirements.txt

# Install in editable mode (optional, enables the `winposture` CLI command)
pip install -e .
```

## Usage

```bash
# Full audit, terminal output only
python -m winposture

# Save HTML report
python -m winposture --html report.html

# Save JSON output
python -m winposture --json report.json

# Run only specific categories
python -m winposture --category firewall,encryption

# Verbose output (show details for every check)
python -m winposture --verbose

# Disable color (for CI / log files)
python -m winposture --no-color

# Show version
python -m winposture --version
```

## Project Structure

```
winposture/
├── src/winposture/
│   ├── checks/         # One file per audit category
│   ├── models.py       # CheckResult and AuditReport dataclasses
│   ├── scanner.py      # Orchestrates all check modules
│   ├── reporter.py     # Terminal + HTML output
│   ├── scoring.py      # Risk score calculation
│   ├── utils.py        # PowerShell / registry helpers
│   └── cli.py          # argparse entry point
├── templates/
│   └── report.html.j2  # HTML report template
└── tests/              # pytest test suite
```

## License

MIT — see [LICENSE](LICENSE).
