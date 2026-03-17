"""WinPosture check modules package.

Each module in this package must expose:
  CATEGORY: str          — logical grouping name (e.g. "Firewall")
  run() -> list[CheckResult]  — performs the checks and returns results
"""
