"""CIS Benchmark reference mapping for WinPosture check results.

Maps check_name values to CIS Microsoft Windows 11 Enterprise Benchmark
control IDs (v3.0.0, Levels 1 and 2).

References are approximate — always verify against the current official
benchmark for your specific OS version and edition before use in a formal
compliance assessment.
"""

from __future__ import annotations

# Maps check_name prefix → CIS control ID.
# Prefix matching allows one entry to cover dynamically-named checks
# (e.g. "BitLocker — C:" is matched by the "BitLocker" key).
_PREFIX_MAP: dict[str, str] = {
    # ── Firewall (CIS Section 9) ──────────────────────────────────────────
    "Firewall — Domain Profile Enabled":        "CIS 9.1.1",
    "Firewall — Private Profile Enabled":       "CIS 9.2.1",
    "Firewall — Public Profile Enabled":        "CIS 9.3.1",
    "Firewall — Domain Default Inbound":        "CIS 9.1.2",
    "Firewall — Private Default Inbound":       "CIS 9.2.2",
    "Firewall — Public Default Inbound":        "CIS 9.3.2",

    # ── Antivirus (CIS Section 5 / Malware Defenses) ─────────────────────
    "Defender Real-Time Protection":            "CIS 10.1",
    "Defender Signature Age":                   "CIS 10.2",
    "Defender Tamper Protection":               "CIS 10.3",

    # ── Encryption (CIS Section 18.9.11) ─────────────────────────────────
    "BitLocker":                                "CIS 18.9.11.1.1",
    "Secure Boot":                              "CIS 18.9.11.2",
    "TPM Status":                               "CIS 18.9.11.3",

    # ── Accounts (CIS Sections 1 & 2.3.1) ────────────────────────────────
    "Guest Account":                            "CIS 2.3.1.1",
    "Built-in Administrator Account":           "CIS 2.3.1.3",
    "Local Administrators":                     "CIS 2.3.1.4",
    "Password Policy — Minimum Length":         "CIS 1.1.4",
    "Password Policy — Account Lockout":        "CIS 1.2.1",
    "Password Policy — Complexity":             "CIS 1.1.5",

    # ── File Sharing / SMB (CIS Sections 2.3.8 & 18.4.11) ───────────────
    "SMBv1 Disabled":                           "CIS 18.4.11.2",
    "SMB Signing Required":                     "CIS 2.3.8.3",
    "SMB Encryption":                           "CIS 2.3.8.5",

    # ── Remote Access / RDP (CIS Section 18.9.59) ────────────────────────
    "RDP Enabled":                              "CIS 18.9.59.2.1",
    "RDP Network Level Authentication":         "CIS 18.9.59.2.2",
    "RDP Port":                                 "CIS 18.9.59.2.3",

    # ── Access Control / UAC (CIS Section 2.3.17) ────────────────────────
    "UAC Enabled":                              "CIS 2.3.17.1",
    "UAC Admin Consent Behavior":               "CIS 2.3.17.2",
    "UAC Secure Desktop":                       "CIS 2.3.17.4",
    "UAC Standard User Behavior":               "CIS 2.3.17.5",
    "UAC Configuration":                        "CIS 2.3.17.1",

    # ── PowerShell (CIS Section 18.9.95) ─────────────────────────────────
    "PowerShell Execution Policy":              "CIS 18.9.95.2",
    "PowerShell Script Block Logging":          "CIS 18.9.95.1.2",
    "PowerShell Module Logging":                "CIS 18.9.95.1.1",
    "PowerShell Constrained Language Mode":     "CIS 18.9.95.3",
    "PowerShell v2":                            "CIS 18.9.95.4",

    # ── Misc (CIS Sections 18.5 & 18.9.8) ────────────────────────────────
    "LLMNR Disabled":                           "CIS 18.5.4.2",
    "AutoPlay Disabled":                        "CIS 18.9.8.2",
    "WinRM Status":                             "CIS 18.9.102.1",
    "Audit Policy":                             "CIS 17.1.1",

    # ── Patching (CIS Section 18.9.101) ──────────────────────────────────
    "Last Windows Update":                      "CIS 18.9.101.2",
    "Windows Update Service":                   "CIS 18.9.101.1",
    "Pending Windows Updates":                  "CIS 18.9.101.2",

    # ── OS / Hardening ────────────────────────────────────────────────────
    "Speculative Execution Mitigations":        "CIS 18.3.5",
}


def lookup(check_name: str) -> str:
    """Return the CIS Benchmark control ID for *check_name*, or ``''`` if unknown.

    Matching is done by prefix so that dynamically-named checks (e.g.
    ``"BitLocker — C:"``) are covered by a single map entry (``"BitLocker"``).

    Args:
        check_name: The ``check_name`` field from a ``CheckResult``.

    Returns:
        CIS control ID string (e.g. ``"CIS 9.1.1"``), or empty string.
    """
    for prefix, cis_id in _PREFIX_MAP.items():
        if check_name.startswith(prefix):
            return cis_id
    return ""
