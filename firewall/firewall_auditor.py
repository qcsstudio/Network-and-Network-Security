"""
=============================================================
 QCSSTUDIO — Firewall Rule Audit Tool
 Author  : Ravi Kant Sankhyan
 Purpose : Parse and audit firewall ACL rules for common
           misconfigurations and security weaknesses
=============================================================
"""

import re
from datetime import datetime

# ─── Sample ACL rules (replace with parsed device output) ────
SAMPLE_ACL = """
permit ip any any
permit tcp any any eq 23
permit tcp any any eq 21
deny   tcp any any eq 22
permit ip 10.0.0.0 0.255.255.255 any
permit tcp any any eq 80
permit tcp any any eq 443
permit icmp any any
permit udp any any eq 161
"""

# ─── Risk Rules ───────────────────────────────────────────────
RISK_RULES = [
    {
        "pattern": r"permit\s+ip\s+any\s+any",
        "severity": "CRITICAL",
        "message": "Overly permissive rule: 'permit ip any any' allows all traffic. Restrict source/destination.",
    },
    {
        "pattern": r"permit\s+tcp\s+any\s+any\s+eq\s+23",
        "severity": "CRITICAL",
        "message": "Telnet (port 23) is permitted from any source. Telnet is unencrypted — use SSH instead.",
    },
    {
        "pattern": r"permit\s+tcp\s+any\s+any\s+eq\s+21",
        "severity": "HIGH",
        "message": "FTP (port 21) is permitted from any source. FTP sends credentials in plaintext — use SFTP/SCP.",
    },
    {
        "pattern": r"deny\s+tcp\s+any\s+any\s+eq\s+22",
        "severity": "HIGH",
        "message": "SSH (port 22) is explicitly denied. Ensure alternative management access exists.",
    },
    {
        "pattern": r"permit\s+icmp\s+any\s+any",
        "severity": "MEDIUM",
        "message": "ICMP permitted from any source. Consider restricting to trusted management subnets.",
    },
    {
        "pattern": r"permit\s+udp\s+any\s+any\s+eq\s+161",
        "severity": "HIGH",
        "message": "SNMP (UDP 161) permitted from any source. Restrict to NMS server IP only.",
    },
]

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
SEVERITY_ICON  = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢", "INFO": "ℹ️"}


def audit_acl(acl_text: str) -> list:
    """Run all risk rules against the ACL and return findings."""
    findings = []
    lines = [l.strip() for l in acl_text.strip().splitlines() if l.strip()]

    for i, line in enumerate(lines, start=1):
        for rule in RISK_RULES:
            if re.search(rule["pattern"], line, re.IGNORECASE):
                findings.append({
                    "line_no": i,
                    "rule": line,
                    "severity": rule["severity"],
                    "message": rule["message"],
                })

    # Sort by severity
    findings.sort(key=lambda x: SEVERITY_ORDER.get(x["severity"], 99))
    return findings


def print_report(findings: list):
    """Print a formatted audit report to console."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print("\n" + "=" * 65)
    print("  QCSSTUDIO — Firewall ACL Audit Report")
    print(f"  Author   : Ravi Kant Sankhyan")
    print(f"  Generated: {timestamp}")
    print("=" * 65)

    if not findings:
        print("\n  ✅ No issues found. ACL looks clean!")
    else:
        print(f"\n  ⚠️  {len(findings)} issue(s) found:\n")
        for f in findings:
            icon = SEVERITY_ICON.get(f["severity"], "•")
            print(f"  {icon} [{f['severity']}] Line {f['line_no']}: {f['rule']}")
            print(f"     → {f['message']}\n")

    # Summary
    counts = {}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    print("─" * 65)
    print("  SUMMARY")
    print("─" * 65)
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        icon = SEVERITY_ICON[sev]
        print(f"  {icon} {sev:<10}: {counts.get(sev, 0)}")
    print("=" * 65)


def save_report(findings: list, filename: str = None):
    """Save the audit report to a text file."""
    if not filename:
        filename = f"firewall_audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    with open(filename, "w") as f:
        f.write("QCSSTUDIO Firewall ACL Audit Report\n")
        f.write(f"Author: Ravi Kant Sankhyan\n")
        f.write(f"Generated: {datetime.now()}\n\n")
        for finding in findings:
            f.write(f"[{finding['severity']}] Line {finding['line_no']}: {finding['rule']}\n")
            f.write(f"  → {finding['message']}\n\n")
    print(f"\n  📄 Report saved to: {filename}")


def main():
    findings = audit_acl(SAMPLE_ACL)
    print_report(findings)
    save_report(findings)


if __name__ == "__main__":
    main()
