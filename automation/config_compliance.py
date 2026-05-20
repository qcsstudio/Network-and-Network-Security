"""
╔══════════════════════════════════════════════════════════════════╗
║         QCSSTUDIO — Configuration Compliance Checker             ║
║         Author  : Ravi Kant Sankhyan                             ║
║         GitHub  : github.com/QCSSTUDIO/Network-and-Network-Security ║
╚══════════════════════════════════════════════════════════════════╝

PURPOSE
───────
Compare live device configurations against a defined "golden config"
baseline. Identify unauthorized changes, missing security settings,
and configuration drift across your fleet. Essential for:

  - Change management audits
  - Compliance evidence (SOC2, ISO 27001, PCI-DSS)
  - Post-incident forensics
  - NOC drift detection

HOW IT WORKS
────────────
  1. Define REQUIRED_LINES — config lines that MUST be present
  2. Define FORBIDDEN_LINES — config lines that must NEVER appear
  3. Connect to each device and pull running config
  4. Check every line against both lists
  5. Output a compliance report with pass/fail per device
"""

import os
import re
import json
from datetime import datetime
from pathlib import Path
from typing import List, Tuple

try:
    from netmiko import ConnectHandler, NetmikoTimeoutException, NetmikoAuthenticationException
except ImportError:
    print("[ERROR] Run: pip install -r requirements.txt")
    raise

# ─────────────────────────────────────────────────────────────────────
# GOLDEN CONFIG — COMPLIANCE RULES
# These rules define your security and operational baseline.
# Customize these to match your organization's standards.
# ─────────────────────────────────────────────────────────────────────

REQUIRED_LINES = [
    # Management & AAA
    r"service password-encryption",
    r"username \S+ privilege 15 secret",
    r"aaa new-model",
    r"aaa authentication login default group (tacacs\+|radius) local",
    r"ip ssh version 2",
    r"ip ssh time-out 60",
    r"ip ssh authentication-retries 3",

    # Logging
    r"logging on",
    r"logging buffered \d+",
    r"logging trap (informational|notifications|warnings|errors)",

    # NTP
    r"ntp server \S+",
    r"ntp authenticate",

    # Banners
    r"banner (login|motd)",

    # Timeouts
    r"exec-timeout \d+ \d+",

    # Disable CDP on external interfaces (check manually if needed)
    # r"no cdp run",

    # SNMP (if used must be v3)
    r"snmp-server group \S+ v3 (auth|priv)",
]

FORBIDDEN_LINES = [
    # Insecure protocols
    r"transport input (all|telnet)(?! ssh)",  # Telnet allowed
    r"ip http server(?! secure)",             # Plain HTTP server
    r"snmp-server community \S+ (RW|rw)",     # SNMP RW community
    r"snmp-server community public",           # Default SNMP community
    r"snmp-server community private",          # Default SNMP community
    r"service finger",                         # Finger protocol
    r"service tcp-small-servers",
    r"service udp-small-servers",
    r"no service password-encryption",
    r"enable password ",                       # Plaintext enable password
    r"username \S+ password ",                 # Plaintext user password
    r"ip source-route",                        # Source routing
    r"ip proxy-arp",                           # Proxy ARP
    r"ip bootp server",                        # BOOTP server
    r"no ip domain-lookup",                    # Sometimes needed but flag for review
]


# ─────────────────────────────────────────────────────────────────────
# DEVICE LIST
# ─────────────────────────────────────────────────────────────────────
DEVICES = [
    {
        "name": "Core-Router-01",
        "device_type": "cisco_ios",
        "host": "192.168.1.1",
        "username": os.environ.get("NET_USERNAME", "admin"),
        "password": os.environ.get("NET_PASSWORD", "changeme"),
        "secret":   os.environ.get("NET_SECRET",   "changeme"),
    },
    {
        "name": "Distribution-SW-01",
        "device_type": "cisco_ios",
        "host": "192.168.1.2",
        "username": os.environ.get("NET_USERNAME", "admin"),
        "password": os.environ.get("NET_PASSWORD", "changeme"),
        "secret":   os.environ.get("NET_SECRET",   "changeme"),
    },
]

REPORT_DIR = Path(__file__).parent / "reports"
REPORT_DIR.mkdir(exist_ok=True)


# ─────────────────────────────────────────────────────────────────────
# COMPLIANCE CHECKS
# ─────────────────────────────────────────────────────────────────────

def check_required(config: str) -> List[Tuple[str, bool]]:
    """Return list of (pattern, found) for all required lines."""
    results = []
    for pattern in REQUIRED_LINES:
        found = bool(re.search(pattern, config, re.IGNORECASE | re.MULTILINE))
        results.append((pattern, found))
    return results


def check_forbidden(config: str) -> List[Tuple[str, bool]]:
    """Return list of (pattern, present) for forbidden lines — present=True is BAD."""
    results = []
    for pattern in FORBIDDEN_LINES:
        present = bool(re.search(pattern, config, re.IGNORECASE | re.MULTILINE))
        results.append((pattern, present))
    return results


def compliance_score(required_results, forbidden_results) -> float:
    """Calculate a compliance percentage score."""
    total   = len(required_results) + len(forbidden_results)
    passed  = sum(1 for _, found in required_results if found)
    passed += sum(1 for _, present in forbidden_results if not present)
    return (passed / total * 100) if total > 0 else 100.0


# ─────────────────────────────────────────────────────────────────────
# REPORTING
# ─────────────────────────────────────────────────────────────────────

COMPLIANCE_GRADE = {
    range(90, 101): ("A", "🟢 COMPLIANT"),
    range(75, 90):  ("B", "🟡 MOSTLY COMPLIANT"),
    range(50, 75):  ("C", "🟠 PARTIALLY COMPLIANT"),
    range(0,  50):  ("D", "🔴 NON-COMPLIANT"),
}

def get_grade(score: float) -> Tuple[str, str]:
    for r, grade in COMPLIANCE_GRADE.items():
        if int(score) in r:
            return grade
    return ("D", "🔴 NON-COMPLIANT")


def print_device_report(device_name: str, required, forbidden, score: float):
    grade_letter, grade_label = get_grade(score)
    print(f"\n  {'═' * 60}")
    print(f"  Device  : {device_name}")
    print(f"  Score   : {score:.1f}%  |  Grade: {grade_letter}  |  {grade_label}")
    print(f"  {'─' * 60}")

    missing   = [(p, f) for p, f in required if not f]
    forbidden_present = [(p, f) for p, f in forbidden if f]

    if missing:
        print(f"\n  ⚠️  MISSING REQUIRED CONFIG ({len(missing)} items):")
        for pattern, _ in missing:
            print(f"      ✗  {pattern}")

    if forbidden_present:
        print(f"\n  🚫 FORBIDDEN CONFIG DETECTED ({len(forbidden_present)} items):")
        for pattern, _ in forbidden_present:
            print(f"      ✗  {pattern}")

    if not missing and not forbidden_present:
        print(f"\n  ✅ Fully compliant — no issues detected.")


def save_json_report(all_results: list):
    ts       = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = REPORT_DIR / f"compliance_report_{ts}.json"
    with open(filename, "w") as f:
        json.dump(all_results, f, indent=2)
    print(f"\n  📄 Full report saved → {filename.name}")


# ─────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────

def main():
    print("\n" + "═" * 68)
    print("  QCSSTUDIO — Configuration Compliance Checker")
    print("  Author  : Ravi Kant Sankhyan")
    print(f"  Run at  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("═" * 68)

    all_results = []

    for device in DEVICES:
        print(f"\n  [+] Connecting to {device['name']} ({device['host']})...")
        try:
            params = {k: v for k, v in device.items() if k != "name"}
            conn   = ConnectHandler(**params)
            conn.enable()
            print(f"      ✅ Connected.")

            config = conn.send_command("show running-config", read_timeout=120)
            conn.disconnect()

        except NetmikoAuthenticationException:
            print(f"      ❌ Authentication failed.")
            continue
        except NetmikoTimeoutException:
            print(f"      ❌ Connection timed out.")
            continue

        required_results  = check_required(config)
        forbidden_results = check_forbidden(config)
        score             = compliance_score(required_results, forbidden_results)
        grade_letter, grade_label = get_grade(score)

        print_device_report(device["name"], required_results, forbidden_results, score)

        all_results.append({
            "device":            device["name"],
            "host":              device["host"],
            "compliance_score":  round(score, 1),
            "grade":             grade_letter,
            "status":            grade_label,
            "missing_required":  [p for p, f in required_results if not f],
            "forbidden_found":   [p for p, f in forbidden_results if f],
        })

    # ─── Final summary ────────────────────────────────────────────
    if all_results:
        print(f"\n  {'═' * 68}")
        print(f"  OVERALL COMPLIANCE SUMMARY")
        print(f"  {'─' * 68}")
        avg_score = sum(r["compliance_score"] for r in all_results) / len(all_results)
        for r in all_results:
            print(f"  {r['status']}  {r['device']:<30} {r['compliance_score']:>5.1f}%  Grade: {r['grade']}")
        print(f"  {'─' * 68}")
        print(f"  Fleet Average Compliance Score: {avg_score:.1f}%")
        print(f"  {'═' * 68}")

        save_json_report(all_results)


if __name__ == "__main__":
    main()
