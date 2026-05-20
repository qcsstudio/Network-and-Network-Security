"""
╔══════════════════════════════════════════════════════════════════╗
║         QCSSTUDIO — Firewall ACL & Rule Audit Engine             ║
║         Author  : Ravi Kant Sankhyan                             ║
║         GitHub  : github.com/QCSSTUDIO/Network-and-Network-Security ║
╚══════════════════════════════════════════════════════════════════╝

PURPOSE
───────
Parse firewall ACL configurations and evaluate each rule against a
comprehensive security ruleset. Produces severity-ranked findings
with remediation guidance — ready to include in security audit reports.

FINDINGS SEVERITY LEVELS
─────────────────────────
  CRITICAL  — Immediate action required. Direct path to exploitation.
  HIGH      — Significant risk. Remediate within 7 days.
  MEDIUM    — Moderate risk. Remediate within 30 days.
  LOW       — Best practice violation. Remediate in next maintenance window.
  INFO      — Informational. Review and document rationale.

USAGE
─────
  Option 1: Paste ACL text directly into ACL_TEXT below
  Option 2: Load from a file: python firewall_auditor.py --file acl.txt
  Option 3: Connect to device live: python firewall_auditor.py --device 192.168.1.254
"""

import re
import json
import argparse
import os
from datetime import datetime
from pathlib import Path
from typing import List, Dict
from dataclasses import dataclass, asdict

# ─────────────────────────────────────────────────────────────────────
# SAMPLE ACL — Replace with your actual ACL output
# ─────────────────────────────────────────────────────────────────────
SAMPLE_ACL = """
permit ip any any
permit tcp any any eq 23
permit tcp any any eq 21
permit tcp any any eq 512
permit tcp any any eq 513
permit tcp any any eq 514
deny   tcp any any eq 22
permit ip 10.0.0.0 0.255.255.255 any
permit tcp any any eq 80
permit tcp any any eq 443
permit icmp any any
permit udp any any eq 161
permit udp any any eq 69
permit tcp any any eq 1433
permit tcp any any eq 3389
permit tcp any any eq 5900
permit tcp any host 10.0.0.100 eq 3306
deny ip any any
"""

# ─────────────────────────────────────────────────────────────────────
# AUDIT RULE DEFINITIONS
# Each rule: pattern, severity, category, description, remediation
# ─────────────────────────────────────────────────────────────────────
@dataclass
class Finding:
    line_no:     int
    rule_line:   str
    severity:    str
    category:    str
    title:       str
    description: str
    remediation: str
    cve_refs:    List[str]


AUDIT_RULES = [
    # ── CRITICAL ──────────────────────────────────────────────────
    {
        "pattern":     r"permit\s+ip\s+any\s+any",
        "severity":    "CRITICAL",
        "category":    "Overly Permissive",
        "title":       "Wildcard permit: allow all IP from any to any",
        "description": (
            "A 'permit ip any any' rule allows all IP traffic from any source to any "
            "destination, completely bypassing firewall protection. This is equivalent "
            "to having no firewall. This rule is frequently found after misconfigured "
            "troubleshooting steps that were never cleaned up."
        ),
        "remediation": (
            "Immediately remove this rule. Replace with specific permits for only the "
            "source/destination/port combinations that are genuinely required. Ensure "
            "there is an explicit 'deny ip any any' at the end of the ACL."
        ),
        "cve_refs": [],
    },
    {
        "pattern":     r"permit\s+tcp\s+any\s+any\s+eq\s+23",
        "severity":    "CRITICAL",
        "category":    "Insecure Protocol",
        "title":       "Telnet (TCP/23) permitted from any source",
        "description": (
            "Telnet transmits all data including credentials in plaintext. Any attacker "
            "with network access (via MITM, rogue switch port, or packet capture on the "
            "same broadcast domain) can trivially capture device usernames and passwords. "
            "Telnet has been deprecated for network device management since SSH became "
            "universally available in the early 2000s."
        ),
        "remediation": (
            "1. Block Telnet: add 'deny tcp any any eq 23' before any permit rules.\n"
            "2. Ensure SSH v2 is enabled on all devices: 'ip ssh version 2'.\n"
            "3. Restrict SSH access to a dedicated management subnet only.\n"
            "4. On Cisco devices: 'line vty 0 4 / transport input ssh'."
        ),
        "cve_refs": ["CVE-1999-0619"],
    },
    {
        "pattern":     r"permit\s+tcp\s+any\s+any\s+eq\s+(512|513|514)",
        "severity":    "CRITICAL",
        "category":    "Insecure Protocol",
        "title":       "BSD r-services (rexec/rlogin/rsh) permitted",
        "description": (
            "The BSD r-services (rexec TCP/512, rlogin TCP/513, rsh TCP/514) are legacy "
            "remote execution protocols with no encryption and weak authentication. rsh "
            "can execute commands with no authentication at all if .rhosts trust is "
            "configured. These services are commonly exploited in lateral movement."
        ),
        "remediation": (
            "Block all r-services immediately. These protocols have no legitimate use "
            "in modern networks. Replace with SSH for all remote management. "
            "Deny TCP 512, 513, and 514 from all sources."
        ),
        "cve_refs": ["CVE-1999-0651", "CVE-2004-1006"],
    },

    # ── HIGH ──────────────────────────────────────────────────────
    {
        "pattern":     r"permit\s+tcp\s+any\s+any\s+eq\s+21",
        "severity":    "HIGH",
        "category":    "Insecure Protocol",
        "title":       "FTP (TCP/21) permitted from any source",
        "description": (
            "FTP transmits credentials and data in plaintext, including the username and "
            "password during the AUTH phase. FTP also uses dynamic data connections that "
            "can complicate firewall state tracking. An attacker with passive network "
            "access can capture FTP credentials trivially."
        ),
        "remediation": (
            "Replace FTP with SFTP (SSH File Transfer Protocol, TCP/22) or FTPS "
            "(FTP over TLS). If FTP must be used for legacy compatibility, restrict "
            "source IPs to known trusted hosts only — never 'any'. "
            "Consider SFTP-only access via SSH subsystem."
        ),
        "cve_refs": [],
    },
    {
        "pattern":     r"permit\s+udp\s+any\s+any\s+eq\s+161",
        "severity":    "HIGH",
        "category":    "Management Exposure",
        "title":       "SNMP (UDP/161) permitted from any source",
        "description": (
            "SNMP v1 and v2c use community strings as shared passwords, transmitted in "
            "plaintext. If an attacker discovers the community string (often 'public' or "
            "'private'), they can read the entire device MIB — including routing tables, "
            "interface details, connected hosts, and in RW mode, modify device config. "
            "Permitting SNMP from 'any' dramatically increases attack surface."
        ),
        "remediation": (
            "1. Restrict SNMP access to your NMS server IP(s) only.\n"
            "2. If SNMP v1/v2c must be used, change community strings from defaults.\n"
            "3. Migrate to SNMPv3 with auth and privacy (AES encryption).\n"
            "4. Cisco example: 'snmp-server community <string> RO <acl_number>'."
        ),
        "cve_refs": ["CVE-2002-0012", "CVE-2002-0013"],
    },
    {
        "pattern":     r"permit\s+tcp\s+any\s+any\s+eq\s+3389",
        "severity":    "HIGH",
        "category":    "Remote Access Exposure",
        "title":       "RDP (TCP/3389) permitted from any source",
        "description": (
            "RDP exposed to broad network access is one of the most common initial access "
            "vectors in ransomware attacks. Brute force, credential stuffing, and exploits "
            "such as BlueKeep (CVE-2019-0708) and DejaBlue target exposed RDP. Permitting "
            "RDP from 'any' essentially puts a login prompt on the public internet."
        ),
        "remediation": (
            "1. Restrict RDP to VPN or jump server IPs only — never 'any'.\n"
            "2. Enable Network Level Authentication (NLA) on all RDP endpoints.\n"
            "3. Enforce MFA for all RDP access.\n"
            "4. Apply patches for CVE-2019-0708 (BlueKeep) immediately if not done.\n"
            "5. Consider replacing RDP with a privileged access workstation (PAW) model."
        ),
        "cve_refs": ["CVE-2019-0708", "CVE-2019-1181", "CVE-2019-1182"],
    },
    {
        "pattern":     r"permit\s+udp\s+any\s+any\s+eq\s+69",
        "severity":    "HIGH",
        "category":    "Insecure Protocol",
        "title":       "TFTP (UDP/69) permitted from any source",
        "description": (
            "TFTP has no authentication mechanism whatsoever. It is used legitimately for "
            "network device firmware updates and PXE boot, but permitting it from 'any' "
            "allows any attacker to read or write files on TFTP servers, potentially "
            "replacing device firmware or exfiltrating config files."
        ),
        "remediation": (
            "Restrict TFTP access to your network management subnet only. "
            "Consider replacing TFTP with SCP (Secure Copy) for IOS image transfers, "
            "which uses SSH for encryption and authentication."
        ),
        "cve_refs": [],
    },
    {
        "pattern":     r"permit\s+tcp\s+any\s+any\s+eq\s+(1433|1521|3306|5432|27017|6379)",
        "severity":    "HIGH",
        "category":    "Database Exposure",
        "title":       "Database port permitted from any source",
        "description": (
            "Database ports (MSSQL/1433, Oracle/1521, MySQL/3306, PostgreSQL/5432, "
            "MongoDB/27017, Redis/6379) should never be directly accessible from broad "
            "network segments. Exposed database ports are primary targets for SQL injection, "
            "brute force, and known exploits. Many database breaches start with direct "
            "network-level access."
        ),
        "remediation": (
            "Database servers must reside in a dedicated DB tier subnet. "
            "Only application server IPs should be permitted to reach DB ports. "
            "Block all database ports at the perimeter and between non-adjacent tiers. "
            "Implement network segmentation with strict inter-VLAN ACLs."
        ),
        "cve_refs": [],
    },

    # ── MEDIUM ────────────────────────────────────────────────────
    {
        "pattern":     r"permit\s+icmp\s+any\s+any",
        "severity":    "MEDIUM",
        "category":    "Reconnaissance Enablement",
        "title":       "ICMP permitted from any source to any destination",
        "description": (
            "Unrestricted ICMP allows attackers to map your network topology via ping "
            "sweeps, traceroute, and timestamp requests. While some ICMP types are "
            "necessary for network operation (type 3 — unreachable, type 11 — TTL exceeded), "
            "permitting all ICMP from any source enables network reconnaissance."
        ),
        "remediation": (
            "Replace 'permit icmp any any' with specific permits:\n"
            "  permit icmp any any echo-reply\n"
            "  permit icmp any any unreachable\n"
            "  permit icmp any any time-exceeded\n"
            "Restrict echo-request to trusted management hosts only."
        ),
        "cve_refs": [],
    },
    {
        "pattern":     r"permit\s+tcp\s+any\s+any\s+eq\s+5900",
        "severity":    "MEDIUM",
        "category":    "Remote Access Exposure",
        "title":       "VNC (TCP/5900) permitted from any source",
        "description": (
            "VNC provides graphical remote access and historically has had weak "
            "authentication and several critical vulnerabilities. VNC traffic is often "
            "unencrypted. Permitting from 'any' exposes workstations and servers to "
            "remote takeover if weak or default passwords are in use."
        ),
        "remediation": (
            "Restrict VNC to management subnet IPs only. "
            "Require VNC connections to tunnel over SSH. "
            "Consider replacing VNC with SSH X11 forwarding or a VPN + RDP approach. "
            "Ensure VNC password authentication is enforced (no unauthenticated VNC)."
        ),
        "cve_refs": ["CVE-2019-15694"],
    },
    {
        "pattern":     r"deny\s+tcp\s+any\s+any\s+eq\s+22",
        "severity":    "MEDIUM",
        "category":    "Management Lockout Risk",
        "title":       "SSH (TCP/22) explicitly denied",
        "description": (
            "SSH is the primary secure management protocol for network devices. "
            "Explicitly denying SSH access may indicate a misconfiguration that could "
            "lock administrators out of devices. Ensure alternative management "
            "access (console, out-of-band management) is available and documented."
        ),
        "remediation": (
            "Verify this deny is intentional and that management access exists via "
            "an alternative path (dedicated mgmt VLAN, out-of-band console). "
            "If SSH should be permitted, add a specific permit for SSH from the "
            "management subnet before this deny rule."
        ),
        "cve_refs": [],
    },
]

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
SEVERITY_ICON  = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "LOW":      "🟢",
    "INFO":     "ℹ️ ",
}

REPORT_DIR = Path(__file__).parent / "reports"
REPORT_DIR.mkdir(exist_ok=True)


def parse_acl(acl_text: str) -> List[str]:
    return [l.strip() for l in acl_text.strip().splitlines() if l.strip()]


def audit(acl_text: str) -> List[Finding]:
    lines    = parse_acl(acl_text)
    findings = []

    for i, line in enumerate(lines, start=1):
        for rule in AUDIT_RULES:
            if re.search(rule["pattern"], line, re.IGNORECASE):
                findings.append(Finding(
                    line_no=i,
                    rule_line=line,
                    severity=rule["severity"],
                    category=rule["category"],
                    title=rule["title"],
                    description=rule["description"],
                    remediation=rule["remediation"],
                    cve_refs=rule["cve_refs"],
                ))

    findings.sort(key=lambda x: SEVERITY_ORDER.get(x.severity, 99))
    return findings


def print_report(findings: List[Finding], acl_source: str):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print("\n" + "═" * 70)
    print("  QCSSTUDIO — Firewall ACL Audit Report")
    print("  Author   : Ravi Kant Sankhyan  |  15+ Years Network Security")
    print(f"  Source   : {acl_source}")
    print(f"  Generated: {ts}")
    print("═" * 70)

    if not findings:
        print("\n  ✅ No issues found. ACL appears clean against all audit rules.")
    else:
        for f in findings:
            icon = SEVERITY_ICON[f.severity]
            print(f"\n  {icon} [{f.severity}]  {f.title}")
            print(f"  {'─' * 66}")
            print(f"  Line {f.line_no}: {f.rule_line}")
            print(f"  Category: {f.category}")
            print(f"\n  Description:")
            for para in f.description.split(". "):
                if para:
                    print(f"    {para.strip()}.")
            print(f"\n  Remediation:")
            for step in f.remediation.split("\n"):
                print(f"    {step}")
            if f.cve_refs:
                print(f"\n  CVE References: {', '.join(f.cve_refs)}")

    # Summary
    counts = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    print(f"\n  {'─' * 70}")
    print(f"  EXECUTIVE SUMMARY")
    print(f"  {'─' * 70}")
    total = len(findings)
    print(f"  Total Findings: {total}")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        count = counts.get(sev, 0)
        bar   = "█" * count
        print(f"  {SEVERITY_ICON[sev]} {sev:<10}: {count:>3}  {bar}")

    if counts.get("CRITICAL", 0) > 0 or counts.get("HIGH", 0) > 0:
        print(f"\n  ⚠️  ACTION REQUIRED: {counts.get('CRITICAL',0)} CRITICAL and "
              f"{counts.get('HIGH',0)} HIGH findings must be remediated immediately.")
    print("═" * 70)


def save_report(findings: List[Finding], acl_source: str):
    ts       = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = REPORT_DIR / f"firewall_audit_{ts}.json"

    report = {
        "meta": {
            "author":    "Ravi Kant Sankhyan | QCSSTUDIO",
            "source":    acl_source,
            "generated": datetime.now().isoformat(),
            "total_findings": len(findings),
        },
        "summary": {},
        "findings": [asdict(f) for f in findings],
    }
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        report["summary"][sev] = sum(1 for f in findings if f.severity == sev)

    with open(filename, "w") as f:
        json.dump(report, f, indent=2)
    print(f"\n  📄 Report saved → {filename}")


def main():
    parser = argparse.ArgumentParser(description="QCSSTUDIO Firewall ACL Auditor")
    parser.add_argument("--file",   help="Path to ACL text file")
    parser.add_argument("--device", help="Device IP (requires NET_USERNAME/NET_PASSWORD env vars)")
    args = parser.parse_args()

    if args.file:
        with open(args.file) as f:
            acl_text = f.read()
        source = args.file
    elif args.device:
        from netmiko import ConnectHandler
        conn = ConnectHandler(
            device_type="cisco_ios",
            host=args.device,
            username=os.environ["NET_USERNAME"],
            password=os.environ["NET_PASSWORD"],
            secret=os.environ.get("NET_SECRET", ""),
        )
        conn.enable()
        acl_text = conn.send_command("show ip access-lists", read_timeout=60)
        conn.disconnect()
        source = args.device
    else:
        acl_text = SAMPLE_ACL
        source   = "Sample ACL (built-in)"

    findings = audit(acl_text)
    print_report(findings, source)
    save_report(findings, source)


if __name__ == "__main__":
    main()
