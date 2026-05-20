"""
╔══════════════════════════════════════════════════════════════════╗
║         QCSSTUDIO — Network Automation Toolkit                   ║
║         Module  : Multi-Device Connector & Config Backup         ║
║         Author  : Ravi Kant Sankhyan                             ║
║         GitHub  : github.com/QCSSTUDIO/Network-and-Network-Security ║
║         Upwork  : upwork.com/freelancers/~01b4709590df4f83e5     ║
╚══════════════════════════════════════════════════════════════════╝

PURPOSE
───────
Connect to multiple network devices simultaneously via SSH, execute
a configurable set of diagnostic and operational show commands, collect
their output, and create timestamped configuration backups — all in a
single automated run. Designed for daily NOC operations, pre-change
snapshots, and compliance evidence collection.

SUPPORTED DEVICES
─────────────────
  Cisco IOS / IOS-XE / IOS-XR / NX-OS
  Juniper JunOS
  Fortinet FortiOS
  Palo Alto PAN-OS
  Aruba AOS-CX
  Any Netmiko-supported device type

USAGE
─────
  1. Edit the DEVICES list below with your device inventory
  2. Edit SHOW_COMMANDS per device type as needed
  3. pip install -r requirements.txt
  4. python device_connector.py [--profile quick|full|backup]

SECURITY NOTE
─────────────
  Never commit real credentials to version control.
  Use environment variables or a secrets vault (HashiCorp Vault,
  AWS Secrets Manager, CyberArk) in production environments.
"""

import os
import sys
import json
import argparse
import threading
from datetime import datetime
from pathlib import Path
from typing import Optional

try:
    from netmiko import ConnectHandler, NetmikoTimeoutException, NetmikoAuthenticationException
    from netmiko.exceptions import NetmikoBaseException
except ImportError:
    print("[ERROR] Netmiko not installed. Run: pip install -r requirements.txt")
    sys.exit(1)

# ─────────────────────────────────────────────────────────────────────
# DEVICE INVENTORY
# Replace with your actual device details.
# In production, load from YAML/JSON inventory or environment variables.
# ─────────────────────────────────────────────────────────────────────
DEVICES = [
    {
        "name": "Core-Router-01",
        "role": "Core Router",
        "site": "HQ-Mumbai",
        "device_type": "cisco_ios",
        "host": "192.168.1.1",
        "username": os.environ.get("NET_USERNAME", "admin"),
        "password": os.environ.get("NET_PASSWORD", "changeme"),
        "secret":   os.environ.get("NET_SECRET",   "changeme"),
        "port": 22,
        "timeout": 30,
    },
    {
        "name": "Distribution-SW-01",
        "role": "Distribution Switch",
        "site": "HQ-Mumbai",
        "device_type": "cisco_ios",
        "host": "192.168.1.2",
        "username": os.environ.get("NET_USERNAME", "admin"),
        "password": os.environ.get("NET_PASSWORD", "changeme"),
        "secret":   os.environ.get("NET_SECRET",   "changeme"),
        "port": 22,
        "timeout": 30,
    },
    {
        "name": "Firewall-FG-01",
        "role": "Perimeter Firewall",
        "site": "HQ-Mumbai",
        "device_type": "fortinet",
        "host": "192.168.1.254",
        "username": os.environ.get("FW_USERNAME", "admin"),
        "password": os.environ.get("FW_PASSWORD", "changeme"),
        "port": 22,
        "timeout": 30,
    },
]

# ─────────────────────────────────────────────────────────────────────
# COMMAND PROFILES
# Different command sets for different use cases.
# ─────────────────────────────────────────────────────────────────────
COMMAND_PROFILES = {
    "quick": {
        "description": "Fast health check — version, interfaces, CPU",
        "cisco_ios": [
            "show version | include Version|uptime|Serial",
            "show ip interface brief",
            "show processes cpu sorted | head 10",
            "show memory statistics | include Processor",
        ],
        "fortinet": [
            "get system status",
            "get system performance status",
        ],
    },
    "full": {
        "description": "Full diagnostic — all routing, ARP, logs, BGP",
        "cisco_ios": [
            "show version",
            "show ip interface brief",
            "show interfaces status",
            "show ip route summary",
            "show ip route",
            "show ip bgp summary",
            "show ip ospf neighbor",
            "show arp",
            "show cdp neighbors detail",
            "show spanning-tree summary",
            "show processes cpu sorted | head 20",
            "show memory statistics",
            "show log | tail 50",
            "show ntp status",
            "show users",
        ],
        "fortinet": [
            "get system status",
            "get system performance status",
            "get router info routing-table all",
            "get system arp",
            "diagnose sys top",
        ],
    },
    "backup": {
        "description": "Config backup only — running and startup configs",
        "cisco_ios": [
            "show running-config",
            "show startup-config",
        ],
        "fortinet": [
            "show full-configuration",
        ],
    },
}

# ─────────────────────────────────────────────────────────────────────
# OUTPUT DIRECTORIES
# ─────────────────────────────────────────────────────────────────────
BASE_DIR   = Path(__file__).parent
BACKUP_DIR = BASE_DIR / "backups"
REPORT_DIR = BASE_DIR / "reports"

for d in [BACKUP_DIR, REPORT_DIR]:
    d.mkdir(exist_ok=True)


# ─────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────

def timestamp() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def log(level: str, device: str, message: str):
    icons = {"INFO": "ℹ️ ", "OK": "✅", "WARN": "⚠️ ", "ERROR": "❌", "STEP": "→ "}
    icon  = icons.get(level, "• ")
    ts    = datetime.now().strftime("%H:%M:%S")
    print(f"  [{ts}] {icon} [{device}] {message}")


def get_commands(device: dict, profile: str) -> list:
    """Return the command list appropriate for this device type and profile."""
    profile_data = COMMAND_PROFILES.get(profile, COMMAND_PROFILES["quick"])
    device_type  = device.get("device_type", "cisco_ios")

    # Normalize device type family
    if device_type.startswith("cisco") or device_type.startswith("aruba"):
        cmd_key = "cisco_ios"
    elif device_type.startswith("fortinet"):
        cmd_key = "fortinet"
    else:
        cmd_key = "cisco_ios"   # Default fallback

    return profile_data.get(cmd_key, profile_data.get("cisco_ios", []))


# ─────────────────────────────────────────────────────────────────────
# CORE CONNECTION & COLLECTION
# ─────────────────────────────────────────────────────────────────────

def connect_device(device: dict) -> Optional[object]:
    """Establish SSH connection, return Netmiko connection object or None."""
    connect_params = {k: v for k, v in device.items()
                      if k not in ("name", "role", "site")}
    try:
        conn = ConnectHandler(**connect_params)
        if device["device_type"].startswith("cisco"):
            conn.enable()
        return conn
    except NetmikoAuthenticationException:
        log("ERROR", device["name"], "Authentication failed — check credentials.")
        return None
    except NetmikoTimeoutException:
        log("ERROR", device["name"], f"Connection timed out to {device['host']}:{device.get('port', 22)}")
        return None
    except Exception as e:
        log("ERROR", device["name"], f"Unexpected error: {e}")
        return None


def collect_commands(conn, device: dict, commands: list) -> dict:
    """Run each command and return {command: output} dict."""
    results = {}
    for cmd in commands:
        log("STEP", device["name"], f"Running: {cmd}")
        try:
            output = conn.send_command(cmd, read_timeout=60)
            results[cmd] = output
        except Exception as e:
            results[cmd] = f"[ERROR] {e}"
            log("WARN", device["name"], f"Command failed: {cmd} — {e}")
    return results


def save_backup(conn, device: dict) -> Optional[Path]:
    """Save running config to a timestamped file."""
    ts       = timestamp()
    filename = BACKUP_DIR / f"{device['name']}_{device['site']}_{ts}.cfg"

    try:
        if device["device_type"].startswith("fortinet"):
            config = conn.send_command("show full-configuration", read_timeout=120)
        else:
            config = conn.send_command("show running-config", read_timeout=120)

        with open(filename, "w") as f:
            f.write(f"! ============================================================\n")
            f.write(f"! Device   : {device['name']}\n")
            f.write(f"! Role     : {device['role']}\n")
            f.write(f"! Site     : {device['site']}\n")
            f.write(f"! Host     : {device['host']}\n")
            f.write(f"! Backed up: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"! ============================================================\n\n")
            f.write(config)

        log("OK", device["name"], f"Config backed up → {filename.name}")
        return filename
    except Exception as e:
        log("ERROR", device["name"], f"Backup failed: {e}")
        return None


def save_report(device: dict, results: dict, backup_path: Optional[Path]):
    """Save full command output to a JSON report."""
    ts       = timestamp()
    filename = REPORT_DIR / f"{device['name']}_{ts}.json"

    report = {
        "device": device["name"],
        "role":   device["role"],
        "site":   device["site"],
        "host":   device["host"],
        "collected_at": datetime.now().isoformat(),
        "backup_file":  str(backup_path) if backup_path else None,
        "command_results": results,
    }
    with open(filename, "w") as f:
        json.dump(report, f, indent=2)

    log("OK", device["name"], f"Report saved → {filename.name}")


# ─────────────────────────────────────────────────────────────────────
# PER-DEVICE WORKER (runs in a thread)
# ─────────────────────────────────────────────────────────────────────

def process_device(device: dict, profile: str, results_store: list, lock: threading.Lock):
    """Full lifecycle for one device: connect → collect → backup → report."""
    result = {
        "device": device["name"],
        "site":   device["site"],
        "host":   device["host"],
        "status": "FAILED",
        "backup": None,
        "commands_run": 0,
    }

    log("INFO", device["name"], f"Connecting to {device['host']} ({device['role']}, {device['site']})")
    conn = connect_device(device)

    if not conn:
        with lock:
            results_store.append(result)
        return

    log("OK", device["name"], "Connected successfully.")

    # Collect commands
    commands      = get_commands(device, profile)
    command_output = collect_commands(conn, device, commands)
    result["commands_run"] = len(command_output)

    # Backup config
    backup_path = save_backup(conn, device)
    result["backup"] = str(backup_path) if backup_path else None

    # Save report
    save_report(device, command_output, backup_path)

    conn.disconnect()
    log("OK", device["name"], "Disconnected cleanly.")

    result["status"] = "SUCCESS"
    with lock:
        results_store.append(result)


# ─────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────

def print_banner():
    print("\n" + "═" * 68)
    print("  QCSSTUDIO — Network Automation & Config Backup Tool")
    print("  Author  : Ravi Kant Sankhyan  |  15+ Years in Networking")
    print("  GitHub  : github.com/QCSSTUDIO/Network-and-Network-Security")
    print("═" * 68)


def print_summary(results: list, elapsed: float):
    success = [r for r in results if r["status"] == "SUCCESS"]
    failed  = [r for r in results if r["status"] == "FAILED"]

    print("\n" + "═" * 68)
    print(f"  SUMMARY  —  Completed in {elapsed:.1f}s")
    print("─" * 68)
    print(f"  {'Device':<30} {'Site':<15} {'Status':<10} {'Cmds':>6}")
    print("─" * 68)
    for r in results:
        icon   = "✅" if r["status"] == "SUCCESS" else "❌"
        cmds   = str(r["commands_run"]) if r["commands_run"] else "—"
        print(f"  {icon} {r['device']:<28} {r['site']:<15} {r['status']:<10} {cmds:>6}")
    print("─" * 68)
    print(f"  Total: {len(results)} devices  |  ✅ {len(success)} OK  |  ❌ {len(failed)} Failed")
    print(f"  Backups saved to : {BACKUP_DIR}")
    print(f"  Reports saved to : {REPORT_DIR}")
    print("═" * 68 + "\n")


def main():
    parser = argparse.ArgumentParser(description="QCSSTUDIO Network Automation Tool")
    parser.add_argument("--profile", choices=["quick", "full", "backup"], default="full",
                        help="Command profile to run (default: full)")
    parser.add_argument("--parallel", action="store_true",
                        help="Run devices in parallel threads (faster, less readable output)")
    args = parser.parse_args()

    print_banner()
    profile_info = COMMAND_PROFILES[args.profile]
    print(f"\n  Profile  : {args.profile} — {profile_info['description']}")
    print(f"  Devices  : {len(DEVICES)}")
    print(f"  Mode     : {'Parallel' if args.parallel else 'Sequential'}")
    print()

    start       = datetime.now()
    results_store = []
    lock          = threading.Lock()

    if args.parallel:
        threads = []
        for device in DEVICES:
            t = threading.Thread(target=process_device,
                                 args=(device, args.profile, results_store, lock))
            threads.append(t)
            t.start()
        for t in threads:
            t.join()
    else:
        for device in DEVICES:
            process_device(device, args.profile, results_store, lock)
            print()

    elapsed = (datetime.now() - start).total_seconds()
    print_summary(results_store, elapsed)


if __name__ == "__main__":
    main()
