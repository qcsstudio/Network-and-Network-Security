"""
=============================================================
 QCSSTUDIO — Network Automation Toolkit
 Author  : Ravi Kant Sankhyan
 Purpose : Connect to network devices, run show commands,
           and backup running configurations
=============================================================
"""

from netmiko import ConnectHandler
from datetime import datetime
import json
import os

# ─── Device Inventory ────────────────────────────────────────
# Edit this list to match your actual devices
DEVICES = [
    {
        "device_type": "cisco_ios",
        "host": "192.168.1.1",
        "username": "admin",
        "password": "your_password",
        "secret": "your_enable_secret",
        "name": "Core-Router-01",
    },
    {
        "device_type": "cisco_ios",
        "host": "192.168.1.2",
        "username": "admin",
        "password": "your_password",
        "secret": "your_enable_secret",
        "name": "Distribution-SW-01",
    },
]

# ─── Commands to run on each device ──────────────────────────
SHOW_COMMANDS = [
    "show version",
    "show ip interface brief",
    "show ip route",
    "show running-config",
]

BACKUP_DIR = "backups"


def connect_to_device(device: dict):
    """Establish SSH connection to a network device."""
    print(f"\n[+] Connecting to {device['name']} ({device['host']})...")
    try:
        conn = ConnectHandler(**{k: v for k, v in device.items() if k != "name"})
        conn.enable()
        print(f"    ✅ Connected to {device['name']}")
        return conn
    except Exception as e:
        print(f"    ❌ Failed to connect to {device['name']}: {e}")
        return None


def run_show_commands(conn, device_name: str) -> dict:
    """Run a set of show commands and return output as a dict."""
    results = {}
    for cmd in SHOW_COMMANDS:
        print(f"    → Running: {cmd}")
        try:
            output = conn.send_command(cmd)
            results[cmd] = output
        except Exception as e:
            results[cmd] = f"ERROR: {e}"
    return results


def backup_config(conn, device_name: str):
    """Save the running config to a timestamped backup file."""
    os.makedirs(BACKUP_DIR, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{BACKUP_DIR}/{device_name}_{timestamp}.txt"

    print(f"    → Backing up config to {filename}")
    try:
        config = conn.send_command("show running-config")
        with open(filename, "w") as f:
            f.write(f"! Backup of {device_name}\n")
            f.write(f"! Timestamp: {datetime.now()}\n")
            f.write("!" + "=" * 60 + "\n\n")
            f.write(config)
        print(f"    ✅ Config saved: {filename}")
        return filename
    except Exception as e:
        print(f"    ❌ Backup failed: {e}")
        return None


def save_results(results: dict, device_name: str):
    """Save command output results to a JSON report file."""
    os.makedirs("reports", exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"reports/{device_name}_{timestamp}.json"
    with open(filename, "w") as f:
        json.dump(results, f, indent=2)
    print(f"    ✅ Report saved: {filename}")


def main():
    print("=" * 60)
    print("  QCSSTUDIO — Network Automation & Config Backup Tool")
    print("  Author: Ravi Kant Sankhyan | 15+ Years in Networking")
    print("=" * 60)

    summary = []

    for device in DEVICES:
        conn = connect_to_device(device)
        if not conn:
            summary.append({"device": device["name"], "status": "FAILED"})
            continue

        # Run show commands
        results = run_show_commands(conn, device["name"])
        save_results(results, device["name"])

        # Backup running config
        backup_file = backup_config(conn, device["name"])

        conn.disconnect()
        print(f"    🔌 Disconnected from {device['name']}")

        summary.append({
            "device": device["name"],
            "host": device["host"],
            "status": "SUCCESS",
            "backup": backup_file,
        })

    # ─── Print Summary ────────────────────────────────────────
    print("\n" + "=" * 60)
    print("  SUMMARY")
    print("=" * 60)
    for item in summary:
        status_icon = "✅" if item["status"] == "SUCCESS" else "❌"
        print(f"  {status_icon} {item['device']} — {item['status']}")
    print("=" * 60)


if __name__ == "__main__":
    main()
