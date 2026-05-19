"""
=============================================================
 QCSSTUDIO — VLAN Bulk Provisioning Script
 Author  : Ravi Kant Sankhyan
 Purpose : Automate VLAN creation across multiple switches
           from a simple JSON inventory file
=============================================================
"""

from netmiko import ConnectHandler
import json

# ─── Load VLAN plan from JSON ─────────────────────────────────
VLAN_PLAN = [
    {"vlan_id": 10,  "name": "MANAGEMENT"},
    {"vlan_id": 20,  "name": "DATA"},
    {"vlan_id": 30,  "name": "VOICE"},
    {"vlan_id": 40,  "name": "SERVERS"},
    {"vlan_id": 50,  "name": "GUEST_WIFI"},
    {"vlan_id": 99,  "name": "NATIVE"},
    {"vlan_id": 100, "name": "SECURITY_CAMS"},
]

SWITCHES = [
    {
        "device_type": "cisco_ios",
        "host": "192.168.1.10",
        "username": "admin",
        "password": "your_password",
        "secret": "your_enable_secret",
        "name": "Access-SW-01",
    },
]


def build_vlan_commands(vlan_plan: list) -> list:
    """Generate Cisco IOS VLAN configuration commands."""
    commands = []
    for vlan in vlan_plan:
        commands.append(f"vlan {vlan['vlan_id']}")
        commands.append(f" name {vlan['name']}")
    commands.append("exit")
    return commands


def provision_vlans(device: dict, vlan_plan: list):
    """Connect to a switch and provision all VLANs."""
    print(f"\n[+] Provisioning VLANs on {device['name']} ({device['host']})...")
    try:
        conn = ConnectHandler(**{k: v for k, v in device.items() if k != "name"})
        conn.enable()

        commands = build_vlan_commands(vlan_plan)
        output = conn.send_config_set(commands)

        print(f"    ✅ VLANs provisioned on {device['name']}")
        print(f"    Configuration output:\n{output}")

        # Verify
        vlan_brief = conn.send_command("show vlan brief")
        print(f"\n    VLAN Brief:\n{vlan_brief}")

        conn.disconnect()

    except Exception as e:
        print(f"    ❌ Error on {device['name']}: {e}")


def main():
    print("=" * 60)
    print("  QCSSTUDIO — VLAN Bulk Provisioning Tool")
    print("  Author: Ravi Kant Sankhyan")
    print("=" * 60)
    print(f"\n  VLANs to provision: {len(VLAN_PLAN)}")
    for v in VLAN_PLAN:
        print(f"    VLAN {v['vlan_id']:>4} — {v['name']}")

    for switch in SWITCHES:
        provision_vlans(switch, VLAN_PLAN)


if __name__ == "__main__":
    main()
