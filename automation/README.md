# ⚙️ Network Automation Scripts

> **Author:** Ravi Kant Sankhyan | QCSSTUDIO

Python-based automation scripts for managing and configuring network devices at scale using **Netmiko**, **NAPALM**, and **Paramiko**.

---

## 📂 Files

| File | Description |
|------|-------------|
| `device_connector.py` | Connect to devices, run show commands & backup configs |
| `vlan_provisioner.py` | Bulk VLAN creation across multiple switches |
| `requirements.txt` | Python dependencies |

---

## 🚀 Setup

```bash
# Install dependencies
pip install -r requirements.txt

# Run device connector
python device_connector.py

# Run VLAN provisioner
python vlan_provisioner.py
```

---

## 🔧 Supported Device Types

| Vendor | Device Type String |
|--------|--------------------|
| Cisco IOS | `cisco_ios` |
| Cisco IOS-XE | `cisco_xe` |
| Cisco NX-OS | `cisco_nxos` |
| Juniper JunOS | `juniper_junos` |
| Fortinet | `fortinet` |
| Palo Alto | `paloalto_panos` |

---

## ⚠️ Security Note

Never hardcode credentials in production scripts. Use environment variables or a secrets vault:

```python
import os
password = os.environ.get("DEVICE_PASSWORD")
```
