# 🖥️ Network Lab Topologies
**Author:** Ravi Kant Sankhyan | QCSSTUDIO

GNS3 and EVE-NG lab files for hands-on practice of CCNA, CCNP and Network Security concepts.

---

## 📂 Lab Index

| Lab | Level | Topology | Concepts Covered |
|-----|-------|----------|-----------------|
| `lab-01-basic-routing` | Beginner | 3 routers | Static routes, default routes |
| `lab-02-ospf-single-area` | Beginner | 4 routers | OSPFv2 single area |
| `lab-03-ospf-multi-area` | Intermediate | 6 routers | OSPFv2 multi-area, ABR, ASBR |
| `lab-04-bgp-basics` | Intermediate | 4 routers | eBGP, iBGP, route advertisement |
| `lab-05-vlan-intervlan` | Beginner | 2 switches + router | VLANs, 802.1Q, router-on-a-stick |
| `lab-06-spanning-tree` | Intermediate | 3 switches | STP, RSTP, port roles |
| `lab-07-firewall-zones` | Intermediate | 1 firewall + 3 hosts | Zone-based firewall, DMZ |
| `lab-08-site-to-site-vpn` | Advanced | 2 routers + 2 hosts | IPSec Site-to-Site VPN |
| `lab-09-network-automation` | Advanced | 5 devices | Python + Netmiko automation |
| `lab-10-security-hardening` | Advanced | Full enterprise topology | CIS hardening, ACLs, AAA |

---

## 🚀 Getting Started

### Prerequisites
- [GNS3](https://www.gns3.com) 2.2+ installed
- Cisco IOS images (obtain legally via Cisco DevNet or CCO)
- 8GB RAM minimum recommended

### Import a Lab
1. Download the `.gns3project` file from the lab folder
2. Open GNS3 → File → Import portable project
3. Browse to the downloaded file and import
4. Start all devices and follow the lab guide in `README.md` inside each lab folder

---

## 📝 Lab Naming Convention

```
lab-XX-topic-name/
├── README.md          # Lab guide with objectives and steps
├── topology.gns3project  # GNS3 project file
├── configs/           # Pre-built device configs
└── solution/          # Completed solution configs
```

---

*Labs maintained by Ravi Kant Sankhyan — QCSSTUDIO. New labs added regularly.*
