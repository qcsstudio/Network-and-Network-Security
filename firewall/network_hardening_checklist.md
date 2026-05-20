# 🔒 Enterprise Network Hardening Checklist
**Author:** Ravi Kant Sankhyan | QCSSTUDIO  
**Version:** 2.0 | Last Reviewed: 2025  
**Standards:** CIS Benchmark v8, NIST SP 800-53 Rev 5, ISO/IEC 27001:2022, PCI-DSS v4.0

> This checklist is derived from 15+ years of enterprise network security audits, penetration tests, and incident response engagements. Each item reflects a real-world finding from actual client environments.

---

## 📋 How to Use This Checklist

| Status | Meaning |
|--------|---------|
| ✅ **Compliant** | Control is implemented and verified |
| ⚠️ **Partial** | Partially implemented — remediation in progress |
| ❌ **Non-Compliant** | Not implemented — action required |
| 🔵 **N/A** | Not applicable to this environment |

**Scoring:** Count ✅ items ÷ Total applicable items × 100 = Compliance %

---

## 1. 🖥️ Device Hardening & Access Control

### 1.1 Authentication & Credentials
- [ ] Default credentials changed on ALL network devices (routers, switches, firewalls, APs)
- [ ] Unique, complex passwords for every device (minimum 14 characters, complexity enforced)
- [ ] Password manager or privileged access management (PAM) tool in use — no spreadsheets
- [ ] `service password-encryption` enabled on all Cisco IOS devices
- [ ] Type 9 (scrypt) or Type 8 (PBKDF2) password hashing used — NOT MD5 (Type 5)
- [ ] No `enable password` in plaintext — only `enable secret`
- [ ] No `username <user> password <plaintext>` in running config
- [ ] Default SNMP community strings ('public', 'private') removed
- [ ] AAA (Authentication, Authorization, Accounting) enabled: `aaa new-model`
- [ ] TACACS+ or RADIUS for centralized authentication to all management planes

### 1.2 Remote Access & Protocols
- [ ] SSH v2 enabled on all devices: `ip ssh version 2`
- [ ] Telnet completely disabled: `transport input ssh` on all VTY lines
- [ ] SSH access restricted to management VLAN subnet only via ACL
- [ ] SSH timeout configured: `ip ssh time-out 60`
- [ ] SSH authentication retries limited: `ip ssh authentication-retries 3`
- [ ] Console port has password and exec-timeout configured
- [ ] AUX port disabled or secured: `no exec` and timeout configured
- [ ] HTTP server disabled: `no ip http server`
- [ ] HTTPS-only if web management required, with TLS 1.2+
- [ ] Out-of-band (OOB) management network for all critical devices

### 1.3 Session & Privilege Management
- [ ] Exec-timeout set on all VTY and console lines: `exec-timeout 5 0` (5 minutes)
- [ ] Privilege levels configured — no blanket privilege 15 for all users
- [ ] Role-based access: read-only accounts for NOC, full access only for senior engineers
- [ ] Login banners configured on all devices (legal warning, authorized use only)
- [ ] `login block-for` configured on IOS to prevent brute force: `login block-for 120 attempts 3 within 60`
- [ ] Failed login attempts logged and alerted

---

## 2. 🔥 Firewall & ACL Security

### 2.1 Firewall Policy
- [ ] Default deny policy at end of all ACLs: explicit `deny ip any any log`
- [ ] Zero 'permit ip any any' rules in any ACL or firewall policy
- [ ] All rules documented with business justification and owner
- [ ] Unused and expired rules removed (quarterly review minimum)
- [ ] Firewall rule change management process in place
- [ ] Bi-directional stateful inspection enabled for all zones

### 2.2 Dangerous Ports & Protocols
- [ ] Telnet (TCP/23) blocked from ALL sources
- [ ] FTP (TCP/21) blocked or restricted to specific authorized hosts
- [ ] rexec (TCP/512), rlogin (TCP/513), rsh (TCP/514) blocked
- [ ] TFTP (UDP/69) restricted to management subnet only
- [ ] SNMP restricted to NMS server IPs only — never `any`
- [ ] NTP restricted to authorized time servers only
- [ ] ICMP restricted — allow only echo-reply, unreachable, time-exceeded
- [ ] NetBIOS (TCP/UDP 137-139) and SMB (TCP/445) blocked at perimeter

### 2.3 Management Plane Protection
- [ ] Management plane protection (MPP) configured on all routers
- [ ] Control plane policing (CoPP) implemented
- [ ] CPU rate limiting for management traffic configured
- [ ] BGP TTL security hack (GTSM) enabled for eBGP peers
- [ ] BGP MD5 or TCP-AO authentication configured for all BGP sessions

### 2.4 DMZ Architecture
- [ ] DMZ implemented for all internet-facing servers
- [ ] No direct routing between Internet and Internal network
- [ ] DMZ servers cannot initiate connections to internal network
- [ ] Database servers in separate isolated tier — never in DMZ
- [ ] WAF in front of all public-facing web applications

---

## 3. 🌐 VLAN & Switching Security

### 3.1 Port Security
- [ ] All unused switch ports administratively shut down: `shutdown`
- [ ] Unused ports assigned to a dedicated isolated 'dead' VLAN (e.g., VLAN 999)
- [ ] Port security enabled on all access ports: `switchport port-security maximum 2`
- [ ] Port security violation action configured: `shutdown` (not `restrict` or `protect`)
- [ ] MAC address sticky learning configured on access ports

### 3.2 STP & Trunking Hardening
- [ ] BPDU Guard enabled on all access ports: `spanning-tree bpduguard enable`
- [ ] Root Guard enabled on ports where root bridge should never appear
- [ ] Loop Guard enabled on designated ports
- [ ] DTP disabled on all access ports: `switchport nonegotiate`
- [ ] Manual trunk configuration on all inter-switch links — no auto-negotiation
- [ ] Native VLAN changed from default VLAN 1 to an unused VLAN
- [ ] VLAN 1 unused for any production traffic
- [ ] Allowed VLANs explicitly configured on all trunks — no `trunk allowed all`

### 3.3 Layer 2 Attack Prevention
- [ ] DHCP Snooping enabled on all VLANs: `ip dhcp snooping vlan <range>`
- [ ] DHCP Snooping trusted ports configured only on uplinks
- [ ] DHCP rate limiting configured on untrusted access ports
- [ ] Dynamic ARP Inspection (DAI) enabled: `ip arp inspection vlan <range>`
- [ ] IP Source Guard enabled on access ports
- [ ] Private VLANs (PVLANs) used in DMZ and server farms for lateral movement prevention

### 3.4 Network Segmentation
- [ ] Corporate, guest, IoT, and server VLANs fully separated
- [ ] Inter-VLAN routing via firewall — not layer 3 switch with open routing
- [ ] Guest network has no access to internal corporate resources
- [ ] IoT/OT devices isolated in dedicated VLAN with internet-only access
- [ ] PCI-DSS cardholder data environment (CDE) in isolated VLAN if applicable

---

## 4. 🔐 VPN & Remote Access Security

### 4.1 VPN Configuration
- [ ] IKEv2 used for all IPSec VPNs — IKEv1 deprecated
- [ ] AES-256 encryption for all VPN tunnels
- [ ] SHA-256 or SHA-384 for integrity — MD5 and SHA-1 prohibited
- [ ] Diffie-Hellman Group 14 or higher (2048-bit or better)
- [ ] Perfect Forward Secrecy (PFS) enabled
- [ ] PPTP, L2TP without IPSec, and SSTP without strong TLS prohibited
- [ ] Certificate-based authentication preferred over PSK for site-to-site

### 4.2 Remote User Access
- [ ] MFA (Multi-Factor Authentication) mandatory for all VPN users
- [ ] Split tunneling policy reviewed and documented — full tunnel preferred for sensitive environments
- [ ] VPN idle session timeout configured (≤30 minutes)
- [ ] Stale/terminated employee VPN accounts removed within 24 hours of offboarding
- [ ] VPN connection logs retained for minimum 90 days
- [ ] Endpoint compliance check before VPN admission (NAC/posture assessment)

---

## 5. ☁️ Cloud Network Security

### 5.1 AWS
- [ ] No security groups with inbound `0.0.0.0/0` on SSH (22), RDP (3389), or database ports
- [ ] Default VPC not used for production workloads
- [ ] VPC Flow Logs enabled on all VPCs, stored in S3 or CloudWatch
- [ ] Subnets properly tiered: public (ALB), private (app), isolated (DB)
- [ ] S3 bucket public access block enabled at account level
- [ ] AWS GuardDuty enabled across all regions
- [ ] AWS CloudTrail enabled, multi-region, log file validation on
- [ ] IAM users have MFA enforced — no exceptions for admin accounts
- [ ] No IAM access keys older than 90 days
- [ ] AWS Config rules deployed for continuous compliance monitoring

### 5.2 Azure
- [ ] NSGs applied at both subnet and NIC level for defense-in-depth
- [ ] Azure Defender / Microsoft Defender for Cloud enabled
- [ ] Azure Activity Log and Diagnostic Logs sent to Log Analytics
- [ ] No public IP addresses on internal VMs without explicit justification
- [ ] Private Endpoints used for PaaS services (Storage, SQL, Key Vault)
- [ ] Azure Firewall or NVA in place for spoke-to-spoke and internet traffic

---

## 6. 📡 Wireless Security

- [ ] WPA3-Enterprise deployed on corporate SSID — WEP and WPA prohibited
- [ ] 802.1X authentication with EAP-TLS or PEAP for corporate wireless
- [ ] Guest wireless on separate VLAN with internet-only access
- [ ] Rogue AP detection enabled and alerting configured
- [ ] Wireless IDS/IPS enabled
- [ ] WPS (Wi-Fi Protected Setup) disabled on all APs
- [ ] SSID broadcast disabled for high-security networks
- [ ] Default SSIDs changed — no vendor names in SSID

---

## 7. 📋 Monitoring, Logging & Response

- [ ] Centralized Syslog server configured on all devices
- [ ] Log retention: minimum 90 days online, 1 year archived
- [ ] SIEM deployed and receiving logs from all network devices
- [ ] Alerting configured for: failed logins, config changes, link flaps, ACL hits
- [ ] NetFlow / sFlow / IPFIX enabled on border routers for traffic analytics
- [ ] NTP synchronization configured on all devices to a trusted source
- [ ] Network vulnerability scanning performed monthly (Nessus, Qualys, OpenVAS)
- [ ] Network asset inventory maintained and reviewed quarterly
- [ ] Incident response playbooks documented and tested annually

---

## 📊 Compliance Scoring

| Section | Items | ✅ Compliant | Score |
|---------|-------|-------------|-------|
| 1. Device Hardening | 26 | | |
| 2. Firewall & ACL | 22 | | |
| 3. VLAN & Switching | 20 | | |
| 4. VPN & Remote Access | 12 | | |
| 5. Cloud Security | 16 | | |
| 6. Wireless | 8 | | |
| 7. Monitoring | 9 | | |
| **TOTAL** | **113** | | |

**Compliance % = (Total Compliant ÷ 113) × 100**

| Score | Grade | Action |
|-------|-------|--------|
| 90–100% | A — Excellent | Maintain and review quarterly |
| 75–89% | B — Good | Remediate remaining gaps within 30 days |
| 50–74% | C — Acceptable | Immediate remediation plan required |
| Below 50% | D — Insufficient | Urgent escalation to management |

---

## ✍️ Audit Sign-Off

| Field | Value |
|-------|-------|
| Auditor | Ravi Kant Sankhyan — QCSSTUDIO |
| Client / Site | |
| Audit Date | |
| Next Review Date | |
| Compliance Score | |
| Grade | |
| Auditor Signature | |

---

*This checklist is maintained by Ravi Kant Sankhyan — QCSSTUDIO.  
Review after every major change and at minimum annually.  
[Upwork](https://www.upwork.com/freelancers/~01b4709590df4f83e5) | [GitHub](https://github.com/QCSSTUDIO)*
