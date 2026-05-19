# 🔒 Network Hardening Checklist
**Author:** Ravi Kant Sankhyan | QCSSTUDIO  
**Based on:** CIS Benchmarks, NIST SP 800-53, ISO 27001

---

## 1. 🖥️ Device Management & Access

- [ ] Disable default credentials on all devices
- [ ] Enforce strong password policy (min 12 chars, complexity)
- [ ] Enable SSH v2 — disable Telnet completely
- [ ] Restrict management access to dedicated management VLAN
- [ ] Enable login banners (legal warning on all devices)
- [ ] Use TACACS+ or RADIUS for centralized AAA
- [ ] Configure session timeout (exec-timeout 5 0)
- [ ] Disable unused management ports (HTTP, HTTPS if not needed)
- [ ] Enable logging to a centralized Syslog / SIEM server
- [ ] Use NTP to synchronize time across all devices

---

## 2. 🔥 Firewall Hardening

- [ ] Apply deny-all default policy (implicit deny at end of ACL)
- [ ] Remove `permit ip any any` rules
- [ ] Block Telnet (TCP 23), FTP (TCP 21) from untrusted zones
- [ ] Restrict SNMP to management host IPs only (no `any`)
- [ ] Disable unused services (finger, small-servers, BOOTP)
- [ ] Enable stateful inspection for all inbound traffic
- [ ] Implement geo-blocking for high-risk countries if applicable
- [ ] Enable anti-spoofing rules (block RFC 1918 from internet)
- [ ] Review and document all firewall rules quarterly
- [ ] Enable logging on deny rules for forensic visibility

---

## 3. 🌐 VLAN & Switching Security

- [ ] Disable unused switch ports and assign to a dead VLAN
- [ ] Enable Port Security on access ports
- [ ] Enable BPDU Guard on all access ports
- [ ] Disable DTP (Dynamic Trunking Protocol) on access ports
- [ ] Change native VLAN from default VLAN 1 to unused VLAN
- [ ] Enable DHCP Snooping on untrusted ports
- [ ] Enable Dynamic ARP Inspection (DAI)
- [ ] Enable IP Source Guard on access ports
- [ ] Segment guest/IoT devices into isolated VLANs
- [ ] Restrict inter-VLAN routing to required traffic only

---

## 4. 🔐 VPN & Remote Access

- [ ] Use IKEv2 or OpenVPN — disable IKEv1 / PPTP
- [ ] Enforce MFA (Multi-Factor Authentication) for VPN access
- [ ] Use certificate-based authentication (not just passwords)
- [ ] Split tunneling — route only corporate traffic through VPN
- [ ] Regularly audit VPN user accounts — remove stale accounts
- [ ] Log all VPN connection attempts (success and failure)
- [ ] Set VPN session timeout for idle connections

---

## 5. ☁️ Cloud Network Security (AWS/Azure)

- [ ] No security groups with `0.0.0.0/0` on SSH (port 22)
- [ ] No security groups with `0.0.0.0/0` on RDP (port 3389)
- [ ] Enable VPC Flow Logs for all VPCs
- [ ] Use private subnets for databases and backend services
- [ ] Enable AWS GuardDuty / Azure Defender for threat detection
- [ ] Restrict S3 buckets / Blob storage from public access
- [ ] Use AWS PrivateLink / Azure Private Endpoints where possible
- [ ] Enable CloudTrail / Azure Activity Log for audit trail
- [ ] Rotate IAM keys and credentials every 90 days
- [ ] Enforce MFA on all cloud admin accounts

---

## 6. 📡 Wireless Network Security

- [ ] Use WPA3 — disable WEP and WPA
- [ ] Separate corporate and guest WiFi on different VLANs
- [ ] Disable SSID broadcast for sensitive networks
- [ ] Implement 802.1X authentication for corporate WiFi
- [ ] Enable Rogue AP detection
- [ ] Change default SSID names (no vendor/org identifiers)
- [ ] Disable WPS (Wi-Fi Protected Setup)

---

## 7. 📋 Monitoring & Incident Response

- [ ] Deploy IDS/IPS (Snort, Suricata, or vendor solution)
- [ ] Configure alerts for failed login attempts (threshold: 5)
- [ ] Monitor for unusual traffic spikes (DDoS indicators)
- [ ] Enable NetFlow / sFlow for traffic analysis
- [ ] Schedule regular vulnerability scans (weekly/monthly)
- [ ] Maintain an asset inventory of all network devices
- [ ] Test incident response playbook quarterly

---

## ✅ Sign-Off

| Reviewer | Date | Signature |
|----------|------|-----------|
| | | |
| | | |

---

*This checklist is maintained by Ravi Kant Sankhyan — QCSSTUDIO. Review quarterly or after major infrastructure changes.*
