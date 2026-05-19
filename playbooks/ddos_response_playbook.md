# 🚨 Incident Response Playbook — DDoS Attack
**Author:** Ravi Kant Sankhyan | QCSSTUDIO  
**Version:** 1.0 | Last Updated: 2025

---

## 📋 Overview

This playbook guides the response team through detecting, containing, and recovering from a **Distributed Denial of Service (DDoS)** attack on network infrastructure.

---

## 🔴 Phase 1 — Detection & Identification (0–15 mins)

### Indicators of DDoS Attack
- [ ] Sudden spike in inbound traffic (check NetFlow / SNMP)
- [ ] CPU/memory spike on border routers or firewalls
- [ ] Packet loss or latency increase on monitored links
- [ ] Alerts from IDS/IPS for SYN flood, UDP flood, or ICMP flood
- [ ] ISP upstream notifications of anomalous traffic

### Immediate Actions
- [ ] Confirm it's an attack and not a legitimate traffic surge
- [ ] Identify attack type: Volumetric / Protocol / Application Layer
- [ ] Identify target: specific IP, service, or entire range
- [ ] Check attack traffic breakdown (source IPs, protocols, ports)
- [ ] Notify NOC / Security Team Lead

**Command: Check traffic on Cisco router**
```bash
show interfaces GigabitEthernet0/0 | include input rate
show ip traffic
```

---

## 🟠 Phase 2 — Containment (15–60 mins)

### Network-Level Mitigation
- [ ] Apply null-route (blackhole) for target IP if sacrificable:
  ```
  ip route 203.0.113.50 255.255.255.255 Null0
  ```
- [ ] Apply upstream ACL to drop attack traffic at border router
- [ ] Enable RTBH (Remotely Triggered Black Hole) with ISP if available
- [ ] Rate-limit ICMP and UDP if flood attack
- [ ] Enable TCP Intercept on Cisco IOS for SYN flood:
  ```
  ip tcp intercept list 101 mode intercept
  ```

### Firewall Actions
- [ ] Block source IP ranges at firewall (geo-block if applicable)
- [ ] Reduce connection table limits temporarily
- [ ] Enable SYN cookies on affected interfaces
- [ ] Increase max incomplete connections threshold

### Escalation
- [ ] Notify ISP and request upstream filtering / scrubbing
- [ ] Engage DDoS mitigation service (Cloudflare, Akamai, etc.) if contracted
- [ ] Notify management and document timeline

---

## 🟡 Phase 3 — Eradication & Recovery (1–4 hours)

- [ ] Confirm attack traffic has subsided
- [ ] Remove null routes and temporary ACLs carefully
- [ ] Restore services in priority order (critical first)
- [ ] Verify service availability from external monitoring tools
- [ ] Re-enable any services that were temporarily shut down
- [ ] Monitor for re-occurrence for at least 24 hours

---

## 🟢 Phase 4 — Post-Incident Review (within 48 hours)

- [ ] Document full attack timeline with timestamps
- [ ] Calculate downtime and business impact
- [ ] Identify gaps in detection or response
- [ ] Update firewall rules and ACLs permanently
- [ ] Review DDoS mitigation architecture — consider scrubbing center
- [ ] Share lessons learned with team

---

## 📞 Escalation Contacts

| Role | Name | Contact |
|------|------|---------|
| Security Lead | | |
| Network Manager | | |
| ISP NOC | | |
| DDoS Mitigation Vendor | | |
| Management | | |

---

## 📊 Severity Matrix

| Attack Volume | Severity | Response Time |
|---------------|----------|---------------|
| < 1 Gbps | LOW | 60 minutes |
| 1–10 Gbps | MEDIUM | 30 minutes |
| 10–100 Gbps | HIGH | 15 minutes |
| > 100 Gbps | CRITICAL | Immediate |

---

*Maintained by Ravi Kant Sankhyan — QCSSTUDIO. Review after every incident and at least annually.*
