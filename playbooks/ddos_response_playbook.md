# 🚨 Incident Response Playbook — DDoS Attack
**Author:** Ravi Kant Sankhyan | QCSSTUDIO  
**Version:** 2.0 | Classification: INTERNAL — RESTRICTED  
**Review Cycle:** Annually or after any DDoS incident

> **IMPORTANT:** This playbook must be reviewed and practiced before an attack occurs.
> Print a physical copy and store in the NOC. Network attacks often degrade the systems
> used to access digital documentation.

---

## 🎯 Scope & Applicability

This playbook applies to Distributed Denial of Service (DDoS) attacks targeting:
- Internet-facing IP addresses and web services
- Border routers and firewalls
- DNS infrastructure
- VPN concentrators and remote access gateways
- Any service causing business disruption due to traffic volumetrics

---

## ⚡ Quick Reference — First 5 Minutes

```
1. CONFIRM    → Is this a DDoS or a legitimate traffic spike?
2. IDENTIFY   → What is being targeted? (IP, port, service)
3. CLASSIFY   → Volumetric / Protocol / Application layer?
4. NOTIFY     → Call Security Lead + NOC Manager immediately
5. DOCUMENT   → Start incident log with exact timestamp
```

---

## 📊 Attack Classification Matrix

| Type | Layer | Indicators | Example Attacks |
|------|-------|-----------|----------------|
| **Volumetric** | L3/L4 | Interface utilization >80%, ISP alerts | UDP Flood, ICMP Flood, DNS Amplification, NTP Amplification |
| **Protocol** | L3/L4 | Firewall/router CPU spike, state table full | SYN Flood, Ping of Death, Smurf, Fragmentation attacks |
| **Application** | L7 | Web server CPU spike, slow responses, HTTP errors | HTTP Flood, Slowloris, RUDY, DNS Query Flood |

---

## 🔴 PHASE 1 — Detection & Identification (T+0 to T+15 minutes)

### 1.1 Detection Indicators

| Signal | Tool to Check | Threshold for Action |
|--------|--------------|---------------------|
| Interface utilization spike | Router SNMP / NetFlow | >70% sustained for 5+ min |
| Sudden packet rate increase | Firewall dashboard | >2x baseline PPS |
| CPU spike on border device | SNMP polling | >80% for 3+ min |
| State table exhaustion | Firewall logs | >90% connection table |
| Service degradation alerts | Monitoring (Nagios/Zabbix) | Response time >3x baseline |
| ISP upstream notification | Email / Phone | Any notification |
| Helpdesk tickets | ITSM system | Multiple simultaneous reports |

### 1.2 Immediate Identification Steps

```bash
# Cisco IOS — Check interface traffic
show interfaces GigabitEthernet0/0 | include input rate|output rate
show interfaces summary | include GigabitEthernet

# Cisco IOS — Check CPU
show processes cpu sorted | head 15

# Check current connections / state table
show ip nat translations total
show conn count   (ASA)

# Check for specific traffic patterns
show ip traffic
debug ip packet detail   (USE WITH EXTREME CAUTION — only on low-traffic links)

# Identify top talkers with NetFlow (if available)
show ip cache flow | sort | head 20
```

### 1.3 Identification Checklist

- [ ] Confirm attack is active — not a monitoring false positive
- [ ] Record exact start time: _______________
- [ ] Identify targeted IP/service: _______________
- [ ] Identify attack type (Volumetric / Protocol / Application): _______________
- [ ] Estimate attack bandwidth/PPS: _______________
- [ ] Identify source IP distribution (single source vs. distributed): _______________
- [ ] Check if any legitimate traffic is collateral: _______________
- [ ] Assign Incident Severity (see matrix below): _______________
- [ ] Notify Security Lead: Time: _______________ By: _______________
- [ ] Open Incident Ticket #: _______________

---

## 🟠 PHASE 2 — Containment & Mitigation (T+15 to T+60 minutes)

> **Principle:** Preserve legitimate traffic where possible. Accept some service degradation to prevent total outage.

### 2.1 Tier 1 — Router/Firewall Level Mitigation

**Null Routing (Blackholing) — use when target IP is sacrificable:**
```
! Cisco IOS — null route the targeted IP
ip route 203.0.113.50 255.255.255.255 Null0 name "DDoS-blackhole-2025"
! Remove when attack subsides:
no ip route 203.0.113.50 255.255.255.255 Null0
```

**Rate Limiting ICMP and UDP Flood:**
```
! Create a rate-limit policy
interface GigabitEthernet0/0
  rate-limit input 100000000 8000 12000 conform-action transmit exceed-action drop
```

**SYN Flood — Enable TCP Intercept (Cisco IOS):**
```
ip tcp intercept list 101
ip tcp intercept mode intercept
ip tcp intercept max-incomplete high 1100
ip tcp intercept max-incomplete low 900
ip tcp intercept one-minute high 1100
ip tcp intercept one-minute low 900
```

**ACL to block known attack source ranges:**
```
ip access-list extended DDOS-BLOCK
  deny ip <attacker-range> <wildcard> any
  permit ip any any
interface GigabitEthernet0/0
  ip access-group DDOS-BLOCK in
```

**Anti-Spoofing (uRPF — Unicast Reverse Path Forwarding):**
```
interface GigabitEthernet0/0
  ip verify unicast source reachable-via rx   ! Strict mode
```

### 2.2 Tier 2 — Firewall Level Mitigation

- [ ] Enable SYN Cookies on the firewall for affected services
- [ ] Reduce maximum embryonic (half-open) connection limit
- [ ] Increase connection timeouts temporarily to prevent rapid reconnect floods
- [ ] Block source countries not relevant to your user base (geo-blocking)
- [ ] Enable botnet traffic filter if available (Cisco ASA/FTD)
- [ ] Rate-limit DNS queries if DNS is being targeted

**Palo Alto — Zone Protection Profile:**
```
Set Zone Protection Profile flood thresholds:
  SYN Flood Activate: 10000 pps
  SYN Flood Drop:     25000 pps
  UDP Flood Activate: 10000 pps
```

**Fortinet FortiGate — DoS Policy:**
```
config firewall DoS-policy
  edit 1
    set interface "wan1"
    set srcaddr "all"
    set service "ALL"
    set anomaly "tcp_syn_flood" "udp_flood" "icmp_flood"
  end
```

### 2.3 Tier 3 — ISP & Upstream Mitigation

- [ ] Contact ISP NOC — provide attack details (source IPs, protocols, target IPs)
- [ ] Request upstream ACL or rate limiting at ISP edge
- [ ] Request RTBH (Remotely Triggered Black Hole) routing if total sacrifice acceptable
- [ ] Engage BGP Flowspec if supported by ISP — granular upstream filtering
- [ ] Activate contracted DDoS mitigation service (Cloudflare Magic Transit, Akamai Prolexic, etc.)

### 2.4 Application Layer (L7) Mitigation

- [ ] Enable WAF rate limiting rules for HTTP flood
- [ ] Implement CAPTCHA challenges for suspicious source IPs
- [ ] Block User-Agent strings associated with known attack tools
- [ ] Enable HTTP request rate limiting (e.g., nginx: `limit_req_zone`)
- [ ] Activate CDN attack mitigation (Cloudflare, Akamai, Fastly)
- [ ] Temporarily increase web server connection queue and timeout

---

## 🟡 PHASE 3 — Recovery & Validation (T+60 min to T+4 hours)

### 3.1 Service Restoration

- [ ] Confirm attack traffic has subsided (monitor for 30+ minutes before restoring)
- [ ] Remove null routes and temporary ACLs in reverse order of application
- [ ] Restore services in priority order:
  - [ ] Priority 1: Customer-facing revenue services
  - [ ] Priority 2: Internal business operations
  - [ ] Priority 3: Non-critical services
- [ ] Validate service restoration from external monitoring probe (not just internal)
- [ ] Notify stakeholders of restoration with timeline

### 3.2 Post-Attack Verification Commands

```bash
# Verify interfaces are clean
show interfaces GigabitEthernet0/0 | include input rate

# Confirm temporary ACLs removed
show ip access-lists DDOS-BLOCK

# Check for any remaining null routes
show ip route 203.0.113.50

# Verify service availability externally
ping -c 50 <public-IP>    (from external host)
curl -I https://yoursite.com
```

---

## 🟢 PHASE 4 — Post-Incident Review (T+24 to T+48 hours)

### 4.1 Incident Documentation

- [ ] Complete incident timeline from first alert to full resolution
- [ ] Record all mitigation actions taken with exact timestamps
- [ ] Calculate total downtime and affected services
- [ ] Estimate business impact (revenue, SLA breach, reputational)
- [ ] Document attack characteristics (volume, type, geographic origin, duration)

### 4.2 Lessons Learned & Hardening

- [ ] Root cause: Was this a new vector or a known weakness that wasn't addressed?
- [ ] Detection gap: How long between attack start and detection? Target: <5 minutes
- [ ] Response gap: How long between detection and first mitigation? Target: <15 minutes
- [ ] Infrastructure gaps: What would have prevented or reduced impact?
  - Scrubbing center / CDN in front of services?
  - More granular rate limiting?
  - Better out-of-band management (not affected by attack traffic)?
- [ ] Update firewall rules and ACLs permanently based on attack signatures
- [ ] Update this playbook with any new learnings
- [ ] Schedule table-top exercise with team in next 30 days

### 4.3 Management Report

Prepare a management-level incident report including:
- Executive summary (1 paragraph, non-technical)
- Attack timeline
- Business impact assessment
- Mitigation actions taken
- Recommendations to prevent recurrence
- Investment requests if applicable (scrubbing center, upgraded links)

---

## 📞 Escalation Contacts

| Role | Name | Primary Contact | Alternate |
|------|------|----------------|-----------|
| Security Lead / CISO | | | |
| Network Manager | | | |
| ISP NOC 24x7 | | | |
| DDoS Mitigation Vendor | | | |
| CEO / Business Owner | | | |
| PR / Communications | | | |

---

## 📊 Severity & SLA Matrix

| Attack Bandwidth | Severity | Max Detection Time | Max Mitigation Time |
|-----------------|----------|--------------------|---------------------|
| < 500 Mbps | LOW | 15 minutes | 60 minutes |
| 500 Mbps – 5 Gbps | MEDIUM | 10 minutes | 30 minutes |
| 5 – 50 Gbps | HIGH | 5 minutes | 15 minutes |
| > 50 Gbps | CRITICAL | 2 minutes | Immediate escalation |

---

## 📎 Appendix: Common DDoS Attack Signatures

| Attack | Protocol | Spoofed? | Amplification Factor | Primary Defense |
|--------|----------|----------|---------------------|-----------------|
| SYN Flood | TCP | Yes | 1x | SYN cookies, TCP intercept |
| UDP Flood | UDP | Yes | 1x | Rate limiting, uRPF |
| ICMP Flood | ICMP | Yes | 1x | Rate limiting |
| DNS Amplification | UDP/53 | Yes | 28–54x | Restrict open resolvers |
| NTP Amplification | UDP/123 | Yes | 556x | Restrict monlist, upgrade NTP |
| Memcached Amplification | UDP/11211 | Yes | 50,000x | Block UDP/11211 at perimeter |
| HTTP Flood | TCP/80,443 | No | 1x | WAF, rate limiting, CAPTCHA |
| Slowloris | TCP/80,443 | No | 1x | Connection timeouts, limits |

---

*Maintained by Ravi Kant Sankhyan — QCSSTUDIO  
Review annually and after every DDoS incident.  
[Upwork](https://www.upwork.com/freelancers/~01b4709590df4f83e5) | [GitHub](https://github.com/QCSSTUDIO)*
