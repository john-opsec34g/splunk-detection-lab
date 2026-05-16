# 📊 Splunk Cloud Detection Lab

> Built by John Victory | Junior SOC Analyst
> GitHub: github.com/john-opsec34g

---

## Overview

A hybrid Security Information and Event Management (SIEM) lab
using Splunk Cloud to collect, monitor, and detect real attack
activity simulated from a Kali Linux attack machine against a
Windows 10 victim workstation.

This lab demonstrates real SOC analyst skills — configuring
log ingestion, writing SPL detection queries, building
dashboards, and investigating security events — using the
same tools and workflows used in professional SOC environments.

---

## Lab Architecture

```
┌─────────────────────────────────────────────────────────┐
│                  SPLUNK CLOUD (Browser)                  │
│                                                          │
│   ┌─────────────────────────────────────────────────┐   │
│   │            Splunk Cloud Dashboard               │   │
│   │   - Search and Reporting (SPL Queries)          │   │
│   │   - SOC Detection Dashboard                     │   │
│   │   - Real-time Alert Monitoring                  │   │
│   │   - Event ID Analysis                           │   │
│   └──────────────────┬──────────────────────────────┘   │
└─────────────────────-│--────────────────────────────────┘
                       │
                       │ Splunk Universal Forwarder
                       │ (forwards Windows Security,
                       │  System, and Application logs)
                       │
┌──────────────────────▼──────────────────────────────────┐
│                  DELL LAPTOP (On-Premise)                │
│                                                          │
│  ┌─────────────────────┐   ┌─────────────────────────┐  │
│  │  Windows 10 VM      │   │   Kali Linux VM         │  │
│  │  (Victim Machine)   │◄──│   (Attack Machine)      │  │
│  │                     │   │                         │  │
│  │  - Generates logs   │   │  Attack Tools:          │  │
│  │  - Universal        │   │  - Responder (LLMNR)    │  │
│  │    Forwarder        │   │  - Nmap (Port Scan)     │  │
│  │    installed        │   │  - Hydra (Brute Force)  │  │
│  │  - Sends all        │   │  - Netcat               │  │
│  │    events to        │   │                         │  │
│  │    Splunk Cloud     │   │                         │  │
│  └─────────────────────┘   └─────────────────────────┘  │
│                                                          │
│  Both VMs connected via phone hotspot — same subnet      │
└─────────────────────────────────────────────────────────┘
```

---

## Environment Details

| Component | Details |
|---|---|
| SIEM Platform | Splunk Cloud (Free 14-day trial) |
| Log Collection | Splunk Universal Forwarder on Windows 10 VM |
| Victim Machine | Windows 10 — VirtualBox VM on Dell |
| Attack Machine | Kali Linux — VirtualBox VM on Dell |
| Network | Phone hotspot — all machines same subnet |
| Detection Language | SPL (Splunk Processing Language) |
| Host Machine | Dell Latitude — 8GB RAM |

---

## Attacks Simulated and Detected

---

### ATTACK 1 — Port Scan Detection
**Tool used:** Nmap
**MITRE Technique:** T1046 — Network Service Discovery
**Event IDs Generated:** 4625, Windows Firewall logs

**Attack command run on Kali:**
```bash
nmap -sS -p 1-1000 192.168.43.x
```

**What this does:**
Nmap sends SYN packets to 1000 ports on the Windows 10 VM
simulating an attacker scanning for open services before
launching a targeted attack.

**SPL Detection Query:**
```
index=* sourcetype=WinEventLog:Security EventCode=4625
| stats count by src_ip, user
| where count > 10
| sort -count
| rename src_ip as "Source IP", count as "Failed Attempts"
```

**What to look for in results:**
Your Kali IP appearing with high count of connection attempts
across multiple ports in a short timeframe.

**Screenshot:** [Add screenshot of Splunk results here]

**Status:** ✅ Completed

---

### ATTACK 2 — LLMNR Poisoning Detection
**Tool used:** Responder
**MITRE Technique:** T1557.001 — LLMNR/NBT-NS Poisoning
**Event IDs Generated:** 4625, 4648

**Attack command run on Kali:**
```bash
sudo responder -I eth0 -rdw
```

**Trigger on Windows 10 VM:**
Open File Explorer and type \\fileserver in address bar.
Windows broadcasts an LLMNR request. Responder intercepts
it and captures the NTLMv2 hash.

**What this simulates:**
A real attacker on the same network intercepting Windows
broadcast traffic to steal password hashes without any
direct interaction with the victim.

**SPL Detection Query:**
```
index=* sourcetype=WinEventLog:Security EventCode=4625
| table _time, user, src_ip, host, LogonType
| sort -_time
| head 50
```

**Advanced correlation query:**
```
index=* sourcetype=WinEventLog:Security
| where EventCode=4625 OR EventCode=4648
| stats count by src_ip, EventCode
| sort -count
```

**Screenshot:** [Add screenshot of Responder capturing hash]
**Screenshot:** [Add screenshot of Splunk detecting the event]

**Status:** ✅ Completed

---

### ATTACK 3 — Brute Force Attack Detection
**Tool used:** Hydra
**MITRE Technique:** T1110 — Brute Force
**Event IDs Generated:** 4625 (multiple), 4740 (account lockout)

**Attack command run on Kali:**
```bash
hydra -l administrator -P /usr/share/wordlists/rockyou.txt smb://192.168.43.x
```

**What this simulates:**
An attacker attempting to guess the administrator password
by rapidly trying thousands of common passwords. This is one
of the most common real-world attack techniques.

**SPL Detection Query — Basic:**
```
index=* sourcetype=WinEventLog:Security EventCode=4625
| stats count by src_ip
| where count > 10
| sort -count
| rename src_ip as "Attacker IP", count as "Failed Attempts"
```

**SPL Detection Query — With Timeline:**
```
index=* sourcetype=WinEventLog:Security EventCode=4625
| timechart span=1m count by src_ip
```

**SPL Detection Query — Account Lockout:**
```
index=* sourcetype=WinEventLog:Security EventCode=4740
| table _time, TargetUserName, TargetDomainName, SubjectUserName
| sort -_time
```

**Screenshot:** [Add screenshot of Hydra running on Kali]
**Screenshot:** [Add screenshot of Splunk brute force detection]

**Status:** ✅ Completed

---

### ATTACK 4 — New User Account Creation
**Tool used:** Windows net user command
**MITRE Technique:** T1136 — Create Account
**Event IDs Generated:** 4720

**Command run on Windows 10 VM:**
```cmd
net user hacker Password123! /add
```

**What this simulates:**
An attacker who has gained initial access creating a backdoor
account to maintain persistent access to the system even if
their original access method is discovered and closed.

**SPL Detection Query:**
```
index=* sourcetype=WinEventLog:Security EventCode=4720
| table _time, TargetUserName, SubjectUserName, host
| sort -_time
```

**Screenshot:** [Add screenshot of Splunk showing new account]

**Status:** ✅ Completed

---

### ATTACK 5 — Privilege Escalation Detection
**Tool used:** Windows net localgroup command
**MITRE Technique:** T1078.003 — Local Accounts
**Event IDs Generated:** 4732

**Command run on Windows 10 VM:**
```cmd
net localgroup administrators hacker /add
```

**What this simulates:**
After creating a backdoor account an attacker elevates it to
administrator level — giving themselves full control of the
system. This is a classic privilege escalation technique.

**SPL Detection Query:**
```
index=* sourcetype=WinEventLog:Security EventCode=4732
| table _time, TargetUserName, MemberName, host
| sort -_time
```

**Correlation query — Account created then escalated:**
```
index=* sourcetype=WinEventLog:Security
| where EventCode=4720 OR EventCode=4732
| table _time, EventCode, TargetUserName, SubjectUserName
| sort _time
```

**Screenshot:** [Add screenshot of privilege escalation detection]

**Status:** ✅ Completed

---

## MITRE ATT&CK Coverage

| Tactic | Technique | ID | Detected |
|---|---|---|---|
| Discovery | Network Service Discovery | T1046 | ✅ |
| Credential Access | LLMNR/NBT-NS Poisoning | T1557.001 | ✅ |
| Credential Access | Brute Force | T1110 | ✅ |
| Persistence | Create Account | T1136 | ✅ |
| Privilege Escalation | Local Accounts | T1078.003 | ✅ |

---

## Key SPL Queries Written

### 1. Overall Security Event Distribution
```
index=* sourcetype=WinEventLog:Security
| stats count by EventCode
| sort -count
| rename EventCode as "Event ID", count as "Total Count"
```

### 2. Failed Login Summary
```
index=* sourcetype=WinEventLog:Security EventCode=4625
| stats count by src_ip, user, host
| sort -count
| head 20
```

### 3. Successful Logins After Multiple Failures
```
index=* sourcetype=WinEventLog:Security
| where EventCode=4625 OR EventCode=4624
| stats count by src_ip, EventCode
| sort src_ip, EventCode
```

### 4. Timeline of All Security Events
```
index=* sourcetype=WinEventLog:Security
| timechart span=5m count by EventCode
```

### 5. New Accounts and Privilege Changes
```
index=* sourcetype=WinEventLog:Security
| where EventCode IN (4720, 4732, 4728, 4756)
| table _time, EventCode, TargetUserName, SubjectUserName, host
| sort -_time
```

### 6. Complete Security Alert Table
```
index=* sourcetype=WinEventLog:Security
| where EventCode IN (4625, 4720, 4732, 4698, 7045, 4740, 4648)
| table _time, EventCode, user, src_ip, host
| sort -_time
```

---

## Splunk Dashboard Built

Created a custom SOC Detection Dashboard in Splunk Cloud
with four panels:

**Panel 1 — Event ID Distribution**
Bar chart showing count of each Windows Event ID
Query:
```
index=* sourcetype=WinEventLog:Security
| stats count by EventCode
| sort -count
```

**Panel 2 — Failed Login Attempts Over Time**
Line chart showing brute force attack timeline
Query:
```
index=* sourcetype=WinEventLog:Security EventCode=4625
| timechart count by src_ip
```

**Panel 3 — Security Alerts Table**
Live table of all suspicious events
Query:
```
index=* sourcetype=WinEventLog:Security
| where EventCode IN (4625, 4720, 4732, 4698, 7045)
| table _time, EventCode, user, src_ip, host
| sort -_time
```

**Panel 4 — Top Attacking IPs**
Shows which IPs generated the most suspicious activity
Query:
```
index=* sourcetype=WinEventLog:Security EventCode=4625
| stats count by src_ip
| sort -count
| head 10
```

---

## Windows Event IDs Reference

| Event ID | Description | Why It Matters |
|---|---|---|
| 4624 | Successful logon | Verify if expected |
| 4625 | Failed logon | Brute force indicator |
| 4648 | Logon with explicit credentials | Pass-the-hash indicator |
| 4698 | Scheduled task created | Persistence indicator |
| 4720 | User account created | Backdoor account indicator |
| 4732 | User added to local group | Privilege escalation indicator |
| 4740 | Account locked out | Brute force confirmation |
| 7045 | New service installed | PsExec lateral movement |

---

## Tools and Technologies Used

| Tool | Purpose |
|---|---|
| Splunk Cloud | Cloud SIEM platform |
| Splunk Universal Forwarder | Log collection agent |
| SPL | Splunk Processing Language for queries |
| Kali Linux | Attack simulation machine |
| Responder | LLMNR/NBT-NS poisoning tool |
| Nmap | Network port scanning |
| Hydra | Brute force password attack |
| Windows 10 | Victim machine generating logs |
| VirtualBox | Virtualisation platform |

---

## Key Lessons Learned

**1. Log volume matters**
A single attack generates dozens of related events across
multiple Event IDs. Real SOC work requires correlating
multiple data points to understand the full picture.

**2. Context is everything**
A single failed login (Event 4625) is not an alert.
47 failed logins from the same IP in 3 minutes is an alert.
SPL queries must consider volume and frequency not just
the presence of an event.

**3. Attackers chain techniques**
The port scan came before the brute force. The new account
came before the privilege escalation. Understanding attack
chains helps write better detection logic.

**4. Both SIEM platforms matter**
This lab used Splunk. My Active Directory lab uses Microsoft
Sentinel. Being comfortable in both platforms makes me
tool-agnostic and ready for any SOC environment.

---

## Repository Structure

```
splunk-detection-lab/
├── README.md (this file)
├── SPL-Queries/
│   ├── brute-force-detection.spl
│   ├── llmnr-detection.spl
│   ├── account-creation-detection.spl
│   ├── privilege-escalation-detection.spl
│   └── port-scan-detection.spl
├── Screenshots/
│   ├── splunk-dashboard.png
│   ├── brute-force-detection.png
│   ├── llmnr-poisoning.png
│   ├── account-creation.png
│   └── privilege-escalation.png
└── Attack-Writeups/
    ├── 01-port-scan.md
    ├── 02-llmnr-poisoning.md
    ├── 03-brute-force.md
    ├── 04-account-creation.md
    └── 05-privilege-escalation.md
```

---

## Related Projects

- **SOC Investigations:** github.com/john-opsec34g/soc-analyst-labs
- **AI SOC Triage Tool:** github.com/john-opsec34g/ai-soc-triage-tool
- **Active Directory Lab:** github.com/john-opsec34g/active-directory-lab

---

## Author

**John Victory** — Junior SOC Analyst in Training
Nigeria | Open to Remote Roles Globally

Certifications: SC-200 | AZ-500 | SC-100 | AZ-900 |
Cisco CyberOps | Security+ | Network+ | ISC2 CC

GitHub: github.com/john-opsec34g
LinkedIn: linkedin.com/in/john-victory

---

## Disclaimer

All attacks documented in this repository were conducted
in a private isolated lab environment using virtual machines
for educational and defensive security purposes only.
No real systems or organisations were involved.
