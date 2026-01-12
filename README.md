# SOC Incident Investigation – Azuki Import/Export 

![Image Alt](https://github.com/Darya-cybersec/CTF-Azuki-Import-Export-Investigation/blob/eeebf6367dbb5567021d790a025d5300dd61ca9e/RANSOM%20NOTE.png
)

- [Scenario Creation](https://github.com/Darya-cybersec/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)

## Date of Incident: 27 November 2025

##  Scenario

Dead in the Water – Azuki Import/Export (梓貿易株式会社)  
One week after the initial compromise, ransom notes are discovered across every system upon arrival Monday morning. It becomes clear that the threat actors were not only stealing data, but were preparing for widespread and destructive impact.

## The CEO needs answers:
- How did they get to our backup infrastructure?
- What exactly did they destroy?
- How did the ransomware spread so fast?
- Can we recover?

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.
The MDE LAW logs are your only source of truth. DeviceProcessEvents
---

## 🔎 Flag Analysis & Findings

### 🐧 PHASE 1: LINUX BACKUP SERVER COMPROMISE (FLAGS 1-12)
**🚩 FLAG 1:** LATERAL MOVEMENT - Remote Access
Attackers pivot to critical infrastructure to eliminate recovery options before deploying ransomware.

**Discovery:** 
Workstations are common initial access and pivot points in ransomware campaigns. To identify which Azuki system was most likely compromised, process activity frequency was analyzed across Azuki devices.
RATIONALE 
The incident brief specifies that four Azuki systems are in scope and provides a starting point to identify relevant devices. The first step was to enumerate all devices associated with the Azuki environment.

 ![Image Alt](https://github.com/Darya-cybersec/CTF-Azuki-Import-Export-Investigation/blob/78310a67f868bfe637a5a58329851cbf54000a86/Picture1.png)

**Outcome:**
This query confirmed the presence of multiple Azuki systems, including servers and workstations. Among these was azuki-adminpc, which aligns with prior context from earlier stages of the investigation as a user-accessible workstation.

To reach Linux-based backup infrastructure from a Windows workstation, attackers commonly use Secure Shell (SSH) for remote access. Therefore, the next step was to inspect process execution on azuki-adminpc for evidence of SSH usage.

![Image Alt](https://github.com/Darya-cybersec/CTF-Azuki-Import-Export-Investigation/blob/01c0ad697d1cd5adcc7b95f8147d18fa5b60ea96/Picture2SSH.png)

**Answer:FLAG 1 🚩: ssh.exe" backup-admin@10.1.0.189**

**MITRE ATT&CK Mapping:** T1021.004 – Remote Services (SSH)

**🚩 FLAG 2:** LATERAL MOVEMENT - Attack Source

**Discovery:** After identifying SSH-based lateral movement originating from the compromised workstation (azuki-adminpc), network telemetry was analyzed to determine the source IP address responsible for initiating the connection. The investigation pivoted to the DeviceNetworkEvents table to examine outbound SSH traffic. Network events were filtered to include only connections from azuki-adminpc using TCP port 22, consistent with SSH activity targeting the backup server (azuki-backupsrv). The LocalIP field was reviewed to identify the IP address that initiated the connection, which was captured as the attack source.

![Image Alt](https://github.com/Darya-cybersec/CTF-Azuki-Import-Export-Investigation/blob/ea11306f91dc04627c43c2bd8698ec86c4000599/Picture3.png)

**Answer:FLAG 2 🚩: 10.1.0.108**

**MITRE ATT&CK Mapping:** T1078.002: Valid Accounts - Domain Accounts

**🚩 FLAG 3:** CREDENTIAL ACCESS - Compromised Account
Administrative accounts with backup privileges provide access to critical recovery infrastructure.

**Discovery:** After identifying SSH-based lateral movement from the compromised workstation, process execution telemetry was reviewed to determine the account used to authenticate to the backup server. DeviceProcessEvents were filtered for SSH command execution originating from azuki-adminpc. The username specified in the SSH command line was extracted and identified as the account used to access the backup infrastructure.

![Image Alt](https://github.com/Darya-cybersec/CTF-Azuki-Import-Export-Investigation/blob/047b1a28c1a9443a0ce5c1ec4f70a0157c506f31/Picture4.png)

**Answer:FLAG 3 🚩: backup-admin**

**MITRE ATT&CK Mapping:** T1078.002: Valid Accounts - Domain Accounts

**🚩 FLAG 4:** DISCOVERY - Directory Enumeration
File system enumeration reveals backup locations and valuable targets for destruction.

**Discovery:** The DeviceProcessEvents table was queried to isolate executions of the ls command on the backup server, as this is a standard Linux utility used to list directory contents. By reviewing the resulting command lines, the directory listing command targeting the primary backup path was identified. The full command line used to enumerate the backup directory contents was captured as evidence of discovery activity consistent with MITRE ATT&CK technique T1083 – File and Directory Discovery.

![Image Alt](https://github.com/Darya-cybersec/CTF-Azuki-Import-Export-Investigation/blob/df1654e20182b5e9858f0cfd1f0997989ebdb3ad/Picture5.png)

**Answer:FLAG 4 🚩: ls --color=auto -la /backups/**

**MITRE ATT&CK Mapping:** T1083: File and Directory Discovery
