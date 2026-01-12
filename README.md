
<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

_____ _ _            _   _                     
  / ____(_) |          | | | |                    
 | (___  _| | ___ _ __ | |_| |    _   _ _ __ __  __
  \___ \| | |/ _ \ '_ \| __| |   | | | | '_ \\ \/ /
  ____) | | |  __/ | | | |_| |___| |_| | | | |>  < 
 |_____/|_|_|\___|_| |_|\__|______\__, |_| |_/_/\_\
                                   __/ |          
                                  |___/           

════════════════════════════════════════════════════════════════════════════════
              SECURITY ASSESSMENT REPORT | SILENTLYNX SECURITY TEAM
════════════════════════════════════════════════════════════════════════════════

┌─────────────────────────────────────────────────────────────────────────────┐
│  CLIENT:          Azuki Logistics Ltd.                                      │
│  ASSESSMENT ID:   SL-ASM-2025-1127-BC844                                    │
│  VICTIM KEY:      AZUKI-BC844-1127                                          │
│  AFFILIATE ID:    SL-AFF-2847                                               │
│  ENCRYPTION ID:   7f3a9c2b-4e8d-1f6a-9b2c-3d7e8f4a1c5b                      │
│  DATE:            November 27, 2025                                         │
│  ASSESSMENT TIME: 7 Days                                                    │
└─────────────────────────────────────────────────────────────────────────────┘




# SOC Incident Investigation – Azuki Import/Export 

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
