# Case Study: UNC5537 Threat Campaign Targeting Snowflake Customer Instances

**Authors:** Kismat Kunwar, Yash Chetanbhai Barot  
**Institution:** Tagliatela College of Engineering  
**Course:** CSYS 6684: Cyber Threat Intelligence and Incident Response  
**Instructor:** Dr. Tirthankar Ghosh  
**Date:** March 23, 2026

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Threat Intelligence Plan](#threat-intelligence-plan)
3. [Incident Analysis & IoCs](#incident-analysis--iocs)
4. [Mitigations](#mitigations)
5. [Conclusion](#conclusion)
6. [References](#references)

---

## Executive Summary

### Case Overview

A financially motivated threat actor known as **UNC5537** executed a systematic credential-based campaign against approximately **165 Snowflake customer instances** in mid-April 2024. The attack did not exploit any weakness in Snowflake's core infrastructure. Instead, UNC5537 used legitimate credentials stolen by infostealer malware — including **Vidar, RisePro, RedLine, Raccoon Stealer, Lumma, and Metastealer** — many of which were harvested as far back as 2020 and remained valid due to inadequate credential hygiene. High-profile victims included **AT&T, Ticketmaster, and Santander Bank**; stolen data was later sold in cybercrime forums and used to extort the affected organizations.

### Most Important Findings

Three compounding failures enabled the breach:

- **No mandatory MFA** — attackers authenticated with stolen passwords alone.
- **Stale credentials** — many credentials dated back to 2020 and had never been rotated.
- **No network allow-lists** — access was not restricted to trusted IP addresses.

Attackers used custom reconnaissance tooling (**FROSTBITE**) alongside legitimate database utilities to stage and exfiltrate data. Critically, many stolen credentials originated from unmanaged contractor devices with no corporate EDR coverage, leaving organizations with no visibility into the initial compromise.

### Recommended Mitigation Strategies

- Enforce mandatory MFA on all cloud platform accounts, including those of third-party contractors.
- Implement credential rotation policies and actively monitor dark web markets for exposed organizational credentials.
- Apply strict network allow-lists to restrict cloud database access to trusted IP ranges.
- Enforce device posture and EDR requirements for all contractor and remote access endpoints.
- Deploy audit log monitoring with behavioral alerts for suspicious query patterns indicative of data staging and exfiltration.

---

## Threat Intelligence Plan

The threat intelligence plan was developed in response to the UNC5537 campaign, structured across strategic, operational, and tactical levels.

### Intelligence Questions

#### Strategic
1. What is the organization's true exposure to third-party and contractor risk?
2. Does the organization fully understand its liability under the cloud shared responsibility model?
3. What is the potential financial and reputational impact of a large-scale data breach and extortion attempt?
4. What are the legal and compliance implications?

#### Operational
1. Is MFA strictly and universally enforced across all cloud accounts?
2. What is the process for credential lifecycle management and rotation?
3. Have network allow-lists been implemented to restrict database access to trusted locations?
4. Is the organization actively monitoring exposed credentials on dark web forums and markets?
5. Do existing security systems identify and prevent unauthorized access using compromised credentials?
6. How often are access controls and permissions reviewed and updated?

#### Tactical
1. Are platform audit logs and login history tables being monitored for rare IP addresses, anomalous login times, or impossible travel detections?
2. Can connections from unauthorized or unrecognized client applications be detected and flagged?
3. Are spikes in reconnaissance and data exfiltration commands being monitored in query logs?
4. Are there anomalous daily error rates or excessive privilege errors indicating unauthorized enumeration attempts?
5. Are authentication attempts originating from known commercial VPN providers or suspicious foreign infrastructure being detected?
6. Are authentication attempts targeting locked, terminated, or dormant user accounts being flagged?

---

## Incident Analysis & IoCs

### Analysis of the Incident

UNC5537 targeted Snowflake customer environments using a consistent, repeatable methodology. Rather than exploiting platform vulnerabilities, attackers authenticated directly using credentials harvested by historical infostealer infections on contractor devices used for both personal and professional purposes.

**Initial Access:** Credentials stolen via Vidar, RisePro, RedLine, Raccoon Stealer, Lumma, and Metastealer — some dating to 2020 — remained valid due to absent MFA and no network allow-lists.

**Reconnaissance:** Attackers authenticated via the native Snowflake web interface (SnowSight) and SnowSQL CLI. They deployed **FROSTBITE** (client application ID: `rapeflake`, available in .NET and Java) and **DBeaver Ultimate** to enumerate users, roles, databases, and tables.

**Data Staging & Exfiltration:** Attackers used standard SQL commands to identify, isolate, compress, and exfiltrate data:

```sql
SHOW TABLES                          -- enumerate databases/tables
SELECT * FROM <table>                -- extract targeted data
CREATE TEMP STAGE                    -- create staging area
COPY INTO @stage COMPRESSION=GZIP   -- compress and stage data
GET @stage                           -- download to attacker infrastructure
```

**Infrastructure:** Traffic was anonymized through **Mullvad** and **Private Internet Access (PIA)** VPNs. Data was transferred to a Moldovan VPS (**ALEXHOST SRL**) and cloud storage (**MEGA**).

### MITRE ATT&CK Mapping

| Tactic | Technique | MITRE ID | Description |
|---|---|---|---|
| Reconnaissance | Gather Victim Identity Information | T1589.001 | Credentials from infostealer campaigns (Vidar, RisePro, RedLine, Raccoon Stealer, Lumma, Metastealer), some dating to 2020 |
| Initial Access | Valid Accounts | T1078.003 | No MFA; direct login via SnowSight and SnowSQL with no allow-lists |
| Discovery | Cloud Infrastructure Discovery | T1580 | SHOW TABLES; FROSTBITE (rapeflake) for user/role/IP enumeration |
| Collection | Data from Cloud Storage | T1530 | SELECT * FROM to isolate targeted data |
| Collection | Archive Collected Data | T1560.001 | COPY INTO with COMPRESSION=GZIP |
| Exfiltration | Exfiltration Over Alternative Protocol | T1048 | GET command to attacker-controlled VPS via ALEXHOST and MEGA |
| Impact | Extortion | T1657 | Victims extorted; data advertised for sale on cybercrime forums |

### Indicators of Compromise

#### Client Application IDs
Connections from the following client applications should be scrutinized and blocked if unauthorized:

- `rapeflake` (FROSTBITE — .NET and Java variants)
- `DBeaver_DBeaverUltimate`
- `Go 1.1.5`
- `JDBC 3.13.30`
- `JDBC 3.15.0`
- `PythonConnector 2.7.6`
- `SnowSQL 1.2.32`
- `Snowsight AI` / `Snowsight Al`
- `Snowflake UI`

#### Behavioral IoCs — Query Log Observables
Monitor `ACCOUNT_USAGE.QUERY_HISTORY` and `READER_ACCOUNT_USAGE.QUERY_HISTORY` for the following commands executed sequentially by a single user account:

- `SHOW TABLES`
- `SELECT * FROM`
- `LIST` / `LS`
- `CREATE TEMP STAGE` / `CREATE TEMPORARY STAGE`
- `COPY INTO`
- `GET`

#### Suspect IP Addresses

| | | | |
|---|---|---|---|
| 5.47.87.202 | 45.134.142.200 | 96.44.191.140 | 154.47.30.150 |
| 19.44.136.56 | 45.155.91.99 | 102.165.16.161 | 169.150.201.25 |
| 37.19.210.21 | 66.115.18.247 | 104.129.24.124 | 176.123.6.193 |
| 45.27.26.205 | 79.127.217.44 | 146.70.117.56 | 176.220.186.152 |
| 45.86.221.146 | 87.249.134.11 | 146.70.117.210 | 184.147.100.29 |
| 93.115.0.49 | 146.70.119.24 | 185.213.155.241 | 194.230.144.50 |
| 146.70.165.227 | 185.248.85.59 | 194.230.144.126 | 194.230.145.76 |
| 146.70.166.176 | 194.230.148.99 | 194.230.158.107 | 194.230.158.178 |
| 194.230.160.5 | 194.230.160.237 | 198.44.129.82 | 198.44.136.82 |
| 198.54.131.152 | 206.217.205.49 | | |

#### Associated Malware Families

- Vidar
- RisePro
- RedLine
- Raccoon Stealer
- Lumma
- Metastealer

---

## Mitigations

Mitigations are mapped to **CIS Controls Version 8** (Center for Internet Security, 2021).

### CIS Control 6 — Access Control Management
The absence of MFA was the most critical failure, enabling authentication with stolen passwords alone.
- **Safeguard 6.3:** Require MFA for all externally facing applications.
- **Safeguard 6.4:** Require MFA for all remote network access.
- **Safeguard 6.5:** Require MFA for all administrative accounts, including third-party-hosted ones.

### CIS Control 5 — Account Management
Attackers used credentials valid since 2020 due to absent rotation policies.
- **Safeguard 5.1:** Maintain a validated inventory of all accounts, reviewed quarterly.
- **Safeguard 5.3:** Disable accounts inactive for more than 45 days.

### CIS Controls 12 & 13 — Network Defense
Breached environments lacked allow-lists, leaving them exposed to untrusted IPs and commercial VPN endpoints.
- **Safeguard 12.2:** Implement segmented, secure network architecture.
- **Safeguard 13.5:** Enforce access controls for all remote assets accessing enterprise resources.

### CIS Control 8 — Audit Log Management
UNC5537 used standard SQL commands detectable via query logs.
- **Safeguard 8.11:** Review audit logs weekly for anomalies.
- **Safeguard 8.12:** Collect logs directly from cloud service providers such as Snowflake.

### CIS Control 10 — Malware Defenses
Initial credential theft occurred via infostealer infections on unmanaged contractor devices.
- **Safeguards 10.1 & 10.2:** Deploy and maintain centrally managed anti-malware software with automatic signature updates across all enterprise assets.

### CIS Control 15 — Service Provider Management
Unmonitored contractor devices provided the initial access vector.
- **Safeguard 15.2:** Maintain a policy for managing service providers.
- **Safeguard 15.4:** Embed minimum security requirements into all third-party contracts.

---

## Conclusion

The UNC5537 campaign demonstrates that sophisticated, large-scale data theft does not require software vulnerabilities — valid credentials and absent controls are sufficient. Three compounding failures enabled the breach: no mandatory MFA, weak credential lifecycle management allowing stolen passwords to remain valid for years, and no network allow-lists restricting access to trusted destinations.

The use of unmanaged contractor devices as the initial access vector highlights a critical gap in third-party risk management. By mapping the campaign to MITRE ATT&CK and applying CIS Controls v8 across each stage of the Cyber Kill Chain, the controls needed to detect, prevent, and disrupt this attack were shown to be both available and accessible.

**The broader takeaway: identity is the primary perimeter in cloud environments.** Organizations that do not manage it as strictly as their network boundaries will remain vulnerable to organized, financially motivated threat actors like UNC5537.

---

## References

- AlienVault. (n.d.). *UNC5537 targets Snowflake customer instances for data theft and extortion.* LevelBlue Open Threat Exchange. https://otx.alienvault.com/pulse/6665c8b01fbe7e6e8e9b4c3a
- Anvilogic. (2024, June 10). *Credential compromise at core of Snowflake's incident.* https://www.anvilogic.com/threat-reports/credential-compromise
- Center for Internet Security. (2021). *CIS critical security controls v8.* https://www.cisecurity.org/controls/v8
- DeepRoot Technologies. (n.d.). *UNC5537: Snowflake database threat campaign.* https://deeproottech.io/unc5537-snowflake-database-threat-campaign/
- Google Threat Intelligence Group. (2024, June 10). *UNC5537 targets Snowflake customer instances for data theft and extortion.* Google Cloud Blog. https://cloud.google.com/blog/topics/threat-intelligence/unc5537-snowflake-data-theft-extortion
- Lyons, J. (2024, June 11). *Snowflake customers not using MFA are not unique — over 165 of them have been compromised.* The Register. https://www.theregister.com/2024/06/11/crims_targeting_snowflake_customers/
- Montini, H. (2024, July 19). *Snowflake data breach.* Proven Data. https://www.provendata.com/blog/snowflake-data-breach
- Mphasis. (2024, June 17). *UNC5537* [PDF]. https://www.mphasis.com/content/dam/mphasis-com/global/en/home/services/cybersecurity/june-17-19-unc5537.pdf
- Pernet, C. (2024, June 12). *Mandiant report: Snowflake users targeted for data theft and extortion.* TechRepublic. https://www.techrepublic.com/article/mandiant-snowflake-data-theft/
