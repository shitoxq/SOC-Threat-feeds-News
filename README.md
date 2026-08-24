# SOC-Threat-feeds-News

## Overview

**SOC-Threat-feeds-News** is a centralized collection of cybersecurity threat intelligence, security news, vulnerabilities, malware campaigns, attack techniques, and other relevant information for the SOC/InfoSec team.

The purpose of this repository is to collect, organize, and share actionable threat information that can support:

* SOC monitoring and detection
* Threat hunting
* Incident response
* Vulnerability management
* SIEM use-case development
* Security awareness
* Threat intelligence reporting

## Objectives

1. Collect relevant cybersecurity news and threat intelligence from trusted sources.
2. Identify emerging threats, vulnerabilities, malware, and attack campaigns.
3. Extract useful **IOCs** such as IP addresses, domains, URLs, hashes, and CVEs.
4. Share important findings with the SOC/InfoSec team.
5. Support the creation and tuning of SIEM detection rules.
6. Maintain a historical reference of significant security events.

## Threat Feed Categories

| Category           | Description                                              |
| ------------------ | -------------------------------------------------------- |
| 🚨 Threat Alerts   | Active attacks, campaigns, and emerging threats          |
| 🦠 Malware         | New malware, ransomware, trojans, loaders, and variants  |
| 🔐 Vulnerabilities | CVEs, zero-days, vendor advisories, and exploits         |
| 🎯 APT             | Advanced Persistent Threat groups and campaigns          |
| 🌐 Network         | DDoS, scanning, exploitation, and network attacks        |
| ☁️ Cloud           | Cloud security incidents and vulnerabilities             |
| 📧 Phishing        | Phishing, BEC, credential theft, and email attacks       |
| 🛡️ Defense        | Detection techniques, mitigations, and security guidance |
| 🧩 IOCs            | IPs, domains, URLs, hashes, and other indicators         |
| 📰 Security News   | Major cybersecurity industry developments                |

## News Collection Workflow

```text
Trusted Sources
      ↓
News / Threat Feed Collection
      ↓
Relevance Filtering
      ↓
Threat Intelligence Analysis
      ↓
IOC Extraction
      ↓
SOC Validation
      ↓
Telegram / Team Notification
      ↓
SIEM / Detection / Threat Hunting Action
```

## Recommended News Format

Each collected threat should contain:

```text
Title:
Date:
Severity:
Category:
Threat Actor:
Affected Product/Organization:
CVE:
Summary:
Impact:
IOCs:
Recommended Action:
Source:
```

## Source Priority

Prioritize information from:

* CISA
* NIST NVD
* MITRE ATT&CK
* Vendor security advisories
* CERT/CSIRT organizations
* Major cybersecurity research teams
* Trusted cybersecurity news organizations

## SOC Action

When a threat is considered relevant to the environment:

* [ ] Check whether affected products/services exist in the environment.
* [ ] Search SIEM for related IOCs or behaviors.
* [ ] Check EDR/firewall/WAF/VPN logs.
* [ ] Validate whether exploitation has been observed.
* [ ] Add relevant IOCs to threat intelligence platforms.
* [ ] Create or tune SIEM detection rules when appropriate.
* [ ] Share critical findings with the SOC/InfoSec team.
* [ ] Track remediation or mitigation actions.

## Notification

Critical or high-impact threats should be summarized and distributed to the SOC/InfoSec team through the approved communication channel, such as Telegram.

Recommended notification structure:

```text
🚨 SOC Threat Intelligence Alert

Title: <Threat Title>
Severity: Critical/High/Medium/Low
Category: <Category>

Summary:
<Short threat summary>

Impact:
<Potential impact>

CVE/IOC:
<CVE or important IOC>

Recommended Action:
<Required SOC action>

Source:
<Trusted source>
```

## Repository Structure

```text
SOC-Threat-feeds-News/
├── README.md
├── feeds/
│   ├── vulnerabilities/
│   ├── malware/
│   ├── ransomware/
│   ├── phishing/
│   ├── apt/
│   └── general/
├── iocs/
│   ├── ip/
│   ├── domain/
│   ├── url/
│   └── hash/
├── reports/
└── automation/
    ├── collectors/
    └── telegram/
```

## Goal

The goal of this project is to transform external cybersecurity news into **actionable intelligence for the SOC**, rather than simply collecting news.

> **Collect → Analyze → Validate → Detect → Respond**

