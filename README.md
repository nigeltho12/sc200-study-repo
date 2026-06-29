# SC-200: Microsoft Security Operations Analyst — Study Repo

> Personal study notes, lab walkthroughs, and KQL references for the SC-200 certification.  
> Built alongside a hands-on **Azure E5 tenant + Azure subscription** lab environment.

[![SC-200](https://img.shields.io/badge/Exam-SC--200-0078D4?style=for-the-badge&logo=Microsoft&logoColor=white)](https://learn.microsoft.com/en-us/certifications/exams/sc-200/)
[![Status](https://img.shields.io/badge/Status-In%20Progress-yellow?style=for-the-badge)]()
[![Environment](https://img.shields.io/badge/Lab-Azure%20E5%20Tenant-0078D4?style=for-the-badge&logo=MicrosoftAzure&logoColor=white)]()

---

## Repo Structure

```
sc200-study-repo/
├── README.md                  ← You are here
├── docs/
│   └── course-overview.md     ← Module map, exam domain weights, environment setup
├── labs/
│   ├── lab-template.md        ← Blank lab journal entry (copy per module)
│   ├── module-01.md           ← Defender XDR Settings
│   ├── module-02.md           ← Managing Assets & Environments
│   ├── module-03.md           ← Sentinel Workspace Design
│   ├── module-04.md           ← Data Ingestion
│   ├── module-05.md           ← Defender Protections
│   ├── module-06.md           ← Defender XDR Detections
│   ├── module-07.md           ← Sentinel Detections
│   ├── module-08.md           ← XDR Incident Response
│   ├── module-09.md           ← MDE Incident Response
│   ├── module-10.md           ← Enriching Investigations
│   ├── module-11.md           ← Sentinel Incident Management
│   ├── module-12.md           ← SOAR / Playbooks
│   ├── module-13.md           ← Threat Hunting (KQL)
│   ├── module-14.md           ← Workbooks
│   └── module-15.md           ← Copilot for Security
├── kql/
│   ├── windows-security-events.kql
│   ├── linux-syslog.kql
│   ├── mde-advanced-hunting.kql
│   └── sentinel-incidents-alerts.kql
└── notes/
    ├── exam-prep.md           ← Domain weights, key concepts, exam tips
    └── purple-team-angles.md  ← Offensive context mapped to detections
```

---

## About This Repo

This is my active study journal for the **SC-200** exam — the Microsoft Security Operations Analyst certification. I'm going through it with full hands-on lab coverage using:

- **Microsoft 365 E5 Developer Tenant** (90-day renewable)
- **Azure Pay-as-you-go subscription** for Sentinel + VMs
- Microsoft Defender XDR, Sentinel, MDE, MDO, MDI, MDCA, Copilot for Security

Every module has a corresponding lab entry in `/labs/` documenting what I built, what I broke, and what I learned. The KQL folder is my running query cheatsheet.

---

## Module Progress

| # | Module | Course | Lab | Date |
|---|--------|:------:|:---:|------|
| 01 | Configuring Microsoft Defender XDR Settings | ⬜ | ⬜ | |
| 02 | Managing Assets and Environments | ⬜ | ⬜ | |
| 03 | Designing and Configuring a Microsoft Sentinel Workspace | ⬜ | ⬜ | |
| 04 | Ingesting Data Sources in Microsoft Sentinel | ⬜ | ⬜ | |
| 05 | Configuring Protections in Microsoft Defender Security Technologies | ⬜ | ⬜ | |
| 06 | Configuring Detection in Microsoft Defender XDR | ⬜ | ⬜ | |
| 07 | Configuring Detections in Microsoft Sentinel | ⬜ | ⬜ | |
| 08 | Responding to Alerts and Incidents in Microsoft Defender XDR | ⬜ | ⬜ | |
| 09 | Responding to Alerts and Incidents in Defender for Endpoint | ⬜ | ⬜ | |
| 10 | Enriching Investigations Using Other Microsoft Tools | ⬜ | ⬜ | |
| 11 | Managing Incidents in Microsoft Sentinel | ⬜ | ⬜ | |
| 12 | Configuring SOAR in Microsoft Sentinel | ⬜ | ⬜ | |
| 13 | Hunting for Threats Using KQL and Microsoft Sentinel | ⬜ | ⬜ | |
| 14 | Analyzing and Interpreting Data Using Workbooks | ⬜ | ⬜ | |
| 15 | Implementing and Using Copilot for Security | ⬜ | ⬜ | |

---

## Related Repos

| Repo | Description |
|------|-------------|
| [Agentic AI SOC Analyst](https://github.com/nigeltho12/Agentic_Soc_AI) | AI-driven SOC simulation agent (Python + LLM + Azure Log Analytics) |
| [Honeynet in Azure](https://github.com/nigeltho12/Honeynet-in-Azure) | Live attack traffic analysis with Microsoft Sentinel |
| [KQL Threat Hunting](https://github.com/nigeltho12/ThreatHuntScenarios-CyberRange) | Detection engineering exercises from the LOG(N) cyber range |
| [BTL1 Reference Repo](https://github.com/nigeltho12/btl1-repo) | Post-exam reference: phishing, DFIR, Splunk, IR |
| [eJPT Study Repo](https://github.com/nigeltho12/ejpt-study-repo) | Offensive security study notes (eJPT v2) |

---

## Certifications

<div>
<img src="https://img.shields.io/badge/-Security%2B-FF0000?&style=for-the-badge&logo=CompTIA&logoColor=white" />
<img src="https://img.shields.io/badge/-Network%2B-007ACC?&style=for-the-badge&logo=CompTIA&logoColor=white" />
<img src="https://img.shields.io/badge/-BTL1-1E3A8A?&style=for-the-badge" />
<img src="https://img.shields.io/badge/-eJPT_v2-8B0000?&style=for-the-badge" />
<img src="https://img.shields.io/badge/-ISC2_CC-000080?&style=for-the-badge" />
<img src="https://img.shields.io/badge/-SC200_In%20Progress-0078D4?&style=for-the-badge&logo=Microsoft&logoColor=white" />
</div>

---

*Connect: [LinkedIn](https://www.linkedin.com/in/nigel-t-8a7995244/) | [GitHub](https://github.com/nigeltho12)*
