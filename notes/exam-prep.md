# SC-200 Exam Prep Notes

## Exam Domain Weights

| Domain | Weight | Priority |
|--------|--------|----------|
| Mitigate threats using Microsoft Sentinel | 50–55% | 🔴 HIGH |
| Mitigate threats using Microsoft Defender XDR | 25–30% | 🟠 MEDIUM |
| Mitigate threats using Microsoft Defender for Cloud | 20–25% | 🟡 MEDIUM |

---

## Sentinel — Concepts to Lock In

### Analytics Rule Types
| Type | Description | When to Use |
|------|-------------|-------------|
| **Scheduled** | KQL runs on a schedule (5 min–14 days) | Most custom detections |
| **NRT (Near Real-Time)** | Runs ~every 1 min, 1-min lookback | High-priority, low-latency detections |
| **Microsoft Security** | Imports alerts from other Defender products | Ingesting MDE/MDO/MDI alerts |
| **Fusion** | ML-based multi-stage attack correlation | Advanced persistent threat scenarios |
| **Anomaly** | Behavior baseline + deviation detection | UEBA-type detections |
| **Threat Intelligence** | Matches IOCs from TI feeds | IP/domain/hash correlation |

### Data Connector Types
| Type | Examples | Notes |
|------|----------|-------|
| **Native / Service-to-Service** | M365, Azure AD, MDE | One-click, no agent |
| **API-based** | AWS CloudTrail, Okta | Requires API key / connector config |
| **Agent-based (AMA)** | Windows Events, Syslog | Azure Monitor Agent (current preferred) |
| **Agent-based (MMA)** | Legacy Windows/Linux | Legacy Log Analytics agent |
| **CEF via Syslog** | Fortinet, Palo Alto, CheckPoint | Syslog forwarder → Linux proxy → Sentinel |
| **Logstash** | Custom pipelines | Flexible, requires maintenance |

### RBAC Roles (Know the Difference)
| Role | Permissions |
|------|------------|
| **Sentinel Reader** | Read incidents, workbooks, analytics rules |
| **Sentinel Responder** | Reader + manage incidents (assign, comment, close) |
| **Sentinel Contributor** | Responder + create/edit analytics rules, playbooks, workbooks |
| **Sentinel Automation Contributor** | Create/edit automation rules and playbooks |

### Automation — Automation Rules vs. Playbooks
- **Automation Rules** run first, automatically, on incident/alert creation or update
- **Playbooks** (Logic Apps) are triggered BY automation rules or manually
- Automation rules can: assign, change status/severity, add tags, run a playbook
- Playbooks can: call APIs, send emails/Teams messages, enrich entities, create tickets

### Watchlists
- CSV-based lookup tables uploaded to Sentinel
- Used in analytics rules via `_GetWatchlist("WatchlistName")`
- Common uses: allow-lists, VIP user lists, malicious IP lists, asset inventories

### Threat Hunting Workflow
1. **Hypothesis** — What am I looking for? (MITRE ATT&CK tactic/technique)
2. **Query** — Write KQL against relevant tables
3. **Bookmark** — Save interesting findings with `Bookmarks`
4. **Promote** — Promote bookmarks to incidents or create detection rules

---

## Defender XDR — Concepts to Lock In

### Incident Correlation
- Defender XDR **automatically correlates alerts** from MDE, MDO, MDI, MDCA into unified incidents
- One incident = multiple alerts from multiple products
- The **Incident Graph** shows entity relationships across all correlated alerts

### Advanced Hunting Tables (MDE)
| Table | Contains |
|-------|---------|
| `DeviceProcessEvents` | Process creation, command lines |
| `DeviceNetworkEvents` | Network connections, DNS lookups |
| `DeviceFileEvents` | File created, modified, deleted |
| `DeviceRegistryEvents` | Registry changes |
| `DeviceLogonEvents` | Logon/logoff events |
| `DeviceEvents` | ASR blocks, tamper events, others |
| `EmailEvents` | Email metadata (MDO) |
| `IdentityLogonEvents` | Identity-based logon events (MDI) |

### Custom Detection Rules
- Built from **Advanced Hunting queries**
- Run every **1–24 hours** (scheduled)
- Can auto-**isolate devices**, **restrict app execution**, **flag users**
- Must output specific columns: `Timestamp`, `DeviceId` / `AccountObjectId` for entity mapping

### Response Actions Available in MDE
| Action | Scope |
|--------|-------|
| Isolate device | Cuts network except Defender comms |
| Restrict app execution | Only Microsoft-signed apps can run |
| Run AV scan | Full/quick scan triggered remotely |
| Collect investigation package | Forensic artifact collection |
| Initiate live response | Remote shell session |
| Block file hash | Global or device-level block |

---

## Defender for Cloud — Concepts to Lock In

- **Defender for Cloud** = CSPM (Cloud Security Posture Management) + CWPP (Cloud Workload Protection)
- **Secure Score** = % of security controls passed; higher = better posture
- **Security recommendations** = actionable hardening steps
- **Alerts** feed into Sentinel via the Defender for Cloud data connector
- **Regulatory Compliance** dashboard maps controls to standards (PCI DSS, NIST, CIS, SOC 2)
- **Defender Plans** per resource type: Servers, Containers, Databases, Storage, App Service, etc.

---

## KQL Must-Know Operators

| Operator | Purpose | Example |
|----------|---------|---------|
| `where` | Filter rows | `where EventID == 4625` |
| `summarize` | Aggregate | `summarize count() by Computer` |
| `extend` | Add calculated column | `extend Hour = bin(TimeGenerated, 1h)` |
| `project` | Select columns | `project TimeGenerated, Computer, EventID` |
| `join` | Join two tables | `Table1 \| join kind=inner Table2 on Key` |
| `mv-expand` | Expand dynamic arrays | `mv-expand Entities` |
| `parse_json` | Parse JSON field | `extend E = parse_json(Entities)` |
| `extract` | Regex extraction | `extract("user (\\w+)", 1, SyslogMessage)` |
| `has` | Case-insensitive string contains | `where Message has "failed"` |
| `has_any` | Contains any of | `where FileName has_any ("cmd.exe", "ps.exe")` |
| `render` | Visualize output | `render timechart` |
| `take` | Limit results | `take 10` |
| `sort by` | Order results | `sort by count_ desc` |
| `ago()` | Relative time | `where TimeGenerated > ago(7d)` |
| `bin()` | Round to interval | `bin(TimeGenerated, 1h)` |
| `dcount()` | Distinct count | `summarize dcount(Computer)` |
| `make_set()` | Unique values into array | `summarize make_set(IPAddress)` |

---

## Common Exam Traps

1. **NRT rules** have a max lookback of **1 minute** — don't confuse with Scheduled rules
2. **Automation rules run before playbooks** — they are evaluated first on every trigger
3. **MMA (legacy agent) vs AMA (new agent)** — exam questions may test when to use each
4. **Defender for Identity sensors** go on **Domain Controllers**, not endpoints
5. **Copilot for Security** is licensed separately via **SCUs (Security Compute Units)**, not M365
6. **CEF connectors** require a **Linux syslog forwarder** VM between the appliance and Sentinel
7. **Watchlist alias** in KQL is `_GetWatchlist("name")`, not a direct table reference
8. **Live Response** requires the device to be online and the MDE sensor running
9. **Fusion rules cannot be edited** — they are managed by Microsoft
10. **Incident severity in Sentinel** is set by analytics rules, not auto-calculated

---

## Resources

- [SC-200 Study Guide (Microsoft Learn)](https://learn.microsoft.com/en-us/certifications/exams/sc-200/)
- [Microsoft Sentinel Documentation](https://learn.microsoft.com/en-us/azure/sentinel/)
- [KQL Quick Reference](https://learn.microsoft.com/en-us/azure/data-explorer/kql-quick-reference)
- [Advanced Hunting Schema Reference](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-schema-tables)
- [MITRE ATT&CK](https://attack.mitre.org/)
- [John Savill's SC-200 Study Cram (YouTube)](https://www.youtube.com/results?search_query=SC-200+study+cram)
