# Purple Team Angles — SC-200

> Mapping SC-200 detection topics to their offensive counterparts.  
> Use this to reinforce the "why" behind each detection and build OSCP-adjacent intuition.

---

## The Purple Team Mindset

SC-200 teaches you to *detect* — purple teaming asks you to also understand *what you're detecting* and *why it works*.  
Every detection rule you build should trace back to a real attack technique.

---

## Detection → Attack Mapping

### Initial Access

| Detection (SC-200) | Offensive Technique | MITRE | KQL Hunt |
|-------------------|---------------------|-------|----------|
| Phishing email alert (MDO) | Spearphishing attachment / link | T1566 | `EmailEvents \| where ThreatTypes has "Phish"` |
| OAuth app consent alert | OAuth phishing (consent grant attack) | T1528 | `AuditLogs \| where OperationName has "Consent to application"` |
| Legacy auth sign-in | Password spray via legacy protocols (SMTP, IMAP) | T1110.003 | `SigninLogs \| where ClientAppUsed has "IMAP"` |

---

### Execution

| Detection (SC-200) | Offensive Technique | MITRE | KQL Hunt |
|-------------------|---------------------|-------|----------|
| Encoded PowerShell in DeviceProcessEvents | PowerShell -EncodedCommand obfuscation | T1059.001 | `DeviceProcessEvents \| where ProcessCommandLine has "-enc"` |
| MSHTA execution | Living-Off-the-Land Binary (LOLBin) | T1218.005 | `DeviceProcessEvents \| where FileName =~ "mshta.exe"` |
| Office macro spawn shell | Malicious macro execution | T1137 | `DeviceProcessEvents \| where InitiatingProcessFileName has "winword"` |
| certutil.exe download | Certutil used to download payload | T1105 | `DeviceProcessEvents \| where ProcessCommandLine has "certutil" and has "urlcache"` |

---

### Persistence

| Detection (SC-200) | Offensive Technique | MITRE | KQL Hunt |
|-------------------|---------------------|-------|----------|
| Run key registry write | Registry Run key persistence | T1547.001 | `DeviceRegistryEvents \| where RegistryKey has "CurrentVersion\\Run"` |
| Scheduled task created (4698) | Scheduled task for persistence | T1053.005 | `SecurityEvent \| where EventID == 4698` |
| Service installed (7045) | New service for persistence | T1543.003 | `SecurityEvent \| where EventID == 7045` |
| WMI subscription | WMI event subscription | T1546.003 | `DeviceEvents \| where ActionType == "WmiBindEventFilterToConsumer"` |

---

### Privilege Escalation

| Detection (SC-200) | Offensive Technique | MITRE | KQL Hunt |
|-------------------|---------------------|-------|----------|
| Token impersonation alert | Token impersonation / theft | T1134 | `DeviceEvents \| where ActionType == "TokenImpersonation"` |
| Sudo abuse (Syslog) | Sudo exploitation on Linux | T1548.003 | `Syslog \| where SyslogMessage has "sudo"` |
| Admin group membership change (4732) | Local group membership manipulation | T1098 | `SecurityEvent \| where EventID == 4732` |

---

### Defense Evasion

| Detection (SC-200) | Offensive Technique | MITRE | KQL Hunt |
|-------------------|---------------------|-------|----------|
| Defender tamper protection alert | Disable or modify security tools | T1562.001 | `DeviceEvents \| where ActionType == "TamperingAttempt"` |
| ASR rule block | AMSI bypass / script block logging disabled | T1562.010 | `DeviceEvents \| where ActionType startswith "Asr"` |
| Registry DisableRealtimeMonitoring | Defender AV disabled via registry | T1562.001 | `DeviceRegistryEvents \| where RegistryValueName has "DisableRealtime"` |

---

### Credential Access

| Detection (SC-200) | Offensive Technique | MITRE | KQL Hunt |
|-------------------|---------------------|-------|----------|
| LSASS access alert (MDE) | LSASS memory credential dumping | T1003.001 | `DeviceEvents \| where ActionType == "CreateRemoteThreadApiCall" \| where FileName == "lsass.exe"` |
| Failed logon spike (4625) | Password brute force / spray | T1110 | `SecurityEvent \| where EventID == 4625 \| summarize count() by Account` |
| Kerberoasting (MDI alert) | SPN enumeration + ticket request | T1558.003 | Alert from MDI: "Kerberos service ticket requested suspiciously" |
| Pass-the-Hash (MDI alert) | NTLM hash reuse for lateral movement | T1550.002 | `IdentityLogonEvents \| where Protocol == "Ntlm" \| where LogonType == "Network"` |

---

### Discovery

| Detection (SC-200) | Offensive Technique | MITRE | KQL Hunt |
|-------------------|---------------------|-------|----------|
| Net.exe / whoami after cmd.exe | Local/domain enumeration | T1087 | `DeviceProcessEvents \| where InitiatingProcessFileName == "cmd.exe" \| where FileName has_any ("net.exe","whoami.exe")` |
| Port scan detection (network events) | Network service scanning | T1046 | `DeviceNetworkEvents \| summarize dcount(RemotePort) by DeviceName, RemoteIP \| where dcount_RemotePort > 20` |
| ipconfig / nslookup / systeminfo | Host/network discovery | T1016/T1082 | `DeviceProcessEvents \| where FileName has_any ("ipconfig","nslookup","systeminfo")` |

---

### Lateral Movement

| Detection (SC-200) | Offensive Technique | MITRE | KQL Hunt |
|-------------------|---------------------|-------|----------|
| Remote service creation | PSExec / remote service abuse | T1021.002 | `SecurityEvent \| where EventID == 7045 \| where Computer != "source-machine"` |
| WMI remote execution | WMI lateral movement | T1021.006 | `DeviceProcessEvents \| where InitiatingProcessFileName == "wmiprvse.exe"` |
| RDP logon from internal host | Remote Desktop lateral movement | T1021.001 | `SecurityEvent \| where EventID == 4624 \| where LogonType == 10` |

---

### Command & Control

| Detection (SC-200) | Offensive Technique | MITRE | KQL Hunt |
|-------------------|---------------------|-------|----------|
| Outbound connection on unusual port | C2 over non-standard port | T1571 | `DeviceNetworkEvents \| where RemotePort in (4444,1337,8080,9001)` |
| Beacon-like periodic connections | Scheduled C2 beaconing | T1071 | `DeviceNetworkEvents \| summarize count() by RemoteIP, bin(Timestamp, 5m) \| where count_ == 1` |
| DNS to suspicious TLD | DNS C2 / DGA domains | T1568 | `DeviceNetworkEvents \| where RemoteUrl has_any (".xyz",".tk",".top")` |

---

## How to Use This File

1. When you build a Sentinel analytics rule, find the matching row here
2. Add the MITRE technique ID to the rule's mapping
3. Note the offensive tool or technique that would trigger it (Metasploit module, manual command, etc.)
4. Cross-reference with your eJPT/OSCP notes for the attacker-side methodology

---

*This file grows as you work through the SC-200 modules. Add a row every time a lab produces an interesting detection.*
