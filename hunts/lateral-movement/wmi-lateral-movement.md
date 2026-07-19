# Hunt: WMI-based Lateral Movement

**ATT&CK Technique(s):** T1047 (Windows Management Instrumentation), T1021 (Remote Services)
**Status:** Draft
**Author:** <you>
**Last updated:** <date>

## 1. Hypothesis

Adversaries are using WMI (`WmiPrvSE.exe` spawning child processes) to execute
commands on remote hosts as a lateral movement technique, in order to evade
detections tuned narrowly around PsExec and RDP-based lateral movement.

## 2. Rationale

WMI lateral movement is well-documented in red team tooling (Impacket's
`wmiexec.py`, Empire, Cobalt Strike's `jump wmi_exec`) and leaves fewer
artifacts than PsExec (no service creation event, no new binary dropped in
most cases). Many environments have strong PsExec/service-creation detections
but nothing tuned for WMI process spawning specifically — this hunt targets
that gap.

## 3. Data sources required

| Source | Fields needed | Why |
|---|---|---|
| Sysmon Event ID 1 | ParentImage, Image, CommandLine, User | Identify processes spawned by WmiPrvSE.exe |
| Windows Security 4688 | ParentProcessName, NewProcessName, CommandLine | Fallback if Sysmon not deployed |
| Windows Security 4624/4625 | LogonType, IpAddress | Correlate logon type 3 (network) around the same time |

## 4. Hunt queries

### Sigma (portable)
```yaml
title: Process Spawned by WMI
status: experimental
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    ParentImage|endswith: '\WmiPrvSE.exe'
  filter_known_mgmt:
    Image|endswith:
      - '\SCNotification.exe'
      - '\ccmexec.exe'
  condition: selection and not filter_known_mgmt
```

### Splunk (SPL)
```
index=sysmon EventCode=1 ParentImage="*WmiPrvSE.exe"
| where NOT match(Image, "(?i)(sccm|ccmexec|scnotification)")
| table _time, host, User, Image, CommandLine
| sort -_time
```

### KQL (Sentinel/Defender)
```kql
DeviceProcessEvents
| where InitiatingProcessFileName =~ "WmiPrvSE.exe"
| where FileName !in~ ("ccmexec.exe", "scnotification.exe")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
```

## 5. Expected legitimate activity

SCCM/ConfigMgr, monitoring agents (e.g. Nagios, SolarWinds), and some backup
software use WMI heavily and will dominate raw results. Building an allowlist
of known management server hostnames/IPs is essential before this hunt is
usable at any scale — start narrow (exclude only confirmed management
infra) rather than broad, so real positives aren't filtered out.

## 6. Validation steps

1. Pull full process tree for the flagged host/timestamp
2. Check whether the source of the WMI call (the "remote" side) is a known
   admin workstation or jump box
3. Look for follow-on activity: new files written, outbound connections,
   credential access indicators
4. Check the account used — service account vs. interactive user, and
   whether that account normally touches that host
5. If unexplained, escalate to IR with the process tree and logon
   correlation as supporting evidence

## 7. Outcome / findings

*(Fill in after running against real or lab data — e.g. "Ran across 30 days
of lab data seeded with Impacket wmiexec activity; hunt caught the seeded
activity with zero false positives after excluding SCCM. Ready to promote
to a standing detection.")*

## 8. Detection follow-up

*(Once validated: note the Sigma rule filename in `queries/sigma/` this was
promoted to.)*
