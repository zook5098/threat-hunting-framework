# Hunt: WMI-based Lateral Movement

**ATT&CK Technique(s):** T1047 (Windows Management Instrumentation), T1021 (Remote Services)
**Status:** Validated (lab data)
**Author:** <you>
**Last updated:** 2026-07-19

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

Ran against a synthetic lab dataset (`lab_data/wmi_process_events.jsonl`, 15
process-creation events) using `lab_data/run_hunt.py`, which reimplements the
Sigma selection/filter logic since there's no live SIEM behind this repo.

- 12 of 15 events were WMI-spawned child processes.
- The known-mgmt filter (`ccmexec.exe`, `SCNotification.exe`) removed 6 SCCM
  events immediately, as expected from section 5.
- 6 hits remained. One (`WerFault.exe` on `SRV-MON02`) traced back to the
  monitoring server's source IP (`10.10.5.20`) and was benign — this is a
  legitimate-activity pattern not covered by the image-name filter alone,
  and confirms that image-name allowlisting isn't sufficient by itself;
  source-context (which host/IP initiated the WMI call) matters too.
- The remaining 5 hits were a single seeded chain: account `asmith` from
  `10.10.9.44` (a regular workstation, not a known admin jump box) spawning
  `cmd.exe`/`rundll32.exe` via WMI across three hosts in ascending order of
  sensitivity — `WKSTN-017` → `SRV-DB01` → `SRV-DC01` — ending with
  `vssadmin list shadows` on the domain controller (shadow-copy/backup
  reconnaissance, a common precursor to credential dumping or ransomware
  staging).
- Zero false positives after tuning. The hunt caught the full seeded chain
  and correctly separated it from SCCM and monitoring-agent noise.

**Caveat:** the lab dataset embeds `SourceIP` directly on the process-creation
event for convenience. In production this hunt requires joining Sysmon Event
ID 1 (or 4688) to a 4624 logon-type-3 event on time+host to get the true
initiating IP — that join is a real implementation detail, not just a filter
tweak, and should be validated against actual log data before relying on it.

## 8. Detection follow-up

Promoted to `queries/sigma/wmi_process_spawn.yml` (status bumped from
`experimental` to `stable`). Follow-up: extend the rule (or a paired
correlation search) to flag WMI-spawned processes whose initiating source IP
is *not* in a maintained allowlist of management/jump-box IPs, rather than
relying on image-name filtering alone — the `WerFault.exe`/monitoring-server
false-positive-that-almost-wasn't in this run is the reason why.
