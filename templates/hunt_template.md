# Hunt: <short descriptive name>

**ATT&CK Technique(s):** T####（sub-technique if applicable）
**Status:** Draft / Validated / Promoted to detection
**Author:** Aaron Thummel
**Last updated:** <date>

## 1. Hypothesis

State the specific adversary behavior in one or two sentences. Be concrete —
"attackers might do bad things" is not a hypothesis. "Adversaries are using
WMI process creation (T1047) to move laterally and execute payloads on
remote hosts, bypassing PSExec-focused detections" is.

## 2. Rationale

Why is this worth hunting for right now? Options:
- Threat intel report / advisory referencing this TTP
- Known detection gap (existing rules only cover technique variant X, not Y)
- Prevalence in recent incidents (industry-wide or internal)
- Red team / pentest finding that this path is viable in your environment

## 3. Data sources required

| Source | Fields needed | Why |
|---|---|---|
| e.g. Sysmon Event ID 1 | ParentImage, Image, CommandLine | Detect WMI spawning suspicious children |
| e.g. Windows Security 4688 | ProcessName, CommandLine | Backup if Sysmon unavailable |

## 4. Hunt queries

### Sigma (portable)
```yaml
title: <title>
status: experimental
logsource:
  category: process_creation
detection:
  selection:
    ParentImage|endswith: '\WmiPrvSE.exe'
  condition: selection
```

### Splunk (SPL)
```
index=sysmon EventCode=1 ParentImage="*WmiPrvSE.exe"
| table _time, host, Image, CommandLine
```

### KQL (Sentinel/Defender)
```kql
DeviceProcessEvents
| where InitiatingProcessFileName =~ "WmiPrvSE.exe"
```

## 5. Expected legitimate activity

Document what normal matches look like so you can build allowlist logic —
e.g. "SCCM, monitoring agents, and backup software routinely spawn child
processes via WMI; filter on known management server IPs/hostnames."

## 6. Validation steps

1. Pivot on host + timestamp to pull full process tree
2. Check parent process reputation / signing
3. Check for network connections or file writes immediately following
4. Cross-reference source host against asset inventory (is it a known
   admin workstation or management server?)
5. Escalate to IR if unexplained

## 7. Outcome / findings

Write up what actually happened when you ran this — even a negative
result ("ran across 90 days of data, zero true positives, confirms low
prevalence in this environment") is a valid and useful outcome to record.

## 8. Detection follow-up

If this hunt surfaced a repeatable, tunable pattern: promote the query to
`queries/sigma/` as a standing detection and note the Sigma rule filename
here for traceability.
