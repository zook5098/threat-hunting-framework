# Hunt: New Scheduled Task Persistence Outside Baseline

**ATT&CK Technique(s):** T1053.005 (Scheduled Task/Job: Scheduled Task)
**Status:** Validated (lab data)
**Author:** <you>
**Last updated:** 2026-07-19

## 1. Hypothesis

Adversaries are creating new scheduled tasks — via `schtasks.exe`, PowerShell's
`New-ScheduledTask`, or direct calls to the Task Scheduler COM API — whose
action points at a staged binary/script outside standard install locations
(`\Users\Public\`, `\AppData\Local\Temp\`, `\ProgramData\`) or invokes
PowerShell with encoded/hidden-window flags, in order to establish
persistence that survives reboot without touching a Run key or installing a
new service (both of which are far more commonly monitored).

## 2. Rationale

Scheduled tasks are a native, dual-use OS feature — nearly every machine has
dozens of legitimate ones (software updaters, backup agents, SCCM). That
volume of "normal" noise is exactly why it's an attractive persistence
mechanism: task-creation events get ignored wholesale rather than baselined.
Documented in the wild by APT29, FIN7, and most red team frameworks
(Cobalt Strike, Covenant) as a standard fallback when service creation is
being watched. Most environments alert on new services and new Run-key
values but have no rule at all for "a new scheduled task pointing somewhere
it shouldn't be."

## 3. Data sources required

| Source | Fields needed | Why |
|---|---|---|
| Windows Security 4698 (A scheduled task was created) | TaskName, TaskContent (XML: Command, Arguments, Triggers), SubjectUserName, host | Core signal — full task definition captured at creation time |
| Microsoft-Windows-TaskScheduler/Operational 106 | TaskName, UserContext | Fallback if Security auditing for 4698 isn't enabled |
| Sysmon Event ID 1 | ParentImage, Image, CommandLine | Catches `schtasks.exe /create` invocation directly as a secondary signal |
| Baseline scheduled task inventory (gold image `schtasks /query /v` or CMDB) | TaskName, Command, Author | Needed to know what's normal per host role — without this, every finding requires re-deriving the baseline by hand |

## 4. Hunt queries

### Sigma (portable)
```yaml
title: Suspicious Scheduled Task Creation
status: experimental
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4698
  suspicious_content:
    TaskContent|contains:
      - '\Users\Public\'
      - '\AppData\Local\Temp\'
      - '\ProgramData\'
      - '-enc '
      - '-EncodedCommand'
      - '-w hidden'
      - '-windowstyle hidden'
  condition: selection and suspicious_content
level: high
```

### Splunk (SPL)
```
index=wineventlog EventCode=4698
| rex field=TaskContent "(?i)<Command>(?<command>[^<]+)</Command>"
| rex field=TaskContent "(?i)<Arguments>(?<arguments>[^<]*)</Arguments>"
| eval task_content=command." ".arguments
| where match(task_content, "(?i)(\\\\users\\\\public\\\\|\\\\appdata\\\\local\\\\temp\\\\|\\\\programdata\\\\|-enc |-encodedcommand|-w hidden|-windowstyle hidden)")
| table _time, host, Subject_User_Name, Task_Name, command, arguments
```

### KQL (Sentinel/Defender)
```kql
DeviceEvents
| where ActionType == "ScheduledTaskCreated"
| extend TaskContent = tostring(parse_json(AdditionalFields).TaskContent)
| where TaskContent has_any (
    @"\Users\Public\", @"\AppData\Local\Temp\", @"\ProgramData\",
    "-enc ", "-EncodedCommand", "-w hidden", "-windowstyle hidden")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, TaskContent
```

## 5. Expected legitimate activity

- Software updaters (Google Update, Adobe AAM, Microsoft Edge Update,
  Dropbox Update, OneDrive) all register scheduled tasks under `SYSTEM`
  pointing to signed binaries in `Program Files` / `Program Files (x86)`.
  These dominate raw 4698 volume and should never match this filter, since
  their paths and arguments contain none of the flagged substrings.
- Backup software and SCCM/ConfigMgr routinely create their own scheduled
  tasks (e.g. hardware inventory cycles, backup jobs) — same pattern,
  signed binary, standard install path.
- Internal IT/deployment scripts run via `powershell.exe -ExecutionPolicy
  Bypass -File "C:\Program Files\...\script.ps1"` are common and should
  **not** trigger this rule — `-ExecutionPolicy Bypass` alone is not in the
  suspicious-flag list. Only encoded (`-enc`/`-EncodedCommand`) or
  hidden-window (`-w hidden`/`-windowstyle hidden`) invocations are flagged,
  specifically to avoid false-positiving on ordinary deployment tooling
  that happens to bypass execution policy from a legitimate, signed,
  Program-Files-hosted script.

## 6. Validation steps

1. Pull the full task XML: command, arguments, trigger type (logon, daily,
   boot), configured run-as account, and whether the "Hidden" flag is set.
2. Check the referenced binary/script path — signed binary under
   `Program Files` (likely benign) vs. unsigned/staged file in `Temp`,
   `AppData`, `ProgramData`, or `Public` (suspicious).
3. Check `SubjectUserName` — does this account normally have rights to
   create tasks on this host? A task created under `SYSTEM` context by a
   push mechanism (PsExec, WMI, GPO) from an account that doesn't normally
   administer that host is a privilege-escalation/lateral-movement
   indicator, not just persistence.
4. Compare `TaskName` against a masquerade pattern — does it borrow a
   legitimate-sounding name (`OneDriveSyncHelper`, `WindowsDefenderUpdateCheck`)
   while pointing to a non-standard path? Name similarity to a real vendor
   task without matching its actual install location is a strong signal.
5. If the task has since run, pull the resulting process tree (Task
   Scheduler Operational log Event ID 200/201) to see what it actually
   executed.
6. Cross-reference `TaskName` + path against the baseline inventory (gold
   image / CMDB) — is this task present on other hosts of the same role,
   or unique to this one?
7. Escalate to IR with the task XML, creating account, and host if
   unexplained.

## 7. Outcome / findings

Ran against a synthetic lab dataset (`lab_data/scheduled_task_events.jsonl`,
15 simulated 4698 events) using `lab_data/run_hunt.py`, which reimplements
the Sigma content-match logic since there's no live SIEM behind this repo.

- 12 of 15 events were legitimate updater/backup/SCCM tasks under `SYSTEM`,
  all pointing to signed binaries under `Program Files` or `Windows\CCM` —
  none matched the filter, as expected.
- One near-miss, included deliberately: a `CompanyIT-InventoryScript` task
  running `powershell.exe -ExecutionPolicy Bypass -File "C:\Program
  Files\CompanyIT\Scripts\Inventory.ps1"`. This correctly did **not** match
  — it confirms the decision in section 5 to key off encoded/hidden-window
  flags specifically rather than any PowerShell invocation or the word
  "bypass", which would have buried this hunt in internal deployment-script
  noise.
- 3 hits, each triggering via a different signal (showing the rule catches
  more than one variant of the same technique, not just one pattern):
  - `WKSTN-044`: `OneDriveSyncHelper` (masquerading name) running
    `powershell.exe -nop -w hidden -enc <base64>` under `SYSTEM`, trigger
    `AtLogon` — flagged on the hidden-window + encoded-command flags.
  - `SRV-WEB02`: `WindowsDefenderUpdateCheck` (masquerading name) running a
    binary staged at `C:\ProgramData\Microsoft\WindowsUpdt\svchost.exe`
    (note: **not** the real `svchost.exe` path), trigger `Daily` — flagged
    on the `\ProgramData\` path.
  - `SRV-APP01`: `Adobe Flash Update` running
    `C:\Users\Public\flashupdt.exe`, created by `jturner` (a helpdesk
    account with no normal admin relationship to that server), trigger
    `AtStartup` — flagged on the `\Users\Public\` path, and the creating
    account is itself worth escalating per validation step 3.
- Zero false positives, including against the deliberate near-miss. All
  three seeded persistence tasks were caught, each via a distinct
  sub-pattern of the same technique.

**Caveat:** this is a single-event content-match rule (unlike the
volume/aggregation approach used for the Kerberoasting hunt) — it depends
entirely on the malicious task's command/arguments containing one of a
known-bad set of substrings. A more careful adversary who stages their
payload under a legitimate-looking `Program Files` subdirectory and invokes
a plain (non-encoded, non-hidden) command would not be caught by this rule
as written. Production tuning should add the masquerade-name-vs-path
mismatch check from validation step 4 as a second, complementary detection
rather than relying on path/flag matching alone.

## 8. Detection follow-up

Promoted to `queries/sigma/scheduled_task_suspicious_content.yml` (status
`experimental` — should run in monitor mode against real 4698 data long
enough to confirm the updater/backup/SCCM baseline holds across the full
fleet before promoting to `stable`).
