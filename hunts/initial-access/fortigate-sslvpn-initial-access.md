# Hunt: Initial Access via FortiGate SSL-VPN (Credential Stuffing → Admin Pivot)

**ATT&CK Technique(s):** T1190 (Exploit Public-Facing Application), T1133 (External Remote Services), T1110.004 (Brute Force: Credential Stuffing), T1078 (Valid Accounts)
**Status:** Validated (lab data)
**Author:** Aaron Thummel
**Last updated:** 2026-07-19

## 1. Hypothesis

Adversaries are gaining initial access through an internet-facing FortiGate
SSL-VPN portal — either by credential-stuffing/brute-forcing valid VPN
accounts, or by exploiting one of the FortiOS SSL-VPN pre-auth RCE
vulnerabilities disclosed since 2022 — and are using that foothold to log
into the FortiGate's own admin interface and create a persistent local admin
account, rather than only pivoting into the internal network. This hunt
targets the authentication and immediate post-auth administrative telemetry
that both entry paths leave behind on the FortiGate itself.

## 2. Rationale

FortiGate SSL-VPN has had a sustained run of critical pre-auth RCE
vulnerabilities — CVE-2022-42475, CVE-2023-27997 ("XORtigate"), and
CVE-2024-21762 — each added to CISA's Known Exploited Vulnerabilities
catalog within days of disclosure, and each used in the wild by ransomware
access brokers and state-linked actors to gain a foothold on unpatched edge
devices. Separately, SSL-VPN portals are a constant credential-stuffing
target since they're internet-reachable by design and often protected by
password alone. Both paths matter for the same reason: the FortiGate is
usually the perimeter and the least-instrumented device in the environment
— no EDR, no Sysmon, often not even fully forwarded to the SIEM — so an
intrusion that starts there is frequently first (and sometimes only)
visible in the device's own VPN and admin logs. Most environments watch
FortiGate traffic logs for allow/deny volume but don't correlate
authentication anomalies with what happens on the admin plane immediately
afterward, which is exactly where this kind of intrusion becomes
unambiguous.

## 3. Data sources required

| Source | Fields needed | Why |
|---|---|---|
| FortiGate VPN event log (`type=event subtype=vpn`) | eventtime, action (`ssl-login-fail`/`tunnel-up`), user, srcip, reason | Detect credential-stuffing bursts and the resulting successful logins |
| FortiGate system/admin event log (`type=event subtype=system`) | eventtime, action (`login`/`logout`/`config-change`), user, srcip, ui, cfgpath, cfgobj | Detect admin-plane logins and config changes following a suspicious VPN session |
| FortiGate traffic log (`type=traffic`) | srcip, dstip, dstport, policyid, action | Secondary signal: anomalous outbound connections originating from the FortiGate's own management interface (out of scope for this hunt's lab validation, noted as follow-on) |
| FortiGuard PSIRT advisories / current FortiOS build in use | CVE ID, affected build range | Context for whether the deployed FortiOS build is exposed to a known pre-auth RCE — changes the urgency of any finding |

## 4. Hunt queries

### Sigma (portable)
```yaml
title: FortiGate SSL-VPN Credential Stuffing Burst
status: experimental
logsource:
  product: fortios
  service: vpn
detection:
  selection:
    subtype: vpn
    action: ssl-login-fail
  timeframe: 10m
  condition: selection | count(user) by srcip > 5
level: high
```

### Splunk (SPL)
```
index=fortigate subtype=vpn action=ssl-login-fail
| bucket _time span=10m
| stats dc(user) as distinct_users values(user) as usernames_tried by _time, srcip
| where distinct_users > 5
| sort -distinct_users
```

### KQL (Sentinel/Defender, via CEF/Syslog connector)
```kql
CommonSecurityLog
| where DeviceVendor == "Fortinet" and DeviceEventClassID == "ssl-login-fail"
| summarize DistinctUsers = dcount(SourceUserName), UsersTried = make_set(SourceUserName)
      by SourceIP, bin(TimeGenerated, 10m)
| where DistinctUsers > 5
| order by DistinctUsers desc
```

## 5. Expected legitimate activity

- A single failed login followed by a success from the same source IP and
  user is normal (typo, expired password re-entry) — the hunt keys on
  **distinct usernames per source IP**, not raw failure count, specifically
  so one user's bad typing doesn't trigger it.
- IT admin logins to the GUI/SSH admin interface and any resulting
  `config-change` events are expected from known management source IPs
  (the internal jump box) — baseline and allowlist these explicitly. An
  admin login or config change from any *other* source IP is the higher-value
  signal this hunt is built to surface, not admin activity in general.
- MSP/vendor remote support sessions, if any are contracted, should be
  documented and allowlisted by source IP the same way as internal admins —
  otherwise every support ticket becomes a false positive.

## 6. Validation steps

1. Pull every VPN and system log entry for the flagged source IP, in
   chronological order, to build the full timeline from first failed login
   through any admin action.
2. Check the account that ultimately succeeded — is it an actively used
   human account, or a stale/legacy/service account that shouldn't have
   interactive SSL-VPN access at all? (The latter is a hygiene finding in
   its own right, independent of whether this specific event is malicious.)
3. Check the current FortiOS build against known SSL-VPN pre-auth RCE CVEs
   (CVE-2022-42475, CVE-2023-27997, CVE-2024-21762). If the build is
   vulnerable, treat the finding with elevated urgency — and note that on a
   truly pre-auth exploit path, there may be **no** corresponding failed/
   successful login event at all, since the attacker never went through
   normal authentication (see caveat in section 7).
4. Check source IP reputation (hosting provider, Tor exit, known scanning
   infrastructure) via threat intel.
5. If any admin-plane login or config change followed from the flagged
   source IP, treat as a confirmed incident immediately: disable any newly
   created admin account, force-reset the credentials of the account used to
   authenticate, and pull a config diff/backup comparison to check for other
   changes (firewall policy edits, logging disabled, new API keys/SNMP
   community strings).
6. Escalate to IR with the full authentication timeline and config-change
   diff as supporting evidence.

## 7. Outcome / findings

Ran against a synthetic lab dataset (`lab_data/fortigate_events.jsonl`, 29
simulated FortiGate VPN/system log events across a business day) using
`lab_data/run_hunt.py`, which reimplements the Sigma aggregation logic
(10-minute bucket, distinct-username count per source IP) plus the
follow-on admin-pivot correlation described in section 6, since there's no
live SIEM behind this repo.

- 17 of 29 events were normal activity: SSL-VPN logins from 6 recurring
  employee source IPs (including three ordinary single-fail-then-success
  patterns — a typo, not a burst) and two legitimate admin sessions from
  the known jump box IP (`10.10.1.5`), each performing a routine config
  change. None of this matched the burst threshold or the "admin action
  from an unallowlisted IP" check.
- One source IP, `185.220.101.7`, attempted SSL-VPN logins against **8
  distinct usernames within a 3-minute window** (`jdoe`, `msmith`,
  `administrator`, `admin`, `test`, `backup`, `guest`, `svc_vpn`) — a
  textbook credential-stuffing/username-spray pattern, well over the
  5-distinct-username threshold.
- The 8th attempt, against `svc_vpn` (a legacy service account with
  standing SSL-VPN access), succeeded roughly 15 seconds after its own
  failed first attempt.
- ~90 seconds after that VPN success, the *same account* (`svc_vpn`) logged
  into the FortiGate's **admin GUI** — from the same external source IP —
  which is itself anomalous: this account had SSL-VPN access, not admin
  rights, as a matter of course, so an admin-plane login from it at all is
  a hard flag regardless of source IP.
- Within the next 90 seconds, two config-change events fired under that
  same suspicious admin session: a new local admin account (`svc_maint`)
  and a modified firewall policy — the persistence and likely
  follow-on-access mechanisms.
- Zero false positives. The hunt correctly ignored all legitimate admin
  activity from the known jump box and flagged the full attack chain from
  first credential-stuffing attempt through backdoor account creation.

**Caveat — the most important one in this hunt:** this entire detection
strategy is authentication-log-based. It assumes the attacker went through
the normal login flow, which is true for credential stuffing but **not**
necessarily true for the pre-auth RCE CVEs referenced in section 2 — a
successful heap-overflow or auth-bypass exploit may generate no VPN
login-failure/success event pattern at all, since it never calls the normal
authentication path. This hunt should be treated as one layer covering the
credential-based initial-access path, not a substitute for patch
management or host/process-level forensics on the FortiGate appliance
itself for the RCE path. That gap is a real limitation, not just a caveat
for completeness — it's the reason this hunt's outcome should never be read
as "this environment is safe from FortiGate SSL-VPN exploitation."

## 8. Detection follow-up

Promoted the credential-stuffing burst detector to
`queries/sigma/fortigate_sslvpn_credential_stuffing.yml` (status
`experimental`). The full multi-stage correlation (burst → success → admin
login → config change) is intentionally *not* promoted as a single Sigma
rule — that kind of cross-log, multi-step correlation belongs in a SIEM
correlation search/notebook rather than a single detection signature, and
should be built directly against real FortiGate log output rather than this
lab's simplified JSON field names.
