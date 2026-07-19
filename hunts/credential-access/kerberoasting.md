# Hunt: Kerberoasting via Abnormal TGS Request Volume

**ATT&CK Technique(s):** T1558.003 (Steal or Forge Kerberos Tickets: Kerberoasting)
**Status:** Validated (lab data)
**Author:** <you>
**Last updated:** 2026-07-19

## 1. Hypothesis

Adversaries with any valid domain credential are requesting Kerberos service
tickets (TGS) for a large number of distinct SPNs in a short window, using
RC4 encryption, in order to harvest crackable ticket material for service
accounts (Kerberoasting) — rather than the noisy, single-target ticket
requests that make up normal service authentication.

## 2. Rationale

Kerberoasting requires no elevated privilege and no interactive logon to the
target — any authenticated domain account can request a TGS for any SPN, and
the KDC will happily hand over a ticket encrypted with the service account's
password hash. Tools like Rubeus (`kerberoast`) and Impacket's
`GetUserSPNs.py` automate requesting tickets for *every* SPN in the domain in
one pass, then crack them offline. Standard perimeter/endpoint detections
don't cover this because the activity is 100% domain-controller-side Kerberos
traffic — no process creation, no file drop, no network connection to the
victim host. Most environments have no detection for it at all beyond
"noticed the account got compromised after the fact."

## 3. Data sources required

| Source | Fields needed | Why |
|---|---|---|
| Windows Security 4769 (Kerberos Service Ticket Operations) | Account Name (requestor), Service Name, Ticket Encryption Type, Client Address, timestamp | Core signal: who requested a ticket for which SPN, with what encryption |
| Windows Security 4768 (TGT request) | Account Name, timestamp | Baseline of normal authentication volume per account |
| AD SPN inventory (`setspn -Q */*` or `Get-ADUser -Filter {ServicePrincipalName -ne "$null"}`) | Account, SPN | Needed to know how many *distinct* SPNs exist and which accounts are legitimately multi-service (backup/monitoring service accounts) |

## 4. Hunt queries

### Sigma (portable)
```yaml
title: Abnormal Volume of Kerberos TGS Requests (Kerberoasting)
status: experimental
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4769
    TicketEncryptionType: '0x17'
  timeframe: 10m
  condition: selection | count(ServiceName) by AccountName > 5
level: high
```

### Splunk (SPL)
```
index=wineventlog EventCode=4769 TicketEncryptionType=0x17
| bucket _time span=10m
| stats dc(ServiceName) as distinct_spns values(ServiceName) as services by _time, Account_Name, Client_Address
| where distinct_spns > 5
| sort -distinct_spns
```

### KQL (Sentinel/Defender)
```kql
SecurityEvent
| where EventID == 4769
| where TicketEncryptionType == "0x17"
| summarize DistinctSPNs = dcount(ServiceName), Services = make_set(ServiceName)
      by AccountName, ClientAddress, bin(TimeGenerated, 10m)
| where DistinctSPNs > 5
| order by DistinctSPNs desc
```

## 5. Expected legitimate activity

- Backup software, vulnerability scanners, and monitoring agents that
  authenticate to many services (e.g. a backup service account touching
  every file server's SPN nightly) can legitimately request tickets for
  several SPNs in a short window. Baseline these accounts explicitly and
  allowlist by account name + expected request volume rather than
  excluding by volume alone.
- RC4 (`0x17`) ticket encryption is not inherently malicious — many
  environments still have service accounts without AES support
  (`msDS-SupportedEncryptionTypes` not set), so the KDC issues RC4 tickets
  for those accounts to *anyone* who asks, attacker or not. RC4 is a
  **downgrade indicator worth flagging**, not proof of compromise by itself;
  it matters most in combination with the volume/burst pattern.
- Normal user activity is typically 0-2 distinct SPN requests in a 10-minute
  window (accessing a file share and a SQL box, say) — nowhere near the
  sweep behavior Rubeus/GetUserSPNs produce.

## 6. Validation steps

1. Identify the requesting account (`AccountName`) — human user, service
   account, or scanning/security-tooling account?
2. Pull the full list of SPNs requested in the burst window — a sweep across
   many *different* service accounts in a couple of minutes is the
   signature; a handful of requests to the same 2-3 services over hours
   is normal.
3. Check `ClientAddress` against asset inventory — expected workstation
   for that user, or something new/unusual (VPN egress, jump box the user
   doesn't normally use)?
4. Check whether the requesting account's normal behavior includes any
   Kerberoasting-adjacent tooling — was this a scheduled vulnerability scan
   window, or unscheduled?
5. Cross-reference the targeted service accounts against privilege — an
   SPN account with elevated group membership (e.g. an old SQL service
   account that's a Domain Admin) makes the finding far more urgent.
6. Watch for follow-on authentication using a targeted service account from
   a new host/IP in the days following the ticket request — that's the
   signal an offline crack succeeded.
7. Escalate to IR with the full ticket-request list, requesting account, and
   any follow-on authentication as supporting evidence.

## 7. Outcome / findings

Ran against a synthetic lab dataset
(`lab_data/kerberos_tgs_events.jsonl`, 34 Kerberos 4769 events across a
simulated business day) using `lab_data/run_hunt.py`, which reimplements the
Sigma aggregation logic (10-minute bucket, distinct SPN count per account,
RC4-only) since there's no live SIEM behind this repo.

- 34 total TGS requests; 24 were RC4-encrypted (`0x17`) and eligible for the
  selection filter.
- Normal user/service accounts (`jkim`, `mrogers`, `svc_backup`) never
  exceeded 3 distinct SPNs in any 10-minute window — `svc_backup`'s nightly
  sweep of file-server SPNs was spread across ~40 minutes, so bucketing into
  10-minute windows kept it under threshold without needing an explicit
  allowlist. Worth noting this is somewhat fragile — a backup job that ran
  faster would have needed an explicit account allowlist instead of relying
  on window timing (see caveat below).
- One account, `tjohnson`, requested RC4 tickets for **9 distinct SPNs
  within a single 2-minute span** — matching the `GetUserSPNs.py`/Rubeus
  sweep pattern. Source IP (`10.10.7.19`) resolved to a standard user
  workstation, not a scanning host or admin jump box.
- One of the 9 targeted SPN accounts, `svc_sqlprod`, is a service account
  with Domain Admin nesting in this lab's AD model — the exact
  high-urgency case section 6 calls out.
- Zero false positives at the >5-distinct-SPN/10-minute threshold. The hunt
  cleanly separated the seeded Kerberoasting sweep from all legitimate
  activity, including the backup service account's own multi-SPN behavior.

**Caveat:** the `svc_backup` near-miss shows this heuristic is timing-sensitive
— a legitimate multi-service account whose requests happen to cluster
tighter than 10 minutes would false-positive, and a slower/throttled
Kerberoasting tool could stretch its sweep past the window to evade it.
Production tuning should pair the volume heuristic with an explicit
allowlist of known multi-SPN service accounts (rather than relying on
request timing alone) and consider a longer rolling window with a
higher threshold as a secondary, harder-to-evade rule.

## 8. Detection follow-up

Promoted to `queries/sigma/kerberoasting_tgs_volume.yml` (status
`experimental` — the timing-window fragility noted above means this should
run in monitor/tune mode against real DC logs for a few weeks, with a
service-account allowlist added, before promoting to `stable`).
