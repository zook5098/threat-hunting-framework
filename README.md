# Threat Hunting Framework

A structured, hypothesis-driven threat hunting repository: every hunt documents *why* it exists, *what data* it needs, the *actual queries* to run, and *how to validate* a finding. Built to show the analytical process behind a hunt, not just a folder of queries.

## Why this structure

Most "threat hunting" repos on GitHub are just query dumps. Hiring managers for senior D&R/hunt roles want to see the reasoning: what adversary behavior are you hypothesizing, what evidence would confirm or refute it, and what do you do once you find something. This repo treats each hunt as a mini investigation with its own writeup.

## Repo structure

```
hunts/
  lateral-movement/
  credential-access/
  persistence/
templates/
  hunt_template.md       <- copy this to start a new hunt
queries/
  sigma/                 <- platform-agnostic detection rules derived from hunts
  splunk/                <- SPL versions
  kql/                   <- KQL versions (Sentinel/Defender)
docs/
  methodology.md         <- the hunting process this repo follows
  data_sources.md        <- what log sources are assumed to exist and why
```

## Hunt template

Every hunt in `hunts/` follows this format (see `templates/hunt_template.md`):

1. **Hypothesis** — the specific adversary behavior being hunted, tied to an ATT&CK technique
2. **Rationale** — why this behavior is worth hunting for (prevalence, blind spots in existing detections, threat intel driver)
3. **Data sources required** — exact log sources/fields needed
4. **Hunt queries** — the actual query, in Sigma first (for portability) then a platform-specific translation
5. **Expected legitimate activity** — what normal/benign matches look like, so you can tune out noise
6. **Validation steps** — what an analyst does once a hit looks interesting, to confirm true/false positive
7. **Outcome / findings** — write-up of what running this hunt actually turned up (even "found nothing, here's why that's still useful")
8. **Detection follow-up** — if the hunt found something repeatable, promote it to a standing Sigma rule in `queries/sigma/`

## Example hunts (planned)

| Hunt | ATT&CK | Status |
|---|---|---|
| [LOLBin-based lateral movement via WMI](hunts/lateral-movement/wmi-lateral-movement.md) | T1047, T1021 | Validated (lab data) |
| [Kerberoasting via abnormal TGS request volume](hunts/credential-access/kerberoasting.md) | T1558.003 | Validated (lab data) |
| Living-off-the-land credential access via comsvcs.dll | T1003.001 | Draft |
| [New scheduled task persistence outside baseline](hunts/persistence/scheduled-task-persistence.md) | T1053.005 | Validated (lab data) |
| Suspicious parent/child process chains (Office → LOLBin) | T1204, T1059 | Draft |

## Methodology

This repo follows a simple loop: **Hypothesize → Collect → Analyze → Validate → Act → Automate**. See `docs/methodology.md` for the full breakdown of each stage and how it maps to the hunt template fields above.

## Status

Framework and template finalized; hunts are being written up and validated against lab data one at a time. Each hunt folder will include the write-up plus the query, so you can see both the "how" and the "why."
