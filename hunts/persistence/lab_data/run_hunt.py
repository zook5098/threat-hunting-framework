#!/usr/bin/env python3
"""
Runs the scheduled task persistence hunt (see ../scheduled-task-persistence.md)
against the synthetic dataset in this directory. Stands in for the
Splunk/KQL query since there's no live SIEM behind this repo -- the
content-match logic mirrors the Sigma rule in
queries/sigma/scheduled_task_suspicious_content.yml.
"""
import json
from pathlib import Path

DATA_FILE = Path(__file__).parent / "scheduled_task_events.jsonl"

SUSPICIOUS_PATHS = ("\\users\\public\\", "\\appdata\\local\\temp\\", "\\programdata\\")
SUSPICIOUS_FLAGS = ("-enc ", "-encodedcommand", "-w hidden", "-windowstyle hidden")


def load_events():
    with open(DATA_FILE) as f:
        return [json.loads(line) for line in f if line.strip()]


def match_reasons(task_content_lower):
    reasons = []
    for path in SUSPICIOUS_PATHS:
        if path in task_content_lower:
            reasons.append(f"path:{path.strip(chr(92))}")
    for flag in SUSPICIOUS_FLAGS:
        if flag in task_content_lower:
            reasons.append(f"flag:{flag.strip()}")
    return reasons


def main():
    events = load_events()
    print(f"Total 4698 (task created) events in dataset: {len(events)}\n")

    print("=== Hunt hits (suspicious path or PowerShell flags in task content) ===")
    hits = []
    for e in events:
        task_content = f"{e['Command']} {e['Arguments']}"
        reasons = match_reasons(task_content.lower())
        if reasons:
            hits.append((e, reasons))
            print(f"\nHost: {e['Host']}  TaskName: {e['TaskName']}  "
                  f"CreatedBy: {e['SubjectUserName']}  Trigger: {e['Trigger']}")
            print(f"    Command:   {e['Command']}")
            print(f"    Arguments: {e['Arguments']}")
            print(f"    Matched:   {', '.join(reasons)}")

    print(f"\n=== Summary ===")
    print(f"Hunt hits: {len(hits)} / {len(events)} events")
    print(f"Affected hosts: {', '.join(sorted({e['Host'] for e, _ in hits}))}")
    print(f"Creating accounts: {', '.join(sorted({e['SubjectUserName'] for e, _ in hits}))}")


if __name__ == "__main__":
    main()
