#!/usr/bin/env python3
"""
Runs the WMI-based lateral movement hunt (see ../wmi-lateral-movement.md)
against the synthetic dataset in this directory. Stands in for the
Splunk/KQL query since there's no live SIEM behind this repo -- the
filter logic mirrors the Sigma rule in queries/sigma/wmi_process_spawn.yml.
"""
import json
from pathlib import Path

DATA_FILE = Path(__file__).parent / "wmi_process_events.jsonl"

KNOWN_MGMT_IMAGES = ("ccmexec.exe", "scnotification.exe")
KNOWN_MGMT_SOURCE_IPS = {"10.10.5.10": "SCCM/ConfigMgr server", "10.10.5.20": "monitoring server (SRV-MON02)"}
KNOWN_ADMIN_JUMPBOXES = {"10.10.1.5"}


def load_events():
    with open(DATA_FILE) as f:
        return [json.loads(line) for line in f if line.strip()]


def matches_selection(event):
    return event["ParentImage"].lower().endswith("\\wmiprvse.exe")


def matches_known_mgmt_filter(event):
    return event["Image"].lower().split("\\")[-1] in KNOWN_MGMT_IMAGES


def main():
    events = load_events()
    selection_hits = [e for e in events if matches_selection(e)]
    sigma_hits = [e for e in selection_hits if not matches_known_mgmt_filter(e)]

    print(f"Total events in dataset:        {len(events)}")
    print(f"WMI-spawned child processes:    {len(selection_hits)}")
    print(f"After known-mgmt filter (hits):  {len(sigma_hits)}\n")

    print("=== Hunt hits (post Sigma filter) ===")
    true_positives = []
    for e in sigma_hits:
        source_ip = e["SourceIP"]
        if source_ip in KNOWN_ADMIN_JUMPBOXES:
            verdict = "benign - known admin jump box"
        elif source_ip in KNOWN_MGMT_SOURCE_IPS:
            verdict = f"benign - {KNOWN_MGMT_SOURCE_IPS[source_ip]}"
        else:
            verdict = "UNEXPLAINED - escalate"
            true_positives.append(e)

        print(f"- {e['Timestamp']} {e['Host']:<12} user={e['User']:<8} "
              f"image={e['Image'].split(chr(92))[-1]:<12} src_ip={source_ip:<12} -> {verdict}")
        print(f"    cmdline: {e['CommandLine']}")

    print(f"\n=== Summary ===")
    print(f"True-positive / unexplained hits: {len(true_positives)}")
    hosts = sorted({e["Host"] for e in true_positives})
    print(f"Affected hosts: {', '.join(hosts)}")
    print(f"Common account across hits: {', '.join(sorted({e['User'] for e in true_positives}))}")
    print(f"Common source IP: {', '.join(sorted({e['SourceIP'] for e in true_positives}))}")


if __name__ == "__main__":
    main()
