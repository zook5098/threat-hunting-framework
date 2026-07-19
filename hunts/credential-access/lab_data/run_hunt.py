#!/usr/bin/env python3
"""
Runs the Kerberoasting hunt (see ../kerberoasting.md) against the synthetic
dataset in this directory. Stands in for the Splunk/KQL query since there's
no live SIEM behind this repo -- the aggregation logic (10-minute bucket,
distinct SPN count per account, RC4-only) mirrors the Sigma rule in
queries/sigma/kerberoasting_tgs_volume.yml.
"""
import json
from collections import defaultdict
from datetime import datetime
from pathlib import Path

DATA_FILE = Path(__file__).parent / "kerberos_tgs_events.jsonl"

RC4 = "0x17"
DISTINCT_SPN_THRESHOLD = 5

# Known multi-SPN service accounts an analyst would baseline in a real
# environment -- used only in the validation/pivot step below, not in the
# detection filter itself (see hunt section 7/8 for why volume alone isn't
# a safe long-term filter).
KNOWN_MULTI_SPN_ACCOUNTS = {"svc_backup"}

# Stand-in for an AD privilege lookup an analyst would do by hand in
# section 6 step 5 ("cross-reference targeted service accounts against
# privilege").
HIGH_PRIVILEGE_SPN_ACCOUNTS = {"svc_sqlprod"}


def load_events():
    with open(DATA_FILE) as f:
        return [json.loads(line) for line in f if line.strip()]


def bucket_key(timestamp):
    dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    return (dt.date(), dt.hour, dt.minute // 10)


def main():
    events = load_events()
    rc4_events = [e for e in events if e["TicketEncryptionType"] == RC4]

    print(f"Total TGS events in dataset: {len(events)}")
    print(f"RC4-encrypted (selection):   {len(rc4_events)}\n")

    # (account, bucket) -> {service_name: [events]}
    buckets = defaultdict(lambda: defaultdict(list))
    for e in rc4_events:
        key = (e["AccountName"], bucket_key(e["Timestamp"]))
        buckets[key][e["ServiceName"]].append(e)

    print("=== Distinct-SPN-per-10min-window, by account (RC4 only) ===")
    hits = []
    for (account, bucket), services in sorted(buckets.items(), key=lambda kv: -len(kv[1])):
        distinct = len(services)
        flag = distinct > DISTINCT_SPN_THRESHOLD
        note = "known multi-SPN account" if account in KNOWN_MULTI_SPN_ACCOUNTS else ""
        marker = "-> HUNT HIT" if flag else ""
        print(f"- {account:<12} window={bucket} distinct_spns={distinct:<3} {note} {marker}")
        if flag:
            hits.append((account, bucket, services))

    print(f"\n=== Hunt hits (>{DISTINCT_SPN_THRESHOLD} distinct SPNs in one window) ===")
    for account, bucket, services in hits:
        client_ips = {e["ClientIP"] for svc_events in services.values() for e in svc_events}
        print(f"\nAccount: {account}  Window: {bucket}  ClientIP(s): {', '.join(client_ips)}")
        for svc in sorted(services):
            priv = " [HIGH-PRIVILEGE SPN ACCOUNT]" if svc.split("/")[-1] in HIGH_PRIVILEGE_SPN_ACCOUNTS else ""
            print(f"    {svc}{priv}")

    print(f"\n=== Summary ===")
    print(f"Accounts flagged: {len(hits)}")


if __name__ == "__main__":
    main()
