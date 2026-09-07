#!/usr/bin/env python3
"""
Runs the FortiGate SSL-VPN initial-access hunt (see
../fortigate-sslvpn-initial-access.md) against the synthetic dataset in
this directory. Stands in for the Splunk/KQL query since there's no live
SIEM behind this repo. Implements two stages:

  1. The Sigma-equivalent burst detector: >5 distinct usernames attempted
     via SSL-VPN from one source IP in a 10-minute window.
  2. The section-6 validation pivot, done programmatically: for any flagged
     source IP, walk forward to find a VPN success, then an admin-plane
     login, then any config changes under that same session -- the full
     credential-stuffing-to-backdoor-account chain.
"""
import json
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path

DATA_FILE = Path(__file__).parent / "fortigate_events.jsonl"

DISTINCT_USER_THRESHOLD = 5
FOLLOW_ON_WINDOW = timedelta(minutes=30)
KNOWN_MGMT_IPS = {"10.10.1.5": "IT admin jump box"}


def load_events():
    with open(DATA_FILE) as f:
        events = [json.loads(line) for line in f if line.strip()]
    for e in events:
        e["_dt"] = datetime.fromisoformat(e["Timestamp"].replace("Z", "+00:00"))
    return sorted(events, key=lambda e: e["_dt"])


def bucket_key(dt):
    return (dt.date(), dt.hour, dt.minute // 10)


def find_next(events, after_dt, src_ip, subtype=None, action=None, within=FOLLOW_ON_WINDOW, user=None):
    for e in events:
        if e["_dt"] <= after_dt or e["_dt"] > after_dt + within:
            continue
        if e["SrcIP"] != src_ip:
            continue
        if subtype and e["Subtype"] != subtype:
            continue
        if action and e["Action"] != action:
            continue
        if user and e.get("User") != user:
            continue
        return e
    return None


def find_all_after(events, after_dt, src_ip, user, within=FOLLOW_ON_WINDOW):
    return [
        e for e in events
        if after_dt < e["_dt"] <= after_dt + within
        and e["SrcIP"] == src_ip
        and e.get("User") == user
        and e["Action"] == "config-change"
    ]


def main():
    events = load_events()
    fail_events = [e for e in events if e["Subtype"] == "vpn" and e["Action"] == "ssl-login-fail"]

    print(f"Total events in dataset: {len(events)}")
    print(f"SSL-VPN login failures:  {len(fail_events)}\n")

    # Stage 1: burst detection
    buckets = defaultdict(lambda: defaultdict(list))
    for e in fail_events:
        buckets[(e["SrcIP"], bucket_key(e["_dt"]))][e["User"]].append(e)

    print("=== Stage 1: distinct usernames per source IP per 10-min window ===")
    flagged_ips = []
    for (src_ip, bucket), users in sorted(buckets.items(), key=lambda kv: -len(kv[1])):
        distinct = len(users)
        flag = distinct > DISTINCT_USER_THRESHOLD
        marker = "-> HUNT HIT (credential stuffing burst)" if flag else ""
        print(f"- {src_ip:<16} window={bucket} distinct_users={distinct:<3} {marker}")
        if flag:
            flagged_ips.append((src_ip, min(e["_dt"] for u in users.values() for e in u)))

    print(f"\n=== Stage 2-4: follow-on correlation for each flagged source IP ===")
    for src_ip, burst_start in flagged_ips:
        print(f"\n--- {src_ip} (burst started {burst_start.isoformat()}) ---")

        success = find_next(events, burst_start, src_ip, subtype="vpn", action="tunnel-up")
        if not success:
            print("  No successful VPN login followed the burst -- brute force, no confirmed compromise.")
            continue
        print(f"  [Stage 2] VPN SUCCESS: user={success['User']} at {success['_dt'].isoformat()}")

        admin_login = find_next(events, success["_dt"], src_ip, subtype="system", action="login", user=success["User"])
        if not admin_login:
            print("  No admin-plane login followed from this account/IP -- VPN-only foothold.")
            continue
        mgmt_note = KNOWN_MGMT_IPS.get(src_ip, "NOT an allowlisted management IP")
        print(f"  [Stage 3] ADMIN LOGIN: user={admin_login['User']} at {admin_login['_dt'].isoformat()} ({mgmt_note})")

        config_changes = find_all_after(events, admin_login["_dt"], src_ip, admin_login["User"])
        if not config_changes:
            print("  No config changes followed the admin login.")
            continue
        print(f"  [Stage 4] CONFIG CHANGES by this session:")
        for c in config_changes:
            severity = "CRITICAL - new admin account" if c.get("CfgPath") == "system.admin" else "notable"
            print(f"      {c['_dt'].isoformat()}  {c['CfgPath']}/{c['CfgObj']}  ({severity})")

    print(f"\n=== Summary ===")
    print(f"Source IPs flagged for credential-stuffing burst: {len(flagged_ips)}")


if __name__ == "__main__":
    main()
