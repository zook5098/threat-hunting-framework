# Hunting Methodology

This repo follows a six-stage loop for every hunt:

1. **Hypothesize** — Form a specific, testable statement about adversary
   behavior, grounded in an ATT&CK technique, threat intel, or a known
   detection gap. Avoid vague hypotheses ("look for malware") in favor of
   specific ones ("adversaries using WMI to spawn remote processes").

2. **Collect** — Identify exactly which log sources and fields are needed
   to test the hypothesis. If the data doesn't exist yet, that's itself a
   finding worth reporting (a visibility gap).

3. **Analyze** — Run the query, examine results, separate expected/benign
   activity from anomalies. This stage produces the bulk of the "noise
   reduction" work — most of a hunt's value is in tuning out the legitimate
   matches, not just writing the initial query.

4. **Validate** — For anything that looks anomalous, pivot to confirm
   whether it's a true or false positive: process trees, logon correlation,
   asset ownership, account behavior baselines.

5. **Act** — If a true positive is found, hand off to IR with the full
   context (process tree, timeline, affected hosts/accounts). If nothing
   is found, document that too — a well-scoped hunt with a negative result
   still tells you something about your environment's exposure.

6. **Automate** — If the hunt surfaced a repeatable, tunable pattern,
   promote it from a manual hunt to a standing detection rule (Sigma),
   so future occurrences are caught automatically instead of requiring
   another manual hunt.

## Why document negative results

A hunt that finds nothing is not a wasted hunt if it's well-scoped — it's
evidence that a particular attack path either isn't being used against you,
or that you lack the visibility to know. Both are useful facts. This repo
treats "ran hunt X, zero true positives, confirms Y" as a valid and
recorded outcome, not a failure to hide.
