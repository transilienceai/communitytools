<!-- ../detectors/unused-rule.md -->
---
name: unused-rule
description: Report rules with zero observed hits only when device-scoped counter or traffic-log evidence and its observation window are supplied. Configuration-only reviews emit usage-unknown manual-review records, never unused-rule claims.
---

# Unused Rule

**Reference implementation:** `fwrr.detectors.unused_rule.UnusedRule` in [firewall-review](https://github.com/ipunithgowda/firewall-review)
**Version pin:** see [`../VERSIONS.md`](../VERSIONS.md)
**Default severity:** Info (zero hits observed) / RequiresManualReview (usage evidence absent or incomplete)

## What it checks
For each rule, looks up a hit-count from `DetectorContext.hit_counts`. A zero value is reportable only with the device/rule identity, observation start and end, counter source, and last reset/reboot/policy-install time when available. The safe title is **“Zero hits observed during the supplied window”**. “Unused” remains a remediation hypothesis until the owner confirms the window is representative.

If hit counts are absent, incomplete, not device-scoped, or have an unknown/reset window, emit a `RequiresManualReview` usage-unknown record. Configuration attributes such as `status disable`, an expired schedule, or names containing `temp`, `old`, or `unused` are lifecycle-review indicators; they are not hit evidence.

## Why this matters
Rules without observed use may be stale, but counters can reset and legitimate emergency or seasonal rules may remain quiet. The `RequiresManualReview` path is first-class: auditors receive an evidence-backed zero-hit observation or an explicit “usage cannot be determined” result—never a guess or a deletion instruction.

## Evidence and remediation gate

A zero-hit row must include the counter/log source, observation window, count, and reset caveat. Recommend owner validation, ticket/history review, a monitoring or disable-first period, rollback steps, and then removal if approved. Never recommend immediate deletion from a static configuration review alone.

## Frameworks cited
- CIS Controls v8.1 — `13.4` (traffic filtering between segments)
- NIST CSF 2.0 — `DE.CM-01` (networks and network services are monitored)

## v0.2 / v0.3 plans
- v0.2: accept per-vendor native hit-count formats (ASA `show access-list` counters, FortiGate session counters, PAN-OS rule-hit-count XML) via a parser sidecar.
- v0.3: rolling 90-day observation window with age-weighted severity — rules unused for >90 days auto-upgrade to Low.
