<!-- ../detectors/shadow-rule.md -->
---
name: shadow-rule
description: Identify exact static shadow candidates when an earlier rule covers the later rule across every modeled match dimension. Missing platform semantics or runtime context produces a Needs Review candidate, not a definitive unreachable-rule claim.
---

# Shadow Rule

**Reference implementation:** `fwrr.detectors.shadow_rule.ShadowRule` in [firewall-review](https://github.com/ipunithgowda/firewall-review)
**Version pin:** see [`../VERSIONS.md`](../VERSIONS.md)
**Default severity:** High

## What it checks
Walks each independently evaluated ruleset in effective order. For each rule `later`, tests whether an earlier rule `earlier` with opposite action covers the later rule across source, destination, source/destination service or port, protocol/application, direction and zone/interface, schedule, address family, policy context/VDOM, and relevant NAT semantics.

Only emit a confirmed static shadow when every applicable dimension is parsed and containment is deterministic. If any dimension is absent or represented only by unresolved objects, label the result **Potential shadowing / overlap**, set `Needs Review`, list the missing dimensions, and require vendor Policy Lookup or an equivalent runtime evaluation before remediation.

Exact duplicates are not shadow findings; route them to `duplicate-rule`. Partial containment is overlap, not full shadowing.

## Why this matters
Confirmed shadowing can hide operator intent. Candidate results are still valuable for review, but overstating reachability is dangerous because platform ordering, object expansion, NAT, schedules, dynamic addresses, routes, and policy context can change the effective match.

## Reproduction / PoC

Show both rules in order and a field-by-field containment table. Record which dimensions were evaluated, which were unresolved, and the parser/detector version. Before disabling or moving a rule, validate with Policy Lookup/equivalent, current objects and routes, recent traffic, owner approval, and a rollback plan.

## Frameworks cited
- NIST CSF 2.0 — `PR.PS-01` (configuration management practices are established)
- CIS Controls v8.1 — `12.2` (establish and maintain a secure network architecture)
- ISO/IEC 27001:2022 — `A.8.9` (configuration management)

## v0.2 / v0.3 plans
- v0.2: partial-overlap detection — flag rules whose traffic is partially (not fully) covered, with the exact overlap quantified and clearly separated from confirmed shadowing.
- v0.3: suggest minimal rule reordering / merge to eliminate shadowing while preserving semantic intent.
