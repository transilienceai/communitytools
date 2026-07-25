<!-- ../detectors/utm-status-orphan.md -->
---
name: utm-status-orphan
description: Flag a FortiGate policy with `set utm-status enable` but no inspection profile attached — inspection is advertised but never applied.
---

# UTM Status Orphan

**Reference implementation:** `fwrr.detectors.utm_status_orphan.UtmStatusOrphan` in [firewall-review](https://github.com/ipunithgowda/firewall-review)
**Version pin:** `utm-status-orphan:0.1.0`
**Default severity:** Medium
**Vendor scope:** FortiGate (FortiOS)

## What it checks
Examines each FortiGate policy that carries `set utm-status enable` and confirms at least one inspection profile is actually attached: a `profile-group`, or one of the individual profiles (`av-profile`, `webfilter-profile`, `ips-sensor`, `application-list`, `dlp-profile`, `ssl-ssh-profile`). A policy that enables UTM but attaches none of these is emitted as a finding. The detector works from the parsed rule (the parser already surfaces `utm-status` and the profile attributes per policy) and re-reads the raw block from source only to quote evidence.

## Why this matters
`utm-status enable` with no profile attached is inspection theatre. An auditor scanning the policy table reads "UTM enabled" and reasonably assumes traffic on that policy is being scanned for malware, exploited, or filtered. Nothing is. The gap is dangerous in two directions: it produces a false positive on a compliance review, and it gives the operations team a false sense of defence-in-depth on a path they believe is inspected. Because the policy looks protected, the missing coverage tends to survive for a long time. Attaching the intended profile (or removing the misleading `utm-status enable`) closes the gap.

## Frameworks cited
- NIST CSF 2.0 — `DE.CM-01` (networks and network services are monitored to find potentially adverse events)
- PCI DSS v4.0.1 — `1.3.4` (restrict and inspect traffic between trusted and untrusted networks)
- CIS Controls v8.1 — `13.6` (collect network traffic flow logs / deploy network intrusion detection)

## Notes and limitations
- FortiGate-specific. The UTM/threat-prevention profile model is a Fortinet construct; PAN-OS security-profile-groups and Cisco FTP policies are different shapes and are not covered here.
- A policy with `utm-status disable` (or no utm-status line) is out of scope: it makes no inspection claim, so there is nothing to contradict.
- The detector confirms a profile is attached, not that the profile is well-configured. An attached-but-empty profile is a deeper check left to the semantic-check catalogue.
