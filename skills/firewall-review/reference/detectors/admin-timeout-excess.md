<!-- ../detectors/admin-timeout-excess.md -->
---
name: admin-timeout-excess
description: Flag FortiGate admin idle-timeout set above the framework ceiling. High when `set admintimeout` under `config system global` exceeds 15 minutes (PCI DSS v4.0.1 §8.2.8).
---

# Admin Timeout Excess

**Reference implementation:** `fwrr.detectors.admin_timeout_excess.AdminTimeoutExcess` in [firewall-review](https://github.com/ipunithgowda/firewall-review)
**Version pin:** `admin-timeout-excess:0.1.0`
**Default severity:** High
**Vendor scope:** FortiGate (FortiOS)

## What it checks
Reads the FortiGate config for `set admintimeout <minutes>` inside `config system global`. FortiGate ships with a 5-minute default, so the setting only appears when an operator has changed it. Any explicit value above 15 minutes is emitted as a finding, quoting the source file and line. This detector reads the source text directly rather than the normalized rule set, because `admintimeout` is a system-global setting the parser does not fold into a per-rule object.

## Why this matters
The admin idle-timeout bounds how long an unattended, already-authenticated admin session stays usable. A walked-away console, an unlocked jump host, or a reusable session token all become a privileged foothold for exactly as long as the timeout allows. PCI DSS v4.0.1 §8.2.8 caps admin session idle time at 15 minutes for this reason. A device configured to 60 or 480 minutes is a deliberate relaxation of that control, and it is the kind of change that gets made once for convenience and never reverted.

## Frameworks cited
- PCI DSS v4.0.1 — `8.2.8` (idle session timeout of 15 minutes or less)
- NIST CSF 2.0 — `PR.AA-04` (identity assertions are protected, conveyed, and verified)
- CIS Controls v8.1 — `5.2` (use unique passwords / session management on administrative accounts)

## Notes and limitations
- FortiGate-specific. Cisco / Palo Alto / cloud equivalents (`exec-timeout`, idle-timeout profiles) are not yet covered by this detector.
- The 15-minute ceiling is the PCI default. Engagements under a stricter internal policy should adjust the threshold in the detector config.
- Absence of an explicit `admintimeout` line means the device is on the 5-minute default and passes silently. No finding is raised for the default.
