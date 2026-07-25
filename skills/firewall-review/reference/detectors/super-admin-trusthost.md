<!-- ../detectors/super-admin-trusthost.md -->
---
name: super-admin-trusthost
description: Flag a FortiGate super-admin / privilege-15 account whose trusthost is a whole RFC1918 super-block (/8, /12, /16) rather than a specific jump-host subnet. PCI DSS v4.0.1 §8.4.2.
---

# Super-Admin Trusthost Too Broad

**Reference implementation:** `fwrr.detectors.super_admin_trusthost.SuperAdminTrusthost` in [firewall-review](https://github.com/ipunithgowda/firewall-review)
**Version pin:** `super-admin-trusthost:0.1.0`
**Default severity:** Critical
**Vendor scope:** FortiGate (FortiOS)

## What it checks
Walks `config system admin` for accounts with `set accprofile super_admin` (or another root-equivalent profile) and inspects their `trusthostN` entries. A finding fires when a trusthost resolves to a whole RFC1918 super-block: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, or any supernet of an equivalent size. The evidence block quotes the admin definition and the offending trusthost line from the source config.

## Why this matters
The trusthost list is the last IP-layer gate in front of the most privileged account on the device. When that gate is a `/8`, every host on the internal estate is permitted to reach the super-admin login. A single compromised workstation anywhere in RFC1918 space then has a clear path to attempt privilege-15 access, and the only thing left standing between it and root is the password and any MFA. A super-admin trusthost should be a specific jump-host subnet, ideally a `/29` or smaller, so that the set of machines able to even attempt the login is tiny and known. PCI DSS v4.0.1 §8.4.2 requires administrative access to be both MFA-protected and restricted to authorized administrative IPs.

## Frameworks cited
- PCI DSS v4.0.1 — `8.4.2` (secure all administrative access with MFA and restrict to authorized systems)
- NIST CSF 2.0 — `PR.AA-05` (access permissions and authorizations are managed, incorporating least privilege)
- CIS Controls v8.1 — `5.4` (restrict administrator privileges to dedicated administrator accounts)
- ISO/IEC 27001:2022 — `A.8.5` (secure authentication)

## Notes and limitations
- FortiGate-specific. The privilege model on other vendors (Cisco privilege levels, PAN-OS admin roles) uses different config primitives and is not covered here.
- A trusthost of `0.0.0.0/0` (no restriction at all) is caught by this detector as the broadest possible case, and should be read as more severe than an RFC1918 super-block.
- The detector does not evaluate whether MFA is enabled on the account; a broad trusthost is flagged regardless, because IP restriction and MFA are independent controls.
