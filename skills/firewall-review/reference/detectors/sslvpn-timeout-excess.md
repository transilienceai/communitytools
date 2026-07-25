<!-- ../detectors/sslvpn-timeout-excess.md -->
---
name: sslvpn-timeout-excess
description: Flag FortiGate SSL-VPN auth/idle-timeout above the PCI DSS v4.0.1 §8.2.8 ceiling (900s), or `tunnel-connect-without-reauth enable` which defeats the timeout entirely.
---

# SSL-VPN Timeout Excess

**Reference implementation:** `fwrr.detectors.sslvpn_timeout_excess.SslvpnTimeoutExcess` in [firewall-review](https://github.com/ipunithgowda/firewall-review)
**Version pin:** `sslvpn-timeout-excess:0.1.0`
**Default severity:** High
**Vendor scope:** FortiGate (FortiOS)

## What it checks
Reads `config vpn ssl settings` for `set idle-timeout <seconds>` and `set auth-timeout <seconds>`, and compares each against the PCI DSS v4.0.1 §8.2.8 ceiling of 900 seconds (15 minutes). FortiGate defaults are idle-timeout 300 and auth-timeout 28800, so the auth-timeout default alone (8 hours) already exceeds the ceiling. The detector also flags `set tunnel-connect-without-reauth enable`, which lets a client reconnect without re-authenticating and defeats the timeout regardless of its value.

## Why this matters
Remote-access VPN is the most common initial-access vector in real incidents. The two timeouts decide how long a stolen or hijacked session stays alive. An 8-hour auth-timeout means a session token lifted from a compromised laptop is valid for a full working day. `tunnel-connect-without-reauth` is worse: it turns a timed session into an effectively permanent one, because the client is allowed back in without proving identity again. Tightening both to the 15-minute regulated ceiling shrinks the window an attacker has to ride a live tunnel.

## Frameworks cited
- PCI DSS v4.0.1 — `8.2.8` (idle session timeout of 15 minutes or less)
- NIST CSF 2.0 — `PR.AA-04` (identity assertions are protected, conveyed, and verified)

## Notes and limitations
- FortiGate-specific. The auth-timeout default of 28800s means many devices fail this check purely on the shipped default. That is intentional: PCI treats the default as non-compliant, so the finding is correct even when the operator never touched the setting.
- IPsec dial-up VPN timeouts are a separate config block and are not covered here.
