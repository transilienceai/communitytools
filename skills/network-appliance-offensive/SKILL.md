---
name: network-appliance-offensive
description: Offensive testing of perimeter network appliances and VPN crypto — IKE/IPsec (aggressive-mode, transform/DH enum, NAT-T), Check Point SIC/OPSEC, safe firmware/patch-level inference for FortiGate/PAN-OS/Cisco ASA/Citrix feeding CVE applicability, NTLM Type-2 target-info decode, handshake-completion TLS-version probing, and an RST-TTL forgery discriminator. The active/offensive counterpart to the static firewall-review skill. Use when a perimeter firewall/VPN/appliance is in scope and you must test it (not just audit a config), without reinventing raw-socket protocol tooling each engagement.
---

# Network-Appliance Offensive

`firewall-review` audits a *config* statically; `infrastructure` covers *generic* ports/DNS/SMB. Neither tests a live perimeter **appliance** or its **VPN crypto** — so IKE builders, SIC/OPSEC fingerprinting, and TTL discriminators were reinvented from raw sockets each engagement, often shallowly, and CVE applicability was left UNDETERMINED across whole estates. This skill provides the deterministic, tested tools and the precondition-gated methodology. **Non-destructive only** — every tool observes/decodes/infers; none fires an exploit, and CVE applicability is a *precondition check*, never a blind "vulnerable."

## Tools

| Tool | Does | Anti-footgun |
|------|------|--------------|
| [`tools/ike_enum.py`](../../tools/ike_enum.py) | IKEv1 aggressive-mode detection, IKEv1/IKEv2 transform + DH-group enum, NOTIFY / NAT-T decode (wraps `ike-scan`, raw ISAKMP SA_INIT builder fallback) | Aggressive-mode support (PSK-hash leak) is the finding; enumerate, don't crack in-band |
| [`tools/checkpoint_sic_opsec.py`](../../tools/checkpoint_sic_opsec.py) | Fingerprint SIC (18190/1), OPSEC LEA/ELA (18183/4), CA (18192/18210), FW1 (256/264), Gaia Portal; emit a CVE-**precondition** map incl. CVE-2024-24919 | CVE-2024-24919 is `applicable` ONLY when the RA/Mobile-Access marker is observed — else `undetermined` |
| [`tools/appliance_version_infer.py`](../../tools/appliance_version_infer.py) | Safe firmware/patch-level inference for FortiGate / PAN-OS / Cisco ASA / Citrix from headers, login markers, cert CN/serial → CVE applicability | Never asserts `applicable` on a low-confidence / unknown version — returns `undetermined` |
| [`tools/tls_handshake_probe.py`](../../tools/tls_handshake_probe.py) | Which TLS versions are supported, by **completed handshake** per pinned protocol | Fixes the `openssl s_client` exit/SECLEVEL false-positive — an aborted handshake ≠ support |
| [`tools/ntlm_decode.py`](../../tools/ntlm_decode.py) | Decode an NTLM Type-2 (CHALLENGE) AV_PAIR block → NetBIOS/DNS host, domain, forest, OS build | Info-leak finding from an unauthenticated challenge; no auth attempted |
| [`tools/perimeter_forensics.py`](../../tools/perimeter_forensics.py) | RST-TTL forgery discriminator (real host vs firewall forging a RST) + IKE NOTIFY decode | Never asserts "internal host behind FW" on RSTs alone — a firewall forges RSTs indistinguishably at this layer; returns `undetermined` without an open-service TTL baseline |

## Workflow

1. **Fingerprint the appliance** — from the port set + banners + login markers, run `appliance_version_infer.py` (vendor + version guess + confidence) and, for Check Point, `checkpoint_sic_opsec.py`. A version guess of `undetermined`/low-confidence stays undetermined — do not score CVEs against it.
2. **VPN crypto** — on UDP 500/4500, run `ike_enum.py`: flag IKEv1 **aggressive mode** (leaks the PSK hash → a finding), enumerate accepted transforms + weak DH groups (1/2/5), and decode NAT-T/NOTIFY. IKEv2-only where IKEv1 RA is absent (a CVE requiring IKEv1 aggressive mode is `not_applicable` there — see `severity-calibration.md` rule 5).
3. **TLS posture** — `tls_handshake_probe.py` per host: report only handshake-*completed* versions; TLS 1.0/1.1 completion is the weak-protocol finding (not an openssl exit code).
4. **Info leaks** — decode any NTLM Type-2 challenge (`ntlm_decode.py`) for internal host/domain/OS intel; record it as an information-disclosure finding.
5. **CVE applicability (precondition-gated)** — for each surfaced appliance CVE, take the vendor+version from step 1 and the precondition map (checkpoint_sic_opsec / appliance_version_infer `applicability`) and mark `applicable` / `undetermined` / `not_applicable`. Enrich the CVE via `python3 tools/nvd-lookup.py`. An `undetermined` applicability is reported as such — never inflated to a confirmed vuln.
6. **Forensics** — if a "closed" host appears live behind the firewall, run `perimeter_forensics.py --classify-ttls` before asserting anything: distinguish a real host RST from a filter-forged RST (needs an open-service TTL baseline; otherwise `undetermined`).

## Anti-Patterns

- Do not score an appliance CVE as confirmed on a version banner alone — banners are backported/spoofable; gate on `applicability` (`severity-calibration.md` rules 4-5).
- Do not claim TLS 1.0/1.1 support from an `openssl s_client` non-zero exit — require a completed handshake (`tls_handshake_probe.py`).
- Do not assert "internal host behind the firewall" from RSTs — a firewall forges RSTs; use the TTL discriminator and accept `undetermined`.
- Do not crack an IKE aggressive-mode PSK hash in-band on the engagement — capturing/flagging the aggressive-mode exposure is the finding; offline cracking needs explicit authorization.

## Reference

- Static counterpart: [`firewall-review`](../firewall-review/SKILL.md) (config audit). Generic network: [`infrastructure`](../infrastructure/SKILL.md).
- CVE precondition / applicability discipline: [`../coordination/reference/severity-calibration.md`](../coordination/reference/severity-calibration.md) (rules 4-5).
