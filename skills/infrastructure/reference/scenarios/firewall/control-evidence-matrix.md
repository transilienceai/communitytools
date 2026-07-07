# Firewall Control Evidence Matrix

## Purpose

Use this matrix to separate controls that can be validated from packets from controls that require firewall administrator evidence.

## Matrix

| Control Area | Externally Testable | Requires Admin/Internal Evidence |
|---|---|---|
| Management plane | Admin ports, web headers, SNMP single-check, vendor service exposure | Admin users, MFA, RBAC, allowed management sources, API tokens, session recording |
| Rulebase quality | Only inferred from exposed services | Any-any rules, public-source allows, object expansion, comments, owners, expiry, hit counts, duplicate/shadow rules |
| Default deny | Filtered/no-response ports, explicit open services | Installed policy, final cleanup/drop rule, logging on denies |
| NAT/port forwards | Internet-facing TCP/UDP exposure | NAT table, automatic NAT objects, business owner, last-hit timestamps |
| Segmentation | Only from the current vantage point | Scans from user, server, DMZ, management, and VPN-pool networks |
| VPN | IKE/IKEv2/NAT-T, Aggressive Mode, portal TLS, exposed VPN ports | VPN communities, IKE proposals, auth method, MFA, allowed groups, split tunnel |
| DNS | Recursion, AXFR, CHAOS, ANY, DNSSEC response size | Resolver role, allowed recursion ACL, rate limiting, logs, software/version |
| Threat Prevention | Sometimes visible through blocked probes, not reliable | Enabled blades, IPS profile, signatures, prevent/detect mode, exceptions |
| Logging/Monitoring | Generate test events | Firewall/SIEM confirmation, alert rules, retention, time sync |
| Patch posture | Banners and safe CVE correlation | Exact version, build, hotfix/Jumbo Take, EOL status |
| Resilience/HA | Usually not safe externally | HA state, failover test, backups, restore test, capacity telemetry |

## Evidence request checklist

Ask administrators for:

- Firewall model, OS version, build, hotfix/Jumbo Take.
- Enabled blades/features/modules.
- Rulebase export with UUIDs, objects, comments, owners, hit counts, disabled rules.
- NAT table and inbound service ownership.
- VPN configuration, proposals, authentication, user/group rules.
- Management access policy and admin account/MFA evidence.
- Threat Prevention policy, signature update status, exceptions.
- Logs for the test window and SIEM alert screenshots.
- HA/failover status, backup/restore proof, capacity graphs, NTP status.

## Reporting guidance

- Put confirmed packet-derived issues in Findings.
- Put missing admin evidence in Required Evidence or Limitations.
- Do not downgrade a confirmed external exposure because internal evidence is missing.
- Do not upgrade a potential CVE to confirmed without version/config or authorized exploit proof.

