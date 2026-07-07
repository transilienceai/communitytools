# External Firewall Posture

## When this applies

- The target is a firewall, VPN gateway, perimeter resolver, WAF edge, secure web gateway, or network security appliance.
- You have IPs, hostnames, or CIDRs but do not have a firewall rulebase export.
- Goal is to classify what can be proven externally versus what requires firewall administrator evidence.

Use `skills/firewall-review` instead when the operator provides a ruleset/config export.

## Safety boundaries

- Do not perform DoS, brute force, fuzzing, credential spraying, or exploit/file-read payloads unless the rules of engagement explicitly allow them.
- Treat CVE checks as correlation unless exploit validation is explicitly authorized.
- Prefer single-probe or bounded checks for UDP and management protocols.
- Save every raw command output under `raw/` and report limitations plainly.

## Output matrix

For each control, mark one of:

| Status | Meaning |
|---|---|
| Confirmed Finding | Externally demonstrated issue with non-destructive evidence |
| Not Observed | Safe external checks did not observe the issue |
| Partially Confirmed | Exposure or precondition observed, but full risk requires admin evidence |
| Requires Admin Evidence | Cannot be proven from packets alone |
| Requires Internal Vantage | Needs scans from user/server/DMZ/management/VPN networks |

## Baseline workflow

1. **Intake**
   - Targets, owner, test window, source IP, permitted protocols, forbidden actions.
   - Confirm DoS/brute-force/exploit boundaries.
2. **Exposure discovery**
   - Host discovery when useful.
   - Full TCP or approved bounded TCP scan.
   - Focused firewall/VPN/admin ports.
   - Bounded UDP checks with protocol-specific probes where possible.
3. **Management-plane checks**
   - See `management-plane-exposure.md`.
4. **DNS resolver checks**
   - See `dns-resolver-posture.md`.
5. **VPN gateway checks**
   - See `vpn-gateway-posture.md`.
6. **Vendor-specific checks**
   - Read the relevant vendor reference, for example `../../vendors/check-point-gateway.md`.
7. **CVE correlation**
   - See `safe-cve-correlation.md`.
8. **Control evidence matrix**
   - See `control-evidence-matrix.md`.

## Focused TCP ports

Start with common management, VPN, and firewall-appliance ports:

```bash
PORTS="22,23,25,53,80,81,110,143,179,264,389,443,444,445,465,500,563,587,636,808,989,990,993,995,1723,3389,4443,5000,5001,5060,5061,5432,5900,8000,8008,8080,8081,8443,8834,9000,9443,10000,10443,18190,18210,18231,18232,18233,18234,18264,19009"
nmap -Pn -sV --version-light -p "$PORTS" --reason -oA raw/tcp-firewall-focused TARGET
```

When root is unavailable, use TCP connect:

```bash
nmap -Pn -sT -sV --version-light -p "$PORTS" --reason -oA raw/tcp-firewall-focused TARGET
```

## Full TCP exposure

Use when approved and target count is small:

```bash
nmap -Pn -sS -p- --min-rate 1000 --max-retries 2 --reason --open -oA raw/tcp-full TARGET
```

If SYN scan is unavailable:

```bash
nmap -Pn -sT -p- --max-retries 2 --reason --open -oA raw/tcp-full TARGET
```

## UDP posture

Raw UDP scans require root and can be slow/ambiguous. Prefer protocol-specific checks for DNS, SNMP, NTP, and IKE.

```bash
nmap -Pn -sU -p 53,123,161,500,4500 --max-retries 1 --reason -oA raw/udp-focused TARGET
```

If raw UDP is unavailable, document the limitation and use protocol-specific tools:

- DNS: `dig`
- IKE/IPsec: `ike-scan`
- SNMP: single `snmpget` with `public` only when allowed; no community brute force
- NTP: `ntpq` or `ntpdate` if installed; avoid monlist DoS-style testing unless explicitly authorized

## Report-ready summary

Every firewall posture report should include:

- Confirmed external exposure.
- Potential CVE exposure and why it is not confirmed.
- Negative observations.
- Required admin evidence.
- Internal vantage tests still needed.
- Raw evidence paths.

