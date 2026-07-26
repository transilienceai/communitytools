---
name: evidence-state-contract
description: Claim-safety contract for firewall reviews. Separates facts proven by supplied configuration from deterministic derivations, runtime-dependent conclusions, business-context decisions, external-control assertions, and unassessed scope.
---

# Evidence-State Contract

Use this contract before validation and reporting. A technically plausible statement is not a finding until its required evidence exists. Unknowns remain visible as gaps; they are never converted into facts to make a report look complete.

## Evidence states

| State | Meaning | Allowed report wording | Typical evidence |
|---|---|---|---|
| `confirmed-static` | Directly present in the supplied configuration | “Policy 89 is enabled and uses service ALL.” | Exact source file, line/offset, quoted stanza, input hash |
| `derived-static` | Reproducible conclusion from parsed configuration | “Policies 12 and 18 have identical normalized match/action tuples.” | Both quoted rules, normalized fields, detector/version, deterministic comparison |
| `conservative-candidate` | Static evidence suggests a condition, but parser context or platform semantics are incomplete | “Potential shadowing candidate; validate with Policy Lookup before change.” | Candidate and related rule, compared dimensions, missing dimensions |
| `runtime-required` | Traffic or live device state is required | “Usage could not be determined from the configuration.” | Required counter/log/query, requested observation window |
| `business-context-required` | Asset classification, owner, data flow, or justification is required | “The rule permits the named segments; whether this violates UAT-to-PROD policy requires the approved zone matrix.” | Required classification matrix, ticket, owner attestation |
| `external-evidence-required` | The conclusion depends on a system outside the export | “Local configuration does not prove upstream MFA coverage.” | IdP/MFA evidence, FortiManager policy package, SIEM, routing or SD-WAN state |
| `not-assessed` | Input was missing, partial, unsupported, or outside scope | “Firewall policy coverage was not assessed for VDOM X because its policy block was not supplied.” | Missing-input record and exact re-export request |

`confirmed-static` and `derived-static` may be reported as confirmed observations. The other states must use `Needs Review`, `CANT-TELL`, `WARNING`, or an equivalent non-assertive status. Severity does not upgrade evidence quality.

## Required claim test

For every observation, record:

1. **Claim** — one narrow statement that the evidence supports.
2. **Evidence** — exact config excerpt or named external/runtime artefact.
3. **Reproduction / PoC** — deterministic steps or field comparison that another reviewer can repeat. For configuration audits, a PoC is evidence reproduction, not exploitation.
4. **Rationale** — why the proven condition matters.
5. **Recommendation** — the least disruptive safe next action.
6. **Evidence state and confidence** — never inferred from severity.
7. **Validation required** — explicit when the state is not confirmed.

If any claim word exceeds the evidence, narrow the claim. Do not compensate with generic framework language.

## Prohibited inferences

| Available evidence | Do not claim | Safe conclusion |
|---|---|---|
| Configuration only; no counters or logs | “Unused rule” or “zero hits” | Usage not assessed; request counters/logs for a defined window |
| `status disable`, expired schedule, or names such as `temp` / `old` | Unused, obsolete, or safe to delete | Lifecycle review candidate; obtain owner and change history |
| Object names containing UAT, DEV, PROD, PCI, CDE, or DMZ | Confirmed prohibited inter-environment flow | Candidate classification; validate the authoritative zone/asset matrix |
| A configured VIP or public address object | Active Internet exposure | Potential exposure; validate interface binding, routing, policy order, NAT, and live reachability |
| A FortiOS version appearing in an advisory range | Exploitation or compromise | Version may be affected; verify exact build, mitigation, and vendor advisory status |
| No local firewall MFA setting | MFA is absent | Local export does not establish whether upstream IdP/MFA is enforced |
| A broad rule with UTM profiles | Safe or compliant | Broad match remains; UTM is a compensating control whose coverage must be evaluated separately |
| Static superset comparison without full match dimensions | Definitively shadowed or redundant | Potential overlap/shadow candidate requiring semantic or runtime validation |

## Runtime and business evidence ledger

Record each unavailable dependency once and link affected observations to it. Minimum gap classes:

- `TRAFFIC`: hit counts, first/last used, log coverage, counter-reset time, observation window.
- `POLICY_EVAL`: Policy Lookup result, active sessions, dynamic address/FQDN resolution, route and SD-WAN selection.
- `CLASSIFICATION`: source/destination environment, asset criticality, regulated scope, approved UAT/DEV-to-PROD matrix.
- `OWNERSHIP`: business owner, purpose, ticket, expiry, recertification decision.
- `CENTRAL_CONTROL`: FortiManager package/overlays, FortiAnalyzer/SIEM retention, upstream proxy/WAF/IPS controls.
- `IDENTITY`: IdP, MFA, authentication policy, privileged-access workflow.
- `COMPLETENESS`: omitted VDOM/policy block, truncated export, unsupported syntax, unresolved objects.

## Mapping to the current schema

The runtime schema currently provides `confidence` and `validation_status`, not a dedicated `evidence_state` field. Until the schema changes:

- retain the evidence state as a report/workbook column and in validation notes;
- map `confirmed-static` / `derived-static` to `Confirmed` only after citation verification;
- map every other state to `Needs Review`;
- put missing dependencies in the Limitations/Evidence Gaps sheet rather than dropping the observation;
- do not store an evidence state in an unrelated field or silently overload severity.

## Release gate

Before delivery, reject or downgrade any row that:

- lacks a source citation for a static claim;
- labels a rule zero-hit without a device-scoped observation window and counter provenance;
- labels a rule shadowed when protocol, direction/zone, schedule, NAT context, order, or object expansion is unresolved;
- asserts a business-policy violation from naming conventions alone;
- recommends deletion without validation and rollback steps;
- reports complete coverage while any in-scope policy block was not parsed.
