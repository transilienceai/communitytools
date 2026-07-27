# Skill / detector / parser version pins — single source of truth

Every artefact this tool emits carries `chain_of_custody.detector_version` and `chain_of_custody.parser_version`. This file is the canonical map. **Skill `.md` frontmatter and inline citations should reference this table — do not duplicate version strings inside individual skill files.**

If the running detector emits a version not listed here, the build is drifting; reconcile here first.

Last updated: 2026-07-27 — added 5 FortiGate-specific detectors, the semantic-check catalogue (v1.0.0), the CIS Fortinet FortiGate Benchmark, the evidence-state contract, and the consolidated network-team workbook profiles including grouped observation/severity presentation.
The inherited skill metadata records detector/parser pins as last verified on 2026-04-25 from `examples/demo-acme-pharmaceuticals_2026-04-24/findings.draft.jsonl`. This contribution could not independently re-verify that statement because the cited runtime repository was inaccessible; see [`IMPLEMENTATION_STATUS.md`](IMPLEMENTATION_STATUS.md).

---

## Tool

| Component | Version |
|---|---|
| `firewall-review` (orchestrator) | `0.1.0` |

## Parsers (`fwrr.parsers.*`)

| Parser | Version | Skill |
|---|---|---|
| `fortigate` | `0.2.0` | `vendor-parsers/fortigate-parser/` |
| `palo-alto` | `0.1.0` | `vendor-parsers/palo-alto-parser/` |
| `cisco-asa` | `0.1.0` | `vendor-parsers/cisco-asa-parser/` |
| `cisco-ios` | `0.1.0` | `vendor-parsers/cisco-ios-parser/` |
| `azure-nsg` | `0.1.0` | `vendor-parsers/azure-nsg-parser/` |
| `aws-sg` | `0.1.0` | `vendor-parsers/aws-sg-parser/` |
| `iptables` | `0.1.0` | `vendor-parsers/iptables-parser/` |

## Detectors (`fwrr.detectors.*`)

| Detector | Version | Severity (default) | Skill |
|---|---|---|---|
| `any-any-broadness` | `0.2.0` | Critical/High/Medium (scales) | `detectors/any-any-broadness/` |
| `public-source-allow` | `0.2.0` | Critical | `detectors/public-source-allow/` |
| `allow-any-ip` | `0.2.0` | Medium | `detectors/allow-any-ip/` |
| `allow-any-protocol` | `0.2.0` | Medium | `detectors/allow-any-protocol/` |
| `allow-icmp` | `0.2.0` | Low | `detectors/allow-icmp/` |
| `admin-services-exposure` | `0.2.0` | High | `detectors/admin-services-exposure/` |
| `cleartext-service` | `0.2.0` | High | `detectors/cleartext-service/` |
| `port-range-too-broad` | `0.1.0` | High | `detectors/port-range-too-broad/` |
| `risky-service` | `0.1.0` | Medium | `detectors/risky-service/` |
| `object-group-expansion` | `0.2.0` | (re-runs inner detectors) | `detectors/object-group-expansion/` |
| `default-deny-presence` | `0.2.0` | Info / Critical (when missing) | `detectors/default-deny-presence/` |
| `rules-end-with-drop-all-and-log` | `0.2.0` | Info | `detectors/rules-end-with-drop-all-and-log/` |
| `unused-rule` | `0.2.0` | Info / RequiresManualReview | `detectors/unused-rule/` |
| `duplicate-rule` | `0.2.0` | Info | `detectors/duplicate-rule/` |
| `shadow-rule` | `0.2.0` | (context-dependent) | `detectors/shadow-rule/` |
| `contradicting-rule` | `0.2.0` | (context-dependent) | `detectors/contradicting-rule/` |
| `rules-no-comments` | `0.1.0` | Info | `detectors/rules-no-comments/` |
| `admin-timeout-excess` | `0.1.0` | High | `detectors/admin-timeout-excess/` — FortiGate |
| `sslvpn-timeout-excess` | `0.1.0` | High | `detectors/sslvpn-timeout-excess/` — FortiGate |
| `super-admin-trusthost` | `0.1.0` | Critical | `detectors/super-admin-trusthost/` — FortiGate |
| `utm-status-orphan` | `0.1.0` | Medium | `detectors/utm-status-orphan/` — FortiGate |
| `service-all-ports` | `0.1.0` | High | `detectors/service-all-ports/` — FortiGate |

## Semantic-check catalogue (`fwrr.semantic.*`)

| Component | Version | Skill |
|---|---|---|
| `semantic-check-catalogue` | `1.0.0` | `semantic/semantic-check-catalogue.md` |

15 named checks across 7 categories. Five have been promoted to deterministic detectors (`SEM-011/012/021/031/060`); the rest run as the auditable LLM pass.

## Validation passes (`fwrr.validation.*`)

| Module | Version | Skill |
|---|---|---|
| `precedence-awareness` | `0.1.0` | `validation/precedence-awareness/` |
| `post-process-enrich` | `0.1.0` | `validation/post-process-enrich/` |

## Reporting

| Module | Version | Skill |
|---|---|---|
| `report-writer-excel` | `0.2.0` | `reporting/report-writer-excel/` |
| `report-writer-pdf` | `0.2.0` | `reporting/report-writer-pdf/` |
| `narrative-framer` | `0.1.0` | `reporting/narrative-framer/` |
| `brand-config` | `0.1.0` | `reporting/brand-config/` |

### Skill-only reporting and validation profiles

These are reusable operating contracts, not claims about implemented `fwrr` modules.

| Component | Version | Skill |
|---|---|---|
| `evidence-state-contract` | `1.0.0` | `validation/evidence-state-contract.md` |
| `network-team-review-workbook` | `1.0.0` | `reporting/network-team-review-workbook.md` |
| `custom-policy-benchmark` | `1.0.0` | `semantic/custom-policy-benchmark.md` |

## Personas (`fwrr.personas.*`)

| Persona | Version | Skill |
|---|---|---|
| `citation-verifier` | `0.1.0` | `personas/citation-verifier/` |
| `cto-reviewer` | `0.1.0` | `personas/cto-reviewer/` |
| `ciso-reviewer` | `0.1.0` | `personas/ciso-reviewer/` |
| `qa-reviewer` | `0.1.0` | `personas/qa-reviewer/` |
| `senior-pentester` | `0.1.0` | `personas/senior-pentester/` |

## Compliance frameworks (pinned)

| Framework | Pinned version | Source | Skill |
|---|---|---|---|
| NIST CSF | `2.0` (Feb 2024) | nist.gov/cyberframework | `compliance/nist-csf-2/` |
| PCI DSS | `v4.0.1` (June 2024) | pcisecuritystandards.org | `compliance/pci-dss-4.0.1/` |
| ISO/IEC 27001 | `2022` (Oct 2022) | iso.org | `compliance/iso-27001-2022/` |
| CIS Controls | `v8.1` (June 2024) | cisecurity.org/controls/v8-1 | `compliance/cis-controls-v8.1/` |
| HIPAA Security Rule | `45 CFR §164` (2013 Final Rule) | hhs.gov/hipaa | (no skill — referenced inline) |
| GDPR | `Reg. 2016/679` | eur-lex.europa.eu | (no skill — referenced inline) |

## Benchmarks

| Benchmark | Pinned version | Source | Skill |
|---|---|---|---|
| CIS Fortinet FortiGate Benchmark | CIS FortiOS — 64 checks (45 deterministic, 19 advisory) | cisecurity.org | `compliance/cis-fortigate-benchmark/` |

Distinct from the CIS Controls v8.1 mapping above: this is a product-hardening benchmark, not a controls framework. Do not mix a benchmark check number with a control safeguard number in a finding's `framework_refs`.

## Drift policy

When a detector emits a version pin not in this table, the citation-verifier should quarantine the finding and surface to the operator. Same for parser versions.

When the operator bumps a detector version (e.g. `any-any-broadness:0.2.0 → 0.3.0`), update:
1. The detector's `_version` constant in [`lib/fwrr/detectors/<name>.py`](https://github.com/ipunithgowda/firewall-review/blob/main/lib/fwrr/detectors/<name>.py)
2. This table
3. CHANGELOG.md with the per-detector behaviour delta

The detector skill files do NOT carry version strings in frontmatter — they reference this table.
