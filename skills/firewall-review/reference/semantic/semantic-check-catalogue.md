<!-- ../semantic/semantic-check-catalogue.md -->
---
name: semantic-check-catalogue
description: Structured, named-question replacement for the ad-hoc senior-pentester LLM pass. A fixed catalogue of context-dependent checks the agent answers per firewall, producing an auditable coverage matrix instead of a free-form finding list.
---

# Semantic-Check Catalogue

**Capability status:** this page documents the catalogue described in PR #32. The cited catalogue YAML/runtime is not shipped in `communitytools` and could not be independently executed during current validation; see [`../IMPLEMENTATION_STATUS.md`](../IMPLEMENTATION_STATUS.md).

**Reference implementation:** `.claude/semantic-checks/catalogue.yaml` + `fwrr.semantic.*` in [firewall-review](https://github.com/ipunithgowda/firewall-review)
**Catalogue version:** `1.0.0`
**Output:** a `semantic-coverage.json` matrix per engagement (checks_run / pass / fail / cant_tell / not_applicable, per firewall)

## What this layer is

The deterministic detector layer covers structural checks: broad rules, cleartext services, missing default-deny, and static shadow candidates. It runs at temperature 0 and is fully reproducible. It cannot, by design, reason about context: whether a source object is genuinely untrusted, whether a management path crosses a tenancy boundary, whether an egress rule to a partner is monitored, or whether incomplete match dimensions change a candidate relationship.

That contextual reasoning was previously the job of an ad-hoc senior-pentester LLM pass, which produced 5 to 15 findings that varied run to run. The semantic-check catalogue replaces that with a fixed list of named questions. The same checks run every engagement, on every device, with the same prompts and the same evidence requirements. The operator can then point at the list and say "we checked these things, here is the verdict per device" — the Nipper-class property of an auditable, repeatable pass, applied to the LLM layer.

## Catalogue shape

`catalogue.yaml` holds 15 checks across 7 categories:

| Category | Checks | Focus |
|---|---|---|
| trust-boundary | 3 | untrusted-zone source reaching trusted-zone destination with broad objects |
| management-plane | 3 | admin / management access exposure and hardening |
| authentication-on-regulated-paths | 2 | timeouts and auth strength on paths into regulated scope |
| egress-monitoring | 2 | outbound paths that are unmonitored or unrestricted |
| segmentation | 2 | segment-to-segment traffic that undercuts declared zoning |
| multi-tenant / cross-vdom | 2 | tenancy-boundary leakage across VDOMs |
| service-object hygiene | 1 | service objects that defeat least-port enforcement |

Each check carries a stable `id` (SEM-XXX, never reused), a `severity_default`, an `applies_to` vendor list, version-pinned `framework_refs`, a one-sentence `question` the agent answers YES / NO / CANT-TELL, an `evaluation` block describing what counts as pass, fail, and common false-positive shapes, and an `evidence_required` block naming what must be quoted from source to substantiate a finding.

## Relationship to the deterministic detectors

Five catalogue checks have been promoted to deterministic Python detectors, because their signal turned out to be structural enough to evaluate without an LLM: SEM-011 (`admin-timeout-excess`), SEM-012 (`super-admin-trusthost`), SEM-021 (`sslvpn-timeout-excess`), SEM-031 (`utm-status-orphan`), and SEM-060 (`service-all-ports`). Promotion is the intended lifecycle: a check starts as an LLM question, and once its evaluation is crisp and false-positive-free, it moves to a temperature-0 detector and stops depending on the model. The remaining catalogue checks stay in the LLM pass because they need judgement the config text alone does not settle.

## Why a coverage matrix, not a finding list

A free-form finding list answers "what did we find". A coverage matrix answers the harder audit question: "what did we look for, and what did we conclude for each item". `cant_tell` is a first-class outcome. A check that cannot be resolved without traffic logs is recorded as `cant_tell`, not silently dropped, and it surfaces in the engagement's Limitations section. That is the honest position, and it is the one an auditor can defend.

## Custom customer benchmarks

Do not encode customer-specific UAT/DEV-to-PROD, regulated-segment, partner-access, or service-matrix rules as free-form semantic guesses. Use [`custom-policy-benchmark.md`](custom-policy-benchmark.md), which requires an authoritative classification and exception model. Object-name hints may produce `cant_tell` classification candidates only.

Every semantic answer also follows [`../validation/evidence-state-contract.md`](../validation/evidence-state-contract.md). Model confidence or persuasive narrative never substitutes for the required evidence.
