# Cloud Posture Review — router

Credentialed, **read-only** configuration review of a cloud tenancy against a pinned control
catalogue. This is the *verdict lane*: every applicable control gets one explicit verdict with
evidence. It is not the same job as the offensive scenarios in
[`../scenarios/`](../scenarios/) — those exploit a cloud you are attacking; this one assesses a
cloud you have been given keys to. Keep the two apart in reporting: an exploited finding and an
unmet control are different artifacts.

## When to use

A tenancy/subscription/cluster is in scope and you hold read-only credentials for it, and the ask
is "review the configuration" (CSPM, cloud posture, benchmark alignment, hardening review).

## Run order

1. **Bind identity to scope — first call, fail closed.** Prove which tenancy/subscription/cluster
   the credential actually belongs to, and stop if it is not the authorised one. `kubectl` defaults
   to `current-context`, and a cloud CLI picks up ambient credentials, so an unbound run can
   enumerate a third party. See [`posture-collect.md`](posture-collect.md).
2. **Collect** — read-only inventory into a raw JSON tree, one file per service per scope unit,
   each carrying the resource OCID/ARN/id and a collection timestamp.
3. **Assess** — evaluate every control in the catalogue against the collected tree. Every control
   gets a verdict; none are skipped silently.
4. **Report** — verdicts become findings via the normal spine (`report_data_build.py` →
   `generate_report.py`). NOT_MET controls become findings; MET controls are the evidenced
   negative that makes the coverage claim real.

## Verdict vocabulary

Exactly these five. A control that is genuinely not applicable is `NOT_APPLICABLE` **with a
reason**; a control that cannot be settled from the API is `REQUIRES_MANUAL_REVIEW` **with what a
human must judge**. Neither is a silent pass.

| Verdict | Meaning |
|---|---|
| `MET` | Evidence shows the control's PASS condition holds |
| `NOT_MET` | Evidence shows it does not — this becomes a finding |
| `PARTIALLY_MET` | Holds for some resources in scope, not all — list which |
| `NOT_APPLICABLE` | The service or feature is not in use; state why |
| `REQUIRES_MANUAL_REVIEW` | The API cannot settle it; state what judgement is needed |

## Exhaustiveness — the part that is easy to get wrong

A cloud posture review is only worth anything if it covers the whole estate. Four traps produce a
**false pass**, and each has bitten real assessments:

- **Compartment/resource-group traversal.** Most OCI checks must walk the whole compartment
  subtree, not the root. A query scoped to one compartment silently reports clean.
- **Regional resources.** Many resources exist per-region. A single-region check misses everything
  elsewhere; enumerate subscribed regions and loop.
- **Inherited vs set.** A setting that is absent may be inheriting a safe default — or an unsafe
  one. Read the effective value, not the presence of a key.
- **Identity domains vs legacy IAM.** OCI tenancies may use either; the user and policy surface
  differs. Detect which before assessing identity controls.

Prefer a tenancy-wide query where one exists (OCI's `oci search resource structured-search` answers
many controls in one call) over an N-compartment walk — fewer calls and no traversal gap.

## Catalogues

Pinned, versioned control sets. One per framework, all sharing one schema so the assessor and the
validator are provider-agnostic.

| Catalogue | Framework | Provider |
|---|---|---|
| [`catalog/cis-oci-foundations-v3.1.1.json`](catalog/cis-oci-foundations-v3.1.1.json) | CIS OCI Foundations Benchmark v3.1.1 — 54 controls | Oracle Cloud |
| [`catalog/mcsb-azure-foundations-v1.json`](catalog/mcsb-azure-foundations-v1.json) | Microsoft Cloud Security Benchmark — 42 controls | Azure |
| [`catalog/nsa-cisa-k8s-hardening-1.2.json`](catalog/nsa-cisa-k8s-hardening-1.2.json) | NSA/CISA Kubernetes Hardening Guide — 30 controls | Kubernetes |

Why these sources rather than a CIS benchmark for each: **Microsoft Cloud Security Benchmark** is
Microsoft's own guidance and ships their crosswalks to CIS, NIST SP 800-53, ISO 27001 and PCI DSS,
so a compliance column cites Microsoft's mapping instead of one we invented — and the "which CIS
Azure edition, at which profile level" question never arises. The **NSA/CISA Kubernetes Hardening
Guide** is a US-government work in the public domain, making it the one source here that could be
quoted directly rather than only cited.

Validate any catalogue with `python3 tools/posture/catalog_validate.py --all`. It is the only thing
checking these files: `scripts/skill_linter.py` globs `*.md`, so catalogue JSON is otherwise
unlinted. Every catalogue ships its validator run in the same PR that adds it.

### Catalogue entry contract

```
control_id     the framework's own numbering (e.g. "1.7") — the citable identifier
section        top-level grouping, must prefix control_id
level          1 or 2 (profile level)
assessment     "Automated" | "Manual"
service        the cloud service the control governs
title          OUR wording of the objective
objective      one sentence: what secure looks like and why
procedure      how an assessor determines the state, concretely
api            real CLI/API invocations that yield the evidence
evidence       the exact artifact proving the verdict (which field, which id)
verdict_rule   the deterministic PASS condition
remediation    how to fix it
caveat         optional; REQUIRED for Manual — what a human must judge, or how a naive
               check produces a false pass
```

## Licensing — read before adding a catalogue

**Benchmark text is not ours to republish.** The CIS Benchmark Terms of Use require written
guidance from CIS Legal to cite benchmarks in third-party documentation *including using portions
of Benchmark Recommendations*, state that hosting a benchmark in any format on a non-CIS site is
never acceptable, and make the benchmarks free for **non-commercial** use only.

The consequences are structural, not stylistic:

- A catalogue carries the **control number, level and assessment status** — identifiers and facts —
  plus **our own title, procedure, evidence rule and remediation**, written from the cloud
  provider's own public API documentation.
- The source PDF never enters the repo. Keep it out via `.gitignore`.
- Deliverables say **"CIS-aligned"** and cite control numbers. They do not claim a certified CIS
  Benchmark assessment unless the engagement holds a CIS SecureSuite licence.
- `catalog_validate.py` enforces this: it rejects authoring-aid fields, source house-style titles,
  and phrasing lifted from the benchmark document.

The same reasoning applies per source. Public-domain frameworks (NIST SP 800-53/800-115, CISA
SCuBA, the NSA/CISA Kubernetes Hardening Guide) may be quoted directly; OWASP is CC BY-SA, so ids
and our own prose; CIS and OSSTMM are restricted as above.

## See also

- [`posture-collect.md`](posture-collect.md) — identity binding, collection tree, partial-collection semantics
- [`../scenarios/`](../scenarios/) — the offensive counterpart (attack, not assess)
- [`../../../cloud-defense/SKILL.md`](../../../cloud-defense/SKILL.md) — turning a posture finding into detection + hardening
