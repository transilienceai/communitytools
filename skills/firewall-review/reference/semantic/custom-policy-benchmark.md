---
name: custom-policy-benchmark
description: Data-driven benchmark for customer-specific firewall policy requirements such as UAT/DEV-to-PROD restrictions, regulated-segment boundaries, approved service matrices, and exception expiry. Requires authoritative classification and policy inputs; naming conventions alone can never produce a confirmed violation.
---

# Custom Policy Benchmark

Use this layer for customer-specific requirements that generic NIST, CIS, PCI DSS, or device-hardening checks cannot decide. Examples include UAT-to-PROD restrictions, PCI/CDE boundaries, partner access, approved management paths, service allowlists, and temporary-rule expiry.

The benchmark evaluates supplied policy. It must not invent the customer's network model.

## Required inputs

Obtain an approved, dated benchmark pack containing:

- segment/zone/object-to-environment mapping;
- protected asset or regulated-scope inventory;
- allowed and prohibited source-environment → destination-environment flows;
- permitted services/applications and direction;
- exception IDs, owners, approvals, and expiry dates;
- policy version, approver, effective date, and in-scope devices/VDOMs.

If an authoritative mapping is missing, emit `CANT-TELL` / `business-context-required`. Object names containing strings such as `UAT`, `DEV`, `PROD`, `PCI`, `CDE`, or `DMZ` may create classification candidates for the network team, but never confirmed failures.

## Minimal benchmark shape

Use YAML or JSON with stable IDs. This example is illustrative and contains no customer policy:

```yaml
benchmark:
  id: customer-policy-example
  version: "1.0"
  approved_by: "<required>"
  effective_date: "<required>"
classifications:
  environments:
    nonprod:
      objects: ["<authoritative object or zone>"]
    prod:
      objects: ["<authoritative object or zone>"]
requirements:
  - id: CUST-SEG-001
    title: Non-production to production access
    source_environment: nonprod
    destination_environment: prod
    action: deny_unless_exception
    allowed_services: []
    exception_required: true
```

Reject a benchmark file that lacks provenance, contains overlapping classifications without precedence, or references objects not found in the supplied inventory. Do not silently infer missing values.

## Evaluation outcomes

| Outcome | Condition |
|---|---|
| `FAIL` | The normalized rule matches a prohibition and every required classification/match field is authoritative |
| `PASS` | The benchmark defines a testable requirement and the assessed policy meets it |
| `CANT-TELL` | Classification, business exception, object expansion, or other required evidence is missing |
| `NOT-APPLICABLE` | Requirement is outside the device/VDOM/direction or no classified asset is present |

Absence of a detected violation is not automatically `PASS`. A pass requires coverage evidence showing that all in-scope rules and required benchmark dimensions were evaluated.

## Deterministic evaluation

For each enabled allow rule:

1. Resolve source and destination objects through the supplied authoritative classification map.
2. Preserve device, VDOM/virtual router, direction, zones/interfaces, schedule, NAT, application/service, and rule order.
3. Expand groups with cycle and unresolved-reference detection.
4. Compare the effective tuple to each applicable requirement.
5. Apply documented exceptions only when ID, owner, approval, scope, and validity period match.
6. Emit one result per requirement/rule pair that fails or cannot be decided.

A confirmed failure must quote the firewall rule and the exact benchmark requirement/version. The reproduction record shows the resolved source/destination classes, compared services, exception lookup, and decision path.

## Report fields

Add these fields to the Network Team Review and coverage matrix:

- benchmark ID/version and requirement ID;
- source/destination environment and classification provenance;
- decision (`FAIL`, `PASS`, `CANT-TELL`, `NOT-APPLICABLE`);
- matched exception ID and validity, if any;
- exact rule evidence and benchmark clause;
- rationale, least-disruptive recommendation, and required business validation.

Customer comments may correct a classification or supply an exception. Record the change as new evidence and rerun the benchmark; do not overwrite the original evaluation without an audit trail.
