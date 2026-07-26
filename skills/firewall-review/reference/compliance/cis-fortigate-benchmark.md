<!-- ../compliance/cis-fortigate-benchmark.md -->
---
name: cis-fortigate-benchmark
description: Deterministic CIS Fortinet FortiGate Benchmark checker — 64 catalogued CIS FortiOS checks re-implemented as config inspectors. 45 carry deterministic PASSED/FAILED logic; 19 runtime-only checks return WARNING, consistent with a Nessus CIS scan.
---

# CIS Fortinet FortiGate Benchmark

**Capability status:** this page documents the catalogue described in PR #32. The inspector runtime and its test evidence are not shipped in `communitytools` and could not be independently executed during current validation; see [`../IMPLEMENTATION_STATUS.md`](../IMPLEMENTATION_STATUS.md).

**Reference implementation:** `scripts/cis_fortigate.py` in [firewall-review](https://github.com/ipunithgowda/firewall-review)
**Benchmark:** CIS Fortinet FortiGate Benchmark (CIS FortiOS)
**API:** `run(config_text: str) -> {check_id: "PASSED" | "FAILED" | "WARNING"}`

## What this layer is

The vendor-agnostic detectors evaluate rule quality: is this rule too broad, is this service cleartext, is there a default-deny. The CIS FortiGate benchmark checker answers a different question — is this device configured to the CIS hardening baseline for FortiOS. It re-implements the 64 catalogued CIS FortiOS checks as inspectors of the config text and structure, so it runs offline against a config export with no access to the live device.

## The 45 / 19 split

- **45 checks carry deterministic PASSED/FAILED logic.** These are settings that are fully determinable from the config: password policy, timeout values, logging destinations, insecure-protocol toggles, SNMP community strings, and similar. They evaluate the same way every run.
- **19 checks return WARNING for every device.** These are the CIS items that cannot be settled from a static config export: firmware currency, removal of the default admin account, profile-to-policy judgement calls, Security Fabric posture, HA health monitoring. A Nessus CIS compliance scan reports these same items as WARNING, and this checker matches that behaviour deliberately so the two outputs reconcile.

## Design rule: no per-device hardcoding

Every check is a real inspector of the config text or structure, so it generalises to any FortiGate config with no ground truth. The checker was calibrated to reproduce a known-good Nessus CIS result on one reference device, then applied unchanged to the remaining configs. The calibration exists to prove the inspectors agree with an independent tool on a device where the answer is known; it is not a lookup table of expected results. A config the checker has never seen gets the same deterministic logic.

## How it fits the pipeline

The benchmark pass is complementary to the rule-quality detectors, not a replacement. A device can have a clean ruleset and still fail CIS hardening (weak password policy, verbose SNMP, no admin timeout), and vice versa. Reporting surfaces the benchmark result as its own section with the per-device PASSED / FAILED / WARNING counts, and the WARNING items feed the engagement Limitations section as "requires runtime verification".

## Framework note

This is a benchmark checker pinned to the CIS Fortinet FortiGate Benchmark. It is distinct from `compliance/cis-controls-v8.1.md`, which maps the vendor-agnostic detectors to the CIS Critical Security Controls v8.1. One is a product-hardening benchmark; the other is a controls framework. Keep the two citations separate — a finding's `framework_refs` should never mix a CIS Benchmark check number with a CIS Control safeguard number.
