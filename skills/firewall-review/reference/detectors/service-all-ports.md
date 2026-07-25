<!-- ../detectors/service-all-ports.md -->
---
name: service-all-ports
description: Flag a FortiGate custom service object whose `tcp-portrange` or `udp-portrange` spans the entire port range (1-65535). Any policy referencing it becomes an effective service=ANY policy.
---

# Service Object Spans All Ports

**Reference implementation:** `fwrr.detectors.service_all_ports.ServiceAllPorts` in [firewall-review](https://github.com/ipunithgowda/firewall-review)
**Version pin:** `service-all-ports:0.1.0`
**Default severity:** High
**Vendor scope:** FortiGate (FortiOS)

## What it checks
Scans `config firewall service custom` blocks for a `set tcp-portrange` or `set udp-portrange` that defines the full range `1-65535` (or an equivalent any-port span). It emits one finding per offending service object, quoting the object name and the port-range line. This is the same read-source-once-per-firewall pattern used by the other FortiGate config detectors.

## Why this matters
Service objects are the mechanism a firewall uses to enforce least-port. A policy that references a service named, say, `SVC-APP-TIER` reads as tightly scoped in the policy table. If that service object is actually defined as `tcp 1-65535`, then every policy referencing it is a service=ANY policy in disguise. The L4 enforcement is gone, and the segmentation the policy appears to provide is an illusion. This is easy to miss on a manual review because the damage lives one level of indirection away from the rule, inside the object definition. Resolving the object back to its port range is exactly the kind of expansion a static analyzer should do for you.

## Frameworks cited
- PCI DSS v4.0.1 — `1.2.1` (restrict inbound and outbound traffic to that which is necessary)
- NIST CSF 2.0 — `PR.IR-01` (networks and environments are protected from unauthorized logical access and usage)
- CIS Controls v8.1 — `12.2` (establish and maintain a secure network architecture)

## Notes and limitations
- FortiGate-specific. The general "port range too broad" concern on other vendors is covered by the vendor-agnostic `port-range-too-broad` detector; this one is the FortiGate service-object variant that resolves the object indirection.
- A service object legitimately defined as any-port for an internal management appliance may be a false positive; precedence-awareness and the operator review pass exist to catch that.
- Named all-services objects such as FortiGate's built-in `ALL` are handled by the broader service=ANY logic, not this custom-object check.
