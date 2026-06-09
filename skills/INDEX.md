# Skill Router

Single navigation surface. Coordinator reads this once at engagement start to pick mounts. Each skill: one-line purpose, primary trigger, "use with" relationships.

## Coordination & Workflow

| Skill | Purpose | Trigger |
|-------|---------|---------|
| [`coordination`](coordination/SKILL.md) | Orchestrate executor / validator / skeptic agents | Every engagement — entry point |
| [`pentest-engagement`](pentest-engagement/SKILL.md) | Scoped web/API/cloud pentest from a scope file — surface expansion → OWASP attack-class coverage → validate → Transilience PDF | A real (non-CTF) pentest defined by a scope file |
| [`hackthebox`](hackthebox/SKILL.md) | Solve HackTheBox challenges/machines/fortresses (flag-shaped) | CTF / HTB target |
| [`skill-update`](skill-update/SKILL.md) | Add or refine skill content from engagement learnings | Post-engagement (parent orchestrator only) |
| [`patt-fetcher`](patt-fetcher/SKILL.md) | Fetch PayloadAllTheThings payloads on demand | Executor needs a comprehensive payload list |
| [`script-generator`](script-generator/SKILL.md) | Generate validated, syntax-checked scripts | Need a tool but no PoC exists yet |

## Cloud-Agent Pipeline (RFP §3.2 / §3.3)

Skills consumed by the cloud-agent task specifications under [`projects/rfp-3.2/`](../projects/rfp-3.2/CLAUDE.md) and [`projects/rfp-3.3/`](../projects/rfp-3.3/CLAUDE.md). They run on schedules or webhook events, not interactively.

| Skill | Purpose | Trigger |
|-------|---------|---------|
| [`ti-ingest`](ti-ingest/SKILL.md) | Convert TI webhook payloads (CVE + asset + claim) to engagement-scope rows | TI platform webhook (task-01) |
| [`regression-sweep`](regression-sweep/SKILL.md) | Weekly re-validation of every confirmed finding; flags drift | Cron Mondays (task-04) |
| [`attack-path-stitcher`](attack-path-stitcher/SKILL.md) | Stitch confirmed single-asset findings into multi-hop attack paths across the org | Cron daily after validation (task-06) |
| [`risk-prioritiser`](risk-prioritiser/SKILL.md) | Rank attack paths by `feasibility × CVSS × business_impact` | Cron daily after stitcher (task-07) |

## Recon & Surface Mapping

| Skill | Purpose | Trigger | Use with |
|-------|---------|---------|----------|
| [`reconnaissance`](reconnaissance/SKILL.md) | Subdomain, port, endpoint, API surface mapping | First batch of any web/network engagement | techstack-identification |
| [`osint`](osint/SKILL.md) | Repo enumeration, secret scanning, employee footprint | Pre-engagement intel, public-source analysis | reconnaissance |
| [`techstack-identification`](techstack-identification/SKILL.md) | Tech-stack inference from public signals | Need to choose attack class from observed surface | reconnaissance, osint |

## Web Application

| Skill | Purpose | Trigger |
|-------|---------|---------|
| [`injection`](injection/SKILL.md) | SQL / NoSQL / OS command / SSTI / XXE / LDAP injection | User input reaches a parser/interpreter |
| [`server-side`](server-side/SKILL.md) | SSRF, HTTP smuggling, path traversal, file upload, deserialization, host-header | Server processes untrusted data |
| [`client-side`](client-side/SKILL.md) | XSS (R/S/DOM), CSRF, clickjacking, CORS, prototype pollution | Browser executes attacker-controlled content |
| [`api-security`](api-security/SKILL.md) | GraphQL, REST, WebSocket, Web LLM | API surface in scope |
| [`authentication`](authentication/SKILL.md) | Auth bypass, JWT, OAuth, password attacks, 2FA | Login/session in scope |
| [`web-app-logic`](web-app-logic/SKILL.md) | Race conditions, IDOR, mass assignment, cache poisoning, business logic | Application logic gates a privileged action |

## Network & System

| Skill | Purpose | Trigger |
|-------|---------|---------|
| [`infrastructure`](infrastructure/SKILL.md) | Port scanning, DNS, SMB/NetBIOS, MITM, IPv6, ICS, hardware/embedded, UPnP/IoT | Non-HTTP services in scope |
| [`system`](system/SKILL.md) | Active Directory, privilege escalation (Linux + Windows), exploit dev | Foothold + need privesc, or AD environment |
| [`cloud-containers`](cloud-containers/SKILL.md) | AWS, Azure, GCP, Docker, Kubernetes | Cloud or container target |

## Specialized

| Skill | Purpose | Trigger |
|-------|---------|---------|
| [`blockchain-security`](blockchain-security/SKILL.md) | Solidity, EVM, smart contract exploitation | Smart contract target |
| [`ai-threat-testing`](ai-threat-testing/SKILL.md) | Prompt injection, model extraction, RAG poisoning, OWASP LLM Top 10 | LLM-backed application |
| [`cryptography`](cryptography/SKILL.md) | Lattice / AGCD / linear-collapse cryptanalysis, padding oracles, secret-sharing recovery | Custom crypto, structured RSA, oracle exposure |
| [`reverse-engineering`](reverse-engineering/SKILL.md) | Static analysis of ELF/PE, custom-VM bytecode, callfuscation, MBA deobfuscation | Compiled binary / custom-ISA program-data file |
| [`mobile-security`](mobile-security/SKILL.md) | Android / iOS app testing — Flutter AOT, IL2CPP, smali, Frida, root-detection bypass | Mobile APK / IPA target |
| [`social-engineering`](social-engineering/SKILL.md) | Phishing, pretexting, vishing, physical sec | People-in-scope authorized engagements |
| [`dfir`](dfir/SKILL.md) | Forensic Sherlocks, network/memory/log analysis, AD attack detection | Defensive / IR / Sherlock challenge |
| [`firewall-review`](firewall-review/SKILL.md) | Static firewall ruleset audit (FortiGate, PAN, ASA, NSG, SG, iptables) | Firewall config provided |
| [`pci-secure-software`](pci-secure-software/SKILL.md) | Automated PCI Secure Software Standard (SSS) v2.0 readiness gap-assessment from source + docs — deterministic Test-Requirement catalog, evidence-bound per-requirement verdicts with blind refutation + citation verification, Transilience gap report | A PCI SSS v2.0 / Secure Software Standard readiness or gap assessment of an application |

## Tooling & Methodology

| Skill | Purpose | Trigger |
|-------|---------|---------|
| [`essential-tools`](essential-tools/SKILL.md) | Burp, Playwright, binary analysis, methodology | Cross-cutting tooling reference |
| [`source-code-scanning`](source-code-scanning/SKILL.md) | SAST, dependency CVEs, secret scanning, malicious-code detection | Source provided |
| [`cve-poc-generator`](cve-poc-generator/SKILL.md) | Research a CVE and produce a PoC + report | CVE in scope, no public PoC found |
| [`cve-risk-score`](cve-risk-score/SKILL.md) | Fetch authoritative CVSS/CWE from NVD | Any CVE mentioned anywhere |

## Platform Operations

| Skill | Purpose | Notes |
|-------|---------|-------|
| [`hackthebox`](hackthebox/SKILL.md) | HackTheBox-platform-specific operations (API, VPN, login flow) | Loaded only when target is on this platform |
| [`hackerone`](hackerone/SKILL.md) | HackerOne workflow (scope CSV parsing, submission format) | Bug bounty engagements |

## Workflow

| Skill | Purpose | Trigger |
|-------|---------|---------|
| [`github-workflow`](github-workflow/SKILL.md) | Branch / commit / PR / issue management | Any git operation requested |

---

## Mounting strategy

Coordinator reads `INDEX.md` at engagement start. Picks 1-2 skills matching the trigger. Reads their `SKILL.md` and the relevant `reference/` files. **Never load all skills.**

For executor spawns: pass the specific reference file path (e.g., `skills/injection/reference/sql-injection-quickstart.md`), not the SKILL.md. The reference file has the actionable content; SKILL.md is navigation.

For validators: do NOT mount the attack skill — biases verdict. Mount only `skills/coordination/reference/VALIDATION.md`.

For cloud-agent tasks: each task in `projects/rfp-3.2/task-NN-*.md` / `projects/rfp-3.3/task-NN-*.md` declares its skill mounts; the runtime loads only those. No coordinator is involved unless the task explicitly invokes `coordination` (only task-03 does).

## Cross-cutting references (always available)

- [`coordination/reference/principles.md`](coordination/reference/principles.md) — engagement principles
- [`coordination/reference/credential-loading.md`](coordination/reference/credential-loading.md) — env-reader rule
- [`coordination/reference/output-discipline.md`](coordination/reference/output-discipline.md) — OUTPUT_DIR tree
- [`coordination/reference/role-matrix.md`](coordination/reference/role-matrix.md) — role contracts
- [`coordination/reference/preflight-checklist.md`](coordination/reference/preflight-checklist.md) — gates before spawning
- [`coordination/reference/bookkeeping.md`](coordination/reference/bookkeeping.md) — experiments.md format
