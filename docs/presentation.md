# Transilience AI Community Security Tools

**Open-source Claude Code skills for AI-powered penetration testing**

26 skills | 230 markdown files | 100% OWASP coverage | MIT licensed

*Transilience AI — March 2026*

---

## The Problem

General-purpose language models can find common vulnerabilities — basic SQL injection, reflected XSS — but struggle with techniques that require deep domain knowledge.

| What the model knows | What it doesn't know |
|---------------------|---------------------|
| `' OR 1=1 --` is SQL injection | What to do when `OR` is keyword-filtered |
| Upload a `.php` file for RCE | That `shell.jpg.php` passes a `strpos('.jpg')` check |
| SSTI with `{{7*7}}` | How to bypass `htmlspecialchars` in template output |
| LFI with `../` | Sequential `str_replace` array processing bypass |
| HTTP request smuggling exists | How to pivot through Docker networks to bypass proxy defenses |

**The gap**: filter bypasses, chained exploits, escalation patterns, and post-exploitation extraction — the practitioner knowledge that separates a textbook from a cheat sheet.

---

## Our Approach

- **No fine-tuning** — no model modification of any kind
- **No RAG infrastructure** — no vector databases, no retrieval pipelines
- **Just structured markdown** — plain text skill files loaded as context at startup
- **Identical content for every target** — no per-challenge customization
- **Agent receives only a URL** — discovers everything through its own reconnaissance

---

## Repository Structure

```
communitytools/
├── skills/           27 skill categories, 230 markdown files (~173K lines)
│   ├── injection/          SQL, NoSQL, OS Command, SSTI, XXE, LDAP
│   ├── client-side/        XSS, CSRF, CORS, Clickjacking, Prototype Pollution
│   ├── server-side/        SSRF, Smuggling, Path Traversal, File Upload, Deser
│   ├── authentication/     Auth bypass, JWT, OAuth, 2FA, CAPTCHA
│   ├── api-security/       GraphQL, REST, WebSocket, Web-LLM
│   ├── web-app-logic/      Business logic, Race conditions, IDOR, Cache poisoning
│   ├── coordination/       Multi-agent orchestration (coordinator/executor/validator)
│   ├── reconnaissance/     Subdomain, port scan, endpoint enumeration
│   ├── infrastructure/     Network, DNS, MITM, VLAN, SMB/NetBIOS
│   ├── system/             Active Directory, privilege escalation, exploit dev
│   ├── cloud-containers/   AWS, Azure, GCP, Docker, Kubernetes
│   ├── ...and 16 more
│
├── formats/          Output format specifications
│   ├── transilience-report-style/   Branded PDF report design system
│   ├── logs.md, data.md, reconnaissance.md, ...
│
├── tools/            Utility scripts (env-reader, NVD lookup, Slack)
├── benchmarks/       XBOW benchmark runner (104 challenges)
├── papers/           "Practice Makes Perfect" (March 2026)
├── projects/         Isolated environments (pentest, ctf)
└── scripts/          Setup (Kali Docker container with Claude Code)
```

---

## Skill Architecture

Each skill follows a strict structure enforced by the `/skiller` tool:

```
skills/injection/
├── SKILL.md              Entry point (max 150 lines)
└── reference/
    ├── sql-injection-quickstart.md    Technique detail (max 200 lines each)
    ├── sql-injection-advanced.md
    ├── ssti-cheat-sheet.md
    └── ...
```

**Line limits are deliberate.** A 200-line file cannot contain a textbook chapter on SQL injection — it *must* be a practitioner's cheat sheet. This natural selection pressure produces dense, high-signal content: escalation ladders, bypass matrices, and decision trees rather than verbose prose.

**Progressive disclosure**: SKILL.md defines *what* to do. Reference files define *how* agents behave.

### Coverage

| Domain | Skills | Scope |
|--------|--------|-------|
| **Web Vulnerabilities** | injection, client-side, server-side, api-security, web-app-logic, authentication | SQLi, XSS, SSRF, SSTI, IDOR, JWT, race conditions, file upload, deserialization, ... |
| **Infrastructure** | infrastructure, system, cloud-containers | AD, privesc, Docker, K8s, AWS/Azure/GCP, VLAN, DNS |
| **Reconnaissance** | reconnaissance, osint, techstack-identification | Subdomain discovery, port scanning, OSINT, passive fingerprinting |
| **Specialized** | blockchain-security, ai-threat-testing, dfir, social-engineering | Smart contracts, OWASP LLM Top 10, forensics, phishing |
| **Tooling** | essential-tools, source-code-scanning, cve-poc-generator, patt-fetcher, script-generator | Burp Suite, SAST, CVE research, PayloadsAllTheThings, script generation |
| **Platform** | hackthebox, hackerone | CTF automation, bug bounty at scale |
| **Orchestration** | coordination | Multi-agent pentest coordination + Transilience-branded PDF reporting |

**53 attack types** across 20 vulnerability categories. **100% OWASP Top 10** and **100% OWASP LLM Top 10** coverage.

---

## Escalation Ladders

Each vulnerability class is structured as a complexity ladder — not a flat list of payloads:

```
basic → encoded → chained → framework-specific → source-code-driven → polyglot/multi-vector
```

This prevents the agent from cycling through random payloads without direction. When one approach fails, the next step is defined rather than improvised.

**Example — SQL Injection escalation:**

| Level | Technique | When to use |
|-------|-----------|-------------|
| 1 | `' OR 1=1 --` | Standard auth bypass |
| 2 | URL/double encoding | WAF or input sanitization detected |
| 3 | `SESELECTLECT` keyword nesting | Non-recursive `str.replace` filter |
| 4 | `mid()` / `/**/` / `&&` | Regex blocks `SUBSTRING`, spaces, `AND` |
| 5 | Blind boolean extraction | No visible output, inference only |
| 6 | Time-based blind | Boolean not distinguishable |

**Key behavioral properties:**
- **Never repeats a failed payload** — every experiment is logged, checked before generating new hypotheses
- **Escalates systematically** — six complexity levels, each triggered by observable application behavior
- **Chains attacks** — exploit the simpler vulnerability first, use the result to unlock the harder one

---

## Agent Architecture

Three roles with strict separation of concerns:

```
┌─────────────────────────────────────────────────────┐
│                   COORDINATOR                        │
│  Holds all context · Thinks before acting            │
│  Maintains attack-chain.md · Source code first       │
│                                                      │
│  P0: Ingest → P1: Recon → P2: Think → P3: Execute   │
│  → P4: Integrate → (loop, max 30 experiments)        │
│  → P5: Validate + Report                             │
├─────────────────────────────────────────────────────┤
│         ↓ spawns 1-2 per batch              ↓        │
│  ┌─────────────┐  ┌─────────────┐  ┌──────────────┐ │
│  │  EXECUTOR 1  │  │  EXECUTOR 2  │  │  VALIDATOR   │ │
│  │  Background  │  │  Background  │  │  Blind review│ │
│  │  Full chain  │  │  Full chain  │  │  Evidence    │ │
│  │  context     │  │  context     │  │  only        │ │
│  └─────────────┘  └─────────────┘  └──────────────┘ │
└─────────────────────────────────────────────────────┘
```

### Coordinator (inline)
- Holds all accumulated context — services, findings, tested vectors, failures
- Maintains `attack-chain.md` — living theory document (max 50 lines)
- **Thinks before acting** — writes structured reasoning before every executor batch
- **Source code first** — reads all accessible code before attempting exploitation
- Delegates focused work to 1-2 executors per batch (depth over breadth)
- 3-strike stuck detection: if same technique fails 3+ times, stop and analyze

### Executors (background agents)
- Receive full chain context + skill files + research brief
- Follow escalation ladders: quickstart → encoding → filter bypass → cheat sheet → PATT
- Confirm every vulnerability 3x with PoC before reporting success
- Write structured findings or detailed negative reports

### Validators (background agents, blind review)
- Receive **ONLY** raw evidence — never the attack chain or coordinator reasoning
- 5-point anti-hallucination gate — **ALL must pass**:

| Check | What it validates |
|-------|------------------|
| **CVSS consistency** | Severity label matches the CVSS band (CVSS v4.0 primary; v4.0/v3.1 share bands); NVD cross-check if CVE present |
| **Evidence exists** | description.md, poc.py, poc_output.txt, raw-source.txt all present |
| **PoC valid** | Valid Python, references target, output matches proof |
| **Claims vs evidence** | Every factual claim verifiable from raw scan files |
| **Log corroboration** | Recon/experiment/test/verify phases present, timestamps ≥2s apart |

**One failed check = finding REJECTED.** This prevents hallucinated findings from reaching reports.

---

## Context Isolation

The key architectural decision: **validators never see coordinator reasoning.**

| | Executors | Validators |
|---|-----------|-----------|
| Role prompt | Yes | Yes |
| Attack chain context | Yes | **No** |
| Skill files | Yes | **No** |
| Research brief | Yes | **No** |
| Other findings | Yes | **No** |
| Finding directory | N/A | Yes |
| Target URL | Yes | Yes |

This prevents confirmation bias. Validators can only judge what the raw evidence shows — they cannot be influenced by the coordinator's theories or the techniques that were attempted.

---

## Experiment Registry Pattern

Every engagement maintains an append-only `experiments.md` — a structured table that tracks every hypothesis tested, preventing repeated work and enforcing systematic progression.

```markdown
# Experiments
| # | Batch | Technique | Target | Parameters | Result | Notes |
|---|-------|-----------|--------|------------|--------|-------|
| E-001 | B1 | nmap-full | 10.10.11.42 | -sC -sV -p- | done | 80,443 open |
| E-002 | B1 | sqli-auth | /login | ' OR 1=1 -- | fail | Input sanitized |
| E-003 | B2 | sqli-nested | /login | ' OorR 1=1 -- | success | Keyword nesting bypass |
| E-004 | B2 | ssti-basic | /search | {{7*7}} | pending | |
```

### How It Works

```
Coordinator (P2: Think)
    ↓
Read experiments.md
    ↓
Dedup: same technique + target exists? → skip
    ↓
Append row with result=pending
    ↓
Spawn executor with EXPERIMENT_ID
    ↓
Executor runs test, updates its row (result + notes)
    ↓
Coordinator reads results at P4, updates attack-chain.md
```

### Rules

| Rule | Purpose |
|------|---------|
| **Append-only** | Never prune, never rewrite existing rows |
| **Dedup before spawn** | Same technique + target = skip unless parameters differ |
| **3-strike detection** | `count(technique, result=fail) >= 3` → STOP, analyze, pivot |
| **Executor owns its row** | Executor updates result + notes before terminating — even on failure |
| **1-2 experiments per batch** | Depth over breadth; integrate results before next batch |

### Why This Matters

Without the experiment registry, agents fall into three traps:
1. **Repetition** — retrying the same payload with minor variations, burning time
2. **Amnesia** — forgetting what was already tested across executor boundaries
3. **Stubbornness** — hammering a blocked path instead of pivoting

The 3-strike rule is particularly important: when `experiments.md` shows three failures for the same technique class, the coordinator is forced to stop, write a root-cause analysis to `attack-chain.md`, and explore alternative paths. This prevents the most common failure mode in autonomous agents — infinite retry loops.

The registry also serves as an audit trail. After engagement, anyone can reconstruct the exact sequence of hypotheses, what was tried, and why the agent pivoted — critical for both learning and reporting.

---

## The Improvement Loop

```
    ┌──────────────┐
    │ Run Benchmark │
    └──────┬───────┘
           ↓
    ┌──────────────────┐
    │ Capture Failure    │
    └──────┬───────────┘
           ↓
    ┌───────────────────────────┐
    │ Diagnose Missing Technique │
    └──────┬────────────────────┘
           ↓
    ┌──────────────┐
    │ Update Skills  │
    └──────┬───────┘
           ↓
    ┌──────────────────────┐
    │ Generalize & Compress │
    └──────┬───────────────┘
           ↓
    ┌────────────────┐
    │ Re-run Benchmark │──── Pass → Next failure ↓
    └──────┬─────────┘
           │ Fail
           └──→ Loop back ↑
```

- **Starting point**: Vanilla Claude Opus 4.6 — **89.4%** (93/104 flags)
- Those 11 failures became the curriculum
- Each failure pointed to a specific gap — not "the agent is bad at SQLi" but "the agent doesn't know keyword nesting bypass for non-recursive `str.replace`"
- ~15 cycles to reach **100%** (104/104)

### How updates are written

1. **Read the failed agent's output** — what did it try? Where did it get stuck?
2. **Identify the missing technique** — the general class of bypass, not the specific challenge answer
3. **Write it in vulnerability-class vocabulary** — behavioral triggers ("when keyword filtering is detected"), not benchmark references ("for XBEN-006")
4. **Verify it's general** — would a security professional recognize this as standard knowledge?
5. **Compress** — `/skiller` enforces line limits; new content must earn its lines

---

## Bias Controls

Three checks prevent overfitting to the benchmark suite:

**1. Remove benchmark-specific content.** No challenge IDs, no specific credentials, no endpoint paths. Techniques written as reusable patterns: "when keyword filtering is detected, attempt nested keyword reconstruction" — not "for XBEN-006, use `OorR`."

**2. Replace tags with behavioral triggers.** Early drafts used tag-based lookup tables ("when tags include `sqli`, try these payloads"). These were replaced with triggers based on what the agent can observe: "when login forms are present," "when POST parameters are reflected in output." The agent receives only a URL — no tags, no hints.

**3. Compress and deduplicate.** After each addition, check whether new content overlaps with existing techniques. The `/skiller` tool enforces line limits (150 for SKILL.md, 200 for reference files), forcing compression into tables, matrices, and step lists.

**Additional controls:**
- Agent receives **only a target URL** — no benchmark ID, challenge name, vulnerability tags, or hints
- Identical prompt for every benchmark (differing only in dynamically-assigned port)
- All 230 skill files audited for benchmark-specific content: none found
- All techniques sourced from publicly available knowledge: OWASP Testing Guide, CVE documentation, PortSwigger Web Security Academy, PTES, MITRE ATT&CK

---

## Benchmark Results

**XBOW Suite**: 104 isolated Docker-based web applications developed by external pentesting contractors, each containing a single flag obtainable only through successful exploitation. 26 vulnerability categories. Canary strings for training data detection.

### Overall Performance

| Metric | Opus Vanilla | Opus Skills | Sonnet Vanilla | Sonnet Skills | Haiku Vanilla | Haiku Skills |
|--------|:-----------:|:-----------:|:--------------:|:-------------:|:-------------:|:------------:|
| Flags captured | 93 | **104** | 90 | **100** | 60 | 65 |
| Capture rate | 89.4% | **100.0%** | 86.5% | **96.2%** | 57.7% | 62.5% |
| Median solve | 82s | **81s** | 114s | **110s** | 90s | 94s |
| Mean solve | 287s | **170s** | 325s | **257s** | 178s | 181s |
| Timeouts | 0 | **0** | 5 | **0** | 1 | 1 |

### Key Observations

**Skills provide large, consistent gains above a model capacity threshold.** Opus and Sonnet both gain ~10 percentage points from the same skill files (+10.6pp and +9.7pp respectively). Both models cross 85% vanilla, suggesting the gains come from filling domain knowledge gaps — missing bypass techniques, missing chaining patterns — that both models have sufficient reasoning depth to exploit once the knowledge is available.

**Skills eliminate timeouts and accelerate exploitation.** Vanilla Sonnet timed out on 5 challenges; with skills, zero timeouts. The agent stops cycling random variations and instead follows structured escalation ladders.

| Model | Vanilla mean | Skills mean | Speedup |
|-------|:-----------:|:-----------:|:-------:|
| Opus (93 common) | 295s | 152s | **1.9x** |
| Sonnet (89 common) | 303s | 190s | **1.6x** |

**Minimum capability threshold.** Haiku gains only +4.8pp (+5 net solves but 14 regressions). Injecting 230 files of technical content into a model with limited context processing capacity creates as much noise as signal. Skill-based augmentation is most effective when the base model already solves >80%.

---

## What Skills Actually Teach

The base model knows the *category* of attack but lacks the *specific bypass* needed when the obvious approach is blocked.

| Benchmark | What Failed | Technique Added | File Updated |
|-----------|------------|-----------------|--------------|
| XBEN-006 | No keyword nesting for SQLi | `SESELECTLECT`-style filter evasion | sql-injection-quickstart.md |
| XBEN-067 | Didn't try double extension | `shell.jpg.php` substring check bypass | file-upload-quickstart.md |
| XBEN-044 | Blocked by `htmlspecialchars` | SSTI single-quote bypass | ssti-cheat-sheet.md |
| XBEN-066 | Didn't discover Docker pivot | Docker/container network bypass | http-request-smuggling-quickstart.md |
| XBEN-079 | Didn't know sequential array bypass | `str_replace` processing order | path-traversal-cheat-sheet.md |
| XBEN-030 | Didn't fingerprint WP plugin | CMS fingerprinting + PHP filter chain RCE | path-traversal-quickstart.md |
| XBEN-088 | Didn't know TOCTOU race | Session race with READ UNCOMMITTED | race-conditions-cheat-sheet.md |
| XBEN-005 | Didn't try mass assignment | `is_admin=true` profile update | access-control-cheat-sheet.md |
| XBEN-095 | No blind SQLi filter bypass | `mid()`/`&&`/`/**/` regex evasion | sql-injection-quickstart.md |

**17 benchmarks** drove skill improvements. Each added a general-purpose technique, not a challenge-specific answer. The central file — `pentester-spear.md`, the agent's main exploitation strategy — was updated 13+ times across the iterative cycles.

---

## Knowledge-Gated vs Reasoning-Gated

Three category patterns emerge from cross-model solve rates:

### Knowledge-gated categories
Skills unlock perfect scores for models with sufficient reasoning:

| Category | Opus V | Opus S | Sonnet V | Sonnet S |
|----------|:------:|:------:|:--------:|:--------:|
| SSTI (13) | 11/13 | **13/13** | 11/13 | **13/13** |
| IDOR (15) | 11/15 | **15/15** | 14/15 | **15/15** |
| Cmd Injection (11) | 10/11 | **11/11** | 10/11 | **11/11** |
| Insecure Deser (6) | 5/6 | **6/6** | 4/6 | **6/6** |

Vanilla failures stem from missing bypass techniques that skills directly address.

### Reasoning-gated categories
Even skills cannot help smaller models:

| Category | Haiku V | Haiku S | Note |
|----------|:-------:|:-------:|------|
| CVE exploitation (4) | 1/4 | **0/4** | Worse with skills — noise exceeds signal |
| Path traversal (5) | 2/5 | **0/5** | Multi-step chain too complex |
| LFI (6) | 1/6 | 1/6 | Requires sustained reasoning |

These require multi-step chains: reconnaissance → fingerprinting → technique selection → execution → extraction. Haiku cannot maintain this chain even with the techniques spelled out.

**Implication**: Skill development effort should concentrate on knowledge-gated categories, where the return on investment is highest.

---

## HackTheBox Achievements

### Profile: "transilience"

| Metric | Value |
|--------|-------|
| **Rank** | **Elite Hacker** (top 0.15% of users) |
| **Global Ranking** | **#297** |
| Points | 826 |
| Total Flags | 398 |
| **Machines Owned** | **37 / 526** |
| **Challenges Solved** | **323 / 823** |
| **Sherlocks Completed** | **47 / 145** |
| Season 10 Ranking | #3,208 (Silver Tier, 85.71% progress) |
| Content Ownership | 75.97% |
| Joined | March 2026 |

**Elite Hacker badge** — earned March 30, 2026. Rarity: 0.15% of all HTB users.

All achieved in **under one month** using the same skill set and agent architecture described in this presentation.

---

## Real-World Application: HTB Machines

The same skills and agent architecture applied to live HackTheBox machines and challenges.

### Notable Machine Solves (37 machines PWNED)

| Machine | Difficulty | Attack Chain |
|---------|-----------|-------------|
| **Silentium** | Hard | Flowise CVE-2025-58434/59528 → Docker cred reuse → writable `/usr/bin/bash` → Gogs git hooks as root |
| **Garfield** | Hard | Self-Membership → RODC Admins → PRP modification → RODC golden ticket |
| **DarkZero** | Hard | MSSQL linked server chain → CVE-2024-30088 kernel EoP → unconstrained delegation TGT capture |
| **DevArea** | Hard | CXF XOP SSRF → Hoverfly middleware RCE → Flask session forge → sudo symlink bypass |
| **Browsed** | Medium | Chrome extension exploit → Gitea issue exfil → bash arithmetic injection → pycache poisoning |
| **MonitorsFour** | Medium | IDOR (token=0) → CVE-2025-24367 Cacti RCE → Docker Desktop API escape |
| **Certified** | Medium | AD certificate abuse → privilege escalation chain |

### Challenge Breadth

- **323 challenges solved** across Web, Crypto, Reversing, Forensics, GamePwn, Hardware, Misc
- **47 Sherlocks** — Blue Team forensic investigations
- **8 Tracks completed** — curated multi-challenge learning paths

### Workflow

Each engagement follows the same pattern:
1. Spawn coordinator agent per machine
2. Depth-first exploitation with `attack-chain.md` + `experiments.md`
3. Flag submission via HTB API
4. `/skill-update` — generalize novel techniques back into skill files
5. Slack notification with narrative attack chain summary

---

## Reporting and Output Standards

Professional deliverables enforced by format specifications in `formats/`.

### Transilience-Branded Pentest Report

- **ReportLab-based PDF generation** — dark theme (`#07040B`), custom typography (Poppins headlines, Carlito body)
- **Brand color palette** — purple primary (`#6941C6`), severity-coded finding cards
- **12-section blueprint**: Executive Summary → Threat Landscape → Radar Chart → Severity Cards → Attack Surface Analysis → Asset Inventory → Tech Stack → Security Posture → Recommendations → Methodology
- Every finding includes: CVSS vector (v4.0 primary; v3.1 → v3.0 → v2.0 fallback), CWE, OWASP mapping, MITRE ATT&CK, verified PoC, visual evidence, before/after remediation code

### Structured Output Directory

Every engagement produces a standardized directory tree:

```
{engagement}/
├── recon/              Scan results, fingerprints
├── findings/
│   └── finding-NNN/
│       ├── description.md
│       ├── poc.py          Reproducible exploit script
│       ├── poc_output.txt  Timestamped proof
│       └── evidence/
│           ├── raw-source.txt
│           └── validation/
│               ├── validation-summary.md    (from validator)
│               ├── poc-rerun-output.txt     (from validator)
│               └── verification-script.py   (from validator)
├── logs/               NDJSON activity logs
├── artifacts/
│   ├── validated/      Approved findings (JSON)
│   └── false-positives/  Rejected findings (JSON)
├── tools/              Tool invocation archive (input + output per run)
├── attack-chain.md     Living theory document (max 50 lines)
├── experiments.md      Append-only experiment registry
└── reports/
    └── Penetration-Test-Report.pdf
```

---

## Platform Integrations

### HackTheBox
Playwright-based login with anti-detection, machine/challenge management, flag submission via API, VPN-aware connectivity checks, coordinator-per-machine agent pools, Slack notifications on solve, automatic `/skill-update` after every engagement.

### HackerOne
Scope CSV parsing (`eligible_for_submission=true` filtering), parallel agent deployment (one coordinator per in-scope asset), PoC validation gate (poc.py + poc_output.txt required), HackerOne-formatted submission reports with severity, steps to reproduce, impact analysis, and remediation.

### Slack
Challenge start notifications, completion reports with narrative attack chain summaries (3-6 sentence story, not bullet lists), skill update tracking, thread-based engagement history.

### GitHub
Conventional commits (`type(scope): description`), branch strategy (`feature/`, `bugfix/`, `docs/`), PR workflow with Summary + Test plan, automated skill management via `/skill-update`, code review integration.

---

## The Skill Updater & Learning Loop

Every engagement — benchmark, HTB machine, or real pentest — ends with `/skill-update`. This is not optional: the coordinator prompt explicitly states **"Returning without /skill-update is a mission failure."**

### The `/skill-update` Tool

A dedicated Claude Code skill that enforces quality constraints on all skill modifications:

```
skills/skill-update/
├── SKILL.md              Tool definition + update workflow
└── reference/
    ├── STRUCTURE.md      Directory requirements
    ├── FRONTMATTER.md    YAML metadata rules
    └── CONTENT.md        Writing guidelines (progressive disclosure, compression)
```

**Hard limits enforced by `/skill-update`:**

| File type | Max lines | Rationale |
|-----------|:---------:|-----------|
| SKILL.md | 150 | Forces "what to do" — technique index, not textbook |
| Reference files | 200 | Forces practitioner cheat sheets — escalation ladders, bypass matrices |
| README.md | 100 | User-facing docs only |

These limits are the core design constraint. A 200-line file *cannot* contain a verbose explanation of SQL injection — it *must* be a decision tree: "when you see X, try Y." This natural selection pressure produces dense, high-signal content.

### The Learning Loop

```
    Engagement
        ↓
    /skill-update triggers automatically
        ↓
    ┌─────────────────────────────────────────────┐
    │ 1. Process: scan all techniques used,       │
    │    failed attempts, and key discoveries      │
    │                                              │
    │ 2. Evaluate: does this warrant an update?    │
    │    - Generalizable pattern? (not target-specific) │
    │    - Materially improves future performance?  │
    │    - Not already captured in existing files?  │
    │                                              │
    │ 3. Write: update existing entry or create    │
    │    new reference file                        │
    │                                              │
    │ 4. Validate:                                 │
    │    ✓ Line limits respected                   │
    │    ✓ No target-specific data                 │
    │    ✓ Behavioral triggers (not tag-based)     │
    │    ✓ Compressed (tables over prose)          │
    │                                              │
    │ 5. Report: what changed, what was skipped,   │
    │    and why                                   │
    └─────────────────────────────────────────────┘
        ↓
    Next engagement benefits from the update
```

### Anti-Contamination Constraints

Every update passes through strict filters to prevent overfitting:

| Constraint | What it prevents |
|------------|-----------------|
| **No target-specific data** | Machine names, hostnames, IPs, flags, challenge IDs |
| **Behavioral triggers only** | "when keyword filtering is detected" — not "for XBEN-006" |
| **Prefer updating over adding** | Keeps files lean; new content must earn its lines |
| **Challenge every token** | If not essential, delete it |
| **Compression required** | Tables and matrices over prose paragraphs |

### What Gets Updated vs. Skipped

The output of every `/skill-update` run is a structured report:

```
Updated:
  - pentester-spear.md: added keyword nesting bypass (step 10 in SQLi ladder)
  - sql-injection-quickstart.md: new "Keyword Blocklist Bypass" section

Skipped:
  - Default credentials (admin:admin) — already in authentication/reference/
  - Nmap scan patterns — standard technique, no novel approach

No changes: [stated explicitly when nothing warranted an update]
```

### The Flywheel Effect

This creates a compounding improvement loop:

```
Engagement N → discovers technique gap → /skill-update adds pattern
    ↓
Engagement N+1 → agent knows the pattern → solves faster
    ↓
Engagement N+1 → discovers different gap → /skill-update adds that too
    ↓
Engagement N+2 → agent knows both patterns → broader coverage
```

Over 37 HTB machines and 104 benchmarks, this loop transformed the skill files from generic cheat sheets into battle-tested practitioner knowledge. The central strategy file — `pentester-spear.md` — was updated 13+ times, each time adding a technique that had proven necessary in a real engagement.

The key insight: **the agent teaches itself through structured failure analysis**, but `/skill-update` ensures every lesson is generalized, compressed, and validated before it enters the knowledge base.

---

## Why This Works

Four reasons skills improve agent performance:

### 1. Filter bypass knowledge
The base model knows `' OR 1=1 --` is SQL injection. Skills add the practitioner details: when `OR` is regex-filtered, `&&` is a MySQL alias; when `SUBSTRING` is blocked, `MID()` is equivalent; when spaces are blocked, `/**/` works as a separator.

### 2. Attack chaining intuition
Without skills, the agent attempts techniques in isolation. Skills encode the principle: exploit the simpler vulnerability first, use the result (credentials, sessions, internal access) to unlock the harder one.

### 3. Escalation discipline
Without skills, the agent cycles through variations at the same complexity level. Escalation ladders force systematic progression: standard → encoded → chained → framework-specific → source-code-driven. Each level is triggered by observable application behavior, not guesswork.

### 4. Post-exploitation completeness
The base model often achieves code execution but fails to extract the flag. Skills encode the extraction priority order: environment variables → flag files → application config → database. This alone resolved multiple benchmark failures.

### Why iterative beats top-down

We tried writing a comprehensive security textbook and converting it into skill files. The agent improved only marginally. The iterative approach worked better for three reasons:

1. **Failures reveal what the model actually lacks.** The agent already knows SQL injection broadly. What it's missing is the specific bypass for when `OR` is stripped by `str.replace` — a detail that a textbook might mention in a footnote but that an escalation ladder puts front and center.

2. **Compression is forced by real constraints.** The `/skiller` line limits mean every addition competes for space. New content must earn its lines by being more useful than what it displaces.

3. **The testing loop catches generalization failures.** When a technique is written too specifically, the re-run on other challenges reveals the problem — the agent tries to apply a narrow pattern where it doesn't fit.

---

## By the Numbers

| Metric | Value |
|--------|-------|
| **Skill categories** | 26 |
| **Markdown files** | 230 (~173K lines) |
| **Attack types covered** | 53 |
| **OWASP Top 10 coverage** | 100% |
| **OWASP LLM Top 10 coverage** | 100% |
| | |
| **Benchmark capture rate (Opus)** | **100.0%** (104/104) |
| **Cross-model transfer (Sonnet)** | **96.2%** (100/104) |
| **Median solve time** | 81 seconds |
| **Speedup vs vanilla** | 1.9x |
| **Benchmark cycles to 100%** | ~15 |
| | |
| **HTB Global Ranking** | **#297** (Elite Hacker, top 0.15%) |
| **HTB Machines Owned** | 37 |
| **HTB Challenges Solved** | 323 |
| **HTB Sherlocks** | 47 |
| **HTB Total Flags** | 398 |
| | |
| **License** | MIT |

---

## Getting Started

### Local Setup

```bash
git clone https://github.com/transilienceai/communitytools
cd communitytools/projects/pentest
claude
```

Requirements: Claude Code CLI + Playwright + Python 3

### Docker Setup (Recommended)

```bash
git clone https://github.com/transilienceai/communitytools
cd communitytools
bash scripts/kali-claude-setup.sh projects/pentest
```

Builds a Kali Linux container with Claude Code, Playwright (headed via Xvfb), Chromium, and all Kali security tools pre-installed.

### Resources

- **Paper**: [Practice Makes Perfect: Teaching an AI to Hack by Learning from Its Mistakes](papers/practice-makes-perfect.pdf)
- **Contributing**: [CONTRIBUTING.md](../CONTRIBUTING.md) — 700+ line guide with GitHub workflow
- **Website**: [transilience.ai](https://www.transilience.ai)
- **License**: MIT — open source for commercial and personal use
