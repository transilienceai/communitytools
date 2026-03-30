# Transilience AI Community Security Tools

<div align="center">

[![MIT License](https://img.shields.io/badge/License-MIT-green.svg)](https://choosealicense.com/licenses/mit/)
[![GitHub stars](https://img.shields.io/github/stars/transilienceai/communitytools)](https://github.com/transilienceai/communitytools/stargazers)
[![Claude AI](https://img.shields.io/badge/Powered%20by-Claude%20AI-blue)](https://claude.ai)

**Open-source Claude Code skills for AI-powered penetration testing, bug bounty hunting, AI threat testing, and security reconnaissance**

[Quick Start](#-quick-start) | [Skills](#-skills) | [Architecture](#-architecture) | [Contributing](CONTRIBUTING.md) | [Website](https://www.transilience.ai)

</div>

---

## Announcement

**Practice Makes Perfect: Teaching an AI to Hack by Learning from Its Mistakes** (March 2026)

We built an autonomous pentesting agent that scores **100% (104/104)** on a published CTF benchmark suite — using only structured markdown skill files, no fine-tuning. Starting from a bare 89.4% baseline, we ran a simple loop roughly 15 times: run the benchmarks, find a failure, diagnose the missing technique, write it into a skill file, and run again. The same skills transfer cross-model: Claude Sonnet 4.6 reaches 96.2% and Claude Haiku 4.5 reaches 62.5%. This repository contains the full skill set described in the paper.

**[Read the paper (PDF)](papers/practice-makes-perfect.pdf)**

---

## Overview

**Transilience AI Community Tools** is a consolidated Claude Code security testing suite — **23 skills** and **2 tool integrations** that cover the full penetration testing lifecycle from reconnaissance to reporting. Agent roles (orchestrator, executor, validator) are defined as skill reference files and spawned dynamically.

### Why Choose Transilience Community Tools?

- **AI-Powered Automation** — Claude orchestrates intelligent security testing workflows
- **Complete OWASP Coverage** — 100% OWASP Top 10 + OWASP LLM Top 10
- **Professional Reporting** — CVSS 3.1, CWE, MITRE ATT&CK, Transilience-branded PDF reports
- **Playwright Integration** — Browser automation for client-side vulnerability testing
- **Payload-Enriched References** — 160+ reference files with inline PayloadsAllTheThings techniques
- **Open Source** — MIT licensed for commercial and personal use

---

## Quick Start

### 1. Clone and enter the project

```bash
git clone https://github.com/transilienceai/communitytools.git
cd communitytools/projects/pentest
```

### 2. Run from docker (optional)
```bash
bash scripts/kali-claude-setup.sh projects/pentest
```

### 3. Open Claude Code and run skills

```bash
claude    # Launch Claude Code from the projects/pentest directory
```

Then use slash commands inside the Claude session:

```
/coordination https://target.com     # Full penetration test
/hackthebox                          # HackTheBox challenge automation
/hackerone                           # Bug bounty workflow
/techstack-identification            # Passive tech stack recon
/reconnaissance target.com           # Attack surface mapping
/source-code-scanning ./app          # Static code analysis
```

---

## Skills

All canonical skill and tool definitions live at the **repo root** (`skills/`, `tools/`). Each project under `projects/` symlinks only the ones it needs — see [Repository Structure](#repository-structure) for details.

Agent roles (orchestrator, executor, validator, script-generator, patt-fetcher) are defined as reference files in `skills/coordination/reference/*-role.md` and spawned dynamically via `Agent(prompt=...)`.

### Skills by Category (23)

#### Vulnerability Testing (10)

| Skill | Coverage |
|-------|----------|
| `/injection` | SQL, NoSQL, OS Command, SSTI, XXE, LDAP/XPath |
| `/client-side` | XSS (Reflected/Stored/DOM), CSRF, Clickjacking, CORS, Prototype Pollution |
| `/server-side` | SSRF, HTTP Smuggling, Path Traversal, File Upload, Deserialization, Host Header |
| `/authentication` | Auth Bypass, JWT, OAuth, Password Attacks, 2FA Bypass, CAPTCHA Bypass |
| `/api-security` | GraphQL, REST API, WebSockets, Web LLM |
| `/web-app-logic` | Business Logic, Race Conditions, Access Control, Cache Poisoning/Deception, IDOR |
| `/cloud-containers` | AWS, Azure, GCP, Docker, Kubernetes |
| `/system` | Active Directory, Privilege Escalation (Linux/Windows), Exploit Development |
| `/infrastructure` | Port Scanning, DNS, MITM, VLAN Hopping, IPv6, SMB/NetBIOS |
| `/social-engineering` | Phishing, Pretexting, Vishing, Physical Security |

#### Reconnaissance (3)

| Skill | Purpose |
|-------|---------|
| `/reconnaissance` | Subdomain discovery, port scanning, endpoint enumeration, API discovery, attack surface mapping |
| `/osint` | Repository enumeration, secret scanning, git history analysis, employee footprint |
| `/techstack-identification` | Passive tech stack inference across 17 intelligence domains |

#### Specialized (3)

| Skill | Purpose |
|-------|---------|
| `/ai-threat-testing` | OWASP LLM Top 10 — prompt injection, model extraction, data poisoning, supply chain |
| `/cve-poc-generator` | CVE research, NVD lookup, safe Python PoC generation, vulnerability reports |
| `/source-code-scanning` | SAST — OWASP Top 10, CWE Top 25, dependency CVEs, hardcoded secrets |

#### Platform Integrations (2)

| Skill | Purpose |
|-------|---------|
| `/hackerone` | Scope CSV parsing, parallel asset testing, PoC validation, platform-ready submissions |
| `/hackthebox` | Playwright-based login, challenge browsing, VPN management, automated solving |

#### Orchestration & Tooling (5)

| Skill | Purpose |
|-------|---------|
| `/coordination` | Engagement orchestration, test planning, output structure |
| `/essential-tools` | Burp Suite, Playwright automation, methodology, reporting standards |
| `/transilience-report-style` | Transilience-branded PDF report generation (ReportLab) |
| `/github-workflow` | Git branching, commits, PRs, issues, code review |
| `/skiller` | Skill scaffolding, validation, GitHub workflow automation |

### Tool Integrations (2)

| Tool | Purpose |
|------|---------|
| **Playwright** | Browser automation for client-side testing via MCP |
| **Kali Linux Tools** | nmap, masscan, nikto, gobuster, ffuf, sqlmap, testssl, and more |

---

## Architecture

The suite uses a **skills-only** architecture with canonical definitions at the repo root, symlinked into isolated project environments:

- **Skills** (`skills/` at root, symlinked into each project's `.claude/skills/`) — User-triggered workflows invoked with `/skill-name`. Each skill contains a `SKILL.md` definition and `reference/` directory with attack techniques, cheat sheets, payloads, and agent role prompts.
- **Role Prompts** (`skills/coordination/reference/*-role.md`) — Define how spawned agents behave (orchestrator, executor, validator, etc.). Read at runtime and passed to `Agent(prompt=...)`.
- **Tools** (`tools/` at root, symlinked into each project's `.claude/tools/`) — Utility scripts for environment reading, integrations.

### Multi-Agent Execution Flow

```mermaid
sequenceDiagram
    participant User
    participant Skill as /coordination Skill (inline)
    participant Roles as Role Prompts (reference/)
    participant Agents as Spawned Agents
    participant Output as Standardized Outputs

    User->>Skill: /coordination https://target.com
    Skill->>Roles: Read orchestrator-role.md
    Skill->>Skill: Execute orchestrator workflow inline

    Skill->>Roles: Read executor-role.md
    Skill->>Agents: Agent(prompt=executor_role + mission) × N
    Note over Agents: SQL/XSS/SSRF/JWT/OAuth/SSTI/XXE...
    Agents-->>Output: findings/*.json + evidence/*.png

    Skill->>Roles: Read validator-role.md
    Skill->>Agents: Agent(prompt=validator_role + finding) × N
    Agents-->>Output: validated/*.json

    Skill->>Output: Phase 6: Generate reports
    Output-->>User: Executive + technical reports
```

### Repository Structure

```
communitytools/
├── CLAUDE.md                        # Project instructions
├── marketplace.json                 # Machine-readable project manifest
├── papers/                          # Research papers
├── benchmarks/                      # XBOW benchmark runner
│
├── skills/                          # ← Canonical skill definitions (source of truth)
│   ├── coordination/
│   │   ├── SKILL.md                 # Orchestration entry point
│   │   └── reference/
│   │       ├── orchestrator-role.md # Agent role prompts
│   │       ├── executor-role.md
│   │       ├── validator-role.md
│   │       ├── script-generator-role.md
│   │       ├── patt-fetcher.md
│   │       ├── OUTPUT_STRUCTURE.md
│   │       └── ...
│   ├── injection/
│   │   ├── SKILL.md
│   │   └── reference/
│   ├── reconnaissance/
│   ├── server-side/
│   └── ...                          # 23 skill directories total
│
├── tools/                           # ← Canonical tool integrations (source of truth)
│   ├── env-reader.py
│   └── slack-send.py
│
└── projects/                        # ← Isolated project environments
    └── pentest/
        └── .claude/
            ├── skills/              # Real directory, contents are symlinks
            │   ├── injection/ → ../../../../skills/injection/
            │   ├── coordination/ → ../../../../skills/coordination/
            │   └── ...              # Each project picks what it needs
            └── tools/               # Real directory, contents are symlinks
                ├── env-reader.py → ../../../../tools/env-reader.py
                └── ...
```

### Why This Structure?

**Canonical root directories** (`skills/`, `tools/`) hold the single source of truth for all definitions. No duplication, no drift. Agent roles live inside `skills/coordination/reference/` as prompt templates.

**Project directories** (`projects/`) are isolated environments designed to be run independently with `claude` from within the project folder. Each project has its own `.claude/` directory with real `skills/` and `tools/` folders — but the contents are **symlinks** pointing back to the canonical sources.

This design gives you:

- **Isolation** — Each project is a self-contained working directory. Run `claude` from `projects/pentest/` and it discovers only the skills that project has symlinked.
- **Single source of truth** — Edit a skill once in `skills/`, and every project that symlinks it gets the update immediately.
- **Selective inclusion** — A new project doesn't need all 23 skills. Symlink only what's relevant.
- **Claude Code compatibility** — Claude Code resolves symlinks transparently via the OS.

**Adding a new project:**

```bash
mkdir -p projects/myproject/.claude/{skills,tools}
cd projects/myproject/.claude/skills

# Symlink only the skills this project needs
ln -s ../../../../skills/injection injection
ln -s ../../../../skills/coordination coordination
ln -s ../../../../skills/reconnaissance reconnaissance
# ... add more as needed

# Same for tools
cd ../tools
ln -s ../../../../tools/env-reader.py env-reader.py
```

---

## Contributing

We welcome contributions from the security community!

**Read the full guide:** [CONTRIBUTING.md](CONTRIBUTING.md)

**Quick path using the Skiller:**
```bash
/skiller
# Select: CREATE → provide details → automated GitHub workflow
# Handles: issue creation, branch, skill generation, validation, commit, PR
```

---

## Security & Legal

**IMPORTANT: These tools are designed for authorized security testing ONLY.**

**Authorized & Legal Use:**
- Penetration testing with written authorization
- Bug bounty programs within scope
- Security research on your own systems
- CTF competitions and training environments
- Educational purposes with proper permissions

**Prohibited & Illegal Use:**
- Unauthorized testing of any systems
- Malicious exploitation of vulnerabilities
- Data theft or system disruption
- Any use that violates local or international laws

**Users are solely responsible for compliance with all applicable laws and regulations.**

### Responsible Disclosure

If you discover a vulnerability using these tools:
1. Do not exploit beyond proof-of-concept
2. Report immediately to the vendor/organization
3. Follow responsible disclosure timelines (typically 90 days)
4. Document thoroughly for remediation

---

## Community & Support

- [GitHub Discussions](https://github.com/transilienceai/communitytools/discussions) — Ask questions, share ideas
- [GitHub Issues](https://github.com/transilienceai/communitytools/issues) — Report bugs, request features
- [Website](https://www.transilience.ai) — Commercial products
- [Email](mailto:contact@transilience.ai) — Enterprise support

---

## Project Stats

| Category | Count |
|----------|-------|
| **Skills** | 23 |
| **Role Prompts** | 5 |
| **Tool Integrations** | 2 |
| **Attack Types** | 53 |
| **Reference Files** | 160+ |

**Coverage:**
- OWASP Top 10 (2021) — 100%
- OWASP LLM Top 10 (2025) — 100%
- SANS Top 25 CWE — 90%+
- MITRE ATT&CK TTPs — mapped for all findings

---

## License

MIT License — Copyright (c) 2026 Transilience AI. See [LICENSE](LICENSE) for details.

---

## Contributors

<a href="https://github.com/transilienceai/communitytools/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=transilienceai/communitytools" />
</a>

---

<div align="center">

**Built by [Transilience AI](https://www.transilience.ai)**

Transilience AI specializes in autonomous security testing and AI security operations.

[![Star this repository](https://img.shields.io/badge/Star%20this%20repo-yellow?style=for-the-badge)](https://github.com/transilienceai/communitytools)

[Website](https://www.transilience.ai) | [Issues](https://github.com/transilienceai/communitytools/issues) | [Discussions](https://github.com/transilienceai/communitytools/discussions)

`claude-code` `ai-security` `penetration-testing` `bug-bounty` `owasp` `llm-security` `ai-threat-testing` `security-automation` `ethical-hacking` `cybersecurity` `appsec` `web-security` `hackerone` `hackthebox` `multi-agent`

</div>
