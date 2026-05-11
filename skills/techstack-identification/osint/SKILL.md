---
name: techstack-osint
description: OSINT-side tech-stack identification — public repositories (GitHub/GitLab), job postings & ATS, and Wayback Machine historical snapshots.
---

# OSINT Tech-Stack Identification

## Scope

Recover technology signals from public, non-target sources:

- **Code repositories** — public GitHub/GitLab orgs, language stats, dependency files (`package.json`, `requirements.txt`, `Gemfile`, `go.mod`, `pom.xml`, `composer.json`), CI configs, `Dockerfile`s.
- **Career signals** — career page, ATS platform (Greenhouse, Lever, Workday, Ashby, iCIMS, Taleo, etc.), job-description tech requirements.
- **Web archives** — Wayback Machine CDX queries to detect historical stack and migrations.

These provide indirect but valuable corroboration; weight lower than direct technical signals.

## Signals (input)

- Public repos: org metadata, language map, dependency files, CI/CD configs, Dockerfile FROM lines
- Career page URL + ATS URL pattern + job-description text
- Wayback CDX snapshots (every 6-12 months over 5y)

## Inferences (output)

- Languages and frameworks (with version ranges from dep files)
- CI/CD platform and pipeline maturity
- Container base images and orchestration manifests
- ATS-derived hiring profile (startup vs enterprise)
- Tech-mention frequency (Core Stack ≥50% / Common 25-50% / Occasional <25%)
- Historical stack timeline + migration events (jQuery → React, WordPress → Next.js, on-prem → cloud)

## Techniques

See [reference/patterns.md](reference/patterns.md).

## When to use

- Phase 2 of tech-stack OSINT (corroborating signal layer)
- Validating a hypothesis from direct signals (e.g. confirm Node.js via `package.json`)
- Detecting recent migrations (current stack different from historical)
- Inferring internal stack when public surface is heavily obscured (Cloudflare-fronted, headless API, etc.)
