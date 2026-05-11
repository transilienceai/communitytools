---
name: techstack-correlation
description: Correlation, confidence scoring, and conflict resolution across all tech-stack signals. Cross-validates and assigns High/Medium/Low confidence per technology.
---

# Tech-Stack Correlation

## Scope

The Phase 4 layer that consumes all detection outputs (frontend, backend, infra, security, OSINT) and produces the final vetted technology list:

- **Cross-validate** signals from independent sources for corroboration
- **Score confidence** per technology (multi-factor weighted scoring)
- **Resolve conflicts** between signals (version mismatch, mutually exclusive frameworks, temporal inconsistencies, categorical ambiguity)
- **Flag** unresolvable conflicts for manual review

## Signals (input)

- Raw signals grouped by category: `http`, `dns`, `tls`, `javascript`, `html`, `repository`, `job`, `archive`
- Inferred technologies from each detection domain (frontend / backend / infra / security)
- Asset inventory (domains, subdomains, IP map) for URL-context resolution

## Inferences (output)

- `correlated_technologies[]` — each with `sources`, `source_count`, `agreement_score`, `corroborating_signals`
- `conflicts[]` — typed (version_mismatch / mutually_exclusive / temporal_inconsistency / categorical_ambiguity), with severity
- `technologies_with_confidence[]` — confidence level (High / Medium / Low), score (0-1), reasoning breakdown
- `confidence_summary` — counts, overall score, per-category breakdown, recommendations
- `confidence_gaps[]` — technologies needing additional evidence with suggested actions

## Techniques

See [reference/patterns.md](reference/patterns.md).

## When to use

- Always — last analysis stage before report generation
- Required to decide what makes the final tech-stack list and at what confidence
- Pure computation; no external requests
