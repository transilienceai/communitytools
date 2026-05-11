# Correlation, Confidence Scoring & Conflict Resolution

Consolidated from `signal_correlator`, `confidence_scorer`, `conflict_resolver`.

## 1. Signal Correlation

For every inferred technology, group all signals across collection skills that reference it. Compute:

- `source_count` — number of distinct skills that produced an evidence row
- `agreement_score` (0-1) — proportion of expected signal types observed (header + JS global + DNS + repo dep, etc.)
- Strength label per signal — `strong` (explicit identifier — header, meta, global), `medium` (URL/cookie/DOM attr), `weak` (job-posting / archive only)

### Strong corroboration patterns

- 3+ independent sources from different domains
- Technical signal **and** job-posting mention
- HTTP header **and** JS global
- DNS record **and** TLS-cert issuer

### Weak corroboration patterns

- 2 sources from the same domain (e.g. both HTML analyses)
- Job posting only
- Archive only

## 2. Conflict Detection (4 types)

| Type | Definition | Example |
|------|-----------|---------|
| `version_mismatch` | Different versions reported | nginx/1.24.0 (current) vs nginx/1.18.0 (archive) |
| `mutually_exclusive` | Frameworks that can't coexist on same context | React + Angular on same URL |
| `temporal_inconsistency` | Archive vs current contradict | jQuery in 2022, gone in 2024 |
| `categorical_ambiguity` | Tech fits multiple categories | Redis as cache (infra) or primary store (backend) |

Severity: `high` (blocks confident inference) / `medium` (needs context) / `low` (cosmetic).

## 3. Source Reliability Weights

```
http_fingerprinting       0.95
javascript_dom_analysis   0.95
tls_certificate_analysis  0.90
dns_intelligence          0.90
html_content_analysis     0.85
code_repository_intel     0.85
job_posting_analysis      0.60
web_archive_analysis      0.50
```

## 4. Confidence Scoring Algorithm

Five components (weighted):

| Factor | Weight | Computation |
|--------|--------|-------------|
| Source diversity | 0.30 | `min(source_count / 4, 1.0)` |
| Signal strength | 0.30 | `(strong*1.0 + medium*0.6 + weak*0.3) / total_signals` |
| Agreement score | 0.20 | from correlation phase |
| Evidence type | 0.15 | `(technical*1.0 + job*0.5 + archive*0.4) / total_evidence` |
| Conflict penalty | 0.05 | `1.0 - penalty` where penalty = high:0.30 / med:0.15 / low:0.05 |

```
confidence_score = 0.30*diversity + 0.30*strength + 0.20*agreement
                 + 0.15*evidence_type + 0.05*(1.0 - conflict_penalty)
```

### Confidence bands

| Band | Score | Interpretation |
|------|-------|----------------|
| High | ≥ 0.70 | Very likely accurate (3+ sources, strong signals, version known) |
| Medium | 0.40-0.69 | Plausible — single strong signal or multiple indirect |
| Low | < 0.40 | Speculative — manual validation needed |

Target distribution: ~50-70% High, ~20-35% Medium, <15% Low. If skewed, recalibrate weights or thresholds.

## 5. Conflict Resolution Decision Tree

```
CONFLICT
├─ Temporal? archive vs current → accept current, log historical note
│
├─ URL/subdomain context? signals from different paths
│   → accept BOTH with context annotation (e.g. React on /, Angular on /admin)
│
├─ Strength tiebreaker? strong vs weak → accept strong, downgrade weak
│
├─ Version-mismatch?
│   ├─ upgrade plausible (e.g. 1.18 → 1.24) → accept latest, add upgrade note
│   └─ downgrade implausible (2.0 → 1.5) → flag for review
│
├─ Mutually-exclusive on SAME url? frameworks can't coexist
│   → flag for manual review (suggest: inspect source, check repo, look for migration)
│
└─ Categorical ambiguity → assign primary by typical use, allow secondary
```

### Resolution rules summary

- **Prioritize current over historical** — archive-only signal never overrides current technical signal
- **URL context separation** is preferred to forcing single-tech resolution
- **Job posting < technical signal** always; downgrade job-only on conflict
- **Confidence adjustments** are small (±0.10 max), never push above 0.85 after a contested resolution
- **Never suppress** evidence — preserve all conflicting signals in output for transparency

## 6. Output Schema

```json
{
  "correlated_technologies": [
    {
      "technology": "React",
      "category": "frontend",
      "sources": ["javascript_dom_analysis", "html_content_analysis", "job_posting_analysis"],
      "source_count": 3,
      "agreement_score": 0.95,
      "corroborating_signals": [{"source", "signal", "strength"}]
    }
  ],
  "conflicts": [
    {"conflict_id", "conflict_type", "technology(ies)", "severity",
     "conflicting_signals": [{"source", "value", "url?", "timestamp?", "signal_strength"}],
     "possible_explanation"}
  ],
  "resolved_conflicts": [
    {"conflict_id", "resolution": {"action", "reasoning", "confidence_adjustment"}, "status"}
  ],
  "unresolved_conflicts": [
    {"conflict_id", "reason_unresolvable", "manual_review_required": true,
     "suggested_actions": []}
  ],
  "technologies_with_confidence": [
    {"technology", "category", "version?", "confidence": "High|Medium|Low",
     "confidence_score": 0.92,
     "confidence_reasoning": {"source_diversity_score", "signal_strength_score",
                              "agreement_score", "evidence_type_score", "conflict_penalty",
                              "weighted_total"},
     "evidence_summary": {"technical_signals", "job_posting_mentions",
                          "strong_evidence_count", "medium_evidence_count", "weak_evidence_count"},
     "confidence_limitations": []}
  ],
  "confidence_summary": {
    "high_confidence_count", "medium_confidence_count", "low_confidence_count",
    "total_technologies", "overall_confidence_score", "high_confidence_percentage",
    "quality_rating", "by_category": { "<cat>": {"high","medium","low","avg_score"} },
    "recommendations": []
  },
  "confidence_gaps": [
    {"technology", "current_confidence", "current_score",
     "missing_evidence_types": [], "recommendations": [],
     "potential_score_improvement", "priority"}
  ]
}
```

## Limits & Errors

- Insufficient data: <10 total signals → return error; <3 sources → mark as low confidence but proceed
- Missing timestamps → skip temporal resolution
- Missing asset inventory → skip URL-context resolution
- Timeout: 30s max per operation
- Streaming for large signal sets (>1000)
- Pure computation — no external requests, sanitize URLs in output, log decisions for audit
