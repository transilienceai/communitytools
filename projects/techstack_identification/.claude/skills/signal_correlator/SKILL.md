# Signal Correlator Skill

## Overview
Cross-validates signals from multiple sources for consistency, identifying corroborating evidence and detecting contradictions across data collection domains.

## Metadata
- **Skill ID**: signal_correlator
- **Version**: 1.0.0
- **Category**: Correlation
- **Phase**: 4 (Correlation)
- **Agent**: correlation_agent
- **Execution Mode**: Parallel with other correlation skills

## Purpose
Analyzes raw signals from Phase 2 data collection and inferred technologies from Phase 3 to identify patterns of agreement, detect inconsistencies, and strengthen findings through multi-source validation.

## Input Requirements

### Required Inputs
```json
{
  "raw_signals": {
    "http_signals": [{"source": "skill_name", "signal": "description", "data": {}}],
    "dns_signals": [{"source": "skill_name", "signal": "description", "data": {}}],
    "tls_signals": [{"source": "skill_name", "signal": "description", "data": {}}],
    "javascript_signals": [{"source": "skill_name", "signal": "description", "data": {}}],
    "html_signals": [{"source": "skill_name", "signal": "description", "data": {}}],
    "repository_signals": [{"source": "skill_name", "signal": "description", "data": {}}],
    "job_signals": [{"source": "skill_name", "signal": "description", "data": {}}],
    "archive_signals": [{"source": "skill_name", "signal": "description", "data": {}}]
  },
  "inferred_technologies": {
    "frontend": [{"name": "string", "evidence": [], "confidence": "string"}],
    "backend": [{"name": "string", "evidence": [], "confidence": "string"}],
    "infrastructure": [{"name": "string", "evidence": [], "confidence": "string"}],
    "security": [{"name": "string", "evidence": [], "confidence": "string"}],
    "devops": [{"name": "string", "evidence": [], "confidence": "string"}],
    "third_party": [{"name": "string", "evidence": [], "confidence": "string"}]
  }
}
```

### Optional Inputs
- `correlation_rules`: Custom correlation logic (defaults to built-in rules)
- `signal_weights`: Importance weighting by source type (defaults to equal weights)

## Operations

### Operation: correlate_signals
Cross-validates signals across all collection sources to identify corroborating evidence.

**Input Parameters**:
- `raw_signals`: Object containing all collected signals by category
- `inferred_technologies`: Technologies identified in Phase 3

**Process**:
1. **Group signals by technology** - Organize all signals that reference same technology
2. **Identify cross-source agreement** - Find signals from different skills pointing to same tech
3. **Detect source diversity** - Count number of independent sources per technology
4. **Flag corroboration patterns** - Mark technologies with multiple independent confirmations
5. **Calculate agreement score** - Quantify level of cross-source consensus

**Output**:
```json
{
  "correlated_technologies": [
    {
      "technology": "React",
      "category": "frontend",
      "sources": ["javascript_dom_analysis", "html_content_analysis", "job_posting_analysis"],
      "source_count": 3,
      "agreement_score": 0.95,
      "corroborating_signals": [
        {
          "source": "javascript_dom_analysis",
          "signal": "window.React detected",
          "strength": "strong"
        },
        {
          "source": "html_content_analysis",
          "signal": "data-reactroot attributes found",
          "strength": "strong"
        },
        {
          "source": "job_posting_analysis",
          "signal": "React mentioned in 3 job postings",
          "strength": "medium"
        }
      ],
      "correlation_status": "strong_corroboration"
    }
  ]
}
```

### Operation: detect_conflicts
Identifies contradictory signals that suggest conflicting technologies or versions.

**Input Parameters**:
- `raw_signals`: All collected signals
- `inferred_technologies`: Technologies from inference phase

**Process**:
1. **Scan for mutually exclusive technologies** - Check for incompatible combinations
2. **Detect version conflicts** - Find different versions reported by different sources
3. **Identify temporal inconsistencies** - Archive data vs current data mismatches
4. **Flag ambiguous signals** - Mark signals that could indicate multiple technologies
5. **Prioritize conflict resolution** - Rank conflicts by impact on report quality

**Output**:
```json
{
  "conflicts": [
    {
      "conflict_type": "version_mismatch",
      "technology": "nginx",
      "conflicting_signals": [
        {
          "source": "http_fingerprinting",
          "value": "nginx/1.24.0",
          "timestamp": "2024-01-20T10:00:00Z"
        },
        {
          "source": "web_archive_analysis",
          "value": "nginx/1.18.0",
          "timestamp": "2023-06-15T14:30:00Z"
        }
      ],
      "severity": "low",
      "resolution_priority": 3
    },
    {
      "conflict_type": "mutually_exclusive",
      "technologies": ["Angular", "React"],
      "conflicting_signals": [
        {
          "source": "html_content_analysis",
          "technology": "Angular",
          "signal": "ng-* attributes detected",
          "url": "https://example.com/admin"
        },
        {
          "source": "javascript_dom_analysis",
          "technology": "React",
          "signal": "window.React detected",
          "url": "https://example.com"
        }
      ],
      "severity": "medium",
      "resolution_priority": 1,
      "possible_explanation": "Different frameworks on different subdomains/paths"
    }
  ]
}
```

### Operation: validate_inference_quality
Assesses the quality of technology inferences based on evidence diversity and strength.

**Input Parameters**:
- `inferred_technologies`: Technologies from Phase 3
- `raw_signals`: Supporting signal data

**Process**:
1. **Check evidence diversity** - Ensure evidence from multiple domains
2. **Validate evidence strength** - Assess reliability of each evidence source
3. **Detect single-source dependencies** - Flag technologies with only one evidence type
4. **Identify weak inferences** - Mark technologies needing additional validation
5. **Generate quality metrics** - Calculate inference quality scores

**Output**:
```json
{
  "quality_assessment": {
    "high_quality_inferences": 45,
    "medium_quality_inferences": 23,
    "low_quality_inferences": 8,
    "technologies_needing_validation": [
      {
        "technology": "PostgreSQL",
        "category": "backend",
        "issue": "single_source_only",
        "source": "job_posting_analysis",
        "recommendation": "Requires technical signal corroboration"
      }
    ],
    "overall_quality_score": 0.78
  }
}
```

## Correlation Rules

### Strong Corroboration Patterns
- **3+ independent sources** from different domains → Strong corroboration
- **Technical signal + job posting** → Strong corroboration
- **HTTP header + JavaScript global** → Strong corroboration
- **DNS record + TLS certificate** → Strong corroboration

### Weak Corroboration Patterns
- **2 sources from same domain** (e.g., both HTML analysis) → Weak corroboration
- **Job posting only** → Weak corroboration (needs technical validation)
- **Archive data only** → Weak corroboration (may be outdated)

### Conflict Detection Patterns
- **Version mismatches** → Check temporal order (upgrade vs downgrade)
- **Framework conflicts** → Check URL paths (different tech per section)
- **Server conflicts** → Check subdomains (different servers per service)
- **Provider conflicts** → Check IP ranges (multi-cloud deployments)

## Signal Weighting

### Source Reliability Weights
```json
{
  "http_fingerprinting": 0.95,
  "javascript_dom_analysis": 0.95,
  "tls_certificate_analysis": 0.90,
  "dns_intelligence": 0.90,
  "html_content_analysis": 0.85,
  "code_repository_intel": 0.85,
  "job_posting_analysis": 0.60,
  "web_archive_analysis": 0.50
}
```

### Signal Strength Classification
- **Strong**: Explicit identifiers (headers, meta tags, globals)
- **Medium**: Indirect indicators (URL patterns, cookies, DOM attributes)
- **Weak**: Speculative (job postings without technical confirmation)

## Output Format

### Success Output
```json
{
  "status": "success",
  "correlation_results": {
    "correlated_technologies": [...],
    "conflicts": [...],
    "quality_assessment": {...}
  },
  "statistics": {
    "total_signals_analyzed": 247,
    "technologies_corroborated": 45,
    "conflicts_detected": 3,
    "single_source_technologies": 8
  },
  "execution_time_ms": 1250
}
```

### Error Output
```json
{
  "status": "error",
  "error_code": "INSUFFICIENT_DATA",
  "error_message": "Less than 10 signals available for correlation",
  "partial_results": {...}
}
```

## Error Handling

### Insufficient Data
- **IF < 10 total signals** → Return error, cannot correlate
- **IF single source only** → Proceed but flag all as low confidence
- **IF no inferred technologies** → Skip correlation, return empty results

### Conflicting Signals
- **DETECT conflicts** → Pass to conflict_resolver skill
- **DOCUMENT ambiguity** → Include in output for transparency
- **NEVER suppress conflicts** → Always report for manual review

### Performance Issues
- **Timeout**: 30 seconds max execution time
- **Large datasets**: Sample if > 1000 signals (stratified sampling)
- **Memory limit**: Stream processing for large signal sets

## Dependencies

### Required Skills
- None (operates on outputs from Phase 2 & 3)

### Required Libraries
- Standard JSON parsing
- Pattern matching utilities
- Statistical correlation functions

### External APIs
- None (pure computation)

## Configuration

### Settings (from settings.json)
```json
{
  "correlation": {
    "min_sources_for_high_confidence": 3,
    "min_agreement_score": 0.7,
    "enable_conflict_detection": true,
    "signal_weight_mode": "reliability_based",
    "max_execution_time_ms": 30000
  }
}
```

## Usage Example

```json
{
  "operation": "correlate_signals",
  "inputs": {
    "raw_signals": { /* Phase 2 output */ },
    "inferred_technologies": { /* Phase 3 output */ }
  }
}
```

## Best Practices

1. **Prioritize source diversity** over signal quantity
2. **Flag conflicts prominently** for manual review
3. **Document reasoning** for correlation conclusions
4. **Preserve all evidence** even if conflicting
5. **Calculate agreement scores** transparently

## Limitations

- **Cannot resolve all conflicts** automatically (human judgment required)
- **Temporal data** may show technology migrations (not errors)
- **Multi-tenant systems** may use different tech per service
- **Correlation does not equal causation** (coincidental similarities possible)

## Security Considerations

- **No external requests** (pure analysis)
- **Sanitize URLs** in output
- **Redact sensitive paths** if detected
- **Log correlation decisions** for audit

## Version History

- **1.0.0** (2024-01-20): Initial implementation with cross-source correlation
