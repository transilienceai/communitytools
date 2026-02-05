# Confidence Scorer Skill

## Overview
Calculates confidence levels for identified technologies based on signal quantity, quality, source diversity, and corroboration patterns.

## Metadata
- **Skill ID**: confidence_scorer
- **Version**: 1.0.0
- **Category**: Correlation
- **Phase**: 4 (Correlation)
- **Agent**: correlation_agent
- **Execution Mode**: Parallel with other correlation skills

## Purpose
Assigns High, Medium, or Low confidence levels to each identified technology using quantitative scoring algorithms that consider evidence strength, source diversity, and cross-validation patterns.

## Input Requirements

### Required Inputs
```json
{
  "correlated_technologies": [
    {
      "technology": "string",
      "category": "frontend|backend|infrastructure|security|devops|third_party",
      "sources": ["array of source skill names"],
      "source_count": "integer",
      "agreement_score": "float (0-1)",
      "corroborating_signals": [
        {
          "source": "string",
          "signal": "string",
          "strength": "strong|medium|weak"
        }
      ]
    }
  ],
  "conflicts": [
    {
      "technology": "string",
      "conflict_type": "string",
      "severity": "high|medium|low"
    }
  ]
}
```

### Optional Inputs
- `scoring_weights`: Custom weights for scoring criteria (defaults to standard weights)
- `confidence_thresholds`: Custom thresholds for High/Medium/Low (defaults to 0.7/0.4)

## Operations

### Operation: calculate_confidence
Assigns confidence level (High/Medium/Low) to each technology based on multi-factor scoring.

**Input Parameters**:
- `correlated_technologies`: Technologies with corroboration data
- `conflicts`: Detected conflicts affecting confidence

**Scoring Criteria** (weighted):
1. **Source Diversity** (30%): Number of independent evidence sources
2. **Signal Strength** (30%): Quality of evidence (explicit vs indirect)
3. **Agreement Score** (20%): Cross-source consensus level
4. **Evidence Type** (15%): Technical signals vs job postings
5. **Conflict Impact** (5%): Presence of contradictory signals

**Confidence Thresholds**:
- **High Confidence**: Score ≥ 0.70
- **Medium Confidence**: Score ≥ 0.40 and < 0.70
- **Low Confidence**: Score < 0.40

**Process**:
1. **Calculate source diversity score** (0-1 based on source count)
2. **Assess signal strength score** (0-1 based on evidence quality)
3. **Factor in agreement score** from correlation analysis
4. **Weight evidence types** (technical > job posting)
5. **Apply conflict penalties** if contradictions exist
6. **Compute weighted total** (0-1 scale)
7. **Map to confidence level** (High/Medium/Low)
8. **Generate explanation** for assigned confidence

**Output**:
```json
{
  "technologies_with_confidence": [
    {
      "technology": "React",
      "category": "frontend",
      "version": "18.x",
      "confidence": "High",
      "confidence_score": 0.92,
      "confidence_reasoning": {
        "source_diversity_score": 1.0,
        "source_count": 4,
        "signal_strength_score": 0.95,
        "agreement_score": 0.95,
        "evidence_type_score": 1.0,
        "conflict_penalty": 0.0,
        "weighted_total": 0.92
      },
      "evidence_summary": {
        "technical_signals": 3,
        "job_posting_mentions": 5,
        "strong_evidence_count": 3,
        "medium_evidence_count": 2,
        "weak_evidence_count": 0
      }
    },
    {
      "technology": "PostgreSQL",
      "category": "backend",
      "confidence": "Medium",
      "confidence_score": 0.55,
      "confidence_reasoning": {
        "source_diversity_score": 0.33,
        "source_count": 1,
        "signal_strength_score": 0.60,
        "agreement_score": 0.50,
        "evidence_type_score": 0.60,
        "conflict_penalty": 0.0,
        "weighted_total": 0.55
      },
      "evidence_summary": {
        "technical_signals": 0,
        "job_posting_mentions": 8,
        "strong_evidence_count": 0,
        "medium_evidence_count": 1,
        "weak_evidence_count": 0
      },
      "confidence_limitations": [
        "Single source only (job_posting_analysis)",
        "No technical signal corroboration",
        "Recommend verification via database connection fingerprinting"
      ]
    }
  ]
}
```

### Operation: generate_confidence_summary
Creates aggregate confidence statistics for the entire report.

**Input Parameters**:
- `technologies_with_confidence`: All scored technologies

**Process**:
1. **Count by confidence level** (High/Medium/Low)
2. **Calculate overall score** (weighted average)
3. **Identify confidence gaps** (technologies needing more evidence)
4. **Generate quality metrics** (% high confidence, etc.)
5. **Provide recommendations** for improving confidence

**Output**:
```json
{
  "confidence_summary": {
    "high_confidence_count": 45,
    "medium_confidence_count": 23,
    "low_confidence_count": 8,
    "total_technologies": 76,
    "overall_confidence_score": 0.78,
    "high_confidence_percentage": 59.2,
    "quality_rating": "Good",
    "by_category": {
      "frontend": {
        "high": 12,
        "medium": 5,
        "low": 1,
        "avg_score": 0.82
      },
      "backend": {
        "high": 8,
        "medium": 9,
        "low": 3,
        "avg_score": 0.65
      },
      "infrastructure": {
        "high": 15,
        "medium": 3,
        "low": 2,
        "avg_score": 0.85
      },
      "security": {
        "high": 5,
        "medium": 2,
        "low": 1,
        "avg_score": 0.73
      },
      "devops": {
        "high": 3,
        "medium": 2,
        "low": 1,
        "avg_score": 0.68
      },
      "third_party": {
        "high": 2,
        "medium": 2,
        "low": 0,
        "avg_score": 0.75
      }
    },
    "recommendations": [
      "23 technologies at medium confidence could be upgraded with additional technical signals",
      "8 low confidence findings should be manually verified or removed"
    ]
  }
}
```

### Operation: identify_confidence_gaps
Highlights technologies that need additional evidence to improve confidence.

**Input Parameters**:
- `technologies_with_confidence`: Scored technologies

**Process**:
1. **Identify medium/low confidence technologies**
2. **Analyze missing evidence types** (what would help)
3. **Suggest additional skills** to run for validation
4. **Prioritize by importance** (critical tech vs nice-to-have)
5. **Generate actionable recommendations**

**Output**:
```json
{
  "confidence_gaps": [
    {
      "technology": "Redis",
      "current_confidence": "Medium",
      "current_score": 0.58,
      "missing_evidence_types": [
        "technical_signal",
        "dns_records",
        "http_headers"
      ],
      "recommendations": [
        "Check for redis-cli banner via network probing (if authorized)",
        "Search for Redis-specific error messages in HTTP responses",
        "Look for redis:// connection strings in public repositories"
      ],
      "potential_score_improvement": 0.25,
      "priority": "medium"
    }
  ]
}
```

## Scoring Algorithm Details

### Source Diversity Score
```
score = min(source_count / 4, 1.0)

Rationale:
- 1 source = 0.25
- 2 sources = 0.50
- 3 sources = 0.75
- 4+ sources = 1.00
```

### Signal Strength Score
```
strong_signals_weight = 1.0
medium_signals_weight = 0.6
weak_signals_weight = 0.3

score = (strong_count * 1.0 + medium_count * 0.6 + weak_count * 0.3) / total_signals
```

### Evidence Type Score
```
technical_signal_weight = 1.0
job_posting_weight = 0.5
archive_data_weight = 0.4

score = (technical_count * 1.0 + job_count * 0.5 + archive_count * 0.4) / total_evidence
```

### Conflict Penalty
```
high_severity_conflict = -0.30
medium_severity_conflict = -0.15
low_severity_conflict = -0.05

Applied to final score if conflicts exist for this technology
```

### Overall Confidence Score
```
confidence_score = (
  source_diversity_score * 0.30 +
  signal_strength_score * 0.30 +
  agreement_score * 0.20 +
  evidence_type_score * 0.15 +
  (1.0 - conflict_penalty) * 0.05
)
```

## Confidence Level Mapping

### High Confidence (≥ 0.70)
**Criteria** (any of):
- 3+ independent evidence sources with strong signals
- Explicit identifier found (meta tag, header, global variable)
- Job posting mentions + 2+ technical signals
- Direct API/service detection with verification

**Interpretation**: Very likely to be accurate

### Medium Confidence (0.40 - 0.69)
**Criteria** (typical):
- 1-2 evidence sources with medium/strong signals
- Indirect indicators (URL patterns, cookies, DOM attributes)
- Job posting mentions without technical corroboration
- Single strong technical signal without cross-validation

**Interpretation**: Plausible but requires additional verification

### Low Confidence (< 0.40)
**Criteria** (typical):
- Single weak signal only
- Speculation based on generic behavior
- Conflicting evidence without clear resolution
- Outdated information without current confirmation

**Interpretation**: Speculative hypothesis requiring manual validation

## Output Format

### Success Output
```json
{
  "status": "success",
  "technologies_with_confidence": [...],
  "confidence_summary": {...},
  "confidence_gaps": [...],
  "statistics": {
    "total_technologies_scored": 76,
    "high_confidence": 45,
    "medium_confidence": 23,
    "low_confidence": 8,
    "average_confidence_score": 0.78
  },
  "execution_time_ms": 850
}
```

### Error Output
```json
{
  "status": "error",
  "error_code": "NO_TECHNOLOGIES",
  "error_message": "No technologies provided for confidence scoring",
  "partial_results": null
}
```

## Error Handling

### No Technologies
- **IF technologies array empty** → Return error, cannot score
- **IF all technologies lack evidence** → Assign all Low confidence

### Missing Correlation Data
- **IF corroboration data missing** → Use evidence count only
- **IF agreement scores unavailable** → Default to 0.5
- **IF conflicts data missing** → Skip conflict penalties

### Invalid Input
- **IF technology missing required fields** → Skip that technology, continue
- **IF confidence threshold invalid** → Use defaults (0.7/0.4)
- **IF weights don't sum to 1.0** → Normalize weights

## Dependencies

### Required Skills
- signal_correlator (provides corroboration data)

### Required Libraries
- Standard mathematical functions (weighted averages)
- JSON processing

### External APIs
- None (pure computation)

## Configuration

### Settings (from settings.json)
```json
{
  "confidence_scoring": {
    "high_confidence_threshold": 0.70,
    "medium_confidence_threshold": 0.40,
    "source_diversity_weight": 0.30,
    "signal_strength_weight": 0.30,
    "agreement_weight": 0.20,
    "evidence_type_weight": 0.15,
    "conflict_weight": 0.05,
    "min_sources_for_high": 3
  }
}
```

## Usage Example

```json
{
  "operation": "calculate_confidence",
  "inputs": {
    "correlated_technologies": [ /* from signal_correlator */ ],
    "conflicts": [ /* from signal_correlator */ ]
  }
}
```

## Best Practices

1. **Be conservative** - When uncertain, assign lower confidence
2. **Document reasoning** - Always explain confidence score
3. **Highlight limitations** - Call out single-source dependencies
4. **Provide recommendations** - Suggest how to improve confidence
5. **Recalculate after edits** - Update scores when evidence added

## Calibration Guidelines

### Calibrate Against Known Examples
- **Test on known tech stacks** to validate scoring accuracy
- **Adjust weights** if consistently over/under-confident
- **Review false positives** and adjust signal strength weights
- **Validate thresholds** (0.7/0.4) against real-world accuracy

### Quality Assurance
- **Target distribution**: 50-70% High, 20-35% Medium, <15% Low
- **IF too many Low**: Loosen thresholds or improve collection
- **IF too many High**: Tighten thresholds or strengthen criteria
- **Monitor accuracy**: Track user feedback on confidence levels

## Limitations

- **Confidence ≠ certainty** (probabilistic estimates only)
- **Context-dependent** (job posting weight varies by company size)
- **Temporal sensitivity** (recent evidence > old evidence)
- **Cannot detect all false positives** (some will have high confidence)

## Security Considerations

- **No external requests** (pure computation)
- **Sanitize output** (remove sensitive paths/URLs)
- **Log scoring decisions** for audit trail
- **Preserve evidence** for forensic review

## Version History

- **1.0.0** (2024-01-20): Initial implementation with multi-factor scoring
