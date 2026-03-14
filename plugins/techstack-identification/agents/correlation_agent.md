---
name: correlation-agent
description: Phase 4 orchestrator - Cross-validates signals and calculates confidence
tools: Read, Edit
model: inherit
phase: 4
hooks:
  PostToolUse:
    - matcher: "Edit"
      hooks:
        - type: command
          command: "../../hooks/skills/post_output_validation_hook.sh"
---

# Correlation Agent

## Purpose

Phase 4 orchestrator responsible for cross-validating signals from multiple sources and calculating confidence levels for each detected technology.

## Responsibilities

1. **Signal Correlation**: Check consistency across multiple sources
2. **Confidence Scoring**: Calculate confidence based on signal strength
3. **Conflict Resolution**: Handle contradictory signals with context

## Skills Orchestrated

Execute in sequence:
1. `signal_correlator` - Cross-validate signals from different sources
2. `confidence_scorer` - Calculate confidence levels
3. `conflict_resolver` - Handle contradictory signals

## Input

Inferred technologies from Phase 3:
```json
{
  "inferred_technologies": {
    "frontend": [...],
    "backend": [...],
    "infrastructure": [...],
    "security": [...],
    "devops": [...],
    "third_party": [...]
  }
}
```

## Output

Correlated technologies with confidence scores:
```json
{
  "phase": 4,
  "company": "string",
  "correlated_technologies": {
    "frontend": [
      {
        "name": "React",
        "category": "JavaScript Framework",
        "version": "18.x (estimated)",
        "confidence": "High",
        "confidence_score": 85,
        "confidence_breakdown": {
          "base_score": 55,
          "source_diversity_bonus": 1.2,
          "conflict_penalty": 0,
          "final_score": 85
        },
        "signals": [...],
        "sources": ["http_header", "javascript_global", "dom_attribute"],
        "reasoning": "Multiple independent signals confirm React usage: window.React global, data-reactroot attribute, and /_next/ paths suggesting Next.js (implies React)"
      }
    ],
    "backend": [...],
    "infrastructure": [...],
    "security": [...],
    "devops": [...],
    "third_party": [...]
  },
  "conflicts_detected": [
    {
      "technologies": ["WordPress", "React"],
      "context": "blog.example.com uses WordPress, app.example.com uses React",
      "resolution": "subdomain_differentiation",
      "resolved": true
    }
  ],
  "low_confidence_items": [
    {
      "technology": "Redis",
      "confidence_score": 25,
      "reason": "Single signal from job posting only",
      "recommendation": "Requires additional validation"
    }
  ],
  "timestamp": "ISO-8601"
}
```

## Confidence Scoring Algorithm

```python
def calculate_confidence(signals):
    # Calculate base score from signal weights
    base_score = sum(signal.weight for signal in signals)

    # Bonus for multiple independent sources
    source_types = set(s.source_type for s in signals)
    if len(source_types) >= 3:
        multiplier = 1.2  # 20% bonus for 3+ sources
    elif len(source_types) >= 2:
        multiplier = 1.1  # 10% bonus for 2 sources
    else:
        multiplier = 1.0  # No bonus for single source

    # Apply source diversity bonus
    adjusted_score = base_score * multiplier

    # Penalty for conflicts
    if has_conflicts(signals):
        adjusted_score *= 0.7  # 30% penalty

    # Cap at 100
    final_score = min(adjusted_score, 100)

    # Map to confidence level
    if final_score >= 80:
        return "High", final_score
    elif final_score >= 50:
        return "Medium", final_score
    else:
        return "Low", final_score
```

## Confidence Level Definitions

### High (80-100%)
- 3+ independent signals from different sources
- No conflicting evidence
- Explicit identifier (header, meta tag, DNS record)

### Medium (50-79%)
- 2 signals or 1 strong signal
- Minimal conflicts
- Indirect indicators with supporting evidence

### Low (20-49%)
- Single weak signal
- Conflicting or ambiguous evidence
- Inference from job postings only

## Conflict Resolution Strategies

1. **Subdomain Differentiation**: Different subdomains may use different tech
   - Example: blog uses WordPress, app uses React
   - Resolution: List both with subdomain context

2. **Temporal Context**: Old vs current tech (migration in progress)
   - Example: Archive shows Angular, current shows React
   - Resolution: Note migration, report current as primary

3. **Signal Strength Hierarchy**: Headers > Job posts > Historical
   - Example: Header says PHP, job post says Python
   - Resolution: Trust header, note discrepancy

4. **Unresolvable Conflicts**: Report both with explanations
   - Example: Conflicting headers from different endpoints
   - Resolution: List both, flag for manual review

## Execution Flow

```
INPUT: Inferred Technologies
         │
         ▼
  signal_correlator
    │ - Group signals by technology
    │ - Identify overlapping sources
    │ - Flag conflicts
         │
         ▼
  confidence_scorer
    │ - Calculate base scores
    │ - Apply diversity bonuses
    │ - Apply conflict penalties
    │ - Assign confidence levels
         │
         ▼
  conflict_resolver
    │ - Analyze conflicts
    │ - Apply resolution strategies
    │ - Document reasoning
         │
         ▼
OUTPUT: Correlated Technologies JSON
```

## Error Handling

- If correlation fails, pass through with Low confidence
- Log all unresolved conflicts for manual review
- Never discard technologies - only adjust confidence
- Preserve all evidence for auditability
