# Conflict Resolver Skill

## Overview
Resolves contradictory signals detected during correlation using context-aware logic, temporal analysis, and domain expertise rules.

## Metadata
- **Skill ID**: conflict_resolver
- **Version**: 1.0.0
- **Category**: Correlation
- **Phase**: 4 (Correlation)
- **Agent**: correlation_agent
- **Execution Mode**: Parallel with other correlation skills

## Purpose
Analyzes conflicting technology signals to determine the most likely accurate interpretation, providing clear reasoning for resolution decisions and flagging unresolvable conflicts for manual review.

## Input Requirements

### Required Inputs
```json
{
  "conflicts": [
    {
      "conflict_id": "uuid",
      "conflict_type": "version_mismatch|mutually_exclusive|temporal_inconsistency|categorical_ambiguity",
      "technology": "string or array",
      "severity": "high|medium|low",
      "conflicting_signals": [
        {
          "source": "skill_name",
          "value": "string",
          "url": "string (optional)",
          "timestamp": "ISO-8601 (optional)",
          "signal_strength": "strong|medium|weak"
        }
      ],
      "possible_explanation": "string (optional)"
    }
  ],
  "asset_inventory": {
    "domains": [],
    "subdomains": [],
    "ip_addresses": []
  }
}
```

### Optional Inputs
- `resolution_rules`: Custom conflict resolution logic
- `resolution_preferences`: User preferences for conflict handling (e.g., prefer latest version)

## Operations

### Operation: resolve_conflicts
Attempts to resolve detected conflicts using rule-based logic and contextual analysis.

**Input Parameters**:
- `conflicts`: Array of detected conflicts from signal_correlator
- `asset_inventory`: Domain/subdomain information for context

**Resolution Strategies by Conflict Type**:

#### 1. Version Mismatch Resolution
```
Conflict: Different versions reported by different sources
Strategy:
  1. Check temporal order (timestamp comparison)
  2. Prioritize current technical signals over archived data
  3. Consider upgrade paths (1.18 → 1.24 plausible, 2.0 → 1.5 unlikely)
  4. If both recent, report both versions with context
```

**Example**:
```json
{
  "conflict_type": "version_mismatch",
  "technology": "nginx",
  "resolution": {
    "action": "accept_latest",
    "resolved_version": "1.24.0",
    "reasoning": "Current HTTP header reports 1.24.0 (2024-01-20), archive shows 1.18.0 (2023-06-15). Accept current version as active.",
    "confidence_adjustment": "none",
    "historical_note": "Previously used nginx/1.18.0 (detected in 2023 archive)"
  }
}
```

#### 2. Mutually Exclusive Technologies Resolution
```
Conflict: Two frameworks that can't coexist (e.g., React + Angular on same page)
Strategy:
  1. Check URL context (different paths/subdomains?)
  2. Examine DOM structure (isolated components?)
  3. Review job postings (migration in progress?)
  4. Prioritize stronger technical signal
  5. If unresolvable, report both with context
```

**Example**:
```json
{
  "conflict_type": "mutually_exclusive",
  "technologies": ["React", "Angular"],
  "resolution": {
    "action": "both_valid_different_contexts",
    "resolved_technologies": [
      {
        "technology": "React",
        "context": "Main public website (example.com)",
        "confidence": "High",
        "evidence_url": "https://example.com"
      },
      {
        "technology": "Angular",
        "context": "Admin panel (example.com/admin)",
        "confidence": "Medium",
        "evidence_url": "https://example.com/admin"
      }
    ],
    "reasoning": "Different frameworks detected on different URL paths. React on main site, Angular on admin panel. Common in microservices architectures.",
    "confidence_adjustment": "none"
  }
}
```

#### 3. Temporal Inconsistency Resolution
```
Conflict: Archive data contradicts current data
Strategy:
  1. Assume technology migration occurred
  2. Prioritize current signals over historical
  3. Document migration timeline
  4. Preserve historical context for report
```

**Example**:
```json
{
  "conflict_type": "temporal_inconsistency",
  "technology": "jQuery",
  "resolution": {
    "action": "technology_migration",
    "current_state": "Not detected in current analysis",
    "historical_state": "jQuery 3.4.1 detected in 2022 archive",
    "reasoning": "jQuery removed between 2022 and 2024. Likely migrated to modern framework (React detected in current analysis).",
    "confidence_adjustment": "increase_react_confidence",
    "migration_note": "Evidence of jQuery → React migration between 2022-2024"
  }
}
```

#### 4. Categorical Ambiguity Resolution
```
Conflict: Technology could fit multiple categories
Strategy:
  1. Check primary use case in detected context
  2. Review official technology documentation
  3. Default to most common categorization
  4. Allow dual categorization if justified
```

**Example**:
```json
{
  "conflict_type": "categorical_ambiguity",
  "technology": "Redis",
  "conflicting_categories": ["backend", "infrastructure"],
  "resolution": {
    "action": "assign_primary_category",
    "primary_category": "infrastructure",
    "secondary_category": "backend",
    "reasoning": "Redis primarily used for caching (infrastructure), but can function as primary database (backend). Categorized as infrastructure based on typical usage patterns.",
    "confidence_adjustment": "none"
  }
}
```

**Process**:
1. **Load conflict data** from signal_correlator
2. **Classify by conflict type** (version, exclusive, temporal, categorical)
3. **Apply resolution strategy** based on conflict type
4. **Gather additional context** (URLs, timestamps, subdomains)
5. **Make resolution decision** (accept, reject, both, flag)
6. **Document reasoning** clearly
7. **Adjust confidence levels** if needed
8. **Flag unresolvable conflicts** for manual review

**Output**:
```json
{
  "resolved_conflicts": [
    {
      "conflict_id": "uuid",
      "original_conflict": { /* original conflict data */ },
      "resolution": { /* resolution decision */ },
      "status": "resolved|flagged_for_review"
    }
  ],
  "unresolved_conflicts": [
    {
      "conflict_id": "uuid",
      "conflict_type": "mutually_exclusive",
      "reason_unresolvable": "Insufficient context to determine URL path separation",
      "manual_review_required": true,
      "suggested_actions": [
        "Manually inspect both URLs to confirm different sections",
        "Check git history for framework migration timeline",
        "Review job postings for migration projects"
      ]
    }
  ],
  "statistics": {
    "total_conflicts": 5,
    "resolved_conflicts": 3,
    "unresolved_conflicts": 2,
    "confidence_adjustments_made": 4
  }
}
```

### Operation: flag_unresolvable
Identifies conflicts that cannot be automatically resolved and require manual review.

**Input Parameters**:
- `conflicts`: Conflicts from resolution attempt

**Flagging Criteria**:
- Equal-strength conflicting signals from reliable sources
- No temporal or contextual differentiation available
- Ambiguous evidence that could support multiple interpretations
- High-severity conflicts with insufficient data

**Process**:
1. **Identify unresolvable patterns** (equal strength, no context)
2. **Document ambiguity** clearly
3. **Suggest manual investigation steps**
4. **Provide alternative interpretations**
5. **Mark for human review** in report

**Output**:
```json
{
  "flagged_conflicts": [
    {
      "conflict_id": "uuid",
      "summary": "React vs Vue framework conflict without URL context",
      "ambiguity_level": "high",
      "manual_review_priority": "high",
      "suggested_interpretations": [
        "Interpretation A: Using React for main app (stronger signal)",
        "Interpretation B: Using Vue for specific components (weaker signal)",
        "Interpretation C: Migration from Vue to React in progress"
      ],
      "recommended_actions": [
        "Manually inspect source code at conflicting URLs",
        "Check package.json in public repositories",
        "Review recent job postings for migration mentions"
      ]
    }
  ]
}
```

### Operation: adjust_confidence_post_resolution
Updates confidence levels for technologies affected by conflict resolution.

**Input Parameters**:
- `resolved_conflicts`: Conflicts with resolution decisions
- `technologies_with_confidence`: Original confidence scores

**Adjustment Rules**:
- **Confidence upgrade**: When conflicting signals resolved in favor of technology
- **Confidence downgrade**: When conflicts indicate uncertainty
- **No adjustment**: When conflict explained by context (different paths)

**Process**:
1. **Map conflicts to affected technologies**
2. **Determine confidence impact** (upgrade/downgrade/none)
3. **Apply adjustment** (+0.1, -0.1, or none)
4. **Recalculate confidence level** (High/Medium/Low)
5. **Document adjustment reasoning**

**Output**:
```json
{
  "confidence_adjustments": [
    {
      "technology": "React",
      "original_confidence": "High",
      "original_score": 0.85,
      "adjustment": "+0.10",
      "adjustment_reason": "Conflict with Angular resolved - React confirmed as primary framework",
      "new_confidence": "High",
      "new_score": 0.95
    },
    {
      "technology": "Angular",
      "original_confidence": "Medium",
      "original_score": 0.60,
      "adjustment": "-0.15",
      "adjustment_reason": "Mutually exclusive conflict with React, Angular only detected on admin subdomain",
      "new_confidence": "Medium",
      "new_score": 0.45
    }
  ]
}
```

## Resolution Rules Database

### Rule: Prioritize Current Over Historical
```
IF conflict_type == "temporal_inconsistency":
    IF one_signal_from_web_archive AND one_signal_current:
        ACCEPT current_signal
        ADD historical_note(archive_signal)
```

### Rule: URL Context Separation
```
IF conflict_type == "mutually_exclusive":
    IF signals_from_different_urls OR signals_from_different_subdomains:
        ACCEPT both_technologies
        ANNOTATE with_url_context
```

### Rule: Signal Strength Tiebreaker
```
IF conflict_unresolvable_by_context:
    IF one_signal_strength == "strong" AND other_signal_strength == "weak":
        ACCEPT strong_signal
        DOWNGRADE other_technology_confidence
```

### Rule: Version Upgrade Path Validation
```
IF conflict_type == "version_mismatch":
    IF version_upgrade_plausible(old_version, new_version):
        ACCEPT new_version
        ADD upgrade_note
    ELSE:
        FLAG for_manual_review
```

### Rule: Job Posting Validation
```
IF technical_signal CONFLICTS WITH job_posting:
    PRIORITIZE technical_signal
    DOWNGRADE job_posting_confidence
    NOTE "Job posting may be outdated or aspirational"
```

## Output Format

### Success Output
```json
{
  "status": "success",
  "resolved_conflicts": [...],
  "unresolved_conflicts": [...],
  "confidence_adjustments": [...],
  "statistics": {
    "total_conflicts": 5,
    "auto_resolved": 3,
    "flagged_for_review": 2,
    "confidence_upgrades": 2,
    "confidence_downgrades": 3
  },
  "execution_time_ms": 950
}
```

### Error Output
```json
{
  "status": "error",
  "error_code": "NO_CONFLICTS",
  "error_message": "No conflicts provided for resolution",
  "partial_results": null
}
```

## Error Handling

### No Conflicts Provided
- **IF conflicts array empty** → Return success with empty results (no work needed)

### Missing Context Data
- **IF asset_inventory missing** → Attempt resolution without URL context
- **IF timestamps missing** → Cannot apply temporal resolution
- **IF signal_strength missing** → Treat all signals as equal strength

### Unresolvable Conflicts
- **NEVER force resolution** when insufficient data
- **ALWAYS flag for manual review** when uncertain
- **DOCUMENT ambiguity** clearly for user

## Dependencies

### Required Skills
- signal_correlator (provides conflict data)

### Required Libraries
- Pattern matching utilities
- Date/time comparison functions
- URL parsing libraries

### External APIs
- None (pure analysis)

## Configuration

### Settings (from settings.json)
```json
{
  "conflict_resolution": {
    "prioritize_current_over_historical": true,
    "allow_multiple_frameworks": true,
    "auto_resolve_version_conflicts": true,
    "confidence_adjustment_delta": 0.10,
    "max_confidence_after_conflict": 0.85,
    "flag_high_severity_conflicts": true
  }
}
```

## Usage Example

```json
{
  "operation": "resolve_conflicts",
  "inputs": {
    "conflicts": [ /* from signal_correlator */ ],
    "asset_inventory": { /* from Phase 1 */ }
  }
}
```

## Best Practices

1. **Be transparent** - Document all resolution decisions clearly
2. **Prefer context over strength** - URL/subdomain separation explains many conflicts
3. **Flag ambiguity** - Don't force resolution when uncertain
4. **Preserve history** - Keep historical signals as context notes
5. **Adjust confidence conservatively** - Small adjustments (±0.10) only

## Resolution Decision Tree

```
CONFLICT DETECTED
    ├─ Check temporal order
    │   ├─ Archive vs Current? → Prioritize current, note historical
    │   └─ Both recent? → Continue to next check
    │
    ├─ Check URL/subdomain context
    │   ├─ Different URLs? → Accept both with context annotation
    │   └─ Same URL? → Continue to next check
    │
    ├─ Check signal strength
    │   ├─ Strong vs Weak? → Accept strong, downgrade weak
    │   └─ Equal strength? → Continue to next check
    │
    ├─ Check technology compatibility
    │   ├─ Can coexist? → Accept both
    │   └─ Mutually exclusive? → Flag for manual review
    │
    └─ UNRESOLVABLE → Flag with suggested investigation steps
```

## Limitations

- **Cannot resolve all conflicts** (human judgment often required)
- **Context inference may be wrong** (URL separation assumption)
- **Version upgrade logic** may not apply to all software
- **No access to internal systems** for definitive answers

## Security Considerations

- **No external requests** (pure analysis)
- **Sanitize URLs** in output
- **Log resolution decisions** for audit
- **Preserve all conflicting evidence** (transparency)

## Version History

- **1.0.0** (2024-01-20): Initial implementation with rule-based conflict resolution
