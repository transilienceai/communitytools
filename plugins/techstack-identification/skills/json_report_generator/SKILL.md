# JSON Report Generator Skill

## Overview
Generates structured TechStackReport JSON output conforming to the defined schema, integrating all data from previous phases into a complete, valid report document.

## Metadata
- **Skill ID**: json_report_generator
- **Version**: 1.0.0
- **Category**: Report Generation
- **Phase**: 5 (Report Generation)
- **Agent**: report_generation_agent
- **Execution Mode**: Sequential (first in report generation phase)

## Purpose
Assembles final technology stack report in JSON format by combining asset inventory, formatted evidence, confidence scores, and metadata into a schema-compliant document ready for storage and export.

## Input Requirements

### Required Inputs
```json
{
  "company_name": "string",
  "analysis_depth": "quick|standard|deep",
  "asset_inventory": {
    "primary_domain": "string",
    "domains": ["array"],
    "subdomains": ["array"],
    "ip_addresses": [
      {
        "ip": "string",
        "domain": "string",
        "provider": "string",
        "asn": "string",
        "region": "string"
      }
    ],
    "certificates": [
      {
        "common_name": "string",
        "issuer": "string",
        "sans": ["array"],
        "valid_until": "date"
      }
    ],
    "api_portals": ["array"]
  },
  "formatted_technologies": [
    {
      "technology": "string",
      "category": "frontend|backend|infrastructure|security|devops|third_party",
      "version": "string (optional)",
      "confidence": "High|Medium|Low",
      "evidence": [
        {
          "type": "string",
          "source": "string",
          "finding": "string",
          "details": "string",
          "strength": "strong|medium|weak",
          "url": "string (optional)",
          "reasoning": "string",
          "timestamp": "ISO-8601"
        }
      ],
      "evidence_summary": {...}
    }
  ],
  "confidence_summary": {
    "high_confidence_count": "integer",
    "medium_confidence_count": "integer",
    "low_confidence_count": "integer",
    "total_technologies": "integer",
    "overall_confidence_score": "float (0-1)",
    "by_category": {...}
  },
  "execution_metadata": {
    "phase_durations": {...},
    "total_signals_collected": "integer",
    "intelligence_domains_queried": "integer",
    "execution_time_seconds": "integer"
  }
}
```

### Optional Inputs
- `domain_hint`: User-provided domain (if given)
- `additional_context`: User-provided context
- `conflicts_resolved`: Conflict resolution summary
- `edit_history`: Previous edits (for updated reports)

## Operations

### Operation: generate_report
Creates complete TechStackReport JSON document from all phase outputs.

**Input Parameters**:
- All required inputs from previous phases

**Process**:
1. **Generate unique report_id** (UUID v4)
2. **Create timestamp** (ISO-8601 UTC)
3. **Assemble asset discovery section** from Phase 1 output
4. **Organize technologies by category** from formatted evidence
5. **Include confidence summary** from Phase 4
6. **Add execution metadata** with statistics
7. **Validate schema compliance** before finalizing
8. **Apply edit history** if updating existing report

**TechStackReport Schema**:
```json
{
  "report_id": "uuid",
  "company": "string",
  "primary_domain": "string",
  "generated_at": "ISO-8601 (UTC)",
  "analysis_depth": "quick|standard|deep",
  "discovered_assets": {
    "domains": ["array of verified domains"],
    "subdomains": ["array of subdomains"],
    "ip_addresses": [
      {
        "ip": "string",
        "domain": "string",
        "provider": "string (e.g., AWS, Google Cloud, Azure)",
        "asn": "string",
        "region": "string"
      }
    ],
    "certificates": [
      {
        "common_name": "string",
        "issuer": "string",
        "sans": ["array of SANs"],
        "valid_until": "date (ISO-8601)"
      }
    ],
    "api_portals": ["array of API documentation URLs"]
  },
  "technologies": {
    "frontend": [
      {
        "name": "string",
        "version": "string (optional)",
        "category": "string (e.g., framework, library, ui_component)",
        "confidence": "High|Medium|Low",
        "evidence": [
          {
            "type": "technical_signal|job_posting|historical|repository",
            "source": "skill_name",
            "finding": "string (summary of what was detected)",
            "details": "string (technical specifics)",
            "strength": "strong|medium|weak",
            "url": "string (optional, for verification)",
            "reasoning": "string (why this indicates the technology)",
            "timestamp": "ISO-8601"
          }
        ],
        "evidence_summary": {
          "total_evidence_count": "integer",
          "technical_evidence_count": "integer",
          "job_posting_count": "integer",
          "strong_evidence_count": "integer",
          "medium_evidence_count": "integer",
          "earliest_detection": "ISO-8601",
          "latest_detection": "ISO-8601"
        }
      }
    ],
    "backend": [ /* same structure */ ],
    "infrastructure": [ /* same structure */ ],
    "security": [ /* same structure */ ],
    "devops": [ /* same structure */ ],
    "third_party": [ /* same structure */ ]
  },
  "confidence_summary": {
    "high_confidence": "integer",
    "medium_confidence": "integer",
    "low_confidence": "integer",
    "total_technologies": "integer",
    "overall_score": "float (0-1)",
    "high_confidence_percentage": "float",
    "quality_rating": "Excellent|Good|Fair|Poor",
    "by_category": {
      "frontend": {
        "high": "integer",
        "medium": "integer",
        "low": "integer",
        "avg_score": "float (0-1)"
      },
      "backend": { /* same structure */ },
      "infrastructure": { /* same structure */ },
      "security": { /* same structure */ },
      "devops": { /* same structure */ },
      "third_party": { /* same structure */ }
    }
  },
  "metadata": {
    "intelligence_domains_queried": "integer (max 17)",
    "total_signals_collected": "integer",
    "execution_time_seconds": "integer",
    "phase_durations": {
      "asset_discovery": "integer (seconds)",
      "data_collection": "integer (seconds)",
      "tech_inference": "integer (seconds)",
      "correlation": "integer (seconds)",
      "report_generation": "integer (seconds)"
    },
    "analysis_completeness": "float (0-1)",
    "domains_analyzed": "integer",
    "subdomains_analyzed": "integer"
  },
  "conflicts_resolved": [
    {
      "conflict_type": "string",
      "resolution": "string",
      "technologies_affected": ["array"]
    }
  ],
  "recommendations": [
    "string (suggestions for manual validation or additional analysis)"
  ],
  "edit_history": [
    {
      "timestamp": "ISO-8601",
      "operation": "string",
      "editor": "string",
      "changes": {...}
    }
  ]
}
```

**Output**:
```json
{
  "status": "success",
  "report": { /* Complete TechStackReport */ },
  "validation": {
    "schema_valid": true,
    "all_required_fields_present": true,
    "data_integrity_check": "passed"
  },
  "report_metadata": {
    "report_size_bytes": 45678,
    "technology_count": 76,
    "evidence_count": 189,
    "generation_time_ms": 1250
  }
}
```

### Operation: validate_schema
Validates generated report against TechStackReport schema requirements.

**Input Parameters**:
- `report`: Generated report JSON

**Validation Checks**:
1. **Required fields present**:
   - report_id, company, primary_domain, generated_at
   - analysis_depth, discovered_assets, technologies
   - confidence_summary, metadata
2. **Data type validation**:
   - UUIDs are valid format
   - Timestamps are ISO-8601
   - Enums match allowed values
   - Numbers are in valid ranges
3. **Referential integrity**:
   - Confidence counts match technology counts
   - Category totals sum correctly
   - Evidence references valid technologies
4. **Logical consistency**:
   - Overall score matches individual scores
   - Phase durations sum to total time
   - Percentage calculations are correct

**Process**:
1. **Check required fields** (fail if missing)
2. **Validate data types** (fail if incorrect)
3. **Verify enum values** (fail if invalid)
4. **Check referential integrity** (warn if inconsistent)
5. **Validate calculations** (warn if incorrect)
6. **Generate validation report**

**Output**:
```json
{
  "validation_result": "valid|invalid|valid_with_warnings",
  "errors": [
    {
      "field": "technologies.frontend[2].confidence",
      "error": "Invalid enum value 'high' (must be 'High', 'Medium', or 'Low')",
      "severity": "error"
    }
  ],
  "warnings": [
    {
      "field": "confidence_summary.overall_score",
      "warning": "Calculated value (0.78) does not match provided value (0.75)",
      "severity": "warning"
    }
  ],
  "validation_summary": {
    "total_checks": 45,
    "passed": 43,
    "warnings": 1,
    "errors": 1
  }
}
```

### Operation: calculate_quality_rating
Assigns overall quality rating (Excellent/Good/Fair/Poor) to the report.

**Input Parameters**:
- `confidence_summary`: Confidence statistics

**Quality Rating Criteria**:
- **Excellent**: ≥80% High confidence, <5% Low confidence
- **Good**: ≥60% High confidence, <15% Low confidence
- **Fair**: ≥40% High confidence, <30% Low confidence
- **Poor**: <40% High confidence OR ≥30% Low confidence

**Process**:
1. **Calculate high confidence percentage**
2. **Calculate low confidence percentage**
3. **Apply rating criteria**
4. **Generate quality explanation**

**Output**:
```json
{
  "quality_rating": "Good",
  "high_confidence_percentage": 59.2,
  "low_confidence_percentage": 10.5,
  "rating_explanation": "Good quality report with majority high-confidence findings. Some medium-confidence technologies require additional validation."
}
```

### Operation: generate_recommendations
Creates actionable recommendations for report users based on confidence gaps and limitations.

**Input Parameters**:
- `technologies`: All identified technologies
- `confidence_summary`: Confidence statistics

**Recommendation Types**:
1. **Manual verification needed** - Low confidence technologies
2. **Additional analysis suggested** - Medium confidence technologies
3. **Missing domains** - Subdomains not analyzed
4. **Evidence gaps** - Single-source technologies
5. **Conflict resolution** - Flagged conflicts requiring human review

**Process**:
1. **Identify low confidence technologies**
2. **Find technologies with limitations**
3. **Detect evidence gaps** (single source)
4. **Check for unresolved conflicts**
5. **Suggest verification methods**
6. **Prioritize recommendations** by impact

**Output**:
```json
{
  "recommendations": [
    "Manually verify 8 low-confidence technologies: PostgreSQL, Redis, Kubernetes, ...",
    "23 medium-confidence technologies could benefit from additional technical signals",
    "Consider authorized port scanning to confirm backend database (PostgreSQL detected via job postings only)",
    "Review admin subdomain (admin.example.com) for separate technology stack",
    "Resolve React vs Angular conflict by inspecting URL paths manually"
  ],
  "prioritized_actions": [
    {
      "priority": "high",
      "action": "Verify PostgreSQL usage (currently Medium confidence, job posting only)",
      "method": "Check for database error messages, connection strings in public repos, or port 5432 visibility"
    },
    {
      "priority": "medium",
      "action": "Investigate React/Angular conflict",
      "method": "Manually inspect https://example.com and https://example.com/admin to confirm different frameworks"
    }
  ]
}
```

## Report Metadata Generation

### Analysis Completeness Calculation
```
completeness = (
  (domains_found / max(domains_expected, 1)) * 0.2 +
  (subdomains_found / max(20, 1)) * 0.2 +
  (intelligence_domains_queried / 17) * 0.3 +
  (technical_signals / max(total_signals, 1)) * 0.3
)

Capped at 1.0
```

### Quality Rating Logic
```python
high_pct = (high_confidence_count / total_technologies) * 100
low_pct = (low_confidence_count / total_technologies) * 100

if high_pct >= 80 and low_pct < 5:
    rating = "Excellent"
elif high_pct >= 60 and low_pct < 15:
    rating = "Good"
elif high_pct >= 40 and low_pct < 30:
    rating = "Fair"
else:
    rating = "Poor"
```

## Output Format

### Success Output
```json
{
  "status": "success",
  "report": { /* Complete TechStackReport */ },
  "report_file_path": "outputs/techstack_reports/Company_20240120_100000.json",
  "validation": {
    "schema_valid": true,
    "quality_rating": "Good"
  },
  "statistics": {
    "total_technologies": 76,
    "total_evidence": 189,
    "report_size_bytes": 45678
  },
  "execution_time_ms": 1250
}
```

### Error Output
```json
{
  "status": "error",
  "error_code": "SCHEMA_VALIDATION_FAILED",
  "error_message": "Report failed schema validation: missing required field 'primary_domain'",
  "validation_errors": [...],
  "partial_report": { /* incomplete report data */ }
}
```

## Error Handling

### Missing Required Data
- **IF company_name missing** → Error, cannot generate report
- **IF primary_domain missing** → Error, cannot generate report
- **IF technologies empty** → Warning, generate report with empty technologies
- **IF confidence_summary missing** → Calculate from technologies

### Data Inconsistencies
- **IF confidence counts don't match** → Recalculate from technologies
- **IF timestamps invalid** → Use current timestamp
- **IF phase durations missing** → Omit from metadata

### Schema Validation Failures
- **IF required field missing** → Error, do not save report
- **IF data type wrong** → Attempt conversion, error if fails
- **IF enum invalid** → Error with allowed values listed
- **IF calculations wrong** → Recalculate, update report

## Dependencies

### Required Skills
- evidence_formatter (provides formatted technologies)
- confidence_scorer (provides confidence summary)

### Required Libraries
- UUID generation (uuid v4)
- JSON schema validator
- Date/time utilities (ISO-8601 formatting)

### External APIs
- None (pure JSON generation)

## Configuration

### Settings (from settings.json)
```json
{
  "report_generation": {
    "output_directory": "outputs/techstack_reports/",
    "naming_convention": "{company}_{timestamp}",
    "validate_before_save": true,
    "include_edit_history": true,
    "include_recommendations": true,
    "max_recommendations": 10
  }
}
```

## File Naming Convention

```
{company_name}_{timestamp}.json

Examples:
- Acme_Corporation_20240120_100000.json
- Example_Inc_20240120_143022.json

Sanitization:
- Replace spaces with underscores
- Remove special characters
- Truncate to 100 chars max
```

## Usage Example

```json
{
  "operation": "generate_report",
  "inputs": {
    "company_name": "Acme Corporation",
    "analysis_depth": "standard",
    "asset_inventory": { /* Phase 1 output */ },
    "formatted_technologies": [ /* Phase 5 evidence_formatter output */ ],
    "confidence_summary": { /* Phase 4 confidence_scorer output */ },
    "execution_metadata": { /* timing data */ }
  }
}
```

## Best Practices

1. **Always validate before saving** - Catch errors early
2. **Generate unique IDs** - Prevent report collisions
3. **Use UTC timestamps** - Consistency across timezones
4. **Recalculate summaries** - Don't trust input calculations
5. **Include edit history** - Track report modifications
6. **Document recommendations** - Help users validate findings

## Schema Versioning

**Current Schema Version**: 1.0

**Version Field** (future):
```json
{
  "schema_version": "1.0",
  "report_id": "...",
  ...
}
```

**Backward Compatibility**:
- Add new optional fields without breaking old parsers
- Never remove required fields
- Deprecate fields before removal (2 major versions)
- Document schema changes in version history

## Limitations

- **Cannot validate technology accuracy** (only schema compliance)
- **Recommendations are generic** (not context-aware)
- **Quality rating is heuristic** (not guaranteed accuracy)
- **Completeness metric is approximate** (domain expectations vary)

## Security Considerations

- **Generate unique UUIDs** (prevent ID collisions)
- **Sanitize file paths** (prevent directory traversal)
- **Validate all inputs** (prevent injection)
- **Redact sensitive URLs** (remove tokens from query params)
- **Set file permissions** (644 for reports)

## Version History

- **1.0.0** (2024-01-20): Initial implementation with TechStackReport schema v1.0
