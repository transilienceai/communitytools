# Evidence Formatter Skill

## Overview
Formats evidence entries with proper sources, reasoning, and citations to create comprehensive, verifiable documentation for all technology identifications.

## Metadata
- **Skill ID**: evidence_formatter
- **Version**: 1.0.0
- **Category**: Report Generation
- **Phase**: 5 (Report Generation)
- **Agent**: report_generation_agent
- **Execution Mode**: Sequential after json_report_generator

## Purpose
Transforms raw evidence data from correlation and confidence scoring into well-structured, human-readable evidence entries with complete attribution, clear reasoning, and verifiable citations.

## Input Requirements

### Required Inputs
```json
{
  "technologies_with_confidence": [
    {
      "technology": "string",
      "category": "frontend|backend|infrastructure|security|devops|third_party",
      "version": "string (optional)",
      "confidence": "High|Medium|Low",
      "confidence_score": "float (0-1)",
      "evidence_summary": {
        "technical_signals": "integer",
        "job_posting_mentions": "integer",
        "strong_evidence_count": "integer",
        "medium_evidence_count": "integer",
        "weak_evidence_count": "integer"
      },
      "corroborating_signals": [
        {
          "source": "skill_name",
          "signal": "description",
          "strength": "strong|medium|weak",
          "url": "string (optional)",
          "timestamp": "ISO-8601 (optional)"
        }
      ]
    }
  ]
}
```

### Optional Inputs
- `formatting_style`: "detailed" | "concise" | "technical" (default: "detailed")
- `include_weak_evidence`: boolean (default: false)
- `max_evidence_per_technology`: integer (default: 10)

## Operations

### Operation: format_evidence
Converts raw signal data into structured evidence entries with proper attribution and reasoning.

**Input Parameters**:
- `technologies_with_confidence`: Technologies with raw evidence data

**Formatting Rules**:
1. **Prioritize evidence** by strength (strong → medium → weak)
2. **Include URLs** when available for verification
3. **Timestamp evidence** for temporal context
4. **Group by evidence type** (technical, job posting, historical)
5. **Deduplicate similar signals** from different sources
6. **Format consistently** across all entries

**Process**:
1. **Extract corroborating signals** for each technology
2. **Sort by strength and source reliability**
3. **Format each evidence entry** with source, signal, and reasoning
4. **Add URL citations** where available
5. **Include timestamp context** for temporal evidence
6. **Group evidence by type** (technical vs job posting)
7. **Limit evidence count** (max 10 per technology by default)
8. **Generate evidence summary** statistics

**Output**:
```json
{
  "formatted_technologies": [
    {
      "technology": "React",
      "category": "frontend",
      "version": "18.x",
      "confidence": "High",
      "evidence": [
        {
          "type": "technical_signal",
          "source": "javascript_dom_analysis",
          "finding": "React global object detected in window scope",
          "details": "window.React and window.ReactDOM globals found on main page",
          "strength": "strong",
          "url": "https://example.com",
          "reasoning": "Direct detection of React framework via global variables indicates active usage",
          "timestamp": "2024-01-20T10:00:00Z"
        },
        {
          "type": "technical_signal",
          "source": "html_content_analysis",
          "finding": "React-specific DOM attributes detected",
          "details": "Multiple elements with data-reactroot and data-reactid attributes found",
          "strength": "strong",
          "url": "https://example.com",
          "reasoning": "React renders DOM with characteristic attributes for component tracking",
          "timestamp": "2024-01-20T10:00:00Z"
        },
        {
          "type": "technical_signal",
          "source": "http_fingerprinting",
          "finding": "React bundle detected in script sources",
          "details": "Script tag loading /static/js/main.*.js (Create React App pattern)",
          "strength": "medium",
          "url": "https://example.com",
          "reasoning": "Create React App uses characteristic bundle naming convention",
          "timestamp": "2024-01-20T10:00:00Z"
        },
        {
          "type": "job_posting",
          "source": "job_posting_analysis",
          "finding": "React mentioned in 5 job postings",
          "details": "Frontend Engineer role: 'Experience with React and Redux required'",
          "strength": "medium",
          "url": "https://example.com/careers",
          "reasoning": "Job requirements confirm React as primary frontend framework",
          "timestamp": "2024-01-15T00:00:00Z"
        }
      ],
      "evidence_summary": {
        "total_evidence_count": 4,
        "technical_evidence_count": 3,
        "job_posting_count": 1,
        "strong_evidence_count": 2,
        "medium_evidence_count": 2,
        "earliest_detection": "2024-01-15T00:00:00Z",
        "latest_detection": "2024-01-20T10:00:00Z"
      }
    },
    {
      "technology": "PostgreSQL",
      "category": "backend",
      "confidence": "Medium",
      "evidence": [
        {
          "type": "job_posting",
          "source": "job_posting_analysis",
          "finding": "PostgreSQL mentioned in 8 job postings",
          "details": "Backend Engineer role: 'PostgreSQL database administration experience preferred'",
          "strength": "medium",
          "url": "https://example.com/careers",
          "reasoning": "Multiple job postings suggest PostgreSQL as primary database",
          "timestamp": "2024-01-18T00:00:00Z"
        }
      ],
      "evidence_summary": {
        "total_evidence_count": 1,
        "technical_evidence_count": 0,
        "job_posting_count": 1,
        "strong_evidence_count": 0,
        "medium_evidence_count": 1,
        "earliest_detection": "2024-01-18T00:00:00Z",
        "latest_detection": "2024-01-18T00:00:00Z"
      },
      "confidence_limitations": [
        "No technical signals detected - based solely on job posting analysis",
        "Recommend verification via database error messages or connection strings"
      ]
    }
  ]
}
```

### Operation: deduplicate_evidence
Removes redundant or highly similar evidence entries to keep reports concise.

**Input Parameters**:
- `formatted_technologies`: Technologies with formatted evidence

**Deduplication Rules**:
- **Same source + similar signal** → Merge into single entry
- **Same finding from multiple skills** → Combine sources, keep one entry
- **Different evidence types with same conclusion** → Keep all (technical + job posting)
- **Timestamp differences only** → Keep most recent

**Process**:
1. **Group evidence by technology**
2. **Calculate similarity scores** between evidence entries (text comparison)
3. **Merge similar entries** (similarity > 80%)
4. **Preserve source attribution** (list all contributing sources)
5. **Keep highest strength** when merging
6. **Retain unique evidence** only

**Output**:
```json
{
  "deduplicated_technologies": [ /* same structure, fewer evidence entries */ ],
  "deduplication_statistics": {
    "original_evidence_count": 247,
    "deduplicated_evidence_count": 189,
    "entries_merged": 58,
    "merge_rate": 0.23
  }
}
```

### Operation: generate_citations
Creates properly formatted citations for all evidence sources for verification purposes.

**Input Parameters**:
- `formatted_technologies`: Technologies with evidence

**Citation Format**:
```
[Source Skill Name] Signal: [Description]
  URL: [URL if available]
  Date: [Detection timestamp]
  Strength: [strong/medium/weak]
```

**Process**:
1. **Extract all evidence entries**
2. **Format citation for each**
3. **Group citations by technology**
4. **Number citations sequentially**
5. **Create citation index**

**Output**:
```json
{
  "technologies_with_citations": [
    {
      "technology": "React",
      "evidence_with_citations": [
        {
          "evidence": { /* evidence object */ },
          "citation": "[1] JavaScript DOM Analysis - React global object detected\n    URL: https://example.com\n    Date: 2024-01-20T10:00:00Z\n    Strength: strong"
        }
      ]
    }
  ],
  "citation_index": {
    "1": {
      "technology": "React",
      "source": "javascript_dom_analysis",
      "url": "https://example.com"
    }
  }
}
```

### Operation: format_confidence_limitations
Documents limitations and caveats for technologies with medium/low confidence.

**Input Parameters**:
- `technologies_with_confidence`: Technologies with confidence scores

**Limitation Types**:
- **Single source dependency** - Only one evidence source
- **No technical signals** - Job posting only
- **Outdated evidence** - Only historical/archive data
- **Weak signals only** - No strong technical indicators
- **Conflicting signals** - Contradictory evidence present

**Process**:
1. **Identify technologies with limitations**
2. **Classify limitation type**
3. **Generate descriptive limitation message**
4. **Provide recommendations** for improvement
5. **Attach to technology entry**

**Output**:
```json
{
  "technologies_with_limitations": [
    {
      "technology": "PostgreSQL",
      "confidence": "Medium",
      "limitations": [
        {
          "type": "single_source_dependency",
          "description": "Evidence based solely on job posting analysis",
          "impact": "Cannot confirm active usage via technical signals",
          "recommendation": "Verify via database error messages, connection strings, or port scanning (if authorized)"
        },
        {
          "type": "no_technical_signals",
          "description": "No direct technical evidence detected",
          "impact": "Technology may be aspirational (hiring for future use) rather than current",
          "recommendation": "Cross-reference with public repositories or API error messages"
        }
      ]
    }
  ]
}
```

## Evidence Type Definitions

### Technical Signal Evidence
- **Source**: Data collection skills (http_fingerprinting, dns_intelligence, etc.)
- **Strength**: Strong to Medium
- **Reliability**: High (directly verifiable)
- **Examples**: HTTP headers, DNS records, JavaScript globals, DOM attributes

### Job Posting Evidence
- **Source**: job_posting_analysis skill
- **Strength**: Medium to Weak
- **Reliability**: Medium (may be aspirational)
- **Examples**: Job requirements, tech stack mentions in descriptions

### Historical Evidence
- **Source**: web_archive_analysis skill
- **Strength**: Weak to Medium
- **Reliability**: Low to Medium (may be outdated)
- **Examples**: Wayback Machine snapshots, technology migrations

### Repository Evidence
- **Source**: code_repository_intel skill
- **Strength**: Medium to Strong
- **Reliability**: Medium to High (public repos may be outdated)
- **Examples**: package.json dependencies, CI/CD configurations

## Formatting Styles

### Detailed Style (default)
- **Include all evidence** (up to max limit)
- **Full reasoning** for each entry
- **Complete citations** with URLs and timestamps
- **Evidence summaries** with statistics
- **Confidence limitations** documented

### Concise Style
- **Top 3 evidence entries** per technology
- **Brief reasoning** (1 sentence)
- **URLs only** (no timestamps)
- **Summary statistics** only
- **No limitation details**

### Technical Style
- **Technical signals only** (exclude job postings)
- **Detailed technical findings** (exact headers, globals, etc.)
- **Full URLs and paths**
- **Timestamps for all**
- **Technical recommendations** for verification

## Output Format

### Success Output
```json
{
  "status": "success",
  "formatted_technologies": [...],
  "statistics": {
    "total_technologies": 76,
    "total_evidence_entries": 189,
    "avg_evidence_per_technology": 2.5,
    "technologies_with_limitations": 12
  },
  "formatting_metadata": {
    "style": "detailed",
    "max_evidence_per_technology": 10,
    "included_weak_evidence": false,
    "deduplication_applied": true
  },
  "execution_time_ms": 650
}
```

### Error Output
```json
{
  "status": "error",
  "error_code": "NO_TECHNOLOGIES",
  "error_message": "No technologies provided for evidence formatting",
  "partial_results": null
}
```

## Error Handling

### Missing Evidence Data
- **IF technology has no evidence** → Add placeholder: "Evidence data unavailable"
- **IF corroborating_signals empty** → Mark as "No detailed evidence recorded"

### Malformed Evidence
- **IF evidence missing required fields** → Skip that entry, continue
- **IF URL invalid** → Format without URL
- **IF timestamp invalid** → Format without timestamp

### Deduplication Failures
- **IF similarity calculation fails** → Skip deduplication, keep all
- **IF merging produces invalid result** → Keep original entries

## Dependencies

### Required Skills
- confidence_scorer (provides confidence data)
- signal_correlator (provides evidence data)

### Required Libraries
- URL validation utilities
- Date/time formatting libraries
- Text similarity algorithms (for deduplication)

### External APIs
- None (pure formatting)

## Configuration

### Settings (from settings.json)
```json
{
  "evidence_formatting": {
    "default_style": "detailed",
    "max_evidence_per_technology": 10,
    "include_weak_evidence": false,
    "deduplicate_evidence": true,
    "similarity_threshold": 0.80,
    "include_citations": true,
    "document_limitations": true
  }
}
```

## Usage Example

```json
{
  "operation": "format_evidence",
  "inputs": {
    "technologies_with_confidence": [ /* from confidence_scorer */ ]
  },
  "options": {
    "formatting_style": "detailed",
    "include_weak_evidence": false,
    "max_evidence_per_technology": 10
  }
}
```

## Best Practices

1. **Prioritize verifiability** - Always include URLs when available
2. **Be transparent** - Document evidence limitations clearly
3. **Deduplicate intelligently** - Merge similar but preserve unique
4. **Format consistently** - Use same structure for all entries
5. **Provide context** - Include reasoning for each piece of evidence

## Evidence Quality Guidelines

### High-Quality Evidence Entry
- **Clear finding statement**
- **Specific technical details**
- **Verifiable URL**
- **Timestamp for context**
- **Reasoning for interpretation**
- **Appropriate strength classification**

### Low-Quality Evidence Entry
- **Vague finding** ("Technology detected")
- **No technical details**
- **No URL for verification**
- **Missing timestamp**
- **No reasoning provided**
- **Strength misclassified**

## Limitations

- **Cannot verify evidence accuracy** (formatting only, not validation)
- **Deduplication may merge distinct evidence** (if very similar)
- **URL sanitization may break links** (security measure)
- **Evidence ordering** subjective (by strength/source)

## Security Considerations

- **Sanitize all URLs** (remove query parameters with tokens)
- **Redact sensitive paths** (/admin, /internal)
- **No credential exposure** in evidence details
- **Log formatting operations** for audit

## Version History

- **1.0.0** (2024-01-20): Initial implementation with multi-style formatting
