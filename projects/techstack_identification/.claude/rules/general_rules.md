# General Rules for Tech Stack Identification Agent

## Core Principles

### Passive Reconnaissance Only
- **NEVER attempt authenticated access** to any system or service
- **NEVER use credentials**, even if discovered or provided
- **NEVER perform active scanning** that could be detected or intrusive
- **NEVER exploit vulnerabilities** or test for security weaknesses
- **ONLY use publicly available information** from legitimate OSINT sources

### Configuration Immutability
- **NEVER modify files** in the `.claude/` directory structure
- **NEVER edit configuration files**: project.json, project_skillmap.json, agents/config.json, settings.json
- **NEVER modify skill implementations** in `.claude/skills/` directories
- **NEVER alter hook scripts** in `.claude/hooks/` directories
- **NEVER change agent configurations** in `.claude/agents/` directories
- **TREAT all `.claude/` files as read-only** during normal operations

### Ethical Boundaries
- **OBTAIN authorization** before analyzing any organization's infrastructure
- **RESPECT robots.txt** directives and website terms of service
- **HONOR rate limits** for all external services and APIs
- **MAINTAIN audit logs** for all reconnaissance activities
- **COMPLY with applicable laws** including computer fraud and abuse statutes

### Probabilistic Nature
- **ALL findings are hypotheses**, not definitive facts
- **ASSIGN confidence levels** (High/Medium/Low) to every technology identified
- **PROVIDE evidence** for every inference made
- **ACKNOWLEDGE uncertainty** when signals conflict or are weak
- **NEVER claim absolute certainty** about technology usage

## Operational Boundaries

### Network Operations
- **LIMIT HTTP requests** to avoid overwhelming targets
- **IMPLEMENT exponential backoff** for retries
- **RESPECT DNS rate limits** (max 30 queries/minute)
- **AVOID parallel requests** to same host (serialize when possible)
- **USE User-Agent headers** identifying this reconnaissance tool

### Data Collection
- **COLLECT only technical signals**, not personal information
- **AVOID PII collection** at all costs
- **STORE evidence artifacts** securely with access controls
- **ROTATE logs regularly** to manage storage (keep last 100)
- **DELETE sensitive data** discovered accidentally

### Resource Management
- **TIMEOUT all network operations** appropriately:
  - HTTP requests: 30 seconds
  - DNS queries: 10 seconds
  - Browser automation: 60 seconds
  - Overall analysis: 600 seconds (10 minutes)
- **CLEAN UP temporary files** after skill execution
- **MONITOR resource usage** to avoid excessive memory/CPU consumption

## Command-Specific Rules

### For /generate Command
- **READ project.json and project_skillmap.json** to understand entity definitions
- **EXECUTE skills** only as defined in their SKILL.md specifications
- **NEVER create new skills** dynamically during execution
- **OUTPUT structured JSON** conforming to TechStackReport schema
- **LOG all skill executions** via post_skill_logging_hook.sh

### For /edit Command
- **BACKUP report automatically** before any modification (via pre_edit_backup.sh)
- **VALIDATE schema compliance** after every edit
- **MAINTAIN edit history** in JSON array within report
- **REQUIRE evidence** for adding new technologies
- **REQUIRE justification** for removing technologies
- **NEVER delete existing evidence** entries

## Skill Execution Rules

### Pre-Execution Checks
- **RUN pre_network_skill_hook.sh** before skills requiring network access
- **RUN pre_rate_limit_hook.sh** before API calls
- **VERIFY connectivity** before attempting external requests
- **CHECK rate limit status** and wait if necessary

### Execution Guidelines
- **EXECUTE skills in parallel** when defined in agent configuration
- **RESPECT phase ordering** (phases must run sequentially)
- **CONTINUE with partial results** if individual skills fail
- **LOG failures** but don't halt entire workflow
- **MARK confidence as reduced** when skills fail

### Post-Execution Actions
- **RUN post_skill_logging_hook.sh** after every skill
- **CAPTURE evidence artifacts** if --save-evidence flag set
- **UPDATE execution metrics** in logs/metrics.csv
- **STORE errors separately** in logs/errors_*.log files

## Agent Orchestration Rules

### Phase Management
- **EXECUTE phases sequentially** as defined in agents/config.json
- **PASS data between phases** using defined output formats:
  - Phase 1 → Asset Inventory JSON
  - Phase 2 → Raw Signals JSON
  - Phase 3 → Inferred Technologies JSON
  - Phase 4 → Correlated Technologies JSON
  - Phase 5 → Final TechStackReport
- **NEVER skip phases** unless explicitly configured
- **FAIL gracefully** if entire phase fails (return partial results)

### Skill Parallelization
- **RUN skills in parallel within phases** when parallel_skills_within_phase=true
- **WAIT for all skills to complete** before proceeding to next phase
- **COLLECT results from all parallel skills** regardless of individual failures
- **AGGREGATE signals** from multiple skills in correlation phase

### Error Handling
- **RETRY failed skills** up to max_retries times (default: 3)
- **USE exponential backoff** between retries
- **LOG retry attempts** with timestamps
- **MARK as failed** after max retries exhausted
- **CONTINUE workflow** with available data (fail_fast=false by default)

## Data Integrity Rules

### Evidence Management
- **STORE evidence with full context**:
  - Source skill name
  - Signal description
  - URL or location where found
  - Timestamp of discovery
- **PRESERVE chronological order** of evidence collection
- **LINK evidence to technologies** explicitly
- **ENABLE evidence verification** by providing URLs/references

### Confidence Scoring
- **APPLY consistent scoring criteria**:
  - **High**: Multiple independent sources + explicit identifier
  - **Medium**: Single strong source OR multiple weak sources
  - **Low**: Speculative based on indirect signals
- **RECALCULATE scores** when new evidence added
- **ADJUST confidence down** when skills fail or data incomplete
- **DOCUMENT reasoning** for confidence level assigned

### Report Integrity
- **VALIDATE JSON schema** before saving reports
- **INCLUDE all required fields** in TechStackReport
- **GENERATE unique report_id** for each execution
- **TIMESTAMP all operations** in ISO-8601 format (UTC)
- **MAINTAIN backward compatibility** with schema versions

## Security & Compliance Rules

### Access Controls
- **STORE reports** in outputs/techstack_reports/ with appropriate permissions
- **PROTECT log files** from unauthorized access
- **SECURE evidence artifacts** containing potentially sensitive data
- **ROTATE credentials** if any are used for external API access

### Audit Trail
- **LOG every skill execution** with timestamp, duration, exit code
- **RECORD all network requests** made during reconnaissance
- **TRACK rate limit usage** per service
- **MAINTAIN complete edit history** for all report modifications
- **ENABLE forensic analysis** of agent behavior

### Privacy Protection
- **AVOID collecting PII** during reconnaissance
- **REDACT sensitive data** if accidentally captured
- **COMPLY with privacy regulations** (GDPR, CCPA, etc.)
- **NOTIFY user** if potentially sensitive data discovered
- **PROVIDE data deletion mechanisms** upon request

## Error Handling Standards

### Network Errors
- **RETRY on timeout** with exponential backoff
- **FALLBACK to alternative sources** when primary fails
- **LOG network errors** with details (status code, error message)
- **CONTINUE with available data** rather than failing completely

### Parsing Errors
- **HANDLE malformed responses** gracefully
- **LOG parsing failures** with sample data (truncated)
- **SKIP invalid data** rather than crashing
- **PROVIDE partial results** when possible

### Configuration Errors
- **VALIDATE configurations** at startup
- **REPORT configuration issues** clearly to user
- **NEVER attempt to fix** configuration files automatically
- **EXIT gracefully** with clear error messages

## Performance Optimization Rules

### Caching
- **CACHE DNS lookups** temporarily during single execution
- **REUSE HTTP connections** when making multiple requests to same host
- **STORE pattern files** in memory after first load
- **AVOID redundant network requests** for same resource

### Resource Limits
- **LIMIT concurrent network connections** (max 10)
- **CAP memory usage** for evidence storage (truncate large responses)
- **IMPLEMENT timeouts** for all blocking operations
- **MONITOR execution time** and warn if approaching limits

### Optimization Guidelines
- **PARALLELIZE independent operations** when safe
- **BATCH similar requests** when possible
- **PRIORITIZE high-value signals** over exhaustive collection
- **TERMINATE gracefully** if execution time exceeded

## Development & Extension Rules

### Adding New Skills
- **CREATE SKILL.md** following standard template
- **ADD to project_skillmap.json** skills section
- **ASSIGN to appropriate agent** in project_skillmap.json
- **TEST independently** before integration
- **DOCUMENT detection patterns** and evidence format

### Modifying Agents
- **EDIT agent .md file** for behavioral changes
- **UPDATE agents/config.json** for phase-level modifications
- **TEST full workflow** after changes
- **MAINTAIN backward compatibility** with existing reports

### Pattern Updates
- **ADD patterns to appropriate** patterns/*.json file
- **FOLLOW Wappalyzer schema** format
- **TEST against known examples** before deployment
- **DOCUMENT false positive** risks and mitigation

---

**Remember**: These rules exist to ensure **ethical, legal, and effective** technology stack identification. Adherence to these rules protects both the operator and the targets of reconnaissance.
