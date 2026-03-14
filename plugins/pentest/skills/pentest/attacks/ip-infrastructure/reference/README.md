# IP Infrastructure Test Reference

Living documentation of IP infrastructure testing techniques. Auto-updated by pentester-executor agents.

## Purpose

**Knowledge accumulation**: Each test appends results to reference files, building institutional knowledge.

**Iterative improvement**: Failed techniques inform better approaches. Successful patterns become standard.

**Audit trail**: Complete test history with commands, results, and learnings.

## Reference Files

| File | Scan Type | Key Focus |
|------|-----------|-----------|
| `syn-scan.md` | TCP SYN scanning | Port discovery, stealth techniques |
| `icmp-scan.md` | ICMP/ping sweeps | Host discovery, network mapping |
| `udp-scan.md` | UDP port scanning | Connectionless service discovery |
| `service-enum.md` | Service versioning | Banner grabbing, CVE mapping |
| `os-fingerprint.md` | OS detection | Stack fingerprinting, passive analysis |
| `ip-reputation.md` | Threat intelligence | Reputation checks, historical data |
| `firewall-detection.md` | Security appliances | Firewall/IDS detection, evasion |

## Usage by Pentester Executor

### Test Execution Flow

1. **Pre-test**: Read relevant reference file for prior learnings
2. **Execute**: Run test with logged command
3. **Append**: Add row to test matrix with results
4. **Learn**: Update "Learnings" section if new pattern discovered
5. **Next**: Use learnings to inform next test

### Logging Format

```markdown
| Row | Target | Command | Result | Duration | Notes |
|-----|--------|---------|--------|----------|-------|
| 1   | 10.0.0.5 | nmap -sS -p- 10.0.0.5 | 22/tcp open | 45s | SSH v2.0 detected |
```

### Learnings Section

Document:
- **Successful**: What worked and why
- **Failed**: What failed and why
- **Patterns**: Recurring behaviors
- **Optimizations**: Speed/stealth improvements

## File Structure

Each reference file contains:

```markdown
# [Scan Type] Testing Log
## Last Updated
## Test Matrix (table of all tests)
## Command Templates
## Common Patterns
## Learnings
  - Successful Techniques
  - Failed Techniques
  - Context-specific notes
## Performance Data (optional)
```

## Improvement Cycle

**Week 1**: Basic techniques, populate test matrix
**Week 2**: Analyze patterns, document successful approaches
**Week 3**: Refine techniques based on learnings
**Week 4**: Optimize for speed/stealth using performance data

Over time, these files become comprehensive playbooks for each scan type.

## Integration

Pentester executor agents:
1. Mount `/attacks/ip-infrastructure/` skill
2. Read `reference/[scan-type].md` before testing
3. Execute tests using proven techniques from "Learnings"
4. Append new results to test matrix
5. Update learnings if new patterns emerge

This creates a **feedback loop**: test → learn → improve → test better.
