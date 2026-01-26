# Delegation Patterns

How the orchestrator delegates to specialized agents.

## Basic Delegation Pattern

```python
Task(
    subagent_type="general-purpose",
    description="SQL injection testing",
    prompt="""
    Deploy SQL Injection Discovery Agent to test target.

    Agent file: .claude/agents/specialized/sql-injection-agent.md
    Target: https://example.com/search?q=test
    Authorization: Confirmed
    Scope: All /search endpoints

    Requirements:
    1. Test for SQL injection in all parameters
    2. Generate verified PoC for findings
    3. Follow OUTPUT_STANDARDS.md format
    4. Report findings with evidence
    """
)
```

## Parallel Deployment (All 32 Agents)

```python
agents = [
    "sql-injection-agent", "xss-agent", "csrf-agent",
    "ssrf-agent", "jwt-agent", # ... all 32
]

for agent in agents:
    Task(
        subagent_type="general-purpose",
        description=f"{agent} testing",
        prompt=f"""
        Deploy .claude/agents/specialized/{agent}.md
        Target: {target_url}
        Authorization: {auth_context}
        Follow 4-phase workflow. Generate verified PoCs.
        """,
        run_in_background=True  # Parallel execution
    )
```

## Discovery-Based Delegation

When agent discovers vulnerability, spawn related agents:

```python
# SQLi discovered
if finding.type == "SQL Injection":
    spawn_agents = [
        "authentication-bypass-agent",  # Test login bypass
        "information-disclosure-agent",  # Test data extraction
        "command-injection-agent"        # Test OS commands
    ]

    for agent in spawn_agents:
        Task(
            subagent_type="general-purpose",
            description=f"{agent} - SQLi escalation",
            prompt=f"""
            Deploy {agent}.md to test exploit chain.
            Context: SQLi found at {finding.location}
            Test for escalation: {agent.objective}
            """
        )
```

## Asset-Based Delegation

When new asset discovered, deploy full suite:

```python
# New subdomain found
if discovery.type == "new_subdomain":
    for agent in all_32_agents:
        Task(
            subagent_type="general-purpose",
            description=f"{agent} on {discovery.subdomain}",
            prompt=f"""
            Deploy {agent}.md to test newly discovered asset.
            Target: {discovery.subdomain}
            Treat as new engagement - full testing.
            """
        )
```

## Required Context for Agents

Always provide:

**1. Target Details**:
```
Target: https://example.com/api/users
Method: GET, POST
Parameters: id, username, email
Functionality: User management API
```

**2. Authorization**:
```json
{
  "authorization": "confirmed",
  "scope": "All /api/* endpoints",
  "out_of_scope": ["/api/admin/delete"],
  "restrictions": [
    "No destructive actions",
    "Rate limit: 10 req/s",
    "Testing window: Mon-Fri 9am-5pm"
  ]
}
```

**3. Requirements**:
- Follow 4-phase workflow
- Generate verified PoC (poc.py + poc_output.txt)
- Create findings/finding-NNN/ folder
- Include all required documentation
- Report to orchestrator with spawn recommendations

## Monitoring Agent Output

```python
# Check agent status
TaskOutput(task_id="agent-001", block=False)

# Wait for completion
TaskOutput(task_id="agent-001", block=True, timeout=300000)

# Parse findings
findings = read_json("outputs/findings/findings.json")
```

## Agent Communication Protocol

Agents report discoveries in standardized format:

```json
{
  "agent_id": "sql-injection-agent-001",
  "status": "completed",
  "vulnerabilities_found": 1,
  "findings": [...],
  "spawn_recommendations": [
    {
      "agent": "authentication-bypass-agent",
      "reason": "Test if SQLi can bypass authentication",
      "priority": "HIGH",
      "context": {"sqli_location": "/search?q="}
    }
  ]
}
```

## Best Practices

1. **Always run agents in parallel** - Use `run_in_background=True`
2. **Provide complete context** - Don't make agents guess scope
3. **Verify PoCs** - Check poc_output.txt before accepting findings
4. **Monitor progress** - Use TaskOutput to track agent status
5. **Spawn recursively** - Act on spawn_recommendations immediately
