# Engagement Types

Domain-specific workflows for different engagement types.

## Web Application Security (Current)

**Indicators**: URLs, web endpoints, APIs, GraphQL, REST, WebSocket

**Workflow**:
1. Invoke `/pentest` skill
2. Deploy 32 web application agents in parallel
3. Monitor for recursive spawning opportunities
4. Verify all PoCs
5. Generate web app security report

**Agents**: 32 specialized web vulnerability agents
**Output**: Web application pentest report with OWASP Top 10 mapping

## Network Penetration Testing (Future)

**Indicators**: IP ranges, CIDR blocks, network segments, firewalls

**Workflow**:
1. Invoke `/pentest-network` skill (future)
2. Deploy network agents: port scanning, service enum, vuln scanning, exploitation
3. Internal/external network testing
4. Privilege escalation testing
5. Generate network pentest report

**Agents**: 20+ network agents (to be added)

## Mobile Application Testing (Future)

**Indicators**: APK files, IPA files, mobile app endpoints

**Workflow**:
1. Invoke `/pentest-mobile` skill (future)
2. Deploy mobile agents: static analysis, dynamic analysis, API testing
3. iOS and Android testing
4. Storage and communication analysis
5. Generate mobile app security report

**Agents**: 15+ mobile agents (to be added)

## Cloud Security Assessment (Future)

**Indicators**: AWS, Azure, GCP, containers, Kubernetes, Lambda, S3

**Workflow**:
1. Invoke `/pentest-cloud` skill (future)
2. Deploy cloud agents: config review, IAM analysis, storage security, compute security
3. Multi-cloud testing
4. Policy and permission analysis
5. Generate cloud security report

**Agents**: 25+ cloud agents (to be added)

## API Security Testing (Current - Web)

**Indicators**: REST APIs, GraphQL, SOAP, gRPC, Swagger/OpenAPI specs

**Workflow**:
1. Invoke `/pentest` skill (covers APIs)
2. Deploy API-focused agents: GraphQL, REST, WebSocket, JWT, OAuth
3. API endpoint enumeration
4. Authentication and authorization testing
5. Generate API security report

**Agents**: GraphQL, REST API, WebSocket, JWT, OAuth agents

## Infrastructure Testing (Future)

**Indicators**: Servers, databases, operating systems, AD/LDAP

**Workflow**:
1. Invoke `/pentest-infrastructure` skill (future)
2. Deploy infrastructure agents: OS hardening, database security, privilege escalation
3. Server and database testing
4. Active Directory testing
5. Generate infrastructure security report

**Agents**: 20+ infrastructure agents (to be added)

## Multi-Domain Assessments

**Example**: E-commerce platform (web app + mobile app + AWS)

**Workflow**:
1. Invoke multiple skills: `/pentest`, `/pentest-mobile`, `/pentest-cloud`
2. Deploy agents for each domain in parallel
3. Coordinate cross-domain testing (e.g., mobile app API endpoints tested by web agents)
4. Identify cross-domain exploit chains
5. Generate consolidated multi-domain report

**Output**: Single comprehensive report covering all domains

## Engagement Type Routing

```python
def identify_engagement_type(target):
    if is_url(target) or is_api(target):
        return "web_application"
    elif is_ip_range(target):
        return "network"
    elif is_apk_or_ipa(target):
        return "mobile"
    elif is_cloud_resource(target):
        return "cloud"
    elif is_multi_domain(target):
        return "multi_domain"
    else:
        ask_user_for_clarification()

engagement_type = identify_engagement_type(user_request)
invoke_appropriate_skill(engagement_type)
deploy_domain_agents(engagement_type)
```

## Current Implementation Status

✅ **Web Application**: Fully implemented (32 agents, /pentest skill)
🔄 **Network**: Future implementation
🔄 **Mobile**: Future implementation
🔄 **Cloud**: Future implementation
🔄 **Infrastructure**: Future implementation
🔄 **Wireless**: Future implementation
