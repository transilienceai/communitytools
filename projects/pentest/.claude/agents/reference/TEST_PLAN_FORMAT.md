# Test Plan Format

Template for creating test plans.

## Structure

```markdown
# Penetration Test Plan

## Target
- URL: https://example.com
- Engagement: example-com-2025-01
- Scope: All endpoints under /api/*, /admin/*

## Reconnaissance Findings
- Login form (2 parameters: username, password)
- API endpoints: /api/users, /api/orders
- File upload: /upload/profile-picture
- Admin panel detected: /admin
- Technologies: Node.js, PostgreSQL, React

## Proposed Executors (15 total)

### High Priority (Always Deploy - 4)
- **SQL Injection Executor** → Login form, API endpoints
- **XSS Executor** → All input fields, search functionality
- **SSRF Executor** → API endpoints, webhook functionality
- **Auth Bypass Executor** → Login form, admin panel

### Attack Surface Specific (11)
- **CSRF Executor** → State-changing forms, API endpoints
- **File Upload Executor** → Profile picture upload
- **JWT Executor** → API authentication tokens
- **Path Traversal Executor** → File operations
- **NoSQL Injection Executor** → Database queries
- **Command Injection Executor** → System operations
- **GraphQL Executor** → GraphQL API endpoints
- **REST API Executor** → REST endpoints
- **CORS Executor** → Cross-origin requests
- **Clickjacking Executor** → Frame-embeddable pages
- **Prototype Pollution Executor** → JavaScript parsing

## Testing Approach
1. Deploy all 15 executors in parallel (single Task call)
2. Each executor follows 4-phase workflow: Recon → Experiment → Test → Verify
3. Monitor progress with non-blocking checks
4. Recursive spawning: If new attack surface discovered, deploy additional executors
5. Aggregate findings after all executors complete

## Estimated Resources
- Executors: 15 agents running in parallel
- Duration: 2-4 hours (depends on target complexity)
- Request rate: Respects rate limits (10 req/s default)
- Output: Activity logs + finding folders + aggregated report

## Execution

After creating the plan:
1. Log plan creation: `{"phase":"planning","action":"create-plan","executors":15,"result":"plan-ready"}`
2. Proceed immediately to executor deployment
3. Deploy all executors in parallel

## Critical Rules

- Always create plan after reconnaissance
- Always log plan creation
- Always proceed immediately to executor deployment after plan creation
