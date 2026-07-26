---
name: api-security
description: API security testing - GraphQL, REST API, WebSocket, and Web-LLM attack techniques.
---

# API Security

Test API endpoints for security vulnerabilities across REST, GraphQL, WebSocket, and LLM-integrated APIs.

## Techniques

| Type | Key Vectors |
|------|-------------|
| **GraphQL** | Introspection, batching attacks, nested query DoS, field suggestion |
| **REST API** | BOLA/IDOR, mass assignment, rate limiting, auth bypass, versioning |
| **WebSocket** | Cross-site hijacking, message manipulation, auth flaws |
| **Web-LLM** | Prompt injection via API, excessive agency, data exfiltration |

## Workflow

1. Discover API endpoints and documentation (Swagger, GraphQL schema)
2. Map authentication and authorization mechanisms
3. Test per API type using appropriate techniques
4. Validate data exposure and access control flaws
5. Capture evidence with HTTP request/response logs

## API at scale (offline corpus / fixture-driven)

For a large or offline API surface — a 2000+ path Swagger, a Postman corpus, a HAR capture — do NOT hand-build the coverage machinery per engagement. Drive it deterministically:

1. **Ingest the corpus → per-endpoint fixtures:** `python3 tools/fixture_ingest.py <openapi|postman|har> -o fixtures.json` normalizes every operation into a request template (method, url with path params filled, sampled body, `object_ref` for id-like path params, security requirement) and STRIPS baked-in auth (the harness injects tokens). This is what turns a large (thousands-of-operations) OpenAPI/Postman corpus into a resumable matrix instead of an untested pile.
2. **Acquire per-role sessions:** via [`authenticated-session-acquisition`](../authenticated-session-acquisition/SKILL.md) (MFA/OTP/SRP → reusable tokens) into the harness's token store.
3. **Replay the per-role authz matrix:** `python3 tools/auth_replay_harness.py --requests fixtures.json --tokens tokens.json [--proxy <vantage>]` replays every endpoint under every role (and cross-tenant), flags BOLA/BFLA where a role got `authorized` on an object/action it should not, and logs an `evidence_id` per (endpoint × role). Egress-route via the provisioned vantage for allowlisted APIs.
4. **Protocol-specific authz:** OData ([`odata-deep-authz.md`](reference/scenarios/rest/odata-deep-authz.md)), Cognito ([`cognito-unauth-and-srp.md`](reference/scenarios/rest/cognito-unauth-and-srp.md)), authenticated WebSocket ([`authenticated-per-role-authz.md`](reference/scenarios/websocket/authenticated-per-role-authz.md)).

The batch is resumable (checkpoint the harness results) so flapping auth never zeroes the run — the recurring at-scale gap. Run the FULL matrix so a clean result is an evidenced negative, not an untested surface.

## Reference

- `reference/graphql*.md` - GraphQL attack techniques and labs
- `reference/scenarios/rest/*.md` - REST API security testing (BOLA/BOPLA, mass assignment, SSPP, content-type confusion)
  - [`scenarios/rest/odata-deep-authz.md`](reference/scenarios/rest/odata-deep-authz.md) - OData `$metadata` enum + `$filter`/`$orderby`/`$expand` cross-tenant BOLA & injection
  - [`scenarios/rest/cognito-unauth-and-srp.md`](reference/scenarios/rest/cognito-unauth-and-srp.md) - Cognito UNSIGNED unauthenticated posture (self-signup/enumeration) + SRP authenticated session
- `reference/websockets*.md` - WebSocket vulnerability testing
  - [`scenarios/websocket/authenticated-per-role-authz.md`](reference/scenarios/websocket/authenticated-per-role-authz.md) - authenticated per-role relay: BOLA/BFLA/channel-authz over the socket
- `reference/web-llm*.md` - Web-LLM attack techniques and labs
