# Verb-Differential Guard Bypass (Blind Method Sweep)

## When this applies

- A controller/route class is auth-guarded on its visible verb (the UI calls
  `GET` and gets `401`/`403` without a session) but a sibling verb
  (`POST`/`PUT`/`PATCH`/`DELETE`) on the **same path** is mounted without the
  class-level guard.
- The server does **not** advertise the hidden verb: `OPTIONS` returns no
  `Allow:` header, returns a wrong/partial one, or is itself blocked — so
  `options-method-enumeration.md` comes up empty while the gap is still there.
- Common in decorator/annotation frameworks (NestJS guards, Spring
  `@PreAuthorize`, Django DRF permission classes) where auth is attached per
  class but one handler carries a leftover public decorator or a new verb was
  added without re-declaring the guard.
- Goal: find the verb that **executes past auth** and reach the state-changing
  or data-exposing action it fronts. This is the function-level-authz (BFLA)
  gap that hides on unlisted verbs — the companion to `owasp-bola-bopla.md`.

## Technique

Do not trust `OPTIONS` to reveal verbs. Sweep **every** method directly against
each sensitive path and read the **status-code differential**, not a header. The
guard's own refusal is the baseline; any verb that returns something *other than*
the refusal shape means a handler ran without the guard in front of it.

Key signal, per verb, unauthenticated:

| Response | Meaning |
|----------|---------|
| `401` / `403` | Guard fired — route is protected on this verb (**baseline, not a finding**) |
| `404` | No handler at this path/verb |
| `405 Method Not Allowed` | Path exists, verb unmounted — framework rejected it before any handler |
| `400` with a stable validation error | Handler **executed** (reached body/DTO parsing) past auth — bypass candidate |
| `500` | Handler executed and threw — reached application code past auth — bypass candidate |
| `2xx` / `201` | Handler executed and succeeded without auth — **confirmed bypass** |

The discriminator is `401/403/404/405` (refused or absent) **versus** anything
that proves a handler body ran (`400`-validation / `500` / `2xx`). A `GET` that
is `401` next to a `POST` that is `400`/`500`/`2xx` on the same path is the
tell.

## Steps

### 1. Collect sensitive paths

From recon (`api-recon-and-discovery.md`, Swagger/OpenAPI, the SPA bundle),
list the paths whose `GET` is auth-gated — admin, moderation, user, object, and
internal-compute prefixes.

### 2. Blind verb sweep (unauthenticated)

Hit every verb on every path and print the status. `curl`:

```bash
API="https://api.target.tld"
paths="admin/users moderation/queue objects/1 integrations/route features/1"

for p in $paths; do
  printf '%-28s' "$p"
  for m in GET POST PUT PATCH DELETE; do
    code=$(curl -s -o /dev/null -w '%{http_code}' -X "$m" \
      -H 'Content-Type: application/json' -d '{}' "$API/$p")
    # flag anything that is NOT a clean refusal/absence
    case $code in 401|403|404|405) mark="" ;; *) mark="<<" ;; esac
    printf ' %s:%s%s' "$m" "$code" "$mark"
  done
  echo
done
# '<<' marks a verb whose handler executed past auth — investigate that one.
```

### 3. Burp Intruder equivalent

Pin the path, fuzz the method:

```
§METHOD§ /api/moderation/queue HTTP/1.1
Host: target.tld
Content-Type: application/json

{}

Payloads: GET, POST, PUT, PATCH, DELETE
```

Sort results by status. The outlier verb (not `401/403/404/405`) is the lead.

### 4. Confirm the gap, then prove impact

For a flagged verb, send a minimal real body and read the response. A `400`
asking for a specific field confirms the handler validated input with no auth in
front; supply the field and check whether the action completes (row created,
record modified, compute triggered). Stop at the smallest proof — you rarely
need to complete a destructive write to show the guard is absent.

### 5. Path-normalization amplifier (optional)

If the base path is refused on all verbs, retry the flagged verb through a
normalization variant that can skip a prefix-matched guard: trailing slash,
`//double`, `/.`, `%2f`, `..;/`, matrix `;param`, and mixed case
(`/API/Moderation`). Any variant that turns a `401` into a handler-executed
status is the same bypass reached by a different route. (See
`waf-bypass-techniques.md` for the encoding set.)

## Verifying success

- The protected verb (usually `GET`) returns `401`/`403` on the exact same path
  — the **control** that proves the guard exists and the differential is real.
- The flagged verb returns a handler-executed status (`400`-validation / `500` /
  `2xx`) unauthenticated.
- Supplying a valid body completes the action (state change or data returned)
  with no session. Capture both requests (the refused control and the executing
  verb) as the evidence pair.

## Common pitfalls

- **`405` is not a bypass** — it means the framework rejected the verb before any
  handler. Only handler-executed statuses (`400`-validation / `500` / `2xx`)
  count.
- **A blanket `401` on every verb** including a wrong one usually means a global
  guard — not vulnerable; move on.
- **`503` can be a fail-closed guard** (e.g. a required ingest secret unset), not
  an open path — confirm it is actually writable before reporting.
- **Reverse proxies** may answer some verbs themselves (`PUT`/`DELETE` blocked at
  nginx) and mask the app. Test the app's direct port separately to see the real
  app-layer behavior, then re-check through the proxy.
- `OPTIONS` silence is **not** proof of safety — this whole technique exists
  because frameworks under-report verbs in `Allow:`.

## Tools

- `curl -X <METHOD>` (the sweep loop above)
- Burp Suite Intruder (method position fuzzing), Repeater (Change request method)
- `ffuf` with `-X` / method wordlist for larger path sets
