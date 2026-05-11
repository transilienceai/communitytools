# Web Application Logic Principles

This file is the entry point for web application logic vulnerabilities. It contains decision logic, sequencing, and cross-cutting gotchas. Specific techniques live under `scenarios/<area>/<scenario>.md`. Use `INDEX.md` to pick a scenario by trigger.

## Decision tree

| Fingerprint | Family | Where to start |
|---|---|---|
| Resource referenced by ID, ownership not checked | `scenarios/access-control/` | `idor-read.md` (read), `idor-action.md` (write/state-change) |
| Privileged page reachable with parameter or header tweak | `scenarios/access-control/` | `parameter-based-controls.md`, `header-bypass.md`, `referer-bypass.md` |
| Endpoint authorised on POST but not GET (or vice versa) | `scenarios/access-control/method-bypass.md` | Switch HTTP method |
| Profile/object update accepts JSON/form body | `scenarios/access-control/mass-assignment.md` | Inject `is_admin`, `role`, etc. |
| Multi-step workflow, gated only on first step | `scenarios/access-control/multi-step-bypass.md` or `scenarios/business-logic/workflow-bypass.md` | Skip directly to confirmation |
| Admin URL discovered via robots.txt / JS / wordlist | `scenarios/access-control/unprotected-functionality.md` | Direct browse |
| Client-side `price`/`quantity` in cart request | `scenarios/business-logic/price-manipulation.md`, `scenarios/business-logic/quantity-manipulation.md` | Modify, integer-overflow, negative |
| Discount/coupon/gift-card interactions | `scenarios/business-logic/coupon-stacking.md`, `scenarios/business-logic/gift-card-loop.md` | Stack / loop |
| Email change sets admin privileges by domain | `scenarios/business-logic/email-domain-bypass.md` | Plus-addressing, IDN homograph |
| Two endpoints sharing state, async jobs | `scenarios/race-conditions/multi-endpoint.md`, `scenarios/race-conditions/single-endpoint-collision.md` | Parallel single-packet attacks |
| Discount, gift card, or one-time-use limit | `scenarios/race-conditions/limit-overrun.md` | 20+ parallel identical requests |
| Login attempts limited per session | `scenarios/race-conditions/rate-limit-bypass.md` | Parallel password volley |
| File upload + post-validation | `scenarios/race-conditions/file-upload-race.md` | Race upload vs deletion |
| Server-side session with verify→re-read split | `scenarios/race-conditions/toctou-session.md` | flip_admin / flip_valid / check threads |
| Verbose stack traces / debug pages exposed | `scenarios/info-disclosure/error-messages.md`, `scenarios/info-disclosure/debug-pages-and-cms-apis.md` | Trigger errors, probe debug paths |
| Modern SPA / heavy JS | `scenarios/info-disclosure/javascript-source-review.md` | grep bundles for endpoints/secrets |
| `.git`, backups, `.env` reachable | `scenarios/info-disclosure/backups-and-version-control.md` | git-dumper + secret scan |
| Container app with multiple ports | `scenarios/info-disclosure/multi-port-and-storage-discovery.md` | Sweep ports, S3 enum |
| App reflects header/parameter into cached response | `scenarios/cache/poisoning-unkeyed-headers.md` or `poisoning-unkeyed-params.md` | Param Miner + reflection test |
| Sensitive endpoint behind cache, abstract paths | `scenarios/cache/deception-path-mapping.md`, `deception-delimiter.md`, `deception-normalization.md` | Trick cache into storing /my-account as /my-account/x.js |
| HTTP smuggling viable + cacheable target | `scenarios/cache/deception-via-smuggling.md` | CL.TE + cache write |

## Sequencing principles

1. **Read source first.** Source code reveals which fields are accepted, where reflection happens, what the cache key includes — saves hours of black-box probing.
2. **Establish a baseline before testing race conditions.** Send the request twice sequentially and document expected behavior. Without this, parallel deviations are noise.
3. **Use a unique identifier per probe.** Reused paths/values can hit your own cached/poisoned data and confuse results. Add `?cb=<random>` or `unique-<id>` per attempt.
4. **Test BOTH halves of a discrepancy.** Cache deception/poisoning is about disagreement — test what cache thinks AND what origin thinks. The same payload may fail one side and reveal the other.
5. **HTTP/2 single-packet for races, HTTP/1.1 for smuggling.** Modern race attacks need the single-packet primitive (`Engine.BURP2`); smuggling requires HTTP/1.1's CL/TE ambiguity (Burp HTTP/1).
6. **Check secondary views after action IDORs.** The consequence of an action IDOR may surface in your archive list, dashboard, or notification feed — not in the response body.
7. **Mass assignment goes both ways.** Try `is_admin=true` AND `is_admin: true` (form vs JSON) AND nested forms (`user[role]=admin`) AND password-change endpoints.
8. **Connection warming reduces race jitter.** 5 GETs to `/` before the attack drops latency variance from ~850ms to ~120ms.
9. **CSRF tokens may be the only thing protecting logic flaws.** Test `csrf=` empty / removed / wrong / reused before assuming a flaw is unreachable.
10. **Document headers AND cookies AND content-type variants.** Logic flaws hide in the format-normalization seams.

## Cross-cutting gotchas

- **PHP loose comparison** (`"0" == 0`, `"admin" == 0`, `null == []`) underlies several logic flaws — try `0`, `null`, `[]`, `true` for any compared value.
- **Session locking** (PHP, Tomcat) serializes requests on a single cookie — race attacks need multiple cookies. `curl -c cookies1.txt` / `cookies2.txt` to provision.
- **Burp Intruder URL-encodes by default** — disable for delimiter / cache-deception payloads.
- **`#` (fragment) is stripped by browsers** — always use `%23` in URLs for cache deception via fragment-normalization tricks.
- **Set-Cookie disables caching** on most caches — pick endpoints that don't set cookies for poisoning.
- **Cache TTL is short on most sites** — script continuous repoisoning every 20–30s with Turbo Intruder.
- **HTTP method conversion (POST↔GET) often bypasses CSRF AND authorization** simultaneously.
- **HPP order is backend-specific:** PHP last, ASP.NET concatenated with comma, Tomcat first, Apache HTTPD first. Test both orders.
- **`order-confirmation=true` style URLs are replayable** if not bound to a single order ID — check after every legitimate purchase.
- **Mass-assignment field names are language-dependent:** `is_admin` (Python), `isAdmin` (Node), `admin` / `role` (Rails), `IsAdmin` (.NET). Try all conventions.
- **TRACE/TRACK echo internal proxy headers** — useful for discovering hidden authentication headers added by upstream balancers.
- **`document.cookie` does NOT include `HttpOnly` cookies** but `localStorage` is fully readable from JS — confirm token storage location before scoping XSS impact.
- **Rails parameter cloaking (semicolons):** cache and origin parse `;` differently — try in BOTH cache poisoning and access control tests.
- **`READ UNCOMMITTED` isolation is the prerequisite for TOCTOU session races** — verify isolation level via SQL or source before investing time.
