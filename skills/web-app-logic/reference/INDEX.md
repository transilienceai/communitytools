# Web Application Logic — Scenario Index

Read `web-app-logic-principles.md` first for the decision tree and sequencing principles. This index maps environment fingerprints to scenario files.

## Access Control

| Trigger / fingerprint | Scenario file | One-line job |
|---|---|---|
| Object-by-ID, no ownership check (read) | `scenarios/access-control/idor-read.md` | Iterate IDs / decode encoded PK |
| Object-by-ID, no ownership check (action) | `scenarios/access-control/idor-action.md` | State-change on others' resources, check secondary views |
| Privilege flag in cookie/JSON/URL | `scenarios/access-control/parameter-based-controls.md` | Set `Admin=true`, `role=admin` |
| Method-bound authorization (POST checked, GET not) | `scenarios/access-control/method-bypass.md` | Switch HTTP method |
| Reverse-proxy URL trust / IP-allowlist / custom identity hdr | `scenarios/access-control/header-bypass.md` | X-Original-URL, X-UserId, IP spoofing |
| Substring Referer check | `scenarios/access-control/referer-bypass.md` | Spoof `Referer: /admin` |
| Multi-step workflow, only step 1 gated | `scenarios/access-control/multi-step-bypass.md` | Skip to confirmation |
| Hidden admin URL discoverable | `scenarios/access-control/unprotected-functionality.md` | robots.txt + JS + ffuf |
| Mass-assign on update endpoint | `scenarios/access-control/mass-assignment.md` | Inject `is_admin`, `role`, etc. |
| 302 redirect or HTML field carries data | `scenarios/access-control/data-leakage-redirect.md` | View raw response body / source |

## Business Logic

| Trigger / fingerprint | Scenario file | One-line job |
|---|---|---|
| Client-side `price` / `cost` parameter | `scenarios/business-logic/price-manipulation.md` | Modify price, type-juggle, HPP |
| `quantity` accepts negative or large values | `scenarios/business-logic/quantity-manipulation.md` | Negative qty / int overflow |
| Coupon redemption flow | `scenarios/business-logic/coupon-stacking.md` | Alternate codes, parameter pollution |
| Privileged email domain | `scenarios/business-logic/email-domain-bypass.md` | Plus-addressing, IDN homograph |
| Multi-step purchase / registration | `scenarios/business-logic/workflow-bypass.md` | Confirmation replay, content-type swap |
| Gift card sold + redeemable for face value | `scenarios/business-logic/gift-card-loop.md` | Coupon × gift-card profit cycle |
| Validator vs business-logic seam | `scenarios/business-logic/parameter-pollution.md` | HPP / type juggling / encoding |
| Regex deny-list on shell input | `scenarios/business-logic/regex-input-validation-bypass.md` | Octal printf, alternate metacharacters |
| Logic flaws gated by weak CSRF / session | `scenarios/business-logic/csrf-and-session-bypass.md` | Empty/wrong/reuse CSRF, swap sessions |
| Bulk Burp scanning for logic flaws | `scenarios/business-logic/burp-extension-scanner.md` | Custom IScannerCheck extension |

## Race Conditions

| Trigger / fingerprint | Scenario file | One-line job |
|---|---|---|
| One-time-use coupon/gift card/quota | `scenarios/race-conditions/limit-overrun.md` | 20× single-packet attack |
| Two endpoints sharing state (cart/checkout) | `scenarios/race-conditions/multi-endpoint.md` | Parallel requests with same cookie |
| Async job reads record after caller returns | `scenarios/race-conditions/single-endpoint-collision.md` | Email-collision style attacks |
| Object-creation race (PHP `null == []`) | `scenarios/race-conditions/partial-construction.md` | 50 confirmations per registration |
| `hash(timestamp)` token generation | `scenarios/race-conditions/timestamp-collision.md` | Parallel reset across users |
| Upload + AV scan + delete | `scenarios/race-conditions/file-upload-race.md` | Save-vs-delete window |
| Login attempt counter post-verify | `scenarios/race-conditions/rate-limit-bypass.md` | Parallel password volley |
| Server-side session, verify→re-read split | `scenarios/race-conditions/toctou-session.md` | flip_admin / flip_valid / check threads |
| Need higher precision than Burp tab groups | `scenarios/race-conditions/advanced-techniques.md` | Single-packet + last-byte sync + warming |
| Triage / detection workflow | `scenarios/race-conditions/detection-and-baseline.md` | PREDICT / PROBE / PROVE methodology |

## Information Disclosure

| Trigger / fingerprint | Scenario file | One-line job |
|---|---|---|
| Verbose error pages, stack traces | `scenarios/info-disclosure/error-messages.md` | Force exception, harvest framework/path/IP info |
| `/phpinfo`, `/debug`, CMS config endpoints | `scenarios/info-disclosure/debug-pages-and-cms-apis.md` | Probe debug paths, Joomla CVE-2023-23752 |
| Heavy-JS SPA | `scenarios/info-disclosure/javascript-source-review.md` | grep bundles for `/api/`, secrets, hidden routes |
| `.git`, backups, `.env`, `.bak` reachable | `scenarios/info-disclosure/backups-and-version-control.md` | git-dumper + secret-scan |
| TRACE / TRACK / OPTIONS / DEBUG | `scenarios/info-disclosure/http-method-disclosure.md` | Echo proxy headers, list methods |
| Compliance / mandatory header audit | `scenarios/info-disclosure/security-headers-audit.md` | HSTS / CSP / Cache-Control / Referrer-Policy |
| SPA storing tokens in localStorage | `scenarios/info-disclosure/client-side-storage-audit.md` | DevTools + bundle grep for setItem |
| Containerised app, multi-port | `scenarios/info-disclosure/multi-port-and-storage-discovery.md` | Port sweep + S3 / MinIO + DB-backup recovery |

## Cache (Deception + Poisoning)

| Trigger / fingerprint | Scenario file | One-line job |
|---|---|---|
| Cache caches static extensions; origin abstracts paths | `scenarios/cache/deception-path-mapping.md` | `/my-account/<id>.js` cache deception |
| Cache vs origin disagree on delimiter | `scenarios/cache/deception-delimiter.md` | `;`, `?`, `#`, `.`, `%00` |
| One side normalizes URL-encoded segments | `scenarios/cache/deception-normalization.md` | `..%2f`, `%23%2f%2e%2e%2f` |
| HTTP smuggling viable + cache front | `scenarios/cache/deception-via-smuggling.md` | CL.TE + cache write |
| Header reflected, not in cache key | `scenarios/cache/poisoning-unkeyed-headers.md` | X-Forwarded-Host, X-Original-URL |
| Param/cookie reflected, not in cache key | `scenarios/cache/poisoning-unkeyed-params.md` | UTM, callback, fehost cookie |
| Tornado-style backend merges body into get_argument; cache key is URL-only | `scenarios/cache/poisoning-body-args.md` | GET-with-body XSS poisoning of cacheable URLs |
