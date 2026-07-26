# Attack-Class Coverage Matrix

The completion contract for **coverage-style engagements** (web / API / cloud / network pentests, as opposed to flag/CTF hunts). A flag engagement is done when the flag submits; a coverage engagement is done when **every applicable (surface-unit × attack-class) cell has been covered or genuinely negated** — enforced deterministically by code, not agent narrative.

The **machine-readable catalog is [`coverage-matrix.json`](coverage-matrix.json)** — 24 classes, each with a `scope` (`unit` | `host` | `asset`), a code-evaluable `applies_when` predicate over surface flags, and a `negative_kind` (`active_probe` | `reachability` | `none`). This markdown is the human companion; `tools/validate_catalog.py` keeps the two in class_id-parity. `tools/enumerate_cells.py` reads the catalog + the discovered surface (`recon/inventory/surface.json` for web, `hosts/<ip>/host.json` for network) to code-produce the applicable-cell work-list `OUTPUT_DIR/applicability/cells.json`; each engagement records coverage as a per-cell `units_tested` ledger in `OUTPUT_DIR/coverage.json`; and `tools/coverage_gate.py` joins the two against real on-disk evidence.

Companion to `ATTACK_INDEX.md` (which inventories *what techniques the library covers*). This file defines *what an engagement must cover before it may be called COMPLETE*. The api-security fingerprint decision tree (`skills/api-security/reference/api-security-principles.md`) tells you where to START once a symptom appears; this matrix defines DONE — including the classes that emit **no fingerprint until actively probed** and are therefore missed by symptom-driven routing.

## Scoping rule

Applicability is decided **by code**, per cell: `tools/enumerate_cells.py` evaluates each class's `applies_when` predicate against the flags of every surface unit / listener / asset (14 agent-set flags the recon agent records, plus 6 code-derived flags — `http_listener`, `tls_listener`, `version_fingerprinted`, `has_api`, `is_apex`, `serves_js` — that the agent cannot fabricate). A `unit`-scope class emits one cell per matching surface unit; `host`-scope one cell per distinct open listener (`host:port`); `asset`-scope one cell per asset. `coverage_ratio = passed_cells / applicable_cells`. **The gate is a hard 100% gate**: `tools/coverage_gate.py` FAILs (exit 1) unless `coverage_ratio == 1.0` with no missing / extra / dangling / false-NA / surface-undercount cells. Marking a code-applicable cell `NA` is a hard fabrication FAIL. (This replaces the old 0.80 soft bar; `validator-role.md` check 8 now runs the gate.)

## Class catalog

`class_id` is the stable key used in `coverage.json`, the THINK schema, and the validator. Technique-ref points at the scenario/skill that covers the technique.

| class_id | Taxonomy | Class — what it is | Applicability trigger | Technique ref |
|----------|----------|--------------------|-----------------------|---------------|
| `API1-BOLA` | API'23 | Broken Object Level Auth (cross-tenant object access) | any object-by-id endpoint | `api-security/.../rest/owasp-bola-bopla.md` |
| `API2-BROKEN-AUTH` | API'23 | Broken Authentication | any auth surface | `authentication/SKILL.md` |
| `API3-BOPLA` | API'23 | Broken Object Property Level Auth / mass-assignment | JSON create/update bodies | `api-security/.../rest/mass-assignment.md` |
| `API4-RESOURCE` | API'23 | Unrestricted Resource Consumption (rate/limit) | any API (characterize only; no flooding) | `api-security/.../rest/api-recon-and-discovery.md` |
| `API5-BFLA` | API'23 | Broken Function Level Auth (role/verb) | role/verb-gated endpoints | `web-app-logic/SKILL.md` |
| `API6-BUSINESS` | API'23 | Unrestricted access to sensitive business flows | workflow endpoints | `web-app-logic/SKILL.md` |
| `API7-SSRF` | API'23 | SSRF — incl. **stored connector/webhook URL** | any server-fetched URL param | `server-side/.../ssrf/*` |
| `API8-MISCONFIG` | API'23 | Security misconfiguration | always | `web-app-logic/SKILL.md` |
| `API9-INVENTORY` | API'23 | Improper inventory (shadow/old versions, **public docs/swagger**) | any API | `api-security/.../rest/exposed-documentation.md` |
| `API10-CONSUMPTION` | API'23 | Unsafe consumption of 3rd-party APIs | API consumes upstream data | `api-security/.../rest/api-recon-and-discovery.md` |
| `WEB-A03-INJECTION` | Web'21 | Injection (SQLi/NoSQLi/cmd/SSTI/XXE) | any input sink | `injection/SKILL.md` |
| `WEB-A04-DESIGN` | Web'21 | Insecure design / logic flaw | any workflow | `web-app-logic/SKILL.md` |
| `WEB-A06-COMPONENTS` | Web'21 | Vulnerable & outdated components | any fingerprinted version | `source-code-scanning/SKILL.md` |
| `WEB-A08-INTEGRITY` | Web'21 | Software/data integrity (deserialization) | deser / CI surface | `server-side/.../insecure-deserialization-resources.md` |
| `XC-SUBDOMAIN-ORIGIN` | Cross-cut | Subdomain/origin exposure (CDN bypass, exposed admin/mgmt panels) | any apex domain in scope | `reconnaissance/.../scenarios/subdomain-enumeration.md` |
| `XC-CORS` | Cross-cut | CORS misconfig (reflected origin / null / credentials) | any browser-reachable API | `api-security/.../rest/cors-misconfiguration.md` |
| `XC-WEBHOOK-ORACLE` | Cross-cut | Unauthenticated webhook/ingress state oracle | any inbound webhook/ingress endpoint | `api-security/.../rest/unauthenticated-webhook-oracle.md` |
| `XC-TRANSPORT-DOWNGRADE` | Cross-cut | HTTPS→HTTP redirect downgrade / missing HSTS | any HTTP listener | `api-security/.../rest/https-downgrade-redirect-hsts.md` |
| `XC-EXISTENCE-ORACLE` | Cross-cut | Unauth existence/enumeration oracle (org/user/object via error-ordering) | any id-keyed unauth response | `api-security/.../rest/unauth-existence-oracle.md` |
| `XC-VERBOSE-ERRORS` | Cross-cut | Verbose errors (stack/schema/framework/token-lifecycle disclosure) | any error surface | `api-security/.../rest/verbose-error-schema-disclosure.md` |
| `XC-SECURITY-HEADERS` | Cross-cut | Security headers — probe API **and** every web origin separately | every distinct host | `api-security/.../rest/https-downgrade-redirect-hsts.md` |
| `XC-STORED-XSS` | Cross-cut | Stored/reflected/DOM XSS (report **persistence** even when render needs follow-up creds) | any stored user-controlled field | `client-side/SKILL.md` |
| `XC-TLS-POSTURE` | Cross-cut | TLS posture (weak ciphers/protocols) via sslscan | any TLS listener | `cryptography/SKILL.md` (sslscan) |
| `XC-SECRET-EXPOSURE` | Cross-cut | Secret/key exposure in JS bundles, docs, git | any static JS / repo | `osint/SKILL.md` |

## Instance-file contract — `OUTPUT_DIR/coverage.json`

Owned by the INTEGRATE agent (sole writer, mirroring the `experiments.md` ownership rule). One row per `class_id`, carrying a per-cell `units_tested` ledger — the code-produced applicable-cell set lives separately in `applicability/cells.json`, so the scoreboard can never fabricate the work-list:

```json
{
  "class_id": "API7-SSRF",
  "taxonomy": "API-2023",
  "title": "Server-Side Request Forgery",
  "applicability": "applicable",        // applicable | not_applicable
  "status": "pending",                  // advisory per-class rollup; the CELLS are authoritative
  "units_tested": [
    { "key": "u-0007", "status": "covered", "e_id": "E-014", "finding_id": "F-003" },
    { "key": "u-0012", "status": "covered_negative", "e_id": "E-018", "negative_kind": "active_probe", "corroborator": "tools/031_ssrf-probe.md" },
    { "key": "u-0021", "status": "deferred", "deferral_reason": "post-auth BOLA needs an MFA/OTP session; no client OTP seed", "client_input_request": "reports/client-input-requests/CIR-003.md", "blocked_on": "otp" }
  ]
}
```

Per-cell rules enforced deterministically by `coverage_gate.py` (scoped to the cell's own asset dir — no cross-asset contamination):
- **covered** requires an `e_id` present in `experiments.md` **and** a `VALID`/`REPAIRED` finding in `artifacts/validated/` whose `class_id` + `unit_refs` + `asset_tag` match the cell. A cell whose only candidates were REJECTED/DROPPED stays uncovered ("reject and keep searching").
- **covered_negative** is a genuinely-clean probe. `active_probe` negatives need a non-agent corroborator (a `tools/NNN_*.md` whose `Experiment: E-NNN` header cites the raw tool output, or a `corroborator` file that exists). `reachability` negatives (only `XC-SUBDOMAIN-ORIGIN`) need ≥ `min_vantages` distinct **verified** regions from `logs/activity/source-ips.jsonl` (auto-`detected` `verified:false` rows are excluded).
- **deferred** is the honest resting state for a cell the tester cannot reach through no fault of their own (MFA/OTP-gated post-auth, IP-allowlist). It requires **both** a `deferral_reason` and a `client_input_request` whose path resolves to a real on-disk CIR file (`blocked_on` ∈ `otp|mfa|test_account|allowlist` is optional). A `deferred` cell is never counted as passed and never a silent miss: the gate buckets it into `deferred_cells`, computes `coverage_ratio` over the *resolvable* (non-deferred) cells, and keeps `complete` false until the parent orchestrator passes `--accept-deferrals` (an all-deferred scope never completes). An **unsubstantiated** `deferred` (missing reason or a CIR that does not resolve) is a hard miss — it cannot dodge the gate. See the `authenticated-session-acquisition` skill and the preflight cred-reach probe.
- **NA** on a code-applicable cell is a hard fabrication FAIL — the code, not the agent, decides applicability.

## How the loop uses it

1. **Bootstrap / recon** emit the structured surface into `recon/inventory/surface.json` (schema `surface/v2`) and seed the `coverage.json` class rows.
2. **THINK** (coverage mode) runs `enumerate_cells.py` + `coverage_gate.py --emit-open` — the OPEN backlog is the exact code-computed remaining `(class_id @ scope_key)` cells — and spends ≥1 mission/batch on the highest-value open cell(s), setting the mission's `covers_cells`. The wildcard slot is preserved.
3. **INTEGRATE** validates each candidate inline, writes the matching `units_tested` entries (coverage-by-VALID), runs `coverage_gate.py`, and reports `coverage_ratio` + `applicable_pending` (= the gate's `missing_cells` count) + `coverage_complete`.
4. The loop is coverage-complete only when the gate's `coverage_complete` is true (`coverage_ratio == 1.0`, no missing/extra/dangling/false-NA cells). "Ran out of hypotheses" is not done.
5. **Engagement validator** check 8 re-runs the gate (hard 100%); at the engagement level, `finalizeEngagement` runs `network_coverage_map.py` (swept-host tail) + the gate over the whole tree and BLOCKS the deliverable unless every applicable cell is covered.
