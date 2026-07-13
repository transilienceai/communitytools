# Deterministic Attack-Pattern Coverage — Reviewed Implementation Plan

Status: **needs-changes** (source plan is directionally sound but has 4 high-severity design breaks, ~15 under-specified goals, and several unauthored per-class VALUES). This document supersedes the in-conversation plan and is implementation-ready once the Open Questions are answered.

---

## Objective

Replace the current narrative attack-class coverage matrix (`coverage-matrix.md` + agent-authored `coverage.json` + soft 0.80 validator gate) with a deterministic, code-enforced system:

1. A machine-readable 24-class catalog (`coverage-matrix.json`) with per-class scope, applicability predicate, negative kind, key, and min-vantages — every value pinned verbatim.
2. A code-produced (surface-unit × attack-class) work-list (`enumerate_cells.py` → `applicability/cells.json`), computed from code-owned inputs so an agent cannot fabricate applicability.
3. A hard 100% coverage gate (`coverage_gate.py`) that fails the build unless **every applicable cell** has cross-checked evidence — for both WEB and NETWORK.
4. A new **Attack Pattern Coverage** section in `report_data.json` and the branded PDF.

The gate — not an agent-reported count — becomes the termination and COMPLETE authority.

---

## Goals (G1–G23)

All 23 goals from the source plan are carried forward. This review adds pinned values, fixes 4 confirmed defects, and attaches a concrete test to each testable goal (G12, G13, G15, G16, G18 have producer-side or wiring-only proofs; the agent write-side is not deterministically testable and is proven statically — noted per goal).

---

## Key architectural corrections (read first)

These four corrections change *where* code lands versus the source plan. They are load-bearing.

**C1 — The workflow JS sandbox cannot exec tools or read the filesystem.** `coordinator-loop.js` and `pentest-engagement.js` run in a sandbox with no `child_process`/`fs`/`Date`/`Math.random` (see `wf-helpers.mjs:4`, `coordinator-loop.js:39/944`). Every tool run is delegated to an `agent()` tool-runner. Therefore: the coverage gate is **never** exec'd by JS. It is run *inside an existing agent runner*, which relays the result via its structured-output schema. This kills the "JS runs `python3 coverage_gate.py` and reads the exit code" wording throughout the source plan.

**C2 — Fold the Report-phase gate into `finalizeEngagement`, not a new pre-finalize call.** `finalizeEngagement()` (`pentest-engagement.js:165`) is the single deterministic runner both WEB (`:931`) and NETWORK (`:684`) already call, and it already runs `report_data_build.py` at step 2. Add the gate as **step 2a of that same runner** (before report_data_build reads `reports/coverage-matrix.json`). One edit covers both modes, adds zero agents, and guarantees ordering.

**C3 — Add `class_id`/`unit_refs` in `persistBatch`/`validateOneCandidate`, NOT in `buildInterim`.** `buildInterim` is parity-locked across three files (`wf-helpers.mjs:522`, `coordinator-loop.js:554`, `validate-findings.js:439`; `parity.test.mjs:44` fails on drift). The candidate already carries `f.covers_class` and the loop already threads `class_id: f.covers_class` in `validateOneCandidate`'s return (`coordinator-loop.js:1000`). Merge `class_id`/`unit_refs`/`asset_tag` onto the interim object *after* `buildInterim` returns and before `persistBatch` writes it. Parity/helpers tests stay green.

**C4 — The canonical validated-finding shape is the `verdict`-based `buildInterim` output, not the `valid/checks` shape in VALIDATION.md.** `report_data_build.py:332` reads `verdict ∈ {VALID, REPAIRED}`; the inline lane writes exactly that via `buildInterim`. `VALIDATION.md:207` documents an older `{valid, checks}` shape — it is stale for the inline lane. **The gate joins on `verdict ∈ {VALID, REPAIRED}`.** Update VALIDATION.md to add `class_id`/`unit_refs` to the documented interim shape (G12/G22).

---

## The pinned 24-class catalog (closes G1)

`skills/coordination/reference/coverage-matrix.json`. Nine fields per class: `class_id`, `taxonomy`, `title`, `scope`, `key_by`, `applies_when`, `negative_kind`, `min_vantages`, `technique_ref`. Scope split is exactly **13 unit / 6 host / 5 asset**. `key_by` is a function of scope: `unit`→`unit_id`, `host`→`listener`, `asset`→`asset_tag`.

Flag vocabulary — **exactly 14 agent-set + 6 code-derived**:

- **14 agent-set** (recon-justifiable, per unit/asset; the agent may set these): `object_by_id`, `json_body`, `role_verb_gated`, `sensitive_flow`, `server_fetched_url`, `input_sink`, `workflow`, `deser_or_ci`, `inbound_webhook`, `id_keyed_unauth`, `stored_field`, `auth_surface`, `consumes_upstream`, `static_js_or_repo`.
- **6 code-derived** (computed by `enumerate_cells.py`; agent-unfabricatable): `http_listener`, `tls_listener`, `version_fingerprinted`, `has_api`, `is_apex`, `serves_js`.

| class_id | taxonomy | scope | applies_when | negative_kind | min_vantages |
|---|---|---|---|---|---|
| API1-BOLA | API'23 | unit | `{any_flag:[object_by_id]}` | active_probe | 0 |
| API3-BOPLA | API'23 | unit | `{any_flag:[json_body]}` | active_probe | 0 |
| API4-RESOURCE | API'23 | unit | `{any_flag:[has_api]}` | active_probe | 0 |
| API5-BFLA | API'23 | unit | `{any_flag:[role_verb_gated]}` | active_probe | 0 |
| API6-BUSINESS | API'23 | unit | `{any_flag:[sensitive_flow]}` | active_probe | 0 |
| API7-SSRF | API'23 | unit | `{any_flag:[server_fetched_url]}` | active_probe | 0 |
| API10-CONSUMPTION | API'23 | unit | `{any_flag:[consumes_upstream]}` | active_probe | 0 |
| WEB-A03-INJECTION | Web'21 | unit | `{any_flag:[input_sink]}` | active_probe | 0 |
| WEB-A04-DESIGN | Web'21 | unit | `{any_flag:[workflow]}` | active_probe | 0 |
| WEB-A08-INTEGRITY | Web'21 | unit | `{any_flag:[deser_or_ci]}` | active_probe | 0 |
| XC-WEBHOOK-ORACLE | Cross-cut | unit | `{any_flag:[inbound_webhook]}` | active_probe | 0 |
| XC-EXISTENCE-ORACLE | Cross-cut | unit | `{any_flag:[id_keyed_unauth]}` | active_probe | 0 |
| XC-STORED-XSS | Cross-cut | unit | `{any_flag:[stored_field]}` | active_probe | 0 |
| WEB-A06-COMPONENTS | Web'21 | host | `{any_flag:[version_fingerprinted]}` | reachability | 2 |
| XC-CORS | Cross-cut | host | `{any_flag:[http_listener]}` | reachability | 2 |
| XC-TRANSPORT-DOWNGRADE | Cross-cut | host | `{any_flag:[http_listener]}` | reachability | 2 |
| XC-VERBOSE-ERRORS | Cross-cut | host | `{any_flag:[http_listener]}` | reachability | 2 |
| XC-SECURITY-HEADERS | Cross-cut | host | `{any_flag:[http_listener]}` | reachability | 2 |
| XC-TLS-POSTURE | Cross-cut | host | `{any_flag:[tls_listener]}` | reachability | 2 |
| API2-BROKEN-AUTH | API'23 | asset | `{any_flag:[auth_surface]}` | active_probe | 0 |
| API8-MISCONFIG | API'23 | asset | `{always:true}` | none | 0 |
| API9-INVENTORY | API'23 | asset | `{any_flag:[has_api]}` | none | 0 |
| XC-SUBDOMAIN-ORIGIN | Cross-cut | asset | `{any_flag:[is_apex]}` | reachability | 2 |
| XC-SECRET-EXPOSURE | Cross-cut | asset | `{any_flag:[serves_js, static_js_or_repo]}` | none | 0 |

Counts: scope {unit:13, host:6, asset:5}; negative_kind {active_probe:14, reachability:7, none:3}. `title` and `technique_ref` copy verbatim from `coverage-matrix.md` rows. **These values are authoritative — the source plan delegated them to a non-existent "design notes" table; they are now pinned here.** (Open Question Q4 asks the user to ratify this split before it is frozen.)

**Predicate DSL grammar** (mirror the PCI `_common.eval_applicability` AST style): a node is one of `{always:true}`, `{any_flag:[...]}`, `{all_flags:[...]}`, `{not:<node>}`. Every leaf flag MUST be one of the 20 vocabulary flags. `validate_catalog.py` parses every `applies_when` against this grammar and rejects unknown flags.

---

## Step-by-step plan

Phasing: **P1 catalog+validator**, **P2 enumerate+gate+tests**, **P3 producers (surface/v2, finding fields, ledger)**, **P4 workflow wiring**, **P5 report section**, **P6 docs+CI**. Ship P1–P2 first (fully offline-testable), then P3–P6.

### P1 — Catalog + structural validator

1. **Author `skills/coordination/reference/coverage-matrix.json`** — the 24-class catalog above, verbatim, with `meta:{class_count:24, scope_split:{unit:13,host:6,asset:5}, agent_flags:[…14…], derived_flags:[…6…]}`.
   - *Files:* `skills/coordination/reference/coverage-matrix.json` (new).

2. **Create `tools/validate_catalog.py`** (G2). Deterministic; exit nonzero on any violation. Checks:
   - (a) exactly 24 classes; (b) each row has all 9 fields; `scope ∈ {unit,host,asset}`; `key_by` consistent with scope; `negative_kind ∈ {active_probe,reachability,none}`; `min_vantages` int ≥0 (and >0 **iff** `negative_kind==reachability`); (c) scope counts exactly {13,6,5}; (d) the two flag-vocab sets are exactly the named 14 and 6; (e) every `applies_when` parses against the DSL grammar and references only vocab flags; (f) **catalog↔md class_id-set parity**.
   - **md parsing must be table-scoped** (fixes G2 gap 3): extract class_ids **only** from backtick-wrapped first cells of the "Class catalog" markdown table (rows matching `^\|\s*\`([A-Z0-9-]+)\`\s*\|`), never a full-file scan — `coverage-matrix.md` contains `class_id` in a header row, prose, and a fenced JSON example (`"class_id": "API7-SSRF"`) that must be ignored.
   - CLI: `--catalog PATH --md PATH` (both overridable so the negative test can point at synthetic fixtures — closes G9 gap 3). Exit 1 on drift/violation, print the offending class_id(s).
   - *Files:* `tools/validate_catalog.py` (new).

### P2 — Enumeration + gate + their tests

3. **Create `tools/enumerate_cells.py`** (G3 WEB + G4 NETWORK). Reads code-owned inputs, writes `<engagement>/applicability/cells.json`. Each cell key = `(asset_tag, scope_key, class_id)`.

   **WEB path** (closes G3 gaps 1–3):
   - Load each asset's `recon/inventory/surface.json` (surface/v2, G10). Units carry agent-set flags only.
   - **Code-derived flag computation** (the load-bearing, unfabricatable part): per unit, from its own `type`/`address`/`evidence_ref` (never from agent flags):
     - `http_listener` — unit `type ∈ {host,port,origin}` whose address scheme/port implies HTTP (`http://`, `:80`, `:8080`, or an origin with any endpoint child), OR any endpoint unit's parsed host:port.
     - `tls_listener` — address scheme `https://`/`:443`/a captured TLS cert in `evidence_ref`.
     - `version_fingerprinted` — a product+version token present on the unit (from a tech-fingerprint evidence_ref).
     - `has_api` — the asset has ≥1 unit of `type=endpoint`.
     - `is_apex` — `asset.apex` equals the asset's registrable domain.
     - `serves_js` — ≥1 unit of `type=page` whose evidence_ref includes a `.js` bundle.
   - **Listener aggregation:** parse `host:port` from each unit's `address` (endpoint/page/param/form units resolve to their origin's host:port; `host`/`port`/`origin` units define listeners directly). Union all flags (agent + derived) of every unit sharing a `host:port` onto that listener. Emit exactly **one host-scope cell per distinct listener** per matching host class.
   - **Roll-up:** union all listener+unit flags to the asset; emit asset-scope cells per matching asset class. `API8-MISCONFIG` (always) emits exactly one asset cell.
   - `scope_key`: unit→`unit_id`; host→the `host:port` listener string; asset→`asset_tag`.

   **NETWORK path** (closes G4 — corrected to the REAL schema):
   - Read `<engagement>/hosts/<ip>/host.json`. **Real schema** (`pentest-engagement.js:512/556/600`): `{ip, live, ports:[{port,proto,state,service,product,version,cpe}], cves, notable, no_surface_from?}`. There is **no** `open_services` string and **no** `reachable_from:"none"` — the source plan was inverted; ignore that wording.
   - **Zero-units guard FIRST:** `if not host.get("live") or not host.get("ports"): emit nothing` — a `{live:false, no_surface_from:[…]}` host yields **zero cells, including no misconfig** (fixes G4 gap 2).
   - Per open port (`state=="open"`): derive `http_listener` (service in {http,https,http-proxy,http-alt,https-alt} or product matches nginx/apache/httpd/iis/tomcat), `tls_listener` (service in {https,ssl,tls}, port 443/8443, or an `ssl-cert` note), `version_fingerprinted` (product && version). Each `<ip>:<port>` is a listener.
   - Mapping: http→{SECURITY-HEADERS, TRANSPORT-DOWNGRADE, VERBOSE-ERRORS, CORS}; tls→{TLS-POSTURE}; version→{WEB-A06-COMPONENTS}; host→{API8-MISCONFIG} once (asset scope; each host `ip` is its own `asset_tag`).
   - *Files:* `tools/enumerate_cells.py` (new).

4. **Create `tools/coverage_gate.py`** (G5–G8). Reads the catalog, `applicability/cells.json`, and — **per cell, scoped to that cell's `asset_tag` only** (fixes cross-asset contamination, Finding H2) — that asset's `coverage.json.units_tested`, `experiments.md` E-set, and `artifacts/validated/*.json`. Writes `<engagement>/reports/coverage-matrix.json`.

   **Covered PASS predicate** (G5): a `units_tested` entry with `status:"covered"`, matching `scope_key`, `e_id` in that asset's E-set, **AND** a validated finding in that asset's `artifacts/validated/` with `verdict ∈ {VALID,REPAIRED}` (C4), `class_id == cell.class_id`, `scope_key ∈ unit_refs`, and `asset_tag == cell.asset_tag`.

   **Covered-negative PASS predicate** (G6): `status:"covered_negative"`, `e_id` in E-set, no contradicting VALID finding (same class_id+scope_key). Then by `negative_kind`:
   - `reachability`: the entry names ≥ `min_vantages` **distinct `region` values** taken from `logs/activity/source-ips.jsonl` rows where `verified==true` (auto-detected `verified:false` rows are excluded — `logs.md:65`). `units_tested.vantages` holds region strings matched against the `region` field.
   - `active_probe`: require a non-agent corroborator for `e_id` — a `tools/NNN_*.md` tool-log or a `logs/activity/tool-invocations.jsonl` row bound to that E-ID (fixes Finding S3: negatives were fully agent-fabricatable).
   - `none`: the `e_id` + no-contradiction is sufficient.

   **FAIL predicates** (G7): on any code-enumerated applicable cell — `status:"NA"` is a **hard fabrication FAIL** (the headline predicate; NA is illegal on a cell code found applicable); `false_NA` (class marked N/A anywhere it has ≥1 applicable cell, or an NA justification quoting a code-derived flag); `extra_cell` (a `units_tested` claim for a cell not in `cells.json`); `dangling` (`e_id` not in E-set); `class_mismatch` (joined finding's `class_id` ≠ cell class); `surface_undercount` (defined below). Reporting: each non-passing cell lands in `missing_cells[]` **with a `reason` field** naming which predicate failed (so NA-fabrication and class-mismatch are distinguishable, not silently generic — closes G7 gap 2 / G8 shape).

   **`surface_undercount` definition** (closes the "see edge cases" void — G7/G8/G9/Q8): the gate independently counts **open listeners** from the code-owned inputs (network: `host.json` ports with `state=="open"`; web: distinct `host:port` from `type∈{host,port,origin}` units + endpoint/page origins) and compares to the number of distinct listeners `enumerate_cells.py` actually produced host-scope cells for. If `enumerated_listeners < independent_listeners` (an open listener produced no host cell → the surface was under-read), raise `surface_undercount`. Default threshold: ≥1 unaccounted listener. (Q8 lets the user demote this to a warning if preferred.)

   **`--allow-equiv`** (G14): OFF by default (strict). When set, a cell whose `equiv_group` matches a PASSing sibling in the same group+class is accepted as covered (gate-time acceptance). `enumerate_cells.py` stamps `equiv_group` onto cells from the unit's `equiv_group` field.

   **Output + exit contract** (G8): write `reports/coverage-matrix.json` = `{applicable, passed, coverage_ratio, missing_cells[], extra_cells[], per_class{}, per_asset{}, complete}`. **`per_class[class_id]` = `{taxonomy, title, applicable, passed, status}`** — embeds `taxonomy`/`title`/`status` so `build_attack_coverage` reads this **one file** (closes G19 coupling / Q17). `coverage_ratio = passed/applicable`; **`applicable==0 → ratio 1.0, complete true`** (graceful for legacy/empty engagements — resolves backward-compat Q1 without a special exemption). Per-class `status` collapses its cells: `covered` if all pass via covered, `covered_negative` if all pass with ≥1 negative, else `pending`. `--emit-open` prints the compact open-cell backlog. **Exit 0** iff `ratio==1.0` and no missing/extra/dangling/false_NA/surface_undercount; **exit 1** otherwise; **exit 2** fail-closed on missing/unparseable catalog or cells.json.
   - CLI: single-asset mode (default: `--asset-dir`) and `--engagement-dir` mode (aggregates all web assets + normalized network hosts into one matrix; runs `enumerate_cells.py` internally if `cells.json` absent so ordering is self-contained).
   - *Files:* `tools/coverage_gate.py` (new).

5. **Create `tools/network_coverage_map.py`** (fixes Finding P4 — the NETWORK 100% gate is otherwise unsatisfiable). For a 1000+ host sweep only the top-N hosts run a coordinator-loop (the sole `units_tested` writer); every other live host would have enumerated cells with no writer, so `coverage_complete` could never reach 1.0. This deterministic mapper reads each live host's existing `hosts/<ip>/recon/` nmap/nuclei output and `host.json`, and for hosts **not** deep-dived writes a per-host `coverage.json.units_tested` + appends `experiments.md` E-rows (`SWEEP-<ip>-NN`) that cite the raw nmap output file as the non-agent corroborator — marking each host/asset cell `covered_negative` (or `covered` where a swept finding exists). INTEGRATE remains the writer for deep-dived hosts; the mapper covers the swept-only remainder. Wired before the network coverage gate.
   - *Files:* `tools/network_coverage_map.py` (new).

6. **Create `tools/test_validate_catalog.py`** and **`tools/test_coverage_gate.py`** (G9; stdlib + subprocess, `test_report_data_build.py` style). Test matrix is in the Test plan section. `test_coverage_gate.py` runs `enumerate_cells.py` as a subprocess against fixtures and inspects `cells.json` (there is no separate `test_enumerate_cells.py`; enumeration is asserted here).
   - *Files:* `tools/test_validate_catalog.py`, `tools/test_coverage_gate.py` (new).

### P3 — Producers

7. **Define surface/v2 + update recon emitters** (G10). Structured inventory `{schema:"surface/v2", asset_tag, apex, units:[{unit_id, asset_tag, type, address, methods[], flags[], equiv_group?, evidence_ref[], notes}], summary}`; `type ∈ {page,endpoint,param,host,port,service,form,origin}`; `flags[]` drawn ONLY from the 14 agent-set flags.
   - **Placement (fixes G10 gap 3):** page/endpoint/param/form-level unit emission belongs in **coordinator-loop's per-asset recon** (`coordinator-loop.js:790` `web` angle discovers endpoints/params/forms), written to `<asset>/recon/inventory/surface.json`. The engagement-level **Expand-synthesis** prompt (`pentest-engagement.js`) emits only host/origin-level units it can know at that stage; it does not manufacture page/param units. Update both prompts; leave `work-list.json`/`EXPAND_SCHEMA` intact (surface/v2 is a **new sibling file**, not a replacement — the plan's "replace the free-form surface.json" premise is inaccurate; today's artifacts are `expanded-surface.md` + `work-list.json`).
   - *Files:* `.claude/workflows/coordinator-loop.js` (recon `web` angle prompt), `.claude/workflows/pentest-engagement.js` (Expand-synthesis prompt), `skills/reconnaissance/reference/scenarios/endpoint-enumeration.md` or `skills/reconnaissance/SKILL.md` (document surface/v2 — pin the exact file in Q9), `formats/reconnaissance.md`.

8. **Add `class_id`/`unit_refs`/`asset_tag` to the validated finding** (G12), via **C3** (persistBatch merge, not buildInterim). In `validateOneCandidate` (`coordinator-loop.js:992`), after `buildInterim`: `interim.class_id = f.covers_class || (f.covers_cells?.[0]?.class_id) || null; interim.unit_refs = (f.covers_cells||[]).map(c=>c.key); interim.asset_tag = ASSET_TAG`. `null` class_id is allowed for wildcard/goal missions (Q10a) — such a finding simply covers no cell. The standalone `validate-findings.js` lane is left unchanged (Q10b): it serves HTB/downstream, not coverage; leaving it avoids a parity edit and it emits findings with `class_id:null` (harmless to the gate).
   - *Files:* `.claude/workflows/coordinator-loop.js` (the merge). **No edit to `buildInterim`/`wf-helpers.mjs`/`parity.test.mjs`.**

9. **Add the `units_tested` per-cell ledger** to `coverage.json` (G11). `units_tested:[{key,status,e_id,finding_id?,negative_kind?,vantages?,justification?}]`; INTEGRATE is the sole writer (a prompt convention, not code-enforced). `cells.json` (code work-list) stays a separate input from `coverage.json` (agent scoreboard). Existing per-class `coverage.json` fields remain for continuity; `units_tested` is the cell-level layer the gate reads. Generalize missions to **`covers_cells:[{key,class_id}]`** (G14) alongside the retained `covers_class` (back-compat); INTEGRATE fans one mission's `covers_cells` into many `units_tested` rows.
   - *Files:* `.claude/workflows/coordinator-loop.js` (THINK_SCHEMA `covers_cells`, INTEGRATE prompt + `new_findings` item carries `covers_cells`).

### P4 — Workflow wiring

10. **coordinator-loop THINK: open-cell injection** (G13). Via **C1**, the THINK **agent** (not the JS) runs, as its first step, `python3 tools/enumerate_cells.py --asset-dir OUTPUT_DIR` then `python3 tools/coverage_gate.py --asset-dir OUTPUT_DIR --emit-open`, and ranks the returned `open_cells` backlog — **replacing** the "Rank the applicable pending classes" prose (`:862`). Add optional `open_cells` to THINK_SCHEMA for observability. On batch 1 (no surface/cells yet) or gate exit 2, the agent falls back to catalog-ordered ranking (documented in the prompt). Backlog is kept compact by emitting only open cells (network 1000-host backlogs are summarized per-class with counts).
    - *Files:* `.claude/workflows/coordinator-loop.js` (thinkPrompt).

11. **coordinator-loop termination = gate result** (G15). Via **C1**, INTEGRATE runs `coverage_gate.py --asset-dir OUTPUT_DIR` and reports **`coverage_complete` (bool)** in INTEGRATE_SCHEMA. The loop's `done` (`:1112`) uses `coverage_complete` instead of `coveragePending===0`; the terminate-suppression guards (`:1057`, `:1114`) key off `!coverage_complete`; the `coverageAdvanced` dry-streak keys off the gate's `passed` delta. Update `integratePrompt` (`:916`) to run the gate and set `goal_reached` from `coverage_complete` (not `applicable_pending==0`).
    - **Both** soft-0.80 sites move to the hard gate: `validator-role.md` check 8 **and** its inlined copy in `coordinator-loop.js:1174` (`FAIL if coverage_ratio < 0.80` → `FAIL unless coverage_gate.py exits 0 / ratio==1.0`); `coverageGapFail`/`status` (`:1191`) follow.
    - *Files:* `.claude/workflows/coordinator-loop.js` (integratePrompt, done/terminate logic, engagement-validator prompt), `skills/coordination/reference/validator-role.md` (check 8).

12. **finalizeEngagement gate** (G16 + G17, via **C2**). In the FINALIZE RUNNER prompt (`pentest-engagement.js:177`), add **step 2a** before step 2: run `python3 tools/coverage_gate.py --engagement-dir ${engagementDir}` (for network, run `network_coverage_map.py` first), read `reports/coverage-matrix.json`, set `coverage_complete`/`coverage_ratio`/`coverage_untested` (= `missing_cells.length`). Add those three to FINALIZE_SCHEMA. Extend the JS hard gate (`:192`): `ok = report_data_ok && renderGateOk && coverage_complete`; on failure `status:'BLOCKED'`, `blocked_reason:'attack-class coverage < 100% (${coverage_untested} cells untested)'`.
    - **Extract the gate to a pure helper** `finalizeGate({report_data_ok, renderGateOk, coverage_complete, untestedCount})` in `wf-helpers.mjs` and unit-test it in `helpers.test.mjs` (so G17 has a deterministic unit test — see Test plan).
    - **engagementStatus source of truth** (G16/G18): after finalize returns, WEB (`:905`) and NETWORK (`:662`) set `engagement_status = (report.coverage_complete && !coverageGaps.length) ? 'COMPLETE' : 'INCOMPLETE_coverage'`. `reconcileAssessed` is **retained** for the `coverage_gaps` payload / degraded-asset backfill (removing it breaks parity+helpers), but the **gate is authoritative for coverage** (Q14 lets the user choose full removal instead).
    - **NETWORK gate** (G18): network Report phase gates `netEngagementStatus = (scanComplete && report.coverage_complete) ? 'COMPLETE' : 'INCOMPLETE_coverage'` (`:662`); pass `mode:'coverage'` to the deep-dive coordinator-loop calls (`:625`).
    - *Files:* `.claude/workflows/pentest-engagement.js` (finalize runner prompt + FINALIZE_SCHEMA + JS gate + WEB/NETWORK status + `mode:'coverage'`), `.claude/workflows/lib/wf-helpers.mjs` (`finalizeGate` helper), `.claude/workflows/lib/helpers.test.mjs` (unit test), `.claude/workflows/lib/parity.test.mjs` (register `finalizeGate` if embedded — otherwise import from lib).

### P5 — Report section

13. **`report_data_build.py: build_attack_coverage(eng_dir)`** (G19). Reads `reports/coverage-matrix.json`; returns `{header, rows, widths, note}` with `rows=[class_id, taxonomy, title, applicable_cells, passed_cells, status]` grouped by taxonomy, `note` = `f"coverage {ratio:.0%} — {untested} cell(s) untested"`. Reads **only** that one file (per_class embeds taxonomy/title/status — see step 4). Returns falsy (key omitted) if the file is absent (mirror the `cve_register` guard). Assign `report['attack_pattern_coverage']` next to `cve_register` (`:362`).
    - *Files:* `tools/report_data_build.py`.

14. **`generate_report.py`: Attack Pattern Coverage section** (G20). After the `coverage_table` block (`:446`), render `data["attack_pattern_coverage"]` via `tbl(...)`. Add a `statuscol` param to `tbl` (mirroring `sevcol`): maps `covered→T["GREEN"]`, `covered_negative→T["BLUE"]`, `pending`/`untested`→`T["SEV"]["Critical"]` (the red band — there is no `T["RED"]`). The status column index and widths follow the 6-column row. `build_attack_coverage` emits exactly the status strings `covered`/`covered_negative`/`pending` so the map keys match.
    - *Files:* `skills/transilience-report-style/reference/generate_report.py`. Mirror into `tools/report_data_build.py`'s sibling generator if one is vendored (check `skills/transilience-report-style/reference/generate_report.py` is the single source).

15. **Schema + example + SKILL section list** (G21). Add `attack_pattern_coverage` (`{header,rows,widths,note}`, same shape as `coverage_table`) to `report-data-schema.json` after `coverage_table` (`:81`); add a block to `example-report-data.json`; add the key to the section list in `skills/transilience-report-style/SKILL.md` (line 16 list; optionally line 28 prose).
    - *Files:* `skills/transilience-report-style/reference/report-data-schema.json`, `skills/transilience-report-style/reference/example-report-data.json`, `skills/transilience-report-style/SKILL.md`.

### P6 — Docs + CI

16. **Contract docs** (G22). `coverage-matrix.md`: add flag vocab + scope + `units_tested` + pointer to `.json`, **and rewrite the now-stale narrative** — line 9 (0.80 → hard 100% gate), the "How the loop uses it" section (`applicable_pending==0` → gate `complete`; THINK ranking → open-cell backlog; check-8 → gate exit 0), and re-phrase covered/covered_negative rules per-cell (Q18 confirms scope of the rewrite). `formats/reconnaissance.md`: surface/v2 + host.json→units. `formats/data.md` **and `VALIDATION.md`** (C4): finding `class_id`+`unit_refs` on the interim/validated shape. `validator-role.md`: check 8 hard gate. `skills/pentest-engagement/SKILL.md:40`: COMPLETE gates on web coverage **and** network scan-completion **and** coverage.
    - *Files:* the six docs above.

17. **CI registration** (G23). Add steps to `.github/workflows/pentest-workflow-tests.yml` `deterministic` job: `python3 tools/test_coverage_gate.py`, `python3 tools/test_validate_catalog.py`, and the three extended report tests. **Broaden the `paths:` filter** to include `tools/**` and `skills/coordination/reference/coverage-matrix.json` (today it is `.claude/workflows/**` + a few vantage scripts, so changes to the new tools would not trigger the job — closes G23 gap 1). Add a `wiring.test.mjs` assertion that the yml contains the two new test invocations (proves the CI-registration clause).
    - *Files:* `.github/workflows/pentest-workflow-tests.yml`, `.claude/workflows/lib/wiring.test.mjs`.

---

## Security & best-practices

1. **Cross-asset evidence isolation (Finding H2 — high).** The `(asset_tag, scope_key, class_id)` key plus an engagement-wide `**/artifacts/validated/*.json` glob would let asset A's finding (unit `u-0007`, `E-001`) satisfy asset B's identically-keyed cell — a coverage-isolation break. **Fix:** `coverage_gate.py` resolves each cell's `units_tested`/`experiments.md`/`validated` **only from that cell's asset directory**, and requires `finding.asset_tag == cell.asset_tag`. `enumerate_cells.py` stamps `asset_tag` on every cell; the persist merge (C3) stamps `asset_tag` on every validated finding.

2. **Covered-negative corroboration (Finding S3 — medium).** `covered_negative` cells are the majority path and were fully agent-fabricatable (one `experiments.md` row + one ledger entry closes any class). **Fix:** `active_probe` negatives require a non-agent corroborator (`tools/NNN_*.md` or `logs/activity/tool-invocations.jsonl` bound to the E-ID); `reachability` negatives require ≥`min_vantages` verified regions. Only `none`-kind classes accept a bare negative.

3. **`verified:false` exclusion.** The reachability geography count excludes auto-detected `verified:false` source-ips rows (`logs.md:65`), so a self-registered vantage cannot inflate the distinct-region count.

4. **Fail-closed.** Missing/unparseable catalog or `cells.json` → exit 2 (never a silent pass). Missing validated dir for an asset → its cells are `missing`, not auto-passed.

5. **No new agent for the gate.** The gate rides existing runners (THINK, INTEGRATE, FINALIZE), preserving the agent-cap budget (Finding H1/minimalism).

---

## Performance & quality

- **NETWORK satisfiability (Finding P4 — high):** `network_coverage_map.py` (step 5) writes evidence for the swept-but-not-deep-dived hosts, so the 100% gate is reachable on a 1000-host sweep without spawning 1000 agents. Q16 asks the user to confirm the mapper approach vs. scoping `coverage_complete` to deep-dived hosts only.
- **Compact backlog:** `--emit-open` summarizes per-class counts for large network backlogs so the THINK prompt stays bounded.
- **Deterministic file order:** enumeration and gate use `sorted()` globs (like `report_data_build.py:323`) for reproducible `cells.json`/matrix output.
- **Minimal blast radius:** C2 (fold into finalize) and C3 (persist-merge, not buildInterim) keep the change off the parity-locked hot paths; `parity.test.mjs`/`helpers.test.mjs` pass unchanged except the additive `finalizeGate` helper test.

---

## Test plan (goal → test)

| Goal | Test | Proves |
|---|---|---|
| G1 catalog | `tools/test_validate_catalog.py::positive` | 24 classes, all 9 fields, scope counts {13,6,5}, flag sets exactly 14+6, every `applies_when` parses, catalog↔md parity. |
| G2 validator | `tools/test_validate_catalog.py::negative`, `::parse_robustness` | drift (id added/removed either side) → exit 1 + id reported; a fixture differing only by the fenced-JSON/prose `class_id` mentions → still exit 0. |
| G3 WEB enumerate | `tools/test_coverage_gate.py::web_enumerate` | 2 units on 1 listener + distinct unit-flag units, **no agent http/tls/version flags** → one unit cell per matching unit; exactly one host cell per distinct listener (proves dedup+flag-union); asset cells incl. always-on API8; code-derived flags injected so header/TLS/component cells appear. All keys unique 3-tuples, no NA rows. |
| G4 NETWORK enumerate | `tools/test_coverage_gate.py::net_enumerate`, `::net_zero_units` | live host `{ports:[443 https nginx 1.28.0, 80 http]}` → TLS-posture+components+header/downgrade/verbose/CORS+misconfig with derived flags; `{live:false,no_surface_from:[…]}` → **zero cells (no misconfig)**. Uses the REAL structured `ports[]` schema. |
| G5 covered PASS | `tools/test_coverage_gate.py::covered` + 4 conjunct-flip variants | baseline exit 0/ratio 1.0; then remove finding (hard FAIL, no longer soft-pending), `class_id` mismatch, `scope_key∉unit_refs`, `verdict:DEMOTED`/absent, dangling `e_id` → each exit 1 with cell in `missing_cells`. |
| G6 covered_negative | `tools/test_coverage_gate.py::reachability_negative` (+3 variants) | 2 verified regions ≥ min_vantages → PASS; single region → FAIL; 2nd region only `verified:false` → FAIL; contradicting VALID finding → FAIL. Plus an `active_probe` negative with/without a tool-log corroborator. |
| G7 FAIL predicates | `tools/test_coverage_gate.py::fail_*` (one per predicate) | `status:NA` on applicable cell → hard fabrication FAIL (reason=`na_fabrication`); `extra_cell`; `class_mismatch`; `false_NA`; `dangling`; `surface_undercount` (host.json with an open listener that yields no host cell). |
| G8 exit/output | `tools/test_coverage_gate.py::exit_contract` | clean→exit 0, 8 keys present, `complete:true`; one untested→exit 1; extra/dangling/false_NA/surface_undercount each→exit 1; missing catalog/cells→exit 2. |
| G9 harness | both test files run under CI | web+network fixtures; every PASS/FAIL branch; ratio==1.0 gate; exit codes; catalog↔md parity (pass+fail via `--catalog/--md` overrides). |
| G10 surface/v2 | `tools/test_coverage_gate.py::surface_schema` conformance over a checked-in surface/v2 fixture | top-level keys present; each unit's `type` in the enum; `flags[]` ⊆ the 14 agent flags (code-derived rejected); enumerate emits ≥1 unit cell per page/param/form unit. (Emitter is agent-authored — not deterministically unit-testable; conformance + consumption is the ceiling.) |
| G11 ledger | `tools/test_coverage_gate.py::ledger` | `cells.json` and `coverage.json` consumed as separate inputs; each `units_tested` subfield exercised; ratio==1.0 only when every enumerated cell resolves. (INTEGRATE write-side = agent behavior, not testable.) |
| G12 finding fields | `.claude/workflows/lib/helpers.test.mjs` (merge-site unit) + `wiring.test.mjs` static assertion | a candidate with `covers_cells` → interim gains `class_id`(string)/`unit_refs`(string[])/`asset_tag`; `buildInterim` itself unchanged (parity green). Producer merge is the proof; agent write-side is not. |
| G13 THINK injection | `wiring.test.mjs` static | thinkPrompt references `enumerate_cells.py` + `coverage_gate.py --emit-open`, injects `open_cells`, and the old "Rank the applicable pending classes" prose is gone. (Behavioral = live LLM, not CI-feasible.) |
| G14 covers_cells/equiv | `tools/test_coverage_gate.py::one_e_id_many_cells`, `::equiv_group` (with/without `--allow-equiv`) + `wiring.test.mjs` | one mission's E-ID closes many same-class cells; `--allow-equiv` accepts one group member as covering the group; strict mode does not. |
| G15 termination | `wiring.test.mjs` static | coordinator-loop `done`/terminate key off gate `coverage_complete` not `coveragePending===0`; validator-role check 8 **and** the inlined `:1174` copy reference gate exit 0 / ratio==1.0 not `< 0.80`. |
| G16 report status | `wiring.test.mjs` static + `tools/test_coverage_gate.py::engagement_dir` | pentest-engagement invokes `coverage_gate.py --engagement-dir` **before** `finalizeEngagement`(via the finalize runner ordering) and derives `engagement_status` from `coverage_complete`; the tool-level exit→status semantics proven by the fixture. |
| G17 finalize gate | `helpers.test.mjs::finalizeGate` unit | all-true→`{ok:true,status:COMPLETE}`; `coverage_complete:false`→`{ok:false,status:BLOCKED,blocked_reason:'attack-class coverage < 100% (N cells untested)'}` with N substituted; `report_data_ok:false`/`renderGateOk:false` keep their existing reasons. |
| G18 network gate | `wiring.test.mjs` static + `tools/test_coverage_gate.py::net_host` | network branch derives `netEngagementStatus` from `scanComplete && coverage_complete`; deep-dive call literal includes `mode:'coverage'`; net host fixture untested→exit 1, filled→exit 0. |
| G19 report builder | `tools/test_report_data_build.py` (extend; fixture writes `reports/coverage-matrix.json`) | `attack_pattern_coverage` present with header/widths; rows = expected 6-tuples grouped by taxonomy; note carries ratio + untested count; **absent file → key omitted**. |
| G20 PDF section | `skills/transilience-report-style/reference/test_generate_report.py` (extend) | data with covered/covered_negative/pending rows renders exit 0 + non-empty PDF (every `statuscol` arm exercised). Colour values not asserted (nested closure + content-stream rg ops) — render-smoke is the ceiling. |
| G21 schema/example | `tools/test_report_schema.py` (extend) | schema `attack_pattern_coverage.type=="object"` with header/rows/widths/note; example carries the block. SKILL list = inspection. |
| G22 docs | `tools/test_validate_catalog.py` (md parity) | only the catalog table is machine-checked; the four prose docs are inspection (prose contracts aren't unit-testable). |
| G23 CI | `wiring.test.mjs` reads the yml + grep in CI | yml contains `python3 tools/test_coverage_gate.py` and `tools/test_validate_catalog.py`, and `paths:` includes `tools/**`. |

**Not deterministically testable (agent write-side, by design):** G12 INTEGRATE writing the fields, G13 THINK ranking, G15 loop consuming the relayed result, G16 the JS binding end-to-end. Each is proven by the closest deterministic surrogate (producer-merge unit test, static `wiring.test.mjs` assertion, or the tool-level fixture) as noted above; a full behavioral proof needs live LLM agents, which CI cannot run — the repo's established convention.

---

## Open questions for the user

1. **Backward-compat.** Confirm the graceful path: legacy/in-flight engagements with no surface/v2 or `units_tested` produce `applicable==0 → ratio 1.0 → COMPLETE` (no special exemption), rather than fail-closed BLOCKED. Acceptable?
2. **NETWORK 100% risk acceptance.** For 1000+ host sweeps, is one un-evidenced code-enumerated cell (e.g. one HTTP port's header cell) blocking the whole engagement acceptable, given `network_coverage_map.py` auto-closes swept cells from nmap/nuclei output? Or do you want a documented network-mode exception?
3. **Canonical validated shape.** Ratify C4: the gate joins on `verdict ∈ {VALID,REPAIRED}` (the `buildInterim` shape `report_data_build.py` already reads), and `class_id`/`unit_refs` are added as fields — historical `{valid,checks}` artifacts simply won't join (they predate coverage). OK?
4. **Per-class VALUES.** Ratify the pinned catalog table (scope 13/6/5, the 14+6 flag vocab, `negative_kind` 14 active_probe / 7 reachability / 3 none, `min_vantages`=2 for reachability else 0). These were undefined in the source plan and are proposed here.
5. **host.json input.** Confirm `enumerate_cells.py` keys on the REAL structured `ports[]` + `live:false`/`no_surface_from` schema (not the fictional `open_services` string / `reachable_from:"none"`), and that the host.json emitter (`pentest-engagement.js:512/556/600`) is **not** changed.
6. **Covered join fields.** Confirm the join is `class_id + (scope_key ∈ unit_refs) + asset_tag` equality, and whether `units_tested.finding_id` (optional) must ALSO match the validated artifact when present.
7. **Reachability counting.** Confirm `vantages` holds region strings matched against `source-ips.jsonl.region`, distinct verified regions counted, `verified:false` excluded.
8. **surface_undercount.** Confirm the proposed definition (enumerated open-listener count < independently-counted open-listener count, ≥1 gap → FAIL) and whether it should hard-FAIL (exit 1) or be demoted to a warning.
9. **surface/v2 emitter placement.** Confirm page/param/form units are emitted by coordinator-loop per-asset recon (not the engagement Expand-synthesis prompt), written to `<asset>/recon/inventory/surface.json`, and which reconnaissance doc file to update (`SKILL.md` vs a scenario).
10. **(a)** For wildcard/goal (`covers_class:null`) missions, is `class_id:null` on the validated finding acceptable (it covers no cell)? **(b)** Should the standalone `validate-findings.js` lane also emit `class_id`/`unit_refs` (touching parity-locked `buildInterim`), or is leaving it (coordinator-loop-only) fine?
11. **reconcileAssessed.** Retain it for `coverage_gaps`/degraded-asset backfill while the gate becomes the coverage source of truth (proposed), or fully remove it (touching `wf-helpers.mjs`+`parity.test.mjs`+`helpers.test.mjs`)?
12. **NETWORK evidence writer.** Confirm `tools/network_coverage_map.py` (batched nmap/nuclei→`units_tested` for swept-only hosts) as the mechanism, vs. scoping `coverage_complete` to deep-dived hosts only.
13. **Docs rewrite scope (G22).** Should the stale 0.80 / `applicable_pending` / scan-completion prose in `coverage-matrix.md` and `pentest-engagement/SKILL.md` be rewritten to the hard-100% model now, or is G22 strictly additive?
14. **CI report tests.** Should the three extended report tests (`test_report_data_build`/`test_report_schema`/`test_generate_report`) also be added as CI steps (currently no python tools test runs in this workflow), or only the two new gate/catalog tests as the goal literally requires?

---

## Findings appendix

### High
- **H1 — Report-phase gate must reuse the finalize runner, not a direct JS `python3` call** (minimalism). The workflow JS never execs; grep for `child_process`/`exec`/`spawn` is empty in both workflow files. *Fix:* fold the gate into `finalizeEngagement`'s existing runner as step 2a; add `coverage_complete`/`coverage_ratio`/`coverage_untested` to FINALIZE_SCHEMA; extend the `:192` hard gate. (Plan §C2, §P4-step12.)
- **H2 — Cross-asset coverage contamination** (security). Engagement-wide join with per-asset (non-unique) `unit_id`/`E-ID` namespaces lets one asset's evidence satisfy another's cells → false 100%. *Fix:* scope every join to the cell's `asset_tag`; require `finding.asset_tag == cell.asset_tag`; stamp `asset_tag` on cells and validated findings. (Plan §Security-1.)
- **P4 — NETWORK 100% gate has no evidence writer for non-deep-dived hosts** (performance/feasibility). Every live host gets enumerated cells, but only top-N run the loop (sole `units_tested` writer) → gate never reaches 1.0 or forces 1000 agents. *Fix:* `tools/network_coverage_map.py` writes swept-host evidence from existing nmap/nuclei output before the network gate. (Plan §P2-step5, §Performance.)

### Medium
- **S3 — covered_negative is agent-fabricatable** (security). The majority path (negatives) needed only an agent-written `experiments.md` row + ledger entry — no independent artifact. *Fix:* `active_probe` negatives require a non-agent corroborator (tool-log / `tool-invocations.jsonl`); `reachability` negatives require ≥`min_vantages` verified regions; only `none`-kind accepts a bare negative. (Plan §Security-2, §P2-step4 covered-negative predicate.)

### Informational / spec gaps closed in this review
- `surface_undercount` was `(see edge cases)` with no such section → now defined (§P2-step4).
- Per-class `key_by`/`applies_when`/`negative_kind`/`min_vantages` were delegated to a non-existent design table → now pinned (§catalog).
- `per_class{}` shape was unspecified but G19 needs taxonomy/title/status from one file → now embeds them (§P2-step4 output).
- Validated-finding shape ambiguity (`verdict` vs `valid/checks`) → resolved to the `verdict` shape (C4).
- G13/G15/G16/G17/G18 had no tests and depended on an impossible JS exec → re-anchored to the finalize runner + `wiring.test.mjs`/`helpers.test.mjs` + tool-level fixtures.
