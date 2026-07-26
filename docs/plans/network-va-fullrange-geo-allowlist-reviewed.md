# Refined Plan — Full-range TCP + message-bus/odd-TLS hunting as the network-VA default, and source-IP/geo-allowlist auto-probe from a second geography

> Lead-reviewer refinement of the network-VA gap-closure plan. Fills every goal gap, keeps the change set minimal (extend existing tools/helpers, never re-implement), bakes in the security/performance findings, and gives a concrete test for every goal. All target paths are repo-root-relative.

## Objective

Close the two systemic gaps that made a prior external network VAPT miss 6 real findings:

1. **Port-range + odd-service gap** — a bounded (1-1024 + curated) default scan missed the ZeroMQ ROUTER sockets on `192.0.2.10:5558,6000` and the expired-cert TLS listener on `192.0.2.11:2234`. Make **full-range TCP** and **message-bus / non-443-TLS hunting** the *default* for network VAs (still bounded and safe on dense internal ranges).
2. **Single-vantage / allowlist gap** — `192.0.2.106` (TSplus) and `192.0.2.40` (Asterisk SIP) were dark from the EU primary vantage but live from a US-cloud vantage. **Detect a source-IP/geo-allowlist signature and auto-probe from a second geography** before concluding "no surface," enforced by a validator gate and reflected in the workflow + recon/infra/coordination guidance.

Enforcement lives in three layers: **Layer 1** the executable workflow (`.claude/workflows/pentest-engagement.js`), **Layer 2** the coordination/validator gates and profile docs, **Layer 3** the recon/infra scenario guidance.

## Goals (G1–G22)

| # | Goal | Layer |
|---|------|-------|
| G1 | `standard` → full-range `-p-` on every reachable host (no bounded-triage stage) | 1 |
| G2 | `light` → `-p 1-1024,<curated less-common>` (the OLD standard set) | 1 |
| G3 | `full` → `-p-` + a UDP top-ports pass | 1 |
| G4 | Drop "Do NOT scan all 65535" for the now-full-range standard path (keep it for `light`) | 1 |
| G5 | Detect TLS-on-odd-ports (e.g. 2234) on every non-443 open port | 1 |
| G6 | Compute allowlist/geo-fence signature (≥1 host answers while ≥1 same-scope sibling is *existence-confirmed but dark*) | 1 |
| G7 | On detection, auto-provision ≤2 extra-geo VMs (default US + EU zone minus primary; `geo_vantages` overrides) | 1 |
| G8 | Re-run `-sn`+full-range on ONLY the filtered hosts from each VM egress; merge newly-reachable hosts/ports | 1 |
| G9 | Tear down every VM (ephemeral, crash-safe); register/decommission each vantage in `source-ips.jsonl` | 1 |
| G10 | Graceful degradation: no creds / `auto_provision:false` → detect+flag, record `no_surface_from:[<geos tried>]` | 1 |
| G11 | Cost bound: detection fires ONLY on a real allowlist signature; clean runs incur no cloud spend | 1 |
| G12 | Parse/honor `geo_vantages` (region/zone list) + `auto_provision` (kill-switch) | 1 |
| G13 | Deep-dive consumes the post-escalation open_ports (in-memory merge before ranking) | 1 |
| G14 | Tighten `preflight-checklist.md:7` — full-range on EVERY reachable host for network/perimeter VAs | 2 |
| G15 | New Phase-1 checkbox — on allowlist detection, second-geo re-probe before "no surface" | 2 |
| G16 | `validator-role.md` check 1 sub-clauses — "no surface" negative FAILs without full-range + named vantage geographies | 2 |
| G17 | Qualify `coverage-matrix.md` `covered_negative` — reachability/surface negatives must name tested vantage geographies | 2 |
| G18 | Infra network-recon "port-range coverage" pattern — full-range default + message-bus + non-443 TLS hunt | 3 |
| G19 | One-line de-bias in reconnaissance `port-scanning.md` — carve out low-host-count perimeter case | 3 |
| G20 | Reframe profile docs (standard=`-p-`, light=bounded, full=`-p-`+UDP) + document `geo_vantages`/`auto_provision` | 2 |
| G21 | Add "Scan & vantage coverage" row to the `CLAUDE.md` cross-cutting table | 2 |
| G22 | (Pending decision 3) Promote `f09_zmtp_probe.py` → `skills/infrastructure/tools/zmtp_probe.py` | 3 |

---

## Step-by-step plan (target files per step)

### Reusable seams first (so the workflow stays thin and testable)

The workflow is a sandboxed JS with **no imports**; deterministic logic is authored once in `.claude/workflows/lib/wf-helpers.mjs`, mirrored as an inline copy in the workflow, and drift-guarded by `parity.test.mjs`. Follow that convention for the new pure logic (G6/G7/G11/G12) so it is unit-testable in isolation.

**New pure helpers → `.claude/workflows/lib/wf-helpers.mjs` (+ inline copy in `pentest-engagement.js`, + `parity.test.mjs` entries):**

- `detectAllowlist(sliceResults)` → `{ signature: boolean, filteredHosts: [{ip, signal}] }`. Pure over the slice results. `filteredHosts` = only hosts the workers put in the new `filtered[]` set (existence-confirmed but no reachable service). `signature = allLiveCount >= 1 && filteredHosts.length >= 1`. Genuinely-down hosts are in `dead_count`, never `filtered[]`, so they never fire the signature (this is the load-bearing discriminator behind the cost bound, G11).
- `resolveGeoZones({ geoVantages, primaryGeo })` → `string[]` (≤2). If `geoVantages` non-empty: use it, drop entries equal to `primaryGeo`, cap at 2 (note truncation). Else default `['us-central1-a','europe-west1-b']` minus the entry whose region matches `primaryGeo` (if `primaryGeo` known), capped at 2. Empty/malformed override → default.
- Keep the existing `chunk`, severity, reconcile helpers untouched.

---

### Layer 1 — `.claude/workflows/pentest-engagement.js` (the executable default)

#### Step 1 — Remap the port profiles (G1, G2, G3, G4)

At the network-tuning input block (currently L276–278):

```js
// scan_profile: light = bounded 1-1024 + curated; standard/full = full-range -p-.
const scanProfile = ['light','standard','full'].includes(String(input.scan_profile)) ? String(input.scan_profile) : 'standard'
const fullPorts = !!input.full_ports || scanProfile === 'full'
const fullRange = fullPorts || scanProfile === 'standard'   // NEW: standard is now full-range too
const udpScan  = !!input.udp || scanProfile === 'full'       // G3: full auto-enables UDP
```

At the portSpec computation (currently L433):

```js
const portSpec = fullRange ? '-p-' : `-p 1-1024,${LESS_COMMON_PORTS}`   // light = OLD standard set (G2)
```

- **G1**: `standard` (and default) → `-p-`.
- **G2**: `light` → `-p 1-1024,${LESS_COMMON_PORTS}` — the bare `'-p 1-1024'` literal is gone.
- **G3**: `full` → `-p-` and `udpScan` true. **Override semantics (decision):** `full` = `-p-` + UDP *by definition*; an explicit `udp:false` under `full` is ignored (use `standard` for `-p-` TCP-only). Documented in G20.
- Re-key everything the prompt keys on `fullPorts` onto **`fullRange`** (see Step 2) so the full-range/bounded branch is correct for `standard`.

**Fix the stale self-descriptions in the SAME file (goal G1 missing #1):**
- `meta.whenToUse` (L4): change `default standard = common 1-1024 + curated less-common; full=all 65535 ONLY when set` → `default standard = full-range -p- on every reachable host; light = bounded 1-1024 + curated; full = -p- + UDP`.
- The `LESS_COMMON_PORTS` comment (L397–399): reword to `Curated less-common ports = the LIGHT profile's bounded set (1-1024 + these). standard/full run full-range -p-.`

#### Step 2 — Scan-worker prompt: full-range two-stage + host-count guard + drop the prohibition (G1, G4, and the two HIGH perf findings)

The default `-p-` must **not** blow up scan time or truncate results on dense internal ranges (HIGH finding: *Unconditional standard=-p- blows up scan time*; and truncation re-miss under a fixed `--host-timeout 12m`). Compute `const fullRange = portSpec === '-p-'` and rewrite the PORT+SERVICE step (L445) into two branches:

- **Full-range branch (`fullRange`)** — host-count-aware, two-stage (matches the codebase's own pattern in `reconnaissance/.../port-scanning.md:62-66` and `network-recon/port-scanning-tcp-udp.md:32-34`):
  1. If the slice's live-host count `> FULL_RANGE_HOST_CAP` (new const, default `32`): fall back to the bounded set `-p 1-1024,${LESS_COMMON_PORTS}`, single-pass `-sS -sV`, and record `"full-range downgraded to bounded on dense slice (N>cap live hosts)"` in `tool_limitations`. (Keeps dense internal VAs fast; matches the Layer-2/Layer-3 "low-host-count perimeter" carve-out.)
  2. Else: **Stage A** fast SYN sweep of all 65535 — `nmap -sS -p- --min-rate 2000 -n -Pn --max-retries 2 -oA <...>-full-syn -iL <live>` (paced by rate, not truncated per-port by host-timeout). **Stage B** version+script only on found-open ports — `nmap -sS -sV --version-intensity 5 -n -Pn -p <found-open> --script ssl-cert,ssl-enum-ciphers --host-timeout 12m -oA <...>-services -iL <live>`. Because Stage B hits only open ports, the 12m timeout no longer truncates high ports (fixes the 5558/2234 re-miss).
  - **No "Do NOT scan all 65535" clause in this branch (G4).**
- **Bounded branch (`light`, or the dense-slice fallback)** — single-pass `nmap -sS -sV -n -Pn ${portSpec} --version-intensity 5 -T4 --max-retries 2 --host-timeout 12m --script ssl-cert,ssl-enum-ciphers ...`, and **keep** the prohibition, reworded to bind to the bounded spec: `Stay within the listed ports — do NOT expand to all 65535 for this bounded profile.`

Re-key the L445 conditional off `fullRange` (the effective spec), **not** `fullPorts`.

#### Step 3 — Odd-port TLS detection (G5) — reframed per the two confirmed findings

The plan's original "openssl s_client against EVERY non-443 open port" is **rejected as written** by two confirmed findings (redundant with `nmap -sV`; blocking/hangs on non-TLS ports like the ZeroMQ 5558). Refined mechanism, still catches 2234:

- Primary: the `--script ssl-cert,ssl-enum-ciphers` already added to the `-sV` step (Step 2) fingerprints TLS on odd ports and grabs the cert — this is what identifies `2234` as a TLS listener with an expired cert. No extra probes.
- Fallback (only where `-sV` returns a service but TLS state is inconclusive): a **bounded** `timeout 8 openssl s_client -connect <ip>:<port> -servername <host> </dev/null 2>/dev/null | openssl x509 -noout -dates` — never an unbounded per-port loop; `</dev/null` + `timeout` prevent hanging on 5558.
- Persist: for a confirmed non-443 TLS listener, set `ports[].service` to `ssl/<svc>` and add a `notable[]` entry (`"TLS listener on non-standard port <p>; cert <subject/expiry>"`) in `host.json`; if the cert is expired/weak, also write a `findings/finding-NNN/` per the existing schema.

#### Step 4 — Allowlist schema + detection, placed BEFORE ranking (G6, G10, G13)

**Schema (SCAN_SLICE_SCHEMA, L402-422):** add a `filtered` array:
```js
filtered: { type:'array', items:{ type:'object', additionalProperties:true, required:['ip'],
  properties:{ ip:{type:'string'}, signal:{type:'string',
    description:'existence proof from THIS vantage: host-up-but-all-filtered | tcp-rst | icmp-admin-prohibited | ptr-resolves | prior-report-known-live' } } } }
```
Worker prompt (L444): after host discovery, for each in-slice IP that shows a **positive existence signal yet no reachable service from this vantage**, record it in `filtered[]` with the signal. Only existence-confirmed hosts go here (a bare no-response host stays in `dead_count`). The worker expands its own CIDRs, so a filtered host inside a `/24` (e.g. `.106`) is surfaced as a named IP — the exact case that defeated the old design.

**Detection + ordering (new block between the inventory synth ~L466 and ranking L469):**
```js
const { signature: allowlistDetected, filteredHosts } = detectAllowlist(sliceResults)
let allLive = sliceResults.flatMap(s => s.live || [])   // change L455 const → let
let escalationPlan = null, geoResults = []
if (allowlistDetected) {
  const geos = resolveGeoZones({ geoVantages, primaryGeo: setup.primary_geo })
  escalationPlan = { detected:true, filtered: filteredHosts.map(h=>h.ip), geos, auto_provision: autoProvision }
  if (autoProvision && !dryRun && geos.length) {
    geoResults = await runGeoEscalation({ engagementDir, geos, geoProvider, filteredHosts, primaryIp: setup.primary_ip })
    // G13: merge geo-reached hosts into the IN-MEMORY set BEFORE ranking
    for (const gr of geoResults) for (const h of (gr.newly_reachable||[])) {
      const ex = allLive.find(x => x.ip === h.ip)
      if (ex) { ex.open_ports = [...new Set([...(ex.open_ports||[]), ...(h.open_ports||[])])]; ex.interesting = true }
      else allLive.push({ ...h, interesting: true })
    }
  }
}
```
This runs BEFORE `ranked` (L469), so post-escalation ports flow into `ranked → deepenHosts → deep-dive` — fixing the confirmed "no-code-change deep-dive claim is wrong" finding (host.json alone never reaches the in-memory deep-dive set).

**dryRun return (L475):** add `port_spec` (already present), `udp: udpScan`, `allowlist_detected`, `escalation_plan: escalationPlan`, and `no_surface_from` (see Step 6). Provisioning is gated on `!dryRun`, so a dryRun records the *plan* only and never spends (fixes the "escalation runs before the dryRun return / real VM spend in a dry run" finding).

#### Step 5 — `runGeoEscalation` (G7, G8, G9) — one provisioning-agent per zone, crash-safe

For each of the ≤2 zones, spawn ONE `general-purpose` agent whose Bash does the whole create→scan→merge→teardown inside a single `trap`:

```
handle=""
trap '[ -n "$handle" ] && tools/provision_vantage.sh --teardown "$handle" --engagement "$DIR" || true' EXIT
line=$(tools/provision_vantage.sh --provider $PROVIDER --region $ZONE --engagement "$DIR" \
        --name "vantage-$ENGID-$ZONE" --ssh-ready)   # creates VM (hardened+labelled+TTL), registers attack-vm egress
handle=$(sed -n 's/.*handle=\([^ ]*\).*/\1/p' <<<"$line"); ip=$(...natIP...)
# SSH in, install nmap, scan ONLY the filtered IPs from the VM egress, scp results back:
ssh <vm> 'sudo apt-get -qq install -y nmap; nmap -sn -n <filtered-ips>; nmap -sS -p- --min-rate 2000 ...; then -sV on open'
# merge: write hosts/<ip>/host.json for newly-reachable (create+backfill), append geo ports to existing host.json
```

- **G7**: `provision_vantage.sh --provider gcp --region <zone>` — `--region` is the gcp **zone** (documented in the wrapper header), so defaults are zones (`us-central1-a`, `europe-west1-b`). ≤2 enforced by `resolveGeoZones`.
- **G8**: re-probe targets ONLY `filteredHosts` (not the whole scope). Merge = the agent writes/creates each `hosts/<ip>/host.json` and returns `newly_reachable:[{ip,open_ports,top_services,max_cvss,cves}]` for the JS in-memory merge (Step 4).
- **G9 teardown/deregister** (fixes the two HIGH VM-leak findings + the append-only-ledger finding): all teardown/registration goes through the wrapper (Step 8), never inline provider CLI. Shell `trap … EXIT` covers mid-run failure; the wrapper's provider-native max-run-duration + the reaper (Step 8) cover SIGKILL/host-kill. "Deregister" = an **appended** `role:decommissioned` line, never a mutation of the append-only `source-ips.jsonl`.

#### Step 6 — Graceful degradation + `no_surface_from` (G10, G11)

- When `allowlistDetected` but `autoProvision === false` OR provisioning failed OR `dryRun`: do NOT bare-`dead` the filtered hosts. Record each still-dark filtered host as `no_surface_from`.
- **Where written:** fold into the existing inventory-synthesis agent (reorder it to run AFTER detection/escalation). Pass it `filteredHosts` + the geos tried + which became reachable; it writes, for each still-dark filtered host, `hosts/<ip>/host.json = {ip, live:false, no_surface_from:[<primary_geo>, ...geosTried], detected_via:<signal>}` and an engagement-level `recon/inventory/filtered-hosts.json`.
- **`<geos tried>`:** `[setup.primary_geo]` plus any provisioned geos. `primary_geo` is derived in Setup by best-effort geolocation of `PRIMARY_IP` (Step 7); if unknown, use the literal `"primary-vantage"` so `no_surface_from` is never empty.
- **G11 cost bound:** provisioning is guarded by `allowlistDetected && autoProvision && !dryRun`. `allowlistDetected` depends on the existence-signal-gated `filteredHosts`, so clean runs (live + genuinely-down) never fire → zero spend. Hard ≤2-VM cap via `resolveGeoZones`.

#### Step 7 — Setup: capture `primary_geo` (G7 "minus the primary's", G10 geos-tried)

In the Setup prompt (L304, right after `PRIMARY_IP` capture), best-effort geolocate: `PRIMARY_GEO=$(curl -s --max-time 5 https://ipinfo.io/$PRIMARY_IP/country || echo unknown)` and add `primary_ip` + `primary_geo` (country code / mapped region label) to `SETUP_SCHEMA` and the return. Never block Setup on it. Registration of the primary already happens here; the geo is metadata only.

#### Step 8 — `tools/provision_vantage.sh` — teardown, reaper, create-time hardening (G7, G9; two HIGH findings)

Extend the EXISTING wrapper (single-source all provider logic; do not re-implement delete inline in JS):

- `--teardown <handle>` — parse `provider:zone:name` / `provider:region:iid`, delete the VM (`gcloud compute instances delete` / `aws ec2 terminate-instances` / `az vm delete`), then append a decommission line via `register_source_ip.py <ip> --role decommissioned --note "torn down <handle>"`. Add a symmetric `--teardown --dry-run` path (emits `torn-down <handle>` + appends the decommission line, no provider call) mirroring the committed create dry-run — this is the CI test seam.
- `--reap --engagement <id>` — idempotent: list + delete every VM labelled `engagement=<id>` (self-heals a prior crash's orphans). Called at escalation start and end. `--reap --dry-run` for CI.
- **Create-time hardening** (fixes *auto-provisioned VMs leak on abrupt termination* + *no 0.0.0.0/0 SSH*): tag/label every VM `engagement=<id>`; set provider-native max lifetime (`gcp: --max-run-duration=<TTL> --instance-termination-action=DELETE`; `aws`: schedule-terminate or shutdown timer; `az`: auto-shutdown); restrict ingress to SSH from `PRIMARY_IP/32` only (egress-only otherwise) via a scoped firewall rule. Add `--ssh-ready` (wait for SSH) and print `handle=` + `ip=` on a stable line.
- Keep the header note that `--region` == gcp ZONE; add that `--teardown`, `--reap`, TTL, and label are the ephemerality guarantees, not the JS `try/finally` alone.

#### Step 9 — Parse the two new inputs (G12)

At the input block (~L275-280):
```js
const autoProvision = input.auto_provision !== false   // default true (kill-switch)
const geoVantages = Array.isArray(input.geo_vantages) ? input.geo_vantages.map(String).filter(Boolean)
  : (typeof input.geo_vantages === 'string' ? input.geo_vantages.split(',').map(s=>s.trim()).filter(Boolean) : [])
const geoProvider = ['gcp','aws','az'].includes(String(input.geo_provider)) ? String(input.geo_provider) : 'gcp'
```
`geo_vantages` accepts an array or comma-separated string of gcp **zones**. `auto_provision:false` + `geo_vantages` set → override is retained in `escalation_plan.geos` but no provisioning occurs (flag-only). ≤2 cap + primary-dedup in `resolveGeoZones`.

---

### Layer 2 — coordination gates + profile docs

#### Step 10 — `skills/coordination/reference/preflight-checklist.md`

- **G14 (line 7):** replace with, scoped to network/perimeter VAs and preserving the bounded carve-out:
  `- [ ] Full-range TCP scan (all 65535) complete on EVERY reachable host for network/perimeter VAs — a bounded port set is acceptable only when the scope explicitly limits it. UDP top-100 where relevant.`
- **G15 (new checkbox after line 16, in the Phase-1 gate):**
  `- [ ] On a source-IP/geo-allowlist signature (a host is existence-confirmed but dark from the primary vantage), provision a second-geography vantage (provision_vantage.sh) and re-probe the filtered hosts before concluding "no surface."`

#### Step 11 — `skills/coordination/reference/validator-role.md`

- **G16 (Engagement Validator check 1, L63):** add sub-clauses:
  `1a. A "no open ports / no external surface" conclusion FAILs (port_coverage:FAIL → engagement_status:GAPS_FOUND) unless (a) a full-range (all-65535) scan ran on the reachable hosts, AND (b) the conclusion names the ≥1 source-ips.jsonl vantage geographies it was derived from; a single-vantage "no surface" is never covered.`
- Update the output-schema example (L87): `"port_coverage": "PASS" | "FAIL — <ports skipped | single-vantage no-surface | full-range missing>"`.

#### Step 12 — `skills/coordination/reference/coverage-matrix.md`

- **G17 (covered_negative rule, L62):** append: `A reachability/surface `covered_negative` (e.g. "no external surface", origin-unreachable) additionally requires naming the tested vantage geographies from `logs/activity/source-ips.jsonl`; a negative derived from a single vantage is treated as `pending`.` (Scope: applies to existing surface/reachability-style negatives; the authoritative network-mode enforcement is validator-role.md check 1 — this keeps the two enforcement points aligned on `source-ips.jsonl`.)

#### Step 13 — `skills/pentest-engagement/SKILL.md` (L30) + `reference/scope-file-format.md` (L62) (G20)

- Reframe the profile line: `light` (`-p 1-1024` + curated less-common) / **`standard`** (full-range `-p-` on every reachable host, DEFAULT) / `full` (`-p-` + bounded UDP top-50). Remove the residual `standard = 1-1024 + curated`, `full … only when explicitly set`, and `UDP is off unless udp:true` wording that now contradicts the reframe (state instead: UDP is off for light/standard, auto-on for full; `udp:true` forces it on standard).
- Document the two new options: `geo_vantages` (≤2 gcp zones; override the default US+EU second-vantage list) and `auto_provision` (default true; set false to detect+flag only, no cloud spend).

#### Step 14 — `CLAUDE.md` cross-cutting table (G21)

Add a row: `| Scan & vantage coverage | [`skills/coordination/reference/preflight-checklist.md`](skills/coordination/reference/preflight-checklist.md) |`.

---

### Layer 3 — recon/infra scenario guidance

#### Step 15 — `skills/infrastructure/reference/scenarios/network-recon/port-scanning-tcp-udp.md` (G18)

Add a concise **"Port-range coverage"** section: default full-range (`-p-`, two-stage SYN→`-sV`) on the small reachable/exposed host set; then hunt **message-bus** listeners (ZeroMQ/ZMTP, AMQP, Kafka, Redis, MQTT) and **non-443 TLS** on high ports via `--script ssl-cert,ssl-enum-ciphers`. Reference the ZMTP prober (Step 17 if G22 approved). Keep the file ≤200 lines.

#### Step 16 — `skills/reconnaissance/reference/scenarios/port-scanning.md` (G19)

One-line de-bias at L13 and the L57-59 "Full TCP fallback" block: full-range is the **default** for the low-host-count perimeter case (not a last resort); leave the L11 "preferred opening move", the L33-41 AD focused-scan archetype, and the L114 "burning 30+ minutes" pitfall unchanged.

#### Step 17 — (G22, pending decision 3) Promote the ZMTP prober

If approved: promote the engagement's read-only ZMTP handshake PoC to a reusable tool at `skills/infrastructure/tools/zmtp_probe.py` (dropping any engagement-specific finding-id prefix), and add a resolvable markdown link + one invocation example to the Step-15 scenario. Read-only ZMTP 3.1 handshake prober; no message frames injected.

---

## Security & best-practices (baked into the steps above)

| Finding (sev) | Where fixed |
|---|---|
| **VM teardown has no reusable tool; "deregister" contradicts append-only ledger** (HIGH) | Step 8 `--teardown` (single-sourced in the wrapper) + Step 5/9 model deregister as an appended `role:decommissioned` line, never a mutation. |
| **Auto-provisioned VMs leak on abrupt termination — try/finally insufficient** (HIGH) | Step 8 provider-native `--max-run-duration`+`DELETE` TTL, `engagement=<id>` label, `--reap` idempotent GC at start+end; Step 5 shell `trap … EXIT`. |
| **auto_provision defaults ON behind a weak signal** (MED) + **signature too broad / fires on nearly every run** (HIGH) | Step 4 existence-signal-gated `filteredHosts` (only existence-confirmed-but-dark hosts fire; genuinely-down never do); ≤2-VM cap; egress registered at create (before probing). Kill-switch `auto_provision:false` (Step 9). |
| **"Deregister" breaks append-only / no-RMW invariant** (MED) | Step 8/9 appended decommission line; report-time dedup pairs attack-vm ↔ decommissioned. |
| **No 0.0.0.0/0 SSH on the VM** | Step 8 ingress restricted to `PRIMARY_IP/32`, egress-only otherwise. |
| Register egress before scanning from it | `provision_vantage.sh` registers the attack-vm IP on create, before the SSH re-probe. |

## Performance & quality (baked in)

| Finding (sev) | Where fixed |
|---|---|
| **Unconditional standard=`-p-` blows up scan time on high-live-host internal VAs** (HIGH) | Step 2 host-count guard (`FULL_RANGE_HOST_CAP=32` → bounded fallback) + two-stage SYN→`-sV`. |
| **`-p-`+`-sV` under fixed `--host-timeout 12m` truncates high ports (re-miss)** (implicit in G1) | Step 2 Stage-B `-sV` runs only on found-open ports → no per-port truncation. |
| **Allowlist signature fires on nearly every run → spend on clean scans** (HIGH) | Step 4 existence-signal discriminator (down ≠ filtered). |
| **`openssl s_client` on every non-443 port: blocking, redundant with `-sV`** (MED ×2) | Step 3 primary = `ssl-cert,ssl-enum-ciphers` NSE; fallback only when inconclusive, bounded by `timeout`+`</dev/null`. |
| **"No code change" deep-dive claim wrong — merged results only hit disk** (MED) | Step 4 in-memory merge of `newly_reachable` into `allLive` before `ranked` (L469). |
| **Escalation before dryRun return → real VM spend in a dry run** (MED) | Step 4 provisioning gated on `!dryRun`; dryRun records the plan only. |

## Test plan (goal → test)

Conventions used: **wiring** = `.claude/workflows/lib/wiring.test.mjs` (static-source regex assertions, side-effect-free — the deterministic proof for prompt/branch wiring); **unit** = `.claude/workflows/lib/helpers.test.mjs` + `parity.test.mjs`; **dryRun** = `Workflow('pentest-engagement', {…, dryRun:true})` asserting the DRY_RUN return; **grep+linter** = content assertion + `python3 scripts/skill_linter.py`; **shell** = `tools/test_provision_vantage.sh`.

| Goal | Test |
|---|---|
| G1 | **wiring**: portSpec `fullRange` branch === `'-p-'`. **dryRun**: no `scan_profile` → `result.port_spec === '-p-'`. |
| G2 | **wiring**: light branch === `` `-p 1-1024,${LESS_COMMON_PORTS}` `` AND no bare `'-p 1-1024'` literal remains. **dryRun**: `scan_profile:'light'` → `port_spec === '-p 1-1024,'+LESS_COMMON_PORTS`. |
| G3 | **wiring**: `udpScan` keyed on `scanProfile === 'full'`. **dryRun**: `scan_profile:'full'` → `port_spec==='-p-'` AND `udp===true` (return now surfaces `udp`). |
| G4 | **wiring**: rendered scan-worker prompt for `fullRange` contains `-p-` and NOT `"Do NOT scan"`; the bounded branch contains the bounded spec AND the reworded prohibition. |
| G5 | **wiring**: prompt contains `ssl-cert,ssl-enum-ciphers` on the `-sV` step AND a bounded `timeout ` + `openssl s_client` + `</dev/null` fallback, and NO unbounded per-port openssl loop. **lab (non-CI)**: TLS-on-2234 + non-TLS-5558 host → `host.json` records 2234 as `ssl/…` in `notable[]`, worker does not hang. |
| G6 | **unit** `detectAllowlist`: POSITIVE (live A + `filtered` sibling B) → `signature true`, B in `filteredHosts`; NEGATIVE (live A + genuinely-down, no signal) → `signature false`. |
| G7 | **unit** `resolveGeoZones`: default = one US + one EU zone minus primary; ≤2 cap; `geo_vantages` override; primary dedup; empty→default. **wiring**: escalation invokes `provision_vantage.sh`, ≤2, gated `!dryRun`. |
| G8 | **wiring**: escalation re-probes ONLY `filteredHosts` and merges `newly_reachable` into `allLive`/`host.json`. **lab (non-CI, documented)**: filtered-from-EU / live-from-US host → `host.json` created with new ports. |
| G9 | **shell**: extend `tools/test_provision_vantage.sh` with `--teardown --dry-run` and `--reap --dry-run` → assert a `role:decommissioned` line is appended. **wiring**: escalation uses `trap … EXIT` + `--teardown`; create uses `--max-run-duration`/label. **live teardown**: not CI-testable (documented). |
| G10 | **dryRun**: `auto_provision:false` over a synthetic allowlist-shaped slice → DRY_RUN return includes `no_surface_from:[<primary geo>]` and zero provisioning (achievable now that the schema carries `filtered[]` and the return surfaces `no_surface_from`). |
| G11 | **unit** `detectAllowlist` NEGATIVE (clean run → false). **wiring**: provisioning gated on `allowlistDetected && autoProvision && !dryRun`. |
| G12 | **unit**: `geo_vantages` array + comma-string coercion; `auto_provision` default true / false honored. **dryRun**: `geo_vantages:[z1,z2]` → `escalation_plan.geos` reflects the override; `auto_provision:false` → no provisioning. |
| G13 | **wiring**: the `newly_reachable → allLive` merge appears BEFORE `ranked`. **lab/stubbed (non-CI)**: host reachable only from 2nd vantage → `deepen_planned` includes its IP. |
| G14 | **grep+linter**: `preflight-checklist.md:7` contains `65535`/`full-range` + `every reachable host`, scoped to network/perimeter, with the bounded-when-scoped carve-out; linter passes. |
| G15 | **grep+linter**: Phase-1 gate has a new `- [ ]` naming source-IP/geo allowlist + second-geography + re-probe before "no surface". |
| G16 | **grep**: check 1 contains both sub-clauses (`full-range` + `source-ips.jsonl vantage geographies`) and the updated `port_coverage` schema descriptor. **fixture (manual)**: a single-vantage "no surface" tree → `port_coverage:FAIL`. |
| G17 | **grep+linter**: `covered_negative` rule references `vantage geograph…` + `source-ips.jsonl`. |
| G18 | **grep+linter**: `"Port-range coverage"` heading + all six bus terms (ZeroMQ/ZMTP, AMQP, Kafka, Redis, MQTT) + non-443 TLS mention. |
| G19 | **grep + diff-review**: L13/L57-59 carve out low-host-count perimeter; L11/L33-41/L114 unchanged; linter passes. |
| G20 | **grep**: SKILL.md + scope-file-format.md show standard=`-p-`, light=bounded, full=`-p-`+UDP, and `geo_vantages`/`auto_provision`; no residual contradictory wording. Cross-check the doc mapping against the workflow portSpec. |
| G21 | **grep + path-exists**: `CLAUDE.md` table has a `Scan & vantage coverage` row linking a file that exists. (Note: `skill_linter.py` scans `skills/` only, not repo-root `CLAUDE.md` — this is a standalone grep, or extend the linter to include `CLAUDE.md`.) |
| G22 | **static**: `skills/infrastructure/tools/zmtp_probe.py` exists, `ast.parse` succeeds, no `f09_` prefix, resolvable link from the Step-15 scenario; linter passes. (Pending decision 3.) |

**Cannot be automated in CI (documented):** the *live* halves of G8/G9/G13 (a real 2nd-geography VM egress + a real allowlisted target, and a real VM teardown) need cloud creds and an allowlisted lab host mirroring a per-host source-IP allowlist. Their CI floor is the wiring/unit/shell-dry-run assertions above; the end-to-end behavior is proven by a manual/lab run (and by re-running against the reference estate).

## Open questions for the user

1. **G22 scope.** Design decision 3 reads "confirmed" (promote the ZMTP prober) but the change block marks it "Optional (pending decision 3)." In or out for this build? If in: confirm target `skills/infrastructure/tools/zmtp_probe.py` and dropping the `f09_` prefix.
2. **Provider + default zones.** Confirm gcp as the default `geo_provider`, that `geo_vantages` entries are gcp **zones** (since `provision_vantage.sh` treats `--region` as the zone), and the exact default second-vantage zones (proposed `us-central1-a` + `europe-west1-b`, minus the primary's).
3. **Remote-exec path for the second-vantage scan.** This plan uses **SSH + remote nmap** (the VM's own IP is the source; `provision_vantage.sh` gains `--ssh-ready` + key/OS-login), not a SOCKS tunnel (can't carry raw SYN). Confirm SSH is acceptable and that extending the wrapper this far is in scope.
4. **VM lifetime + auto_provision default.** Confirm a provider-native max lifetime (proposed 2h) as the crash backstop, and that `auto_provision` defaults **true** (unattended provisioning) given the strengthened existence-signal discriminator — or prefer defaulting to **detect+flag** with provisioning opt-in.
5. **Live-only test acceptance.** Confirm that manual/lab verification is acceptable for the un-CI-able halves of G8/G9/G13 (real VM + real allowlisted target), with the wiring/unit/shell-dry-run assertions as the CI floor.

---

## Findings appendix (grouped by severity)

### High
- **VM teardown has no reusable tool; "deregister" contradicts the append-only ledger.** `provision_vantage.sh` is create-only; `register_source_ip.py` is append-only by design. → **Fixed** Step 8 (`--teardown` single-sourced) + Step 5/9 (append `role:decommissioned`, never mutate).
- **Auto-provisioned VMs leak on abrupt termination (try/finally is not sufficient).** `finally` does not run on SIGKILL/OOM/host-timeout; a killed run leaks a public, cost-accruing VM. → **Fixed** Step 8 provider-native TTL (`--max-run-duration`+`DELETE`) + `engagement=<id>` label + idempotent `--reap` at start/end; Step 5 `trap … EXIT`; ingress locked to `PRIMARY_IP/32`.
- **Allowlist signature too broad — fires on nearly every run (spend on clean scans).** "≥1 live + ≥1 filtered" is the normal case. → **Fixed** Step 4 existence-signal-gated `filteredHosts` (down ≠ filtered); ≤2-VM cap; `!dryRun` gate.
- **Unconditional standard=`-p-` blows up scan time / truncates on high-live-host internal VAs.** → **Fixed** Step 2 `FULL_RANGE_HOST_CAP` host-count guard + two-stage SYN→`-sV` (only open ports get `-sV`).

### Medium
- **auto_provision defaults ON behind a weak signal (unattended spend + scans from a new geo with no human gate).** → **Mitigated** Step 4 stronger discriminator + ≤2 cap + register-before-probe; kill-switch `auto_provision:false`; Open Q4 lets the user choose detect+flag default.
- **"Deregister" breaks the append-only / no-RMW invariant of `source-ips.jsonl`.** → **Fixed** Step 8/9 appended decommission line + report-time dedup.
- **`openssl s_client` on every non-443 port is blocking and redundant with `-sV`.** → **Fixed** Step 3 `ssl-*` NSE primary + bounded (`timeout`/`</dev/null`) fallback only when inconclusive.
- **"No code change" deep-dive claim is wrong — merged results only hit disk, never the in-memory live set.** → **Fixed** Step 4 in-memory merge into `allLive` before `ranked`.
- **Escalation runs before the dryRun return and scans execute under dryRun — risk of real VM spend in a dry run.** → **Fixed** Step 4 `!dryRun` gate; dryRun records the plan only.

### Low / process
- `skill_linter.py` scans `skills/` only — it does not cover repo-root `CLAUDE.md` (G21). Use a standalone grep+path-exists, or extend the linter. (Plan step notes flagged the earlier wrong linter path `.claude/skills/skill-update/scripts/skill_linter.py`; the real path is `scripts/skill_linter.py`.)
- The DRY_RUN path still runs real per-slice nmap before returning (pre-existing behavior); acceptable since provisioning is `!dryRun`-gated. Documented so testers don't expect a fully offline dryRun.
