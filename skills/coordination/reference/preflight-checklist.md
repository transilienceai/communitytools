# Pre-flight Checklist

Run before spawning any executor batch. Write the checklist to `attack-chain.md`. Any unchecked item → fix before spawning. **Never spawn an executor "to learn" — spawn only to test a clear hypothesis.**

## Phase 1 (recon) gate

- [ ] Full-range TCP scan (all 65535) complete on EVERY reachable host for network/perimeter VAs — a bounded port set is acceptable only when the scope explicitly limits it (message buses and non-443 TLS live on high ports). UDP top-100 where relevant.
- [ ] Every accessible source code path read (web app source, scripts, configs, share contents).
- [ ] Every readable share spidered with **both** anonymous (`-u '' -p ''`) and guest (`-u guest -p ''`) where applicable. Different share lists can return.
- [ ] Every binary downloaded from the target decompiled or strings-dumped.
- [ ] Every form/admin panel surveyed — each input field is a potential injection point.
- [ ] Platform/lab metadata read (whatever the host platform exposes — starter creds, machine info, tags).
- [ ] Credential presence — for every var in the scope file's `creds_env`, load via `python3 tools/env-reader.py <vars>` (per `credential-loading.md`). Never `AskUserQuestion`.
- [ ] Credential reachability (per in-scope realm/tenant) — present creds are not working creds. For each realm, acquire a session via [`authenticated-session-acquisition`](../../authenticated-session-acquisition/SKILL.md) (or send one minimal authenticated request) and confirm an authorized response (not 401/403/login-redirect). Creds that are present but unauthenticated (expired, wrong tenant, MFA/OTP-gated with no seed, IP-allowlist blocked) count as **missing for that realm**.
- [ ] On reachability failure — route, do NOT global-block. A missing/unreachable credential never blocks the whole engagement (the unauthenticated surface is always tested): file `reports/client-input-requests/CIR-NNN.md` ("needs test account / OTP seed / allowlist for `<realm>`"), set a realm-level `BLOCKED_REASON` in `attack-chain.md`, and mark that realm's post-auth coverage cells `status:"deferred"` (with `deferral_reason` + `client_input_request` → the CIR; see `coverage-matrix.md`). Terminate `status=BLOCKED` only if the ENTIRE scope is auth-gated.
- [ ] DNS / vhost enumeration done if HTTP services present.
- [ ] All discovered hostnames added to `/etc/hosts`.
- [ ] Source vantage recorded
- [ ] Any extra egress (VM/proxy/VPN) registered via provision_vantage.sh / register_source_ip.py
- [ ] Every vantage you intend to *count* is VERIFIED, not merely registered: an egress echo taken from that vantage (`curl -s ifconfig.me` run THERE) piped through `python3 tools/verify_source_ip.py --ip <ip> --role attack-vm|vpn --region <exit-geography> --evidence-file - --engagement <root>`. Registration alone writes `verified:false` and can never close a reachability negative. `region` = the real exit geography; one egress under two region spellings still counts once. `provision_vantage.sh --ssh-ready` does this for you on gcp.
- [ ] On a filtered/dark signature (existence-confirmed but dark from the primary vantage), first DIAGNOSE: `python3 tools/vantage_diagnose.py --ip <host> [--json]` classifies **down | geo-fence | ip-allowlist | reachable** and runs the cloud-auth precheck (so "no vantage" is only ever concluded when no cloud provider is authed). check-host.net (active third-party probe) stays OFF unless RoE permits `--allow-third-party-probe`.
- [ ] Provision a second-geography vantage (provision_vantage.sh) and re-probe the filtered hosts ONLY for a geo-fence/ip-allowlist classification AND only when cloud auth exists. Never assert "no external surface" without naming the vantage geographies tested AND the diagnosis.

## Surface-expansion gate (mandatory when an apex domain is in scope)

- [ ] CT-log / passive-DNS sweep of EVERY in-scope apex (`crt.sh`, `certspotter`, `subfinder`) → `recon/inventory/subdomains.json`.
- [ ] CDN/WAF-fronted hosts get an explicit origin-discovery pass (direct cloud endpoints, archive.org CDX, historical A records).
- [ ] All discovered hosts added to the inventory AND to `/etc/hosts`.
- [ ] Run even in grey-box where hostnames were provided: provided != complete; scope = discovered surface.

## Web/API attack-class surface gate (mandatory for any HTTP/API target)

These classes emit NO fingerprint until actively probed — they will never appear as a symptom-driven hypothesis. Probe each explicitly, on the API AND each discovered web origin:

- [ ] CORS (reflected origin / `null` origin / credentialed).
- [ ] Security headers (HSTS / CSP / X-Frame-Options / X-Content-Type-Options) on the API AND every origin.
- [ ] Redirect scheme-downgrade (https → http `Location`).
- [ ] Unauth webhook / ingress probe.
- [ ] Unauth existence oracles.
- [ ] Verbose-error probe.
- [ ] Public docs / `swagger` / `openapi.json` / `redoc`.
- [ ] TLS posture via `sslscan`.

Reference `skills/coordination/reference/coverage-matrix.md` as the authoritative class list.

## Phase 2 (think) gate

- [ ] Three hypotheses written to `attack-chain.md` for the next batch.
- [ ] At least one tagged `[wildcard]` — an angle no mounted skill explicitly prescribes.
- [ ] Chosen hypothesis: 1-2, with the rejected ones recorded for backlog.
- [ ] Each hypothesis names: goal (what it would unlock), technique (what to run), target (where to run), expected signal (how you'll know it worked).

## Phase 3 (spawn) gate

- [ ] EXPERIMENT_ID assigned per executor.
- [ ] Goal column populated in experiments.md before spawn (result=pending).
- [ ] Skill files mounted: 1-2 relevant — never the full set.
- [ ] PATT_URL chosen (specific, not the full map).
- [ ] CHAIN_CONTEXT extract is current.

## Stuck gate (fires before declaring P4b)

Before writing "stuck" to attack-chain.md, confirm thoroughness:

- [ ] Every share spidered (null + guest + auth where creds exist).
- [ ] Every readable file inspected for credentials, tokens, keys, paths.
- [ ] Every alternate username casing tried (lowercase, capitalized, ALL-CAPS).
- [ ] Every readable LDAP attribute scanned (description, info, scriptPath, comment).
- [ ] Every config / env / SYSVOL / installer-log searched for cleartext secrets.
- [ ] PSReadLine history (Windows), .bash_history, .python_history (Linux) read where reachable.
- [ ] Every accessible service tried with both null and authenticated probes.

If any unchecked: that's where to spend the next experiment, not P4b.

## Easy-target gate

On Easy-rated targets, "user flag captured but root failed" is a temporary `status=FAILED_partial`, never a final state. Restart from recon with fresh hypotheses if no progress in 5 batches after user-foothold.
