---
name: authenticated-session-acquisition
description: Acquire an authenticated session THROUGH MFA/OTP on an in-scope target and emit a reusable session artifact (Playwright storageState + Bearer) so executors can test the post-auth attack surface. Use when the highest-value authenticated classes (BOLA/IDOR/mass-assignment/injection on the real data APIs) are blocked because login is gated by SMS-OTP or TOTP MFA. Distinct from the authentication skill (which ATTACKS auth); this one legitimately authenticates and hands the session to the rest of the engagement.
---

# Authenticated Session Acquisition

On financial and multi-tenant targets the login is gated by SMS OTP / TOTP MFA that an autonomous run cannot satisfy, so the post-auth surface (BOLA/IDOR/mass-assignment/injection on the real data APIs, session handling, API pivots) silently collapses to pre-auth findings only. This skill's job is narrow and concrete: **get one legitimate authenticated session and hand it to the executors as a reusable artifact.** It does not attack the auth mechanism — see [`authentication`](../authentication/SKILL.md) for that.

## The artifact contract (how the session reaches executors)

Emit both, into the engagement's OUTPUT_DIR, referenced BY NAME (never inline secrets — [`credential-loading.md`](../coordination/reference/credential-loading.md)):

- `OUTPUT_DIR/<asset>/session/storageState.json` — the Playwright storage state (cookies + localStorage) for browser-driven post-auth testing.
- `OUTPUT_DIR/<asset>/session/bearer.txt` — the raw access/ID token (+ its `expires_at`) for direct API replay.

Executors consume these exactly like any env-loaded secret: the scope file's `creds_env` names the realm, and the session path is passed as a file reference, so no token is ever written into a prompt, `experiments.md`, or `attack-chain.md`. Re-run this skill when the token expires (record `expires_at`; refresh rather than re-login where a refresh token exists).

## Modes (pick by what the client can provide)

| Mode | When | How |
|------|------|-----|
| **TOTP-from-seed** | The client shared the TOTP secret (Base32 seed) for a test account | Generate the current code deterministically with [`tools/totp_now.py`](../../tools/totp_now.py) `<BASE32_SEED>`, submit it in the login flow. Fully autonomous, repeatable. |
| **Explicit-OTP** | The operator can read a one-time code (SMS/email/authenticator) at run time | Drive login to the OTP prompt, the operator supplies the code once, continue. |
| **Human-in-the-loop resume** | OTP arrives out-of-band and the run must pause | Persist the pre-OTP browser context, pause; the operator completes the challenge; resume and capture `storageState`. |

## Provider recipes

Detailed per-IdP flows are in [`reference/session-acquisition.md`](reference/session-acquisition.md): **Auth0**, **Okta**, **Amazon Cognito** (SRP auth + the UNSIGNED unauthenticated-posture check), and **Descope**. Each recipe ends by exporting `storageState.json` + `bearer.txt` in the contract above.

## When a session cannot be acquired — defer honestly, do not fake

If no test account / OTP seed is available and no OTP can be relayed, the realm's post-auth surface is untestable **through no fault of the tester**. Record it honestly instead of a fabricated `NA` or a silent miss:

1. File a client-input request at `reports/client-input-requests/CIR-NNN.md` naming exactly what's needed ("needs test account / OTP seed / allowlist for `<realm>`").
2. Set a realm-level `BLOCKED_REASON` in `attack-chain.md`.
3. Mark that realm's post-auth coverage cells `status:"deferred"` in `coverage.json`, each carrying `deferral_reason` + `client_input_request` (the CIR path) — see [`coverage-matrix.md`](../coordination/reference/coverage-matrix.md). The deterministic gate then discloses the deferred surface in the report rather than hiding it, and only the parent orchestrator (via `coverage_gate.py --accept-deferrals`) may finalize a substantiated-deferred engagement. A scope that is *entirely* auth-gated never completes.

The preflight cred-reach probe ([`preflight-checklist.md`](../coordination/reference/preflight-checklist.md), Phase-1 gate) is what triggers this path: present creds are not working creds; verify reachability per realm before spawning post-auth executors.

## Workflow

1. Read the scope: which realms/tenants are in `creds_env`, which assets are behind them, `roe.reversible_writes` for the test tenant.
2. Identify the IdP (login redirect host / `/.well-known/openid-configuration` / SDK bundle) → pick the recipe.
3. Acquire the session in the appropriate mode → write `storageState.json` + `bearer.txt`.
4. Verify: one minimal authenticated request returns an authorized response (not 401/403/login-redirect).
5. Hand the artifact paths to the post-auth executor batch; on failure, run the defer path above.

## Anti-Patterns

- Do not paste tokens, seeds, or cookies into prompts, `experiments.md`, `attack-chain.md`, or any `tools/*.md` — reference the artifact file by path only.
- Do not brute-force or bypass the OTP/MFA challenge here — that is an `authentication` finding, not session acquisition.
- Do not mark an MFA-blocked cell `covered`/`NA` — mark it `deferred` with a filed CIR so the gate discloses it.
- Do not test outside the authenticated tenant you were given, and honor `roe.reversible_writes` (create-then-delete only in your own test tenant).

## Reference

- [`reference/session-acquisition.md`](reference/session-acquisition.md) — per-IdP acquisition recipes (Auth0 / Okta / Cognito / Descope) + the storageState/Bearer export.
- [`tools/totp_now.py`](../../tools/totp_now.py) — stdlib RFC-6238 TOTP generator (the TOTP-from-seed mode).
