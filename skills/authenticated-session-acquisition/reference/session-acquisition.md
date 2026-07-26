# Session-acquisition recipes

Per-IdP flows to obtain a legitimate authenticated session on an in-scope target and export the reusable artifact. All hosts/realms/creds are placeholders (`<DOMAIN>`, `<REALM>`, env-var NAMES) — never hard-code real values here; read them via `python3 tools/env-reader.py <VARS>` and from the scope file's `creds_env`.

## Identify the IdP first

- Login redirect host → `auth0.com`/`okta.com`/`.auth.<region>.amazoncognito.com`/`descope.com`.
- `GET https://<login-host>/.well-known/openid-configuration` → issuer, `token_endpoint`, `authorization_endpoint`.
- SPA bundle: grep for `auth0-spa-js`, `@okta/okta-auth-js`, `amazon-cognito-identity-js`/`amplify`, `@descope/web-js-sdk`.

## The export contract (end every recipe with this)

Write both under `OUTPUT_DIR/<asset>/session/`:
- `storageState.json` — Playwright `context.storage_state(path=...)` after login.
- `bearer.txt` — the access/ID token, one line, plus a second line `expires_at=<unix>`.

```python
# after a successful Playwright login:
ctx.storage_state(path=f"{OUT}/session/storageState.json")
tok = page.evaluate("() => window.localStorage.getItem('<token-key>')")  # or capture from the token response
open(f"{OUT}/session/bearer.txt", "w").write(f"{tok}\nexpires_at={exp}\n")
```

Executors then load `storageState.json` into a fresh context (browser tests) or send `Authorization: Bearer $(head -1 bearer.txt)` (API replay).

## TOTP-from-seed (deterministic, autonomous)

When the client provided a TOTP Base32 seed for a test account (referenced by a `creds_env` NAME, value in `.env`):

```bash
SEED=$(python3 tools/env-reader.py <REALM>_TOTP_SEED | sed -n 's/^ENV_VALUES:.*<REALM>_TOTP_SEED=//p')
CODE=$(python3 tools/totp_now.py "$SEED")   # current 6-digit RFC-6238 code
```

Drive the login form to the OTP prompt, type `$CODE`, submit. `totp_now.py` is stdlib-only (no pyotp/oathtool). Regenerate the code immediately before submission (30 s step); if the step rolls over mid-submit, re-read and retry once.

## Explicit-OTP (operator supplies the code at run time)

Drive login to the OTP prompt, print a clear operator request, read one line from the operator (SMS/email/authenticator code), submit it, continue to `storageState`. Use when the code cannot be generated (SMS to a real number, push approval).

## Human-in-the-loop resume (OTP is out-of-band, run must pause)

Persist the pre-OTP context and pause; the operator completes the challenge in a headed browser or supplies the post-challenge cookies; resume and export. Keep the paused browser context alive (`storage_state` before pausing so nothing is lost on a crash).

## Auth0

- SPA: authorization-code + PKCE via `authorization_endpoint`; MFA (TOTP/SMS) is an interstitial `mfa` challenge → satisfy with the TOTP-from-seed or OTP mode, then the callback drops the `code` → exchange at `token_endpoint`.
- ROPG shortcut (only if the tenant enables it AND the client is authorized): `POST /oauth/token` `grant_type=password` with `<REALM>_USER`/`<REALM>_PASS`; an MFA-required response returns an `mfa_token` → `POST /mfa/challenge` then `POST /oauth/token` `grant_type=http://auth0.com/oauth/grant-type/mfa-otp` with the TOTP code. Capture `access_token` → `bearer.txt`.

## Okta

- `/oauth2/default/.well-known/openid-configuration` → endpoints. Interactive: authorization-code + PKCE; MFA factors surface via the Okta sign-in widget or the `/api/v1/authn` state machine (`MFA_REQUIRED` → `/api/v1/authn/factors/<id>/verify` with the TOTP/OTP code → `sessionToken`) → resume the OIDC redirect with the `sessionToken` to get the code → token.
- Capture the `access_token`/`id_token` from the token response → `bearer.txt`; `storage_state` after the app loads.

## Amazon Cognito (SRP + UNSIGNED posture)

- **Authenticated (SRP):** use `amazon-cognito-identity-js` SRP (`InitiateAuth USER_SRP_AUTH` → `RespondToAuthChallenge PASSWORD_VERIFIER` → on `SOFTWARE_TOKEN_MFA`/`SMS_MFA`, `RespondToAuthChallenge` with the TOTP-from-seed or OTP code) → `AuthenticationResult.{AccessToken,IdToken}` → `bearer.txt`. Region + `ClientId` + `UserPoolId` come from the SPA config.
- **UNSIGNED unauthenticated-posture check (record as its own negative/finding):** unauthenticated `cognito-idp` calls (`InitiateAuth`, `SignUp`, `ForgotPassword`) with `X-Amz-User-Agent` and NO SigV4 signature reveal whether self-signup is open, whether user-existence is oracle-able, and password policy. This is the pre-auth Cognito surface — enumerate it before (or when you cannot) acquire a session.

## Descope

- Flows are declarative; the SDK (`@descope/web-js-sdk`) drives `/v1/auth/otp/*` and `/v1/auth/totp/*`. For a Bearer, complete the flow (`otp/verify` or `totp/verify` with the TOTP-from-seed/OTP code) → the session JWT (`DS`/`DSR` cookies + `sessionJwt`) → `bearer.txt` from `sessionJwt`; `storage_state` carries the cookies. Note Descope issues short-lived session JWTs with a refresh cookie — prefer refresh over re-login within a run.

## Verify before handing off

One minimal authenticated request must return an authorized response (a real object, not 401/403/redirect-to-login). Only then pass the artifact paths to the post-auth executor batch. If it fails, run the defer path in the SKILL (file a CIR, set `BLOCKED_REASON`, mark the cells `deferred`).
