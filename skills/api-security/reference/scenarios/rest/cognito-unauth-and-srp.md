# Amazon Cognito — unauthenticated posture (UNSIGNED) + SRP re-auth

Cognito User Pools expose a public `cognito-idp` API that answers **unauthenticated, unsigned** calls (no SigV4) — so the pre-auth posture (self-signup open? user-existence oracle? password policy?) is testable with nothing but the `ClientId`, and a legitimate session is obtainable via SRP for the authenticated surface. Both are recurring on mobile/SPA finance targets.

## Recover the pool config

From the SPA/mobile bundle or `amplifyconfiguration.json`/`aws-exports.js`: `Region`, `UserPoolId` (`<region>_XXXX`), and the app `ClientId`. These are public by design — having them is not the finding; what they *unlock* unauthenticated is.

## UNSIGNED unauthenticated-posture probes (no credentials, no SigV4)

Call `https://cognito-idp.<region>.amazonaws.com/` with `Content-Type: application/x-amz-json-1.1` and `X-Amz-Target: AWSCognitoIdentityProviderService.<Op>` — no `Authorization` header. Each `Op` reveals posture:

- **`SignUp`** with a throwaway user → if it succeeds (or returns `UsernameExistsException` vs a generic error), **self-registration is open** and/or a **username-existence oracle** exists. A finance pool that accepts public `SignUp` is a finding.
- **`ForgotPassword`** → the response distinguishes existing vs non-existing users (delivery medium leaked, or `UserNotFoundException`) = **account enumeration**.
- **`InitiateAuth`** (`USER_PASSWORD_AUTH` or `USER_SRP_AUTH`) with a known-good username + bad password → `NotAuthorizedException` ("Incorrect username or password") vs `UserNotFoundException` = enumeration if the pool leaks the difference. Also reveals whether `USER_PASSWORD_AUTH` (plaintext-password flow) is enabled — a weaker-than-SRP config worth reporting.
- **`ResendConfirmationCode`** → confirms unconfirmed-account existence.
- The **password policy** and MFA config surface in the challenge/exception responses.

Record each as an information-disclosure / weak-config finding with the exact request + response. Do NOT brute-force (`severity-calibration.md`: an enumeration oracle is scored as the demonstrated leak, not as "accounts compromised").

## SRP authenticated session (for the post-auth surface)

To reach the authenticated API with a provided test account, complete SRP (never send the password in plaintext unless only `USER_PASSWORD_AUTH` is offered):

1. `InitiateAuth` `AuthFlow=USER_SRP_AUTH` with `SRP_A` (your computed public value) → returns `SRP_B`, `SALT`, `SECRET_BLOCK`, `USERNAME`.
2. Compute the SRP session key + password claim signature (`amazon-cognito-identity-js` implements this; `tools/auth_replay_harness.py` can shell to it or reuse the SDK).
3. `RespondToAuthChallenge` `PASSWORD_VERIFIER` with the signature + timestamp → on `SOFTWARE_TOKEN_MFA`/`SMS_MFA`, respond with the TOTP-from-seed / OTP code (see the `authenticated-session-acquisition` skill) → `AuthenticationResult.{AccessToken,IdToken,RefreshToken}`.
4. Feed the `AccessToken` as `Authorization` (or the `IdToken` per the API's expectation) into the post-auth BOLA/BFLA battery.

## Verify & score

- Open public `SignUp` on a sensitive pool, or a clear user-existence oracle, is a real Medium/High per data sensitivity — evidence = the unsigned request + the distinguishing response.
- `USER_PASSWORD_AUTH` enabled (plaintext-password flow) is a weak-config finding.
- Having `ClientId`/`UserPoolId` is NOT itself a finding — only what they unlock unauthenticated is.

## Tie-in

The SRP session feeds `authenticated-session-acquisition` (which emits the reusable `storageState`+Bearer) and then the per-role authz matrix via `tools/auth_replay_harness.py`. Pair with [`authentication`](../../../../authentication/SKILL.md) for token/OAuth attacks on the issued JWTs.
