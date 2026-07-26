# Severity Calibration — common false-High checklist

The recurring domain fallacies that inflate findings, applied **deterministically at the VALIDATION layer** (before a finding is accepted), not reactively after the PDF is built. Distinct from `VALIDATION.md` Check 1 (pure CVSS score↔vector↔band arithmetic, automated by `tools/cvss_lint.py`) — this file is domain *reasoning*: is the claimed impact actually demonstrated and reachable?

Each rule: the inflated claim → the precondition it omits → the calibrated verdict. A validator/refuter runs this list against every proposed High/Critical (and any CVE-backed finding) and downgrades or rejects when a precondition is unmet. These are the highest-frequency false-High patterns in web, cloud and network testing, which is why they are checked mechanically rather than left to reviewer judgement.

## 1. CORS — reflected origin ≠ token theft

- **Claim:** "wildcard/reflected `Access-Control-Allow-Origin` → account takeover / token theft" scored High.
- **Missing precondition:** `Access-Control-Allow-Credentials: true` **AND** the sensitive data is served on **ambient cookies** (not a `Authorization: Bearer` header the attacker's page can't read). A reflected origin **without** ACAC:true leaks nothing cross-origin that the attacker couldn't already fetch server-side.
- **Calibrated:** reflected-origin + `ACAC:true` + cookie-auth'd sensitive endpoint → Medium/High per data sensitivity. Reflected-origin **without** ACAC:true, or a Bearer-only API → Low/Info (missing-hardening), never token-theft. Canonical detail: `skills/api-security` / `skills/client-side` (CORS scenarios); `tools/passive_web_probe.py` records the ACAC bit.

## 2. Azure Entra sign-in codes — AADSTS50126 ≠ "MFA disabled"

- **Claim:** "`AADSTS50126` (invalid username or password) returned before an MFA prompt → MFA is not enforced" scored High.
- **Missing precondition:** Entra evaluates **credentials first, Conditional-Access/MFA second** — a wrong password *always* returns 50126 before any MFA challenge, on a fully MFA-enforced tenant. The absence of an MFA prompt on a *failed* auth proves nothing about MFA.
- **Calibrated:** "MFA not enforced" requires a **successful** primary auth that then completes with **no** second factor (e.g. token issued with `amr` lacking `mfa`). Otherwise → Info (not a finding). Other auth-code ordering fallacies (50053 lockout, 50076 vs 50079) follow the same "code ordering ≠ control absence" rule.

## 3. Enabler ≠ demonstrated compromise

- **Claim:** a *capability* scored as if *exploited* — spray-capability as "credentials compromised"; a Golden-SAML/certificate template as "domain compromised"; a writable ACL as "privilege escalated"; an SSRF reachability as "metadata creds stolen."
- **Missing precondition:** the actual exploitation was not run to impact. An enabler is real but its severity is the *demonstrated* step, not the hypothesized end-state.
- **Calibrated:** score the **demonstrated** state; describe the latent escalation as impact/likelihood, not as achieved. `needs_live_confirmation:true` where the chain is plausible but unrun. (Distinct from a genuinely reproduced chain, which scores at its proven impact.)

## 4. Scanner-"Critical" on backported / appliance-bundled packages

- **Claim:** a vulners/nuclei/`-sV` version-match "Critical" on `openssl`/`sudo`/`bash`/a bundled library, taken at face value.
- **Missing precondition:** distros **backport** security fixes without bumping the visible version (RHEL/Debian), and appliances **bundle** patched forks — so the banner version is not the patch level. The CVE may be already fixed.
- **Calibrated:** a version-only match is at most a **candidate** — confirm via the vendor's backport changelog / a behavioral PoC before scoring. Unconfirmed backport-suspect matches → Info/Low with a "version-only, backport-unverified" caveat. Canonical detail: `skills/system` privesc scenarios.

## 5. Verified CVE without applicability / precondition check

- **Claim:** an NVD-verified, correctly-versioned CVE scored at its NVD base regardless of whether the vulnerable feature is reachable or in use.
- **Missing precondition:** the vulnerable code path must be **enabled and reachable** — e.g. an IKEv1 aggressive-mode CVE on a gateway with only IKEv2 RA configured; an inbound HTTP-request-smuggling CVE mis-applied to an outbound-only client; a plugin CVE where the plugin is absent.
- **Calibrated:** layer a **precondition/reachability gate** on top of the version/class match (beyond `tools/nvd-lookup.py`'s CVSS): state the required config and the observed config; if the precondition is unmet or undetermined → downgrade to Info or mark `needs_live_confirmation`. A CVE is only scored at impact when the vulnerable feature is confirmed active.

## How to use (validator / refuter)

For each proposed finding, before ACCEPT:
1. If it is CORS / Azure-auth / an enabler / a scanner-version-Critical / a CVE-backed claim, apply the matching rule above.
2. If the omitted precondition is unmet → **downgrade** to the calibrated band, or **REJECT** if the claimed impact collapses entirely.
3. Record the calibration rationale in the finding's `calibration` field (rendered by the report) — see `formats/transilience-report-style/pentest-report.md` §7.

This checklist stops **inflation**; `VALIDATION.md` Check 6 (root-cause severity floor) stops **deflation**; Check 1 + `cvss_lint` keep the arithmetic self-consistent.
