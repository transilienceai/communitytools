# WAF / CDN edge triage, origin discovery & real-browser fallback

Reputation / geo / bot-challenge edges (Akamai, Sucuri, Imperva, F5 XC ASM, Cloudflare, Vercel, CloudFront) repeatedly deny every tester vantage — leaving the app layer at recon-only depth or written off entirely. This is both an **access** problem (you must reach the app to test it) and, when the origin is directly reachable, a **finding**. Two false-positive traps also live here. Pair with [`preflight-checklist.md`](../../coordination/reference/preflight-checklist.md) (the diagnose→provision vantage gate) and `tools/passive_web_probe.py` (the deterministic block-page / soft-404 classifier).

## 1. Triage — which kind of edge is denying you

Classify BEFORE reacting; the fix differs per class.

| Edge | Fingerprint | Deny class | What actually works |
|------|-------------|-----------|---------------------|
| **Akamai** | `AkamaiGHost`, `Reference #<hex>` error, `X-Akamai-*` | IP-reputation (often) or geo | New/clean egress IP; direct origin; a real browser |
| **Cloudflare** | `Server: cloudflare`, `cf-ray`, 1020/1010 challenge | Bot-challenge / IP-reputation | Managed-challenge solve is out of scope — use direct origin or a real headed browser; `CF-Connecting-IP` quirks |
| **Sucuri** | `X-Sucuri-ID`, `Server: Sucuri/Cloudproxy` | IP-reputation | Origin discovery (sibling host / GoDaddy origin) |
| **Imperva/Incapsula** | `X-Iinfo`, `incap_ses` cookie, `_Incapsula_` | Bot-challenge | Real browser; direct origin |
| **F5 XC ASM** | 269-byte `Request Rejected` + `Support ID` | Signature block | Reword payloads; direct origin; **not** a file-exposure (see §4) |
| **Vercel** | `x-vercel-*`, `/404` catch-all | Host-edge / soft-404 | `*.vercel.app` aliases can bypass a host edge block; content-diff (see §4) |
| **CloudFront** | `X-Amz-Cf-Id`, `Via: ... cloudfront` | Geo / origin-shield | Direct origin bucket/ALB; geo vantage |
| **AppTrana** | `406 Not Acceptable` on payloads | Signature block | Reword; direct origin — **not** a file-exposure |

Distinguish the deny **class** (it drives everything): **IP-reputation** (a clean 2nd egress works — see `tools/vantage_diagnose.py`), **geo** (any out-of-country vantage works), **bot-challenge** (needs a real browser, not curl/Playwright-CDP), or a **signature block** (reword payloads; the app is reachable, the WAF just rejects specific requests).

## 2. Origin discovery — the direct-to-origin bypass (access AND a High finding)

When the edge is a reverse proxy, the origin IP is frequently reachable directly — which is BOTH your test vantage AND a reportable High (the WAF/CDN protection is trivially bypassed). Hunt it:

- **Sibling hosts / SANs:** other records on the same apex (`api.`, `origin.`, `direct.`, `cpanel.`, mail records) often point at the un-fronted origin. Enumerate the cert SANs (`crt.sh`, the served cert's `subjectAltName`).
- **CT logs / passive DNS:** `crt.sh`, Censys, Shodan `ssl.cert.subject`, SecurityTrails historical A records — a pre-CDN A record is often still live.
- **Cloud endpoints:** the raw S3 bucket / ALB DNS / App-Service default hostname / GoDaddy shared-host IP (Sucuri origins frequently sit on GoDaddy).
- **Confirm with a host-pinned request** (this is the money move — the vhost mechanic from [`vhost-enumeration.md`](scenarios/vhost-enumeration.md)):
  ```
  curl -sk --resolve <apex>:443:<candidate-origin-ip> https://<apex>/ -o /dev/null -w '%{http_code} %{ssl_verify_result}\n'
  ```
  A `200` with a **valid cert for the apex** served straight off the origin IP = confirmed direct-origin exposure. Use that pinned vantage for the whole engagement, and file the bypass as a finding: *"WAF/CDN (`<vendor>`) bypassable — origin `<ip>` (`<ASN>`) serves the application directly with a valid `<apex>` certificate, defeating the edge's rate-limiting / signature / geo controls."*

## 3. Real-browser gentle-serial fallback — and PERSIST raw HTTP

When the edge is a **bot-challenge** (Cloudflare/Imperva) and no direct origin exists, curl/Playwright-over-CDP are detected. The only reliable, in-scope path observed is a **real headless browser driven gently and serially** (e.g. `chromium --dump-dom`, or a genuine headed Chrome), single request at a time, human-paced, from an un-flagged egress — Playwright/CDP/curl were all detected where this worked.

**Critical:** persist the **raw HTTP response + headers**, not just the rendered DOM. Saving only the DOM has downgraded genuine findings for "lack of primary evidence." Capture the response body, status, and full headers per request (via the browser's network events / a `--save-har`-style capture), and store them alongside any screenshot. Pace to avoid greylisting (a burst re-trips fail2ban / GoDaddy blocks and loses the vantage).

## 4. Two false-positive traps (deterministic, in the probe path)

- **WAF block page returned as 200/403/406** — a reject body is not a file. F5 XC's 269-byte `Request Rejected`, Vercel's `/404`, AppTrana's `406`, an Akamai `Reference #` page — logging these as `.env`/`.git`/`.DS_Store` exposures is a false positive. `tools/passive_web_probe.py` fingerprints reject bodies as blocks regardless of status code before reporting any secret/file exposure.
- **SPA / Blazor soft-404 catch-all** — a single-page app that returns an identical 200 body (e.g. a 5101-byte shell) for *every* path makes `.git/config` or `/api/admin` "exist" as a false positive. Baseline a random nonsense path first; require the candidate's **size + body** to differ from that baseline before reporting existence. `tools/passive_web_probe.py` runs this content-diff (its `_ERROR_PATH` baseline) — never assert existence on status code alone.

## Route it

- WAF-blocked host → run this playbook via `pentest-engagement` before declaring "no surface": triage → origin discovery → (if bot-challenge) real-browser gentle-serial persisting raw HTTP.
- The block-page + soft-404 classifiers are deterministic in `tools/passive_web_probe.py`; the origin-bypass, when confirmed, is a finding, not just a vantage.
