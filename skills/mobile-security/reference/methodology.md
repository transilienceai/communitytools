# Mobile VAPT — Methodology & Phase Backbone

The navigator that sequences every mobile recipe into a repeatable, MASTG-aligned
flow. Static-first is the default; **dynamic is a first-class phase**, not an
anti-pattern, whenever a control can only be proven at runtime (pinning enforced,
Keystore-backed key, root-detection reaction, IPC guard). Each phase names the
reference file that owns it — read this hub first, then jump.

## When to use

- Start of any Android/iOS engagement — before picking a scenario recipe.
- To decide whether a control needs a device (dynamic) or a dump suffices (static).
- To assemble the client→API pivot that feeds the api-security / server-side skills.

Scoping, authorization/RoE, credential loading, and vantage are **out of scope
here** → [`../../coordination/reference/preflight-checklist.md`](../../coordination/reference/preflight-checklist.md). Do them first.

## Phase backbone

| # | Phase | Entry criterion | Exit criterion | Owning reference |
|---|-------|-----------------|----------------|------------------|
| 0 | ACQUIRE | Preflight signed off | Artifact + sha256 + version recorded | this file (below) |
| 1 | TRIAGE | Artifact on disk | Automated baseline (MobSF) reviewed, framework fingerprinted | this file (below) |
| 2 | STATIC | Framework known | Secrets, endpoints, storage/crypto/pinning code mapped | android-static-analysis.md · ios-static-analysis.md · framework recipes |
| 3 | DYNAMIC | A control needs runtime proof | Pinning/root/Keystore/IPC verified live | android-dynamic-analysis.md · ios-dynamic-analysis.md |
| 4 | NETWORK | Proxy trusted or pinning bypassed | Full API traffic captured, TLS posture graded | android/ios-dynamic-analysis.md (MITM setup) |
| 5 | STORAGE | Device/emulator with app data | On-device artifacts triaged (DB/prefs/Keychain/logs) | android/ios-dynamic-analysis.md |
| 6 | PLATFORM/IPC | Manifest/Info.plist parsed | Exported components, deep links, URL schemes exercised | android/ios-static + dynamic |
| 7 | BACKEND PIVOT | Endpoint inventory built (Phase 2/4) | Hypotheses handed to API/server-side skills | api-security cross-links (below) |
| 8 | REPORT | Findings tagged MASVS+MASTG | Validated + drafted | validate → report (below) |

Phases 3–6 are iterative, not strictly serial: a pinning bypass in DYNAMIC
unblocks NETWORK, which surfaces endpoints that send you back to STATIC.

## Phase 0 — ACQUIRE + evidence integrity

Capture hash + version **before** touching the artifact. Record in the audit log.

```bash
# --- Android: pull installed splits (base + config/density/abi/language) ---
adb shell pm path com.example.app                 # lists every split apk
adb pull /data/app/~~<hash>/com.example.app-<h>/base.apk .   # per path line
# .apks / .apkm / .xapk bundle -> single installable, universal apk:
bundletool build-apks --bundle=app.aab --output=app.apks --mode=universal
unzip -o app.apks universal.apk -d .              # merged apk for static tools
aapt2 dump badging base.apk | grep -E 'package|versionName'   # package+version
sha256sum base.apk *.apk | tee ACQUIRE.sha256     # integrity anchor

# --- iOS: acquire then decrypt (App Store binaries are FairPlay-encrypted) ---
ipatool download -b com.example.app -o app.ipa    # or Apple Configurator export
shasum -a 256 app.ipa | tee -a ACQUIRE.sha256
plutil -p Payload/*.app/Info.plist | grep -Ei 'CFBundleShortVersion|Identifier'
```

`bundletool` is versioned — pin a release jar (`bundletool-all-<ver>.jar`) rather
than trusting `PATH`. iOS decryption (frida-ios-dump / `flexdecrypt`) needs a
jailbroken device → [`ios-static-analysis.md`](ios-static-analysis.md).

## Phase 1 — TRIAGE (automated baseline)

One fast automated pass to fingerprint the framework and pre-populate the MASVS
grid. **Never the deliverable** — its output is a worklist, not a finding set.

```bash
# MobSF static scan (self-hosted; API mode is scriptable)
docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf:latest
curl -F 'file=@base.apk' -H "Authorization:$MOBSF_KEY" http://127.0.0.1:8000/api/v1/upload
# framework fingerprint (routes you to the owning recipe):
unzip -l base.apk | grep -E 'libapp\.so|libflutter\.so' && echo FLUTTER
unzip -l base.apk | grep -E 'libhermes\.so|index\.android\.bundle' && echo RN_HERMES
unzip -l base.apk | grep -E 'libil2cpp\.so|global-metadata\.dat' && echo UNITY
unzip -l base.apk | grep -E 'classes[0-9]*\.dex' && echo NATIVE_ANDROID
```

Framework → recipe: Flutter → [`flutter-aot-reversing.md`](flutter-aot-reversing.md); RN/Hermes →
[`scenarios/android/react-native-hermes.md`](scenarios/android/react-native-hermes.md); Unity → [`../../reverse-engineering/reference/scenarios/static-analysis/unity-il2cpp-recipe.md`](../../reverse-engineering/reference/scenarios/static-analysis/unity-il2cpp-recipe.md);
custom `.so` logic → [`scenarios/android/native-lib-host-extraction.md`](scenarios/android/native-lib-host-extraction.md); stock →
[`android-static-analysis.md`](android-static-analysis.md) / [`ios-static-analysis.md`](ios-static-analysis.md).

## MASVS v2.x coverage map

Tag **every** finding with its MASVS control id **and** the covering MASTG-TEST id
so it hands cleanly to the reporting skill. Groups × owning file:

| MASVS group | Android file | iOS file | Coverage class_id(s) | Typical MASTG / MASWE |
|-------------|--------------|----------|----------------------|------------------------|
| STORAGE | android-static + dynamic | ios-static + dynamic | `MAS-STORAGE-LOCAL` `MAS-STORAGE-LOGS` | MASTG-TEST-0200s · MASWE-0006 |
| CRYPTO | android-static-analysis.md | ios-static-analysis.md | `MAS-CRYPTO-WEAK` `MAS-CRYPTO-KEYMGMT` | MASTG-TEST-0210s · MASWE-0009 |
| AUTH | dynamic + backend pivot | dynamic + backend pivot | `MAS-AUTH-LOCAL` | MASTG-TEST-0017 · MASWE-0040 |
| NETWORK | android-dynamic-analysis.md | ios-dynamic-analysis.md | `MAS-NETWORK-CLEARTEXT` `MAS-NETWORK-PINNING` | MASTG-TEST-0230s · MASWE-0050 |
| PLATFORM | android-static (manifest/IPC) | ios-static (Info.plist/URL) | `MAS-PLATFORM-IPC` `MAS-PLATFORM-WEBVIEW` `MAS-PLATFORM-SCREEN` | MASTG-TEST-0250s · MASWE-0060 |
| CODE | framework recipes + static | ios-static-analysis.md | `MAS-CODE-SECRETS` `MAS-CODE-DEPENDENCY` | MASTG-TEST-0270s · MASWE-0071 |
| RESILIENCE | android-dynamic-analysis.md | ios-dynamic-analysis.md | `MAS-RESILIENCE-ROOT` `MAS-RESILIENCE-INTEGRITY` | MASTG-TEST-0280s · MASWE-0100 |
| PRIVACY | privacy-testing.md | privacy-testing.md | `MAS-PRIVACY-DATA` | MASTG-TEST-0300s · MASWE-0110 |

The `class_id` column is not decoration: in a coverage-mode engagement those 15
classes ARE the completion contract, enumerated per app by
`tools/enumerate_cells.py` from `recon/inventory/mobile-surface.json` and gated at
a hard 100% by `tools/coverage_gate.py`. "I ran out of ideas" is not done; an open
cell is. Per-class technique detail, and what a genuine negative has to look like,
live in [`masvs-class-map.md`](masvs-class-map.md). Note `proof_mode`: a `runtime`
class cannot be closed from the artifact, and a `static` class can never be
device-deferred — a missing device does not excuse the manifest.

RESILIENCE (root/jailbreak/anti-debug/pinning enforcement) is inherently
runtime — presence is static, **defeat is dynamic**. Do not score a bypass you
have not run.

## Phase 7 — the client→API pivot (highest-value output)

The single most valuable deliverable: an endpoint/param/auth-scheme inventory
mined from the dumped client, routed to the API skills. Client-visible authz
checks are **server-side hypotheses to confirm**, never findings on their own.

```bash
# harvest endpoints + params + auth scheme from every decompiled surface
grep -rhoE 'https?://[A-Za-z0-9._~:/?#@!$&()*+,;=%-]+' out/ decompiled.js smali/ \
  | sort -u > endpoints.txt
grep -rhnEi 'authorization|bearer|x-api-key|hmac|/v[0-9]+/|\{id\}|user_id|account' out/ \
  | sort -u > auth_and_idor_surface.txt
```

Route each class:
- Object/field-level access on `{id}`/`user_id` → BOLA/BFLA →
  [`../../api-security/reference/scenarios/rest/owasp-bola-bopla.md`](../../api-security/reference/scenarios/rest/owasp-bola-bopla.md).
- Client sends fields the UI never exposes (role/isAdmin/price) → mass assignment →
  [`../../api-security/reference/scenarios/rest/mass-assignment.md`](../../api-security/reference/scenarios/rest/mass-assignment.md).
- Encrypted request envelopes (KEY/IV/SALT/SIGNATURE) → reverse the crypto in the
  framework recipe, then replay against the live API.

A client-side IDOR (predictable id in the request) is proof of *intent*, not of
*vulnerability* — confirm the server does not enforce ownership before scoring.

## Dynamic phase — mobile delta only

Frida primitives (spawn/attach, `Interceptor`, `Stalker`, `Java.perform`, iOS
ObjC hooks) are **not re-taught here** →
[`../../reverse-engineering/reference/scenarios/dynamic-analysis/frida-hooking.md`](../../reverse-engineering/reference/scenarios/dynamic-analysis/frida-hooking.md).
Mobile-specific bring-up and the hook targets live in
[`android-dynamic-analysis.md`](android-dynamic-analysis.md) and [`ios-dynamic-analysis.md`](ios-dynamic-analysis.md) (frida-server push,
`objection`, MITM proxy + CA install, pinning/root-detection bypass). For native
syscall/library tracing use [`../../reverse-engineering/reference/scenarios/dynamic-analysis/ltrace-strace.md`](../../reverse-engineering/reference/scenarios/dynamic-analysis/ltrace-strace.md);
for stripped/packed `.so` internals, [`../../reverse-engineering/reference/scenarios/static-analysis/elf-analysis.md`](../../reverse-engineering/reference/scenarios/static-analysis/elf-analysis.md) and
[`../../reverse-engineering/reference/scenarios/obfuscation/packed-binaries.md`](../../reverse-engineering/reference/scenarios/obfuscation/packed-binaries.md).

## Anti-Patterns

- Shipping the MobSF/automated report as the finding set — it is a triage seed.
- Analyzing an artifact before recording its sha256 + version (broken evidence chain).
- Skipping DYNAMIC for pinning/root/Keystore claims — statically "present" ≠ enforced.
- Scoring a client-side IDOR/authz check without confirming server-side behavior.
- Emitting a finding with no MASVS control id + MASTG-TEST id — it won't map in the report.
- Re-implementing Frida/ELF/IL2CPP primitives here instead of cross-linking them.

## Cross-references

- Framework recipes: [`flutter-aot-reversing.md`](flutter-aot-reversing.md) · [`scenarios/android/react-native-hermes.md`](scenarios/android/react-native-hermes.md) ·
  [`scenarios/android/native-lib-host-extraction.md`](scenarios/android/native-lib-host-extraction.md).
- Platform phases: [`android-static-analysis.md`](android-static-analysis.md) · [`android-dynamic-analysis.md`](android-dynamic-analysis.md) ·
  [`ios-static-analysis.md`](ios-static-analysis.md) · [`ios-dynamic-analysis.md`](ios-dynamic-analysis.md) · [`privacy-testing.md`](privacy-testing.md).
- RE primitives: [`../../reverse-engineering/reference/scenarios/dynamic-analysis/frida-hooking.md`](../../reverse-engineering/reference/scenarios/dynamic-analysis/frida-hooking.md) ·
  [`../../reverse-engineering/reference/scenarios/static-analysis/elf-analysis.md`](../../reverse-engineering/reference/scenarios/static-analysis/elf-analysis.md) ·
  [`../../reverse-engineering/reference/scenarios/static-analysis/unity-il2cpp-recipe.md`](../../reverse-engineering/reference/scenarios/static-analysis/unity-il2cpp-recipe.md).
- Backend pivot: [`../../api-security/reference/scenarios/rest/owasp-bola-bopla.md`](../../api-security/reference/scenarios/rest/owasp-bola-bopla.md) ·
  [`../../api-security/reference/scenarios/rest/mass-assignment.md`](../../api-security/reference/scenarios/rest/mass-assignment.md).
- Hand-off (deferred, do not restate): RoE/preflight →
  [`../../coordination/reference/preflight-checklist.md`](../../coordination/reference/preflight-checklist.md); validation →
  [`../../coordination/reference/VALIDATION.md`](../../coordination/reference/VALIDATION.md); severity/report →
  [`../../transilience-report-style/SKILL.md`](../../transilience-report-style/SKILL.md).
