# Mobile — React Native + Hermes (Android) Static Analysis

When an Android APK ships **React Native with the Hermes engine**, the application logic — auth, API endpoints, token storage, business rules, hardcoded secrets — lives in the **Hermes bytecode bundle** (`assets/index.android.bundle`), not in `classes*.dex`. The dex is the RN bridge + native-module wrapper. Decompile the bundle first; treat the dex as a secondary surface.

## When to use

- APK contains `lib/<abi>/libhermes.so` + `libreact_*.so` and `assets/index.android.bundle`.
- The bundle starts with the Hermes magic `c6 1f bc 03 c1 03 19 1f` (HBC) — compiled bytecode, needs a decompiler. (If it starts with `var __BUNDLE` / `(function`, it is plain JS — just read it.)
- You need to recover API base URLs, JWT/OAuth flow, secret material, or business logic that black-box API testing will not reveal.
- RN build with no Hermes lib (Metro JSC bundle) — same JS surface, take the plain-JS path.

## Fingerprint + bundle format

```bash
unzip -l app.apk | grep -E 'libhermes|libreact_|index\.android\.bundle'
unzip -j app.apk assets/index.android.bundle -d ./bundle
xxd -l 16 ./bundle/index.android.bundle
# c61fbc03 c103191f 60000000 ...
#  └ HBC magic ──────┘ └─ u32 LE bytecode version (0x60 = 96)
```

The HBC **version** (the `u32` after the 8-byte magic) sets tool compatibility — RN 0.73.x ⇒ HBC v96, older RN ⇒ lower (84/89/90). `strings libhermes.so | grep -i 'for RN'` confirms the React Native version.

## Decompilation toolchain

| Tool | Command | When | Notes |
|------|---------|------|-------|
| **hermes-dec** | `hbc-decompiler` / `hbc-disassembler` | primary | `pip3 install hermes-dec` (or `pip3 install git+https://github.com/P1sec/hermes-dec` if the PyPI name doesn't resolve). Version-flexible — decompiles **HBC v96** to readable pseudo-JS; disassembler emits `.hasm` with preserved function names. |
| **hbctool** | `hbctool disasm` / `asm` | patch/repack | Only when you must *modify + reassemble* the bundle. ⚠ Upstream (bongtrop) tops out around **HBC 84** — v89/v90/v96 asm/disasm need a maintained community fork; verify the installed build's supported versions before repacking a newer bundle. `hermes-dec` stays fine for read-only decompilation of v96. |
| **strings** | `strings -n 6` | fallback | The Hermes string table holds URLs/paths/keys/error messages; reassemble endpoints from it when a decompile is partial. |

```bash
pip3 install hermes-dec || pip3 install git+https://github.com/P1sec/hermes-dec
hbc-decompiler index.android.bundle decompiled.js     # pseudo-JS (primary)
hbc-disassembler index.android.bundle disasm.hasm     # cross-check / when decompile chokes
strings -n 6 index.android.bundle > bundle_strings.txt
# dex + manifest in parallel:
jadx -d jadx_out app.apk
apktool d -f -o apktool_out app.apk
```

The decompiler can emit a multi-million-line file — grep it, do not read top-to-bottom. Hermes packs string literals into one table, so URLs/paths appear as fragments; reassemble from `decompiled.js`, not raw `strings` alone.

## Secrets fast-path

RN tooling (`react-native-config` / Gradle `buildConfigField`) injects build-time config into the **app-package `BuildConfig.java`** — the single richest secret source, often richer than `strings.xml`.

```bash
# 1. canonical secret inventory (app package, NOT library BuildConfigs)
find jadx_out/sources -path '*<app/pkg/path>*/BuildConfig.java' -exec grep -nE 'public static final String' {} +
# 2. resource mirror
grep -nEi 'API_KEY|TOKEN|SECRET|COOKIE|PASSWORD|_KEY' apktool_out/res/values/strings.xml
# 3. cloud config (Firebase / Maps)
grep -rnE 'AIza[0-9A-Za-z_-]{35}|firebaseio\.com|appspot\.com|storage_bucket' apktool_out/res/
# 4. then the bundle
grep -nEi 'https?://|api[_-]?key|bearer |authorization|secret' decompiled.js | sort -u
```

Treat every recovered key as live until proven otherwise — build-time-injected backend tokens (platform-API JWTs, tenant tokens, cloud-service keys) are frequently long-lived and recoverable with no root.

## RN-specific attack surface (MASVS map)

- **STORAGE** — `AsyncStorage` writes plaintext to `/data/data/<pkg>/databases/RKStorage` (SQLite) or `files/`; `react-native-mmkv` (`libreactnativemmkv.so`) is also plaintext by default. Grep the bundle for `AsyncStorage.setItem` / `MMKV` near `token`/`refresh`/`session`. Flag tokens stored without Keystore/Keychain.
- **NETWORK** — check **two** pinning layers: `res/xml/network_security_config.xml` (`<pin-set>`, `cleartextTrafficPermitted`) **and** the JS layer (`react-native-ssl-pinning`, TrustKit, fetch SPKI pins in the bundle). An empty NSC does not imply "no pinning" — RN apps often pin in JS. Map staging↔prod endpoint bleed (prod hosts hardcoded in a staging build).
- **PLATFORM** — WebView config is set in JS: grep for `originWhitelist` (`['*']`), `allowFileAccess`, `allowingReadAccessToURL`, `mixedContentMode:'compatibility'`, `javaScriptEnabled`. In the manifest, map deep-link / OAuth-callback schemes and exported library receivers (`react-native-push-notification` registers receivers `exported=true` with no permission by default).
- **CODE / OTA** — **CodePush / App Center OTA**: when a `CodePushDeploymentKey` is present and no signing public key is configured (no `CodePushPublicKey` meta-data / Gradle key), anyone controlling the deployment key can push an arbitrary JS bundle that runs with full app privileges = RCE-equivalent in the sandbox. Verify both the deployment key and the absence of bundle signing.
- **CODE / CVE** — recover bundled versions for CVE mapping: okhttp from its UA constant (`strings classes*.dex | grep -o 'okhttp/[0-9.]*'`), RN from `libhermes.so`, native parsers (`libpdfium.so`, Fresco) from `.so` + `.properties`. Run `python3 tools/nvd-lookup.py <CVE-ID>` per hit. An app that renders **server-supplied PDFs/images** through an outdated native parser carries a reachable memory-corruption class.
- **AUTH** — client-side `jwt-decode` without signature verification is expected for display, but flag it where a claim drives a trust/authorization decision in JS. Confirm OAuth uses PKCE + `state`.
- **RESILIENCE** — presence of `JailMonkey` (root/jailbreak), `react-native-ssl-pinning`, `ScreenGuard` (screenshot block), or Play Integrity is statically evident; document presence/absence here. When RESILIENCE is in scope (MAS-L2 / MASA), inventory is not the finding — actively bypass each control and show the protected flow still runs, and confirm the backend actually verifies the Play Integrity verdict/nonce (client-only checks are bypassable regardless). See [android-dynamic-analysis.md](../../android-dynamic-analysis.md). (Pinning is MASVS-NETWORK-2, screenshot-block is MASVS-PLATFORM-3; JailMonkey/Play-Integrity are the true MASVS-RESILIENCE items.)

## Anti-Patterns

- Treating `classes*.dex` as the primary surface — it is the RN bridge/wrapper; the logic is in the Hermes bundle.
- Concluding "no certificate pinning" from an empty `network_security_config.xml` — check the JS layer too.
- Reaching for Frida / an emulator before decompiling the bundle — static recovery is faster and needs no device.
- Reporting a CVE from a library's mere presence — confirm the exact version *and* a reachable code path first.
- Grepping only the app-package name and missing secrets RN mirrors into `strings.xml` and the Firebase `google-services` resources.

## Cross-references

- [../../flutter-aot-reversing.md](../../flutter-aot-reversing.md) — the Flutter/Dart analogue (when `libapp.so` is present instead of Hermes).
- [native-lib-host-extraction.md](native-lib-host-extraction.md) — when business logic sits in a custom native `.so` beyond the standard RN set.
- [android-static-analysis.md](../../android-static-analysis.md) — stock-Android SAST around the RN app (manifest, exported components, storage, crypto, signing).
- [android-dynamic-analysis.md](../../android-dynamic-analysis.md) — interception + dual-layer pinning bypass (native + JS), runtime storage/secret dump, RASP bypass.
- [methodology.md](../../methodology.md) — phase flow and the client→API pivot for endpoints recovered from the bundle.
