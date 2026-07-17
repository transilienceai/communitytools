# iOS — Static Analysis (SAST) of the IPA & Mach-O

Static-first inspection of an iOS app: acquire the IPA, defeat FairPlay, then read the Mach-O, `Info.plist`, entitlements, and storage/IPC surface **before** touching a device. Runtime dumps (Keychain contents, pasteboard, live pinning) live in [ios-dynamic-analysis.md](ios-dynamic-analysis.md). RoE/preflight → [../../coordination/reference/preflight-checklist.md](../../coordination/reference/preflight-checklist.md).

## When to use

- Target ships an `.ipa` (or you can pull `.app` from a device) and you want the auth flow, endpoints, secrets, and crypto contract from the binary — not black-box guessing.
- Cross-platform-on-iOS: Flutter (`Frameworks/App.framework`), RN (`main.jsbundle`), Cordova (`www/`), Xamarin/MAUI (`.dll`) — fingerprint below, then hand off to the matching recipe.
- Dynamic testing blocked (no jailbreak yet) — static recovers most findings with zero runtime.

## BLOCKING prerequisite — acquisition + FairPlay decryption

App Store binaries are **FairPlay-encrypted**: `strings`, `class-dump`, and Ghidra see ciphertext until decrypted. This is the first gate. (MASVS-RESILIENCE-2; MASTG *Acquiring / Decrypting the App Binary*.)

```bash
# Acquire (choose one)
ipatool download -b com.example.app --purchase       # authed App Store pull
# or Apple Configurator: add app → ~/Library/.../Apps/*.ipa
unzip -o app.ipa -d app_ipa && ls app_ipa/Payload/*.app

# Encryption check — the load command that decides everything
otool -l app_ipa/Payload/*.app/<Executable> | grep -A4 LC_ENCRYPTION_INFO
#   cryptid 1  => App Store encrypted (class-dump/strings/Ghidra all break)
#   cryptid 0  => plaintext, proceed
```

If `cryptid == 1`, decrypt on a **jailbroken device or Corellium** (the decrypted pages only exist in RAM at runtime):

| Tool | Invocation | Notes |
|------|-----------|-------|
| **frida-ios-dump** | `python3 dump.py -o out.ipa com.example.app` | Frida-based; needs `frida-server` on device. git: `AloneMonkey/frida-ios-dump`. |
| **bagbak** | `bagbak com.example.app -o out` | Node/Frida; handles app-extensions + frameworks. |
| **flexdecrypt** | `flexdecrypt Bundle/<bin> > dec` | on-device Mach-O decrypt; per-binary. |

```bash
# Verify decryption succeeded before analysis:
otool -l out/Payload/*.app/<Executable> | grep -A4 LC_ENCRYPTION_INFO   # expect cryptid 0
```

Decrypt **every** Mach-O (main binary + each `Frameworks/*.framework/<bin>` + `PlugIns/*.appex`); extensions are independently encrypted.

## Mach-O / ObjC / Swift reverse engineering

General native-analysis mindset (imports, xrefs, disasm triage) is in [../../reverse-engineering/reference/scenarios/static-analysis/elf-analysis.md](../../reverse-engineering/reference/scenarios/static-analysis/elf-analysis.md); Mach-O differs — load commands not program headers, `LC_MAIN` entry, fat/universal slices, ObjC/Swift metadata sections.

```bash
lipo -info <bin> && lipo -thin arm64 <bin> -output bin.arm64   # split a fat binary
otool -hv bin.arm64            # header + flags (PIE, arch)
otool -l  bin.arm64            # all load commands (LC_RPATH, LC_LOAD_DYLIB, min-OS)
rabin2 -I bin.arm64            # radare2 one-shot: arch, pic, canary, crypto, nx, stripped
jtool2 -l bin.arm64           # jtool2 alternative to otool -l; --sig for code-sig blob

# ObjC/Swift interface recovery
class-dump -H -o hdr/ bin.arm64                     # ObjC @interface headers (ObjC-only)
dsdump --objc --swift bin.arm64 > hdr/dsdump.txt    # ObjC + Swift symbols/metadata (git: derekselander/dsdump)
xcrun swift-demangle '$s4MyApp...'                  # decode a Swift mangled symbol (ships with Xcode)
```

Load into **Ghidra** (ARM64 + Swift demangler, `Analysis → Demangler Swift`) or **Hopper**. For symbols that resolve into system frameworks, extract the shared cache:

```bash
ipsw dyld extract dyld_shared_cache_arm64e Foundation          # blacktop/ipsw (current)
dyld_shared_cache_util -extract ./out dyld_shared_cache_arm64e # older alt
```

## Info.plist — ATS (transport security)

```bash
plutil -p Payload/*.app/Info.plist | grep -A30 NSAppTransportSecurity
```

Flag, worst-first (MASVS-NETWORK-1; MASTG-TEST-0067):

- `NSAllowsArbitraryLoads = true` — ATS off app-wide (cleartext everywhere). `...ForMedia` / `...InWebContent` are narrower but still weakening.
- Per-domain `NSExceptionDomains` → `NSExceptionAllowsInsecureHTTPLoads = true` (cleartext to that host), `NSExceptionMinimumTLSVersion = TLSv1.0/1.1` (downgrade), `NSExceptionRequiresForwardSecrecy = false`.

## Entitlements + provisioning

```bash
codesign -d --entitlements :- Payload/*.app                     # entitlements XML (stdout)
security cms -D -i Payload/*.app/embedded.mobileprovision        # provisioning profile
```

Check: `get-task-allow = true` (**debuggable production build** — MASVS-RESILIENCE, MASTG-TEST-0089), over-broad `keychain-access-groups` (cross-app Keychain sharing), `com.apple.developer.associated-domains` (Universal Links / web-cred autofill), `aps-environment`, wildcard app-IDs.

## Binary hardening

```bash
rabin2 -I bin.arm64 | grep -E 'pic|canary|nx|crypto|stripped'   # pic=true => PIE/ASLR
otool -hv bin.arm64 | grep PIE                                  # PIE flag
otool -Iv bin.arm64 | grep -E '__stack_chk_(guard|fail)'        # stack canary present
otool -Iv bin.arm64 | grep -E '_objc_release|_objc_autorelease' # ARC in use
```

Missing PIE / canary / ARC = weakened binary protections (MASVS-RESILIENCE-1). Report as posture, not a standalone exploit.

## Local storage — static indicators

Runtime dump of actual on-disk data → [ios-dynamic-analysis.md](ios-dynamic-analysis.md). Statically, sandbox layout to reason about: `Documents/`, `Library/Preferences/*.plist` (NSUserDefaults), `Library/Application Support/*.sqlite` (Core Data), `Library/Caches/`, plus Realm files. NSUserDefaults and unencrypted SQLite/Realm are **not secure storage** (MASVS-STORAGE-1/2; MASTG-TEST-0052/0054). Grep decompiled/headers:

```bash
grep -rniE 'UserDefaults|writeToFile|NSData.*writeTo|Realm|sqlite3_open' hdr/
grep -rniE 'kSecAttrAccessible[A-Za-z]+' hdr/          # Keychain accessibility class
grep -rniE 'SecAccessControl|kSecAccessControl(Biometry|DevicePasscode|UserPresence)' hdr/
grep -rniE 'NSFileProtection(Complete|CompleteUntilFirstUserAuthentication|None)' hdr/
```

- **Keychain accessibility** (MASVS-STORAGE-2, MASVS-CRYPTO-2): `WhenUnlocked` > `AfterFirstUnlock` > `Always`/`AlwaysThisDeviceOnly` (deprecated, weakest). `*ThisDeviceOnly` blocks backup exfil. Secrets without `SecAccessControl` biometry/passcode = accessible whenever the class allows.
- **NSFileProtection** (MASVS-STORAGE-2): `Complete` (locked-at-rest) > `CompleteUntilFirstUserAuthentication` (default) > `None` (readable off a stolen-but-unlocked or jailbroken device).

## URL schemes + Universal Links (MASVS-PLATFORM-1)

```bash
plutil -p Payload/*.app/Info.plist | grep -A6 CFBundleURLTypes   # custom scheme(s)
# Universal Links: entitlement + the server file
curl -s https://example.com/.well-known/apple-app-site-association | plutil -p -
```

Custom schemes are **squattable** (any app can register `myapp://`) — never trust them for auth/secrets. Audit `application(_:open:options:)` and `continueUserActivity:` handlers for unvalidated deep-link params driving navigation, WebView loads, or trust decisions (MASTG-TEST-0075). Grep headers for `openURL`, `continueUserActivity`, `restorationHandler`.

## WebViews (MASVS-PLATFORM-2)

```bash
grep -rniE 'UIWebView|WKWebView|WKUserContentController|addScriptMessageHandler' hdr/
grep -rniE 'allowFileAccessFromFileURLs|allowUniversalAccessFromFileURLs|loadFileURL|allowingReadAccessToURL' hdr/
```

- **UIWebView** is deprecated/unpatched — flag any occurrence.
- `allowUniversalAccessFromFileURLs` / `allowFileAccessFromFileURLs = true` on a `file://` load = local-file exfil / same-origin bypass. Confirm `loadFileURL(_:allowingReadAccessToURL:)` scopes read access tightly.
- Every `WKScriptMessageHandler` (`addScriptMessageHandler`) is a JS→native bridge — enumerate the message names and what native side-effects they trigger (MASTG-TEST-0071).

## Pasteboard, backgrounding, secure entry

- `UIPasteboard.general` writes of secrets → globally readable (systemwide pasteboard); flag near token/PAN/OTP. (MASVS-STORAGE-1)
- No blur/overlay in `applicationDidEnterBackground` ⇒ app-switcher snapshot leaks the last screen (MASVS-STORAGE-2, MASTG-TEST-0053) — check for a `sceneWillResignActive` masking view.
- Secret text fields must set `isSecureTextEntry = true`; grep for password/PIN/OTP fields missing it.

## Automated baseline + SBOM

```bash
# MobSF static scan — baseline every IPA, then verify its findings by hand
docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf:latest
# upload the .ipa via the web UI or REST /api/v1/upload+scan

# Embedded framework SBOM (version → CVE mapping via tools/nvd-lookup.py)
ls -1 Payload/*.app/Frameworks/*.framework | sed 's#.*/##'
for p in Payload/*.app/Frameworks/*.framework/Info.plist; do
  plutil -extract CFBundleShortVersionString raw "$p"; done
```

Treat MobSF as a lead generator, not ground truth — it over- and under-reports; confirm each item against the binary. Validation discipline → [../../coordination/reference/VALIDATION.md](../../coordination/reference/VALIDATION.md).

## Cross-platform-on-iOS fingerprint & handoff

| Runtime | On-disk tell | Where the logic is → recipe |
|---------|--------------|------------------------------|
| **Flutter** | `Frameworks/App.framework/App` + `Flutter.framework/Flutter` | Dart AOT snapshot — [flutter-aot-reversing.md](flutter-aot-reversing.md); blutter needs the Flutter engine binary (`Flutter.framework/Flutter`) alongside `App` |
| **React Native** | `main.jsbundle` (+ `hermes.framework` if Hermes) | JS/Hermes bytecode — [scenarios/android/react-native-hermes.md](scenarios/android/react-native-hermes.md) |
| **Cordova/Ionic** | `www/`, `config.xml` | plain JS/HTML in `www/` — read directly |
| **Xamarin/MAUI** | `*.dll`, `*.aotdata`, `libmonosgen` | .NET assemblies — decompile with ilspycmd/dnSpy |
| **Custom native `.dylib`** | non-standard `Frameworks/*.dylib` | native ARM64 — [scenarios/android/native-lib-host-extraction.md](scenarios/android/native-lib-host-extraction.md) mindset, Mach-O tooling above |

## Anti-Patterns

- Running `class-dump`/`strings`/Ghidra on a `cryptid 1` binary and reporting "no secrets found" — you read ciphertext. Decrypt first, always re-check `cryptid == 0`.
- Decrypting only the main executable and skipping `Frameworks/*` and `PlugIns/*.appex` — each is separately encrypted and often holds the real logic.
- Concluding "no cleartext" from ATS alone — a per-domain `NSExceptionAllowsInsecureHTTPLoads` or a `TLSv1.0` floor reopens it; and pinning is orthogonal (checked at runtime).
- Trusting a custom URL scheme as an identity/authorization channel — schemes are squattable; Universal Links (with a served AASA) are the stronger primitive.
- Treating MobSF output as final — it is a baseline; every finding needs binary/plist confirmation before it ships.
- Reaching for Frida before the static pass — see the primitives (spawn/attach, `Interceptor`, ObjC hooks) in [../../reverse-engineering/reference/scenarios/dynamic-analysis/frida-hooking.md](../../reverse-engineering/reference/scenarios/dynamic-analysis/frida-hooking.md) once static is exhausted, not before.

## Cross-references

- [methodology.md](methodology.md) — where iOS SAST sits in the overall mobile workflow.
- [ios-dynamic-analysis.md](ios-dynamic-analysis.md) — jailbreak bring-up, runtime Keychain/pasteboard/storage dumps, live ATS/pinning bypass, ObjC method hooking.
- [flutter-aot-reversing.md](flutter-aot-reversing.md) · [scenarios/android/react-native-hermes.md](scenarios/android/react-native-hermes.md) · [scenarios/android/native-lib-host-extraction.md](scenarios/android/native-lib-host-extraction.md) — cross-platform runtimes shipped inside the IPA.
- [../../reverse-engineering/reference/scenarios/static-analysis/elf-analysis.md](../../reverse-engineering/reference/scenarios/static-analysis/elf-analysis.md) — native static-analysis mindset (Mach-O deltas noted above).
- [../../reverse-engineering/reference/scenarios/dynamic-analysis/frida-hooking.md](../../reverse-engineering/reference/scenarios/dynamic-analysis/frida-hooking.md) · [../../reverse-engineering/reference/scenarios/dynamic-analysis/ltrace-strace.md](../../reverse-engineering/reference/scenarios/dynamic-analysis/ltrace-strace.md) — instrumentation primitives.
- API pivot once you recover endpoints/params from the binary: [../../api-security/reference/scenarios/rest/owasp-bola-bopla.md](../../api-security/reference/scenarios/rest/owasp-bola-bopla.md) · [../../api-security/reference/scenarios/rest/mass-assignment.md](../../api-security/reference/scenarios/rest/mass-assignment.md).
- [privacy-testing.md](privacy-testing.md) — ATS/tracking/data-collection privacy angle.
