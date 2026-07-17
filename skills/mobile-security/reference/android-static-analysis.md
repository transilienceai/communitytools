# Android — Static Analysis (SAST) & Stock-App Attack Surface

Stock-Android (Kotlin/Java + native) SAST methodology. Framework-specific paths live in scenarios: Flutter → [flutter-aot-reversing.md](flutter-aot-reversing.md); RN/Hermes → [scenarios/android/react-native-hermes.md](scenarios/android/react-native-hermes.md); custom `.so` → [scenarios/android/native-lib-host-extraction.md](scenarios/android/native-lib-host-extraction.md). Scoping/RoE, scoring, and reporting are NOT here — see [../../coordination/reference/preflight-checklist.md](../../coordination/reference/preflight-checklist.md), [../../coordination/reference/VALIDATION.md](../../coordination/reference/VALIDATION.md), [../../transilience-report-style/SKILL.md](../../transilience-report-style/SKILL.md).

## When to use

- You have an APK/AAB and want the full stock-Android finding pass before any device work.
- The app is plain Kotlin/Java (dex is the logic, not a Hermes/Dart/IL2CPP wrapper — else route to the scenario).
- Static identifies the surface; runtime *confirmation* (drozer/adb/Frida) → [android-dynamic-analysis.md](android-dynamic-analysis.md).

## 1. Automated baseline FIRST (seeds the manual pass, never replaces it)

Run these to fingerprint and mass-triage, then read the dumped code by hand — automation misses reachability and business logic.

```bash
apkid -r app.apk                       # packer/obfuscator/anti-analysis fingerprint (pip install apkid)
# → packed/DexGuard/obfuscated? unpack first: ../../reverse-engineering/reference/scenarios/obfuscation/packed-binaries.md
docker run --rm -it -p 8000:8000 opensecurity/mobile-security-framework-mobsf:latest  # MobSF: manifest/perm/cert/secret/CVSS + CycloneDX SBOM
jadx -d jadx_out app.apk               # decompile to Java (--deobf if names mangled)
apktool d -f -o apktool_out app.apk    # smali + decoded resources/manifest
apkleaks -f app.apk -o apkleaks.txt    # endpoints, S3, API-key regexes
mobsfscan jadx_out/sources             # Android SAST rules (pip install mobsfscan)
semgrep --config p/java --config p/kotlin jadx_out/sources
trufflehog filesystem jadx_out --only-verified ; gitleaks dir jadx_out   # secret breadth
```

`apkid` decides static-vs-unpack-first. `MobSF` CVSS/severity is a *starting hint*, not the final score (scoring lives in the coordination skill).

## 2. Manifest triage (MASVS-PLATFORM-1 / MASWE-0028)

```bash
aapt dump badging app.apk | grep -E 'launchable|permission'
aapt dump xmltree app.apk AndroidManifest.xml | grep -iE 'exported|permission|scheme|debuggable|allowBackup'
```

| Check | Flag when | ID |
|-------|-----------|----|
| `android:exported` component | reachable activity/service/receiver/provider w/ no `permission` | MASTG-TEST-0024 |
| Implicit-export default | `minSdkVersion<31` + intent-filter + no explicit `exported` → exported by default | MASWE-0028 |
| `protectionLevel` | custom perm is `normal`/`dangerous` where `signature` intended | MASVS-PLATFORM-1 |
| `android:debuggable="true"` | in a release build → `run-as` any user | MASWE-0069 |
| `android:allowBackup="true"` | no `dataExtractionRules`/`fullBackupContent` → `adb backup` exfil | MASVS-STORAGE-2 |
| `usesCleartextTraffic="true"` | or absent NSC on `targetSdk<28` | MASVS-NETWORK-1 |

## 3. IPC / component exploitation surface (static ID; probe → dynamic)

- **ContentProvider SQLi** — `query()` concatenating `projection`/`selection`/`sortOrder`; `content://<auth>/…` reachable if provider exported or `grantUriPermissions`. MASWE-0107, MASTG-TEST-0025.
- **Provider path traversal** — `openFile()` resolving a caller path without canonicalize → `content://<auth>/../../databases/...`. CWE-22.
- **Mutable PendingIntent** — `FLAG_MUTABLE` (or pre-API-31 default) wrapping an *implicit* base intent; a receiver rewrites it to hit a private component with the app's identity. CWE-927 / MASWE-0117.
- **Intent redirection** — component forwards `getParcelableExtra("...")`/`getIntent()` straight into `startActivity`/`bindService`. CWE-940.
- **Deep links & App Links** — enumerate `<data android:scheme/host/pathPrefix>`; custom schemes are collidable (any app registers them). Verify App Links: `autoVerify="true"` **and** a served `https://<host>/.well-known/assetlinks.json` matching the signing cert; a broken assetlinks silently downgrades to a pickable chooser.

```bash
grep -rEn '\.query\(|rawQuery\(|openFile\(|getParcelableExtra|startActivity\(getIntent' jadx_out/sources
grep -rE 'PendingIntent\.(getActivity|getBroadcast|getService)' jadx_out/sources   # inspect FLAG_MUTABLE/no FLAG_IMMUTABLE
```

## 4. Native WebView (MASVS-PLATFORM-2 / MASWE-0069)

```bash
grep -rEn 'addJavascriptInterface|@JavascriptInterface|setJavaScriptEnabled|setAllowFileAccess|shouldOverrideUrlLoading|loadUrl' jadx_out/sources
```

- **`addJavascriptInterface`** exposed to remote/untrusted content → reflection RCE (`getClass().getClassLoader()…`). CWE-749, MASTG-TEST-0032.
- **`setAllowFileAccessFromFileURLs` / `setAllowUniversalAccessFromFileURLs` = true** → `file://` UXSS / local-file exfil.
- **`shouldOverrideUrlLoading`** parsing `intent:`/`javascript:`/deep-link schemes → intent redirection into the app.

## 5. Storage review (MASVS-STORAGE-1/2)

```bash
grep -rEn 'MODE_WORLD_READABLE|MODE_WORLD_WRITEABLE|getExternalStorage|Log\.(d|v|i|w|e)\(|EncryptedSharedPreferences' jadx_out/sources
```

- Plaintext `SharedPreferences`/SQLite holding tokens/PII; secrets in `Log.*`; world-readable or external-storage writes of sensitive data. MASWE-0006/0009.
- **Android Keystore** — inspect `KeyGenParameterSpec`: prefer `setIsStrongBoxBacked(true)`, `setUserAuthenticationRequired(true)`, `setInvalidatedByBiometricEnrollment(true)`, and key attestation. At runtime `KeyInfo.isInsideSecureHardware()` proves hardware backing; a software-only key or `setUserAuthenticationRequired(false)` on a high-value key is the finding. MASVS-CRYPTO-2, MASTG-TEST-0208.

## 6. Crypto-primitive weakness enumeration (a FINDING pass)

This is a *flag-the-weakness* sweep — do not reverse the whole envelope here (that's the Flutter/RN scenarios).

```bash
grep -rEn 'Cipher\.getInstance|MessageDigest\.getInstance|KeyGenerator|SecretKeySpec|IvParameterSpec|new Random\(|SecureRandom' jadx_out/sources
```

| Pattern | Finding | ID |
|---------|---------|----|
| `MD5`/`SHA-1` for integrity/signing | broken hash | MASWE-0021 |
| `DES`/`DESede`/`RC4`, or `AES/ECB` | weak/leaky cipher | MASWE-0020 |
| `AES/CBC` with no MAC/GCM | malleable, padding-oracle | MASVS-CRYPTO-1 |
| hardcoded `SecretKeySpec(bytes,…)` | static key in APK | MASWE-0014 |
| same buffer → key and `IvParameterSpec` | key==IV | MASWE-0024 |
| `java.util.Random` for key/IV/nonce/token | predictable → use `SecureRandom` | MASWE-0022 |

## 7. network_security_config parse (MASVS-NETWORK-2, MASTG-TEST-0067)

```bash
cat apktool_out/res/xml/network_security_config.xml   # path per <application android:networkSecurityConfig>
```

Flag: `<trust-anchors><certificates src="user"/>` (trusts user CAs → interceptable), `cleartextTrafficPermitted="true"` in base or any `<domain-config>`, base-config weaker than domain-config, and a `<debug-overrides>` block shipped in release (trusts debug CAs if `debuggable`). Absence of a `<pin-set>` on a security-sensitive app is a hardening gap, not a break.

## 8. APK signing (MASVS-RESILIENCE / integrity)

```bash
apksigner verify --verbose --print-certs app.apk
```

- **v1-only (JAR) signature + `minSdk<24`** → **Janus / CVE-2017-13156** (prepend a dex, signature still verifies). Require v2/v3 scheme.
- Debug cert (`CN=Android Debug`) or a known-leaked platform key in a production build.

## 9. Supply chain / SBOM (MASVS-CODE-3)

```bash
cdxgen -t android -o sbom.json app.apk      # or export MobSF's CycloneDX SBOM
# map every pinned version:
python3 tools/nvd-lookup.py CVE-YYYY-NNNNN
```

Recover pinned versions (okhttp UA constant, `*.properties`, `.so` build strings), cross-ref Google **Play SDK Index** (known-bad/outdated SDKs) and **OSV**. Report a CVE only with confirmed version *and* a reachable path — never presence alone.

## Anti-Patterns

- Shipping MobSF/semgrep output as the report — automation seeds the manual pass; reachability and business logic are yours.
- Calling a component "safe" because `exported` is unset on `minSdk<31` — an intent-filter still makes it exported by default.
- "No pinning" from an empty `<pin-set>` — pinning may be in an OkHttp `CertificatePinner`/TrustManager in code (grep it).
- Reporting a crypto string without the call site — `AES/ECB` in dead code or a vendored test vector is not a finding; confirm the data path.
- Guessing a hardware-backed key statically — only `KeyInfo.isInsideSecureHardware()` at runtime proves it → confirm in dynamic.

## Cross-references

- [methodology.md](methodology.md) — where this pass sits in the overall mobile flow.
- [android-dynamic-analysis.md](android-dynamic-analysis.md) — confirm exported-component/provider/WebView/Keystore findings on-device (drozer, adb, Frida bring-up).
- [ios-static-analysis.md](ios-static-analysis.md) / [privacy-testing.md](privacy-testing.md) — iOS analogue; data-collection/permission review.
- [scenarios/android/react-native-hermes.md](scenarios/android/react-native-hermes.md), [flutter-aot-reversing.md](flutter-aot-reversing.md), [scenarios/android/native-lib-host-extraction.md](scenarios/android/native-lib-host-extraction.md) — framework-specific logic paths.
- [../../reverse-engineering/reference/scenarios/static-analysis/elf-analysis.md](../../reverse-engineering/reference/scenarios/static-analysis/elf-analysis.md) — bundled `.so` disassembly; [../../reverse-engineering/reference/scenarios/static-analysis/unity-il2cpp-recipe.md](../../reverse-engineering/reference/scenarios/static-analysis/unity-il2cpp-recipe.md) — Unity IL2CPP dump.
- [../../reverse-engineering/reference/scenarios/obfuscation/packed-binaries.md](../../reverse-engineering/reference/scenarios/obfuscation/packed-binaries.md) — unpack when `apkid` flags a packer.
- [../../reverse-engineering/reference/scenarios/dynamic-analysis/frida-hooking.md](../../reverse-engineering/reference/scenarios/dynamic-analysis/frida-hooking.md) / [../../reverse-engineering/reference/scenarios/dynamic-analysis/ltrace-strace.md](../../reverse-engineering/reference/scenarios/dynamic-analysis/ltrace-strace.md) — runtime hook/trace primitives (do not re-teach; mobile bring-up in dynamic file).
- [../../api-security/reference/scenarios/rest/owasp-bola-bopla.md](../../api-security/reference/scenarios/rest/owasp-bola-bopla.md) / [../../api-security/reference/scenarios/rest/mass-assignment.md](../../api-security/reference/scenarios/rest/mass-assignment.md) — pivot recovered endpoints/params to server-side authz testing.
