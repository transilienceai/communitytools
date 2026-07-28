---
name: mobile-security
description: Mobile application security testing (Android + iOS) mapped to OWASP MASVS/MASTG — static reversing (Flutter AOT, Unity IL2CPP, React Native/Hermes, native ARM64, Mach-O/Swift), SAST (manifest/IPC, storage, crypto, signing), dynamic analysis (Frida/objection, TLS-pinning + root/jailbreak bypass, traffic interception), and privacy testing.
---

# Mobile Security

## Scope

End-to-end mobile application VAPT for **Android (APK/AAB)** and **iOS (IPA)**, aligned to the OWASP **MASVS v2.x** control groups and the **MASTG** testing process. Four complementary tiers:

1. **Static reverse engineering** of compiled artifacts — Dart AOT snapshots, Unity IL2CPP, React Native/Hermes bytecode, native ARM64 `.so`/Mach-O, smali. Recover secrets, endpoints, and the crypto contract without a device.
2. **SAST** — manifest / `Info.plist`, exported-component & IPC surface, WebView, local storage, cryptographic-primitive weakness, code-signing, and automated baseline (MobSF/apkid/apkleaks) → then manual deep-dive.
3. **Dynamic analysis (DAST)** — Frida/objection instrumentation, traffic interception, TLS-pinning bypass across stacks, Keychain/Keystore runtime dumps, IPC probing, and root/jailbreak/anti-tamper defeat for MAS-L2 / MASA scope.
4. **Privacy** — data-collection inventory, tracker/SDK enumeration, PII leakage, declared-vs-actual (Play Data Safety / Apple Privacy Manifest).

**Static dump first** (faster, no device); dynamic is a first-class phase whenever a control can only be proven at runtime (enforced pinning, Keystore-backed keys, root reaction, IPC guards). Cross-asset stitching, scoring, and reporting are owned by sibling skills — this skill produces MASVS/MASTG-tagged findings and hands them off.

## Coverage contract

In a coverage-mode engagement (`pentest-engagement` mobile mode) completion is **code-enforced, not narrative**. Two surfaces are gated, and both are mandatory:

| Surface | File | Classes |
|---|---|---|
| The app bundle | `recon/inventory/mobile-surface.json` | the 15 `MAS-*` MASVS classes |
| The backend recovered **from** the bundle | `<apex>-api/recon/inventory/surface.json` | the ordinary OWASP API/web classes |

The second row is where the material risk has historically been. A decompiled bundle hands you the full server contract, and that surface is not browser-reachable — so it is systematically under-tested by everyone, including the app's own developers. Recovering the endpoint inventory and driving it through the API classes is not an optional extra; a bundle that yields zero endpoints is treated as a **failed acquisition**.

Per-class detail: [`reference/masvs-class-map.md`](reference/masvs-class-map.md). Two rules worth internalising before you write a negative:

- **`proof_mode: runtime` cannot be closed statically.** Pinning and root detection are the classic traps: static analysis can prove a control is *inert* (a `CertificatePinner` built and never attached, a RootBeer that no DEX references) — raise that as a positive. It can never prove the control is *effective*; that needs a bypass attempt that failed, and a failed bypass is a legitimate, reportable result.
- **`proof_mode: static` can never be device-deferred.** No device does not excuse the manifest, the signature, the bundled dependencies, or the secrets in the artifact.

## When to use

- Target ships an **Android APK/AAB** or **iOS IPA** — extract and inspect before any runtime testing.
- Built with **Flutter** (`lib/arm64-v8a/libapp.so` / iOS `App.framework`), **Unity** (`libil2cpp.so` + `global-metadata.dat`), or **React Native + Hermes** (`libhermes.so` + `index.android.bundle`) — needs a runtime-aware decompiler, not just jadx.
- Stock Android/iOS app — you need the manifest/IPC/storage/crypto/signing attack surface (SAST) and, where a control is runtime-only, dynamic confirmation.
- App uses **encrypted API envelopes** (KEY/IV/SALT/SIGNATURE headers) and you need to reverse the crypto contract, then replay against the live API.
- **TLS pinning / root / jailbreak detection** blocks testing — bypass it dynamically (or defeat it statically) and demonstrate the protected flow.
- You suspect **IDOR / mass assignment / business-logic** flaws easier to find in the dumped client, then confirmed server-side.
- You need a **MASVS-PRIVACY** pass (trackers, over-collection, PII leakage, declared-vs-actual).

## Methodology

Start at **[reference/methodology.md](reference/methodology.md)** — the phase backbone (ACQUIRE → TRIAGE → STATIC → DYNAMIC → NETWORK → STORAGE → PLATFORM/IPC → BACKEND PIVOT → REPORT), app acquisition + evidence integrity, the MASVS→file coverage map, finding-tagging convention, and the client→API pivot. It routes to every reference below. Do preflight ([../coordination/reference/preflight-checklist.md](../coordination/reference/preflight-checklist.md)) first.

## References

**Cross-cutting**
- [reference/methodology.md](reference/methodology.md) — the hub: phases, acquisition (adb pull / bundletool / ipatool), MASVS/MASTG tagging, backend pivot.
- [reference/privacy-testing.md](reference/privacy-testing.md) — MASVS-PRIVACY for both platforms: trackers/SDKs, PII channels, declared-vs-actual.

**Android**
- [reference/android-static-analysis.md](reference/android-static-analysis.md) — SAST: MobSF/apkid/apkleaks baseline, manifest & exported-component/IPC, ContentProvider SQLi/traversal, PendingIntent, deep links, native WebView RCE, storage & Keystore review, crypto-primitive weakness pass, NSC, apksigner/Janus, SBOM.
- [reference/android-dynamic-analysis.md](reference/android-dynamic-analysis.md) — DAST: device/Magisk/Zygisk setup, frida-server bring-up, objection recipes, interception + Android-7 user-CA workarounds, cross-stack pinning bypass (OkHttp/BoringSSL-Flutter/RN), drozer IPC, runtime storage, RESILIENCE active bypass + repack/resign.

**iOS**
- [reference/ios-static-analysis.md](reference/ios-static-analysis.md) — SAST: IPA acquisition + FairPlay decrypt (cryptid), Mach-O/ObjC/Swift RE, ATS, entitlements/provisioning, binary hardening, Keychain accessibility + Data Protection, URL schemes/Universal Links, WKWebView, pasteboard/snapshot, MobSF/SBOM.
- [reference/ios-dynamic-analysis.md](reference/ios-dynamic-analysis.md) — DAST: jailbroken vs non-JB (objection patchipa / frida-gadget) bring-up, objection/Frida on iOS, SSL Kill Switch / SecTrust pinning bypass, Keychain dump, LAContext biometric bypass, jailbreak/anti-debug defeat, method tracing.

**Framework-specific reverse engineering**
- [reference/flutter-aot-reversing.md](reference/flutter-aot-reversing.md) — Flutter/Dart AOT with blutter; HTTP crypto-envelope patterns (fast_rsa OAEP-SHA256 + AES-256-CBC) and the weaknesses to report.
- [reference/scenarios/android/react-native-hermes.md](reference/scenarios/android/react-native-hermes.md) — RN+Hermes: HBC-version check, decompile `index.android.bundle` with hermes-dec, BuildConfig secret fast-path, RN-specific MASVS surface.
- [reference/scenarios/android/native-lib-host-extraction.md](reference/scenarios/android/native-lib-host-extraction.md) — host-side `dlopen` of an Android `.so` with a Bionic→glibc forwarder + `strcmp`/`memcmp` interceptor (no Frida/emulator).

**Cross-skill (reused capabilities — cross-linked, not duplicated)**
- [../reverse-engineering/reference/scenarios/static-analysis/unity-il2cpp-recipe.md](../reverse-engineering/reference/scenarios/static-analysis/unity-il2cpp-recipe.md) — Unity `libil2cpp.so` + `global-metadata.dat` dump (Il2CppDumper/Il2CppInspector).
- [../reverse-engineering/reference/scenarios/dynamic-analysis/frida-hooking.md](../reverse-engineering/reference/scenarios/dynamic-analysis/frida-hooking.md) — Frida hooking primitives (spawn/attach, Interceptor, Stalker, `Java.perform`, ObjC hooks) used by both dynamic files.
- [../reverse-engineering/reference/scenarios/obfuscation/packed-binaries.md](../reverse-engineering/reference/scenarios/obfuscation/packed-binaries.md) — packer / anti-analysis unpacking for obfuscated APKs/`.so`.
- [../reverse-engineering/reference/scenarios/obfuscation/hash-dispatcher-chain.md](../reverse-engineering/reference/scenarios/obfuscation/hash-dispatcher-chain.md) — Z3 over polynomial-hash dispatcher chains in a native `.so`.
- [../api-security/reference/scenarios/rest/owasp-bola-bopla.md](../api-security/reference/scenarios/rest/owasp-bola-bopla.md) · [../api-security/reference/scenarios/rest/mass-assignment.md](../api-security/reference/scenarios/rest/mass-assignment.md) — the client→API pivot for endpoints/IDOR recovered from the client.

**Deterministic control-wiring detector**
- [`../../tools/apk_control_wiring.py`](../../tools/apk_control_wiring.py) — static cross-reference over a decompiled Android tree that distinguishes a REAL applied control from an ORPHANED one: RootBeer/SafetyNet/Play-Integrity **shipped-but-unwired** (referenced but the result gates nothing), `CertificatePinner` **built-but-not-attached** to an OkHttpClient, hardcoded AES/DES key literals + their invoke-sites, and bundled-but-never-loaded `.so`. Run it in the STATIC phase BEFORE authoring remediation verdicts — a naive re-test that only greps for the control's presence wrongly reports an inert control "fixed" (a recurring mobile re-test crux).

## Anti-patterns

- Reaching for Frida/emulator before the static dump exists — static-first is faster and needs no device. But do not treat dynamic as out of scope: pinning enforcement, Keystore binding, root reaction, and IPC reachability are runtime-only.
- Reporting a control as *present* (root/pinning/tamper detection) without an active bypass attempt — MAS-L2 / MASA require you defeat it or prove you can't.
- Concluding "no pinning" from an empty `network_security_config.xml`, or "no secrets" from a `cryptid 1` iOS binary — check the JS/native pin layers, and decrypt the IPA first.
- Stopping at a client-side IDOR — it is a server-side hypothesis; confirm via the api-security pivot.
- Reporting a CVE from a library's mere presence — confirm the exact version *and* a reachable code path.
