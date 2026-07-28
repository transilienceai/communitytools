# MASVS coverage-class map

The 15 `MAS-*` classes in [`coverage-matrix.json`](../../coordination/reference/coverage-matrix.json) are the completion contract for a mobile app bundle. This file is each class's technique reference: what closes the cell, what the negative has to look like, and which file in this skill carries the detail.

**Read the scope rule first.** These classes cover the **app artifact only**. The backend the app talks to is enumerated as a separate web asset (`recon/inventory/surface.json`) and owes the ordinary 24 web/API classes. A mobile engagement that stops at the bundle has tested the smaller half — recovering the endpoint inventory and driving it through the API classes is where the material findings have historically been.

**`proof_mode` is enforced, not advisory.** It describes what closing the cell **as a negative** costs: `static` (the artifact suffices), `runtime` (a running instance is required), `either` (both routes work). `coverage_gate.py` rejects a deferral whose `blocked_on` is `"device"` on any cell that is not `runtime` — "no device was available" can never excuse work the static route could still have done. A genuine `runtime` cell blocked by a missing device defers honestly (`deferral_reason` + an on-disk `client_input_request`), never a static grep dressed up as a negative. Deferrals for other blockers are unaffected.

**The general rule for a negative.** Every MAS class is `negative_kind: active_probe`, so `covered_negative` requires a non-agent corroborator — a `tools/NNN_*.md` whose `Experiment: E-NNN` header cites raw tool output, or a `corroborator` file path that exists. "I looked and it seemed fine" is not a negative.

---

## Unit-scope classes

### MAS-STORAGE-LOCAL
*Sensitive data in local storage.* One cell per `type: storage` unit. `runtime`: the negative is a claim about what the store actually holds. Close it by dumping the store and showing what is in it — `adb pull` / `objection android sqlite`, or the iOS container and Keychain. A negative needs the store's actual contents, not the absence of a grep hit.
→ [`android-static-analysis.md`](android-static-analysis.md) §5, [`android-dynamic-analysis.md`](android-dynamic-analysis.md), [`ios-static-analysis.md`](ios-static-analysis.md) (Keychain accessibility), [`ios-dynamic-analysis.md`](ios-dynamic-analysis.md)

### MAS-CRYPTO-WEAK
*Weak primitive at a call-site.* One cell per `type: crypto-use` unit. ECB, a static IV, MD5/SHA-1 for anything security-bearing, a seeded `SecureRandom`. Static analysis is sufficient and authoritative here — the primitive is visible in the decompiled call.
→ [`android-static-analysis.md`](android-static-analysis.md) §6

### MAS-PLATFORM-IPC
*Exported component reachable by a third-party app.* One cell per `type: component` / `type: deeplink` unit. `runtime`: reachability from another app is the claim, so it needs an actual `am start` / drozer invocation or an iOS URL-scheme open. A manifest read tells you the attack surface, not whether it is exploitable. Use `equiv_group` for near-identical activities so one real probe credits the family.
→ [`android-static-analysis.md`](android-static-analysis.md) §2-3, [`android-dynamic-analysis.md`](android-dynamic-analysis.md) (drozer), [`ios-static-analysis.md`](ios-static-analysis.md) (URL schemes)

### MAS-PLATFORM-WEBVIEW
*WebView misconfiguration.* One cell per `type: webview` unit. JS bridges, `allowFileAccess`, `allowUniversalAccessFromFileURLs`, mixed content, and whether any server- or notification-supplied URL can reach the view.
→ [`android-static-analysis.md`](android-static-analysis.md) §4, [`ios-static-analysis.md`](ios-static-analysis.md) (WebViews)

---

## Asset-scope classes

Each applies to **every** app — there is no flag that turns one off. An app that genuinely lacks the feature closes the cell as a corroborated negative naming what was checked and why it is absent.

### MAS-STORAGE-LOGS
*Leakage to logs, backups, crash/analytics sinks.* `runtime`: capture `logcat` / the iOS log stream through a real session, and check `allowBackup` / iCloud exclusion behaviour by actually taking a backup.
→ [`android-static-analysis.md`](android-static-analysis.md) §5, [`android-dynamic-analysis.md`](android-dynamic-analysis.md)

### MAS-CRYPTO-KEYMGMT
*Key management.* Hardcoded keys, and whether key material is bound to the Keystore/Keychain or merely stored beside the data it protects. A recovered key that decrypts real traffic is the strongest form of this finding.
→ [`android-static-analysis.md`](android-static-analysis.md) §5-6, [`ios-static-analysis.md`](ios-static-analysis.md)

### MAS-AUTH-LOCAL
*Biometric/PIN bypass and server-binding.* `runtime`: the question is whether defeating the local gate yields access, which only a hooked run answers. An app with no local authenticator closes as a negative that says so.
→ [`ios-dynamic-analysis.md`](ios-dynamic-analysis.md) (biometric bypass), [`android-dynamic-analysis.md`](android-dynamic-analysis.md)

### MAS-NETWORK-CLEARTEXT
*Cleartext permitted.* `static`: `usesCleartextTraffic`, the network-security-config XML, and iOS ATS exceptions are declarations in the artifact. Record the parsed config, not a claim about it.
→ [`android-static-analysis.md`](android-static-analysis.md) §7, [`ios-static-analysis.md`](ios-static-analysis.md) (ATS)

### MAS-NETWORK-PINNING
*Pinning absent, inert, or bypassable.* `runtime`, and this is the class most often got wrong. `tools/apk_control_wiring.py` can prove statically that a `CertificatePinner` is **built and never attached** (`pinning_present_but_inert`) — that is a positive finding and may be raised from static evidence. The **negative** ("pinning is enforced") is a runtime claim and requires an actual interception attempt that failed. Never infer enforcement from the presence of pinning code.
→ [`android-dynamic-analysis.md`](android-dynamic-analysis.md) (cross-stack pinning bypass), [`ios-dynamic-analysis.md`](ios-dynamic-analysis.md)

### MAS-PLATFORM-SCREEN
*UI-channel leakage.* `runtime`: FLAG_SECURE behaviour, the task-switcher snapshot, pasteboard contents, keyboard cache. All of these are observed on a device, not read from a manifest.
→ [`ios-dynamic-analysis.md`](ios-dynamic-analysis.md) (pasteboard/snapshot), [`android-dynamic-analysis.md`](android-dynamic-analysis.md)

### MAS-CODE-DEPENDENCY
*Vulnerable bundled components.* `static`: build the SBOM, screen it for CVEs, and check reachability before scoring — a vulnerable library that is bundled but never loaded is a different finding from one on a live path. `apk_control_wiring.py` distinguishes bundled from loaded native libraries.
→ [`android-static-analysis.md`](android-static-analysis.md) §9, [`ios-static-analysis.md`](ios-static-analysis.md) (SBOM)

### MAS-CODE-SECRETS
*Secrets recoverable from the artifact.* `static`: strings, resources, `BuildConfig`, the JS/AOT bundle, native `.so` data. A live credential found here is scored on what it unlocks, so validate it against the service before assigning severity — and note that a decompiled bundle is also where the backend endpoint inventory comes from.
→ [`react-native-hermes.md`](scenarios/android/react-native-hermes.md), [`flutter-aot-reversing.md`](flutter-aot-reversing.md), [`native-lib-host-extraction.md`](scenarios/android/native-lib-host-extraction.md), [`methodology.md`](methodology.md) (client→API pivot)

### MAS-RESILIENCE-ROOT
*Root/jailbreak and anti-debug.* `runtime`. As with pinning: `apk_control_wiring.py` can prove a detector is **shipped but unwired** (`shipped_but_unwired`) — a positive from static evidence. The negative ("the gate is effective") requires a bypass attempt that failed, and an attempt that failed is a legitimate, reportable outcome. Do not score a bypass you did not run.
→ [`android-dynamic-analysis.md`](android-dynamic-analysis.md) (RESILIENCE active bypass), [`ios-dynamic-analysis.md`](ios-dynamic-analysis.md) (jailbreak/anti-debug defeat)

### MAS-RESILIENCE-INTEGRITY
*Signing and repackaging.* `static`: `apksigner verify -v` for the scheme set and the signer identity (a release artifact carrying `CN=Android Debug` is a finding), Janus applicability, and whether repack+resign is accepted by the backend.
→ [`android-static-analysis.md`](android-static-analysis.md) §8, [`ios-static-analysis.md`](ios-static-analysis.md) (binary hardening, entitlements)

### MAS-PRIVACY-DATA
*Declared-vs-actual collection.* Permission over-ask, tracker/SDK inventory, and what actually leaves the device versus what the store listing and privacy policy declare. `runtime`: the declaration half is static, but the load-bearing claim — what actually egresses — is not.
→ [`privacy-testing.md`](privacy-testing.md)

---

## Reading the surface file

Units come from `recon/inventory/mobile-surface.json` (`mobile-surface/v1`), written by `tools/mobile_surface_build.py`. Unit `type` implies its flag, so a `type: webview` unit enumerates `MAS-PLATFORM-WEBVIEW` even if the agent forgot the flag — the mapping only ever *adds* work. `address` is a report anchor and is never parsed, so an Android component name or a container path is safe to use verbatim.

Cross-references: [`methodology.md`](methodology.md) for the phase backbone and the client→API pivot; [`../../coordination/reference/coverage-matrix.md`](../../coordination/reference/coverage-matrix.md) for the gate semantics.
