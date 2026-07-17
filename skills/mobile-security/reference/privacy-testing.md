# Mobile — Privacy Testing (MASVS-PRIVACY, Android + iOS)

MASVS-PRIVACY (added to MASVS v2 in 2023, a baseline audit expectation by 2026) asks a different question than the rest of the standard: not "can an attacker reach the data" but "does the app collect, expose, and share *more* than it declares." Most of this work is **static and in-wheelhouse** — you already decompiled the artifact for the other reference files; here you inventory what it touches and **diff declared-vs-actual**. The divergence *is* the finding.

## When to use

- Scope calls for a privacy / data-protection review, or the client publishes a Play **Data Safety** label / Apple **Privacy Nutrition Label** you can hold the binary against.
- Regulated data (health, finance, children, location) and a GDPR / DPDP / CCPA posture question is in scope.
- You already have a decoded APK/IPA from `android-static-analysis.md` / `ios-static-analysis.md` and want the privacy pass "for free."

Scope, authorization, and RoE come from [`../../coordination/reference/preflight-checklist.md`](../../coordination/reference/preflight-checklist.md). Severity/scoring and the report live in [`../../transilience-report-style/SKILL.md`](../../transilience-report-style/SKILL.md) — do **not** score here.

## The four controls (what each maps to)

| Control | Plain meaning | Primary evidence source |
|---------|---------------|-------------------------|
| **MASVS-PRIVACY-1** | Data minimization — collect/access only what the feature needs | manifest permissions, purpose strings, required-reason APIs |
| **MASVS-PRIVACY-2** | Transparency — collection is disclosed & matches declared labels | Data Safety / Nutrition Label vs observed egress |
| **MASVS-PRIVACY-3** | User control — consent, opt-out, deletion actually work | trackers firing pre-consent; ATT/consent gating |
| **MASVS-PRIVACY-4** | Off-device resilience — no PII leaked via logs, IPC, clipboard, backups, 3rd-party SDKs | runtime capture + SDK inventory |

## Data-collection inventory

### Android — dangerous-permission over-ask (MASVS-PRIVACY-1)

```bash
# Declared permissions (apkanalyzer ships with Android SDK cmdline-tools):
apkanalyzer manifest permissions app.apk
aapt dump permissions app.apk           # fallback if apkanalyzer absent
```

Flag every **dangerous** / **special** permission with no matching feature in the decompiled code — the classic over-ask. Grep the dex for the *use*, not just the grant:

```bash
grep -rnE 'getLastKnownLocation|requestLocationUpdates|FusedLocation' jadx_out/   # LOCATION
grep -rnE 'getDeviceId|getImei|getSubscriberId|getSimSerial'          jadx_out/   # READ_PHONE_STATE
grep -rnE 'query\(.*ContactsContract|CallLog\.'                       jadx_out/   # CONTACTS/CALL_LOG
grep -rnE 'AdvertisingIdClient|com\.google\.android\.gms\.ads'        jadx_out/   # AD_ID (AAID)
```

`READ_PHONE_STATE`/`READ_PHONE_NUMBERS`, `ACCESS_BACKGROUND_LOCATION`, `QUERY_ALL_PACKAGES`, and `com.google.android.gms.permission.AD_ID` are the high-signal over-asks. A granted-but-unused permission is a MASVS-PRIVACY-1 gap.

### iOS — purpose strings + required-reason APIs (MASVS-PRIVACY-1/2)

```bash
plutil -p Payload/*.app/Info.plist | grep -iE 'UsageDescription'      # NS*UsageDescription
# Required-Reason API manifest (Apple-mandated since May 2024):
find Payload -name 'PrivacyInfo.xcprivacy' -exec plutil -p {} \;
```

Every accessed sensitive class needs an `NS*UsageDescription` purpose string; a missing or boilerplate one ("This app needs access") is a transparency defect. `PrivacyInfo.xcprivacy` must declare `NSPrivacyAccessedAPITypes` (file-timestamp, system-boot-time, disk-space, active-keyboard, `UserDefaults`) and `NSPrivacyTracking`. Cross-check the manifest against actual symbol use (`nm`/class-dump from [`ios-static-analysis.md`](ios-static-analysis.md)) — an **undeclared** required-reason API call is a reportable divergence.

## Tracker / ad / analytics SDK enumeration (MASVS-PRIVACY-4)

| Platform | Tool | Command |
|----------|------|---------|
| Android | **exodus-standalone** | `docker run --rm -v "$PWD":/mnt exodusprivacy/exodus-standalone /mnt/app.apk` |
| Android | **MobSF** trackers | upload APK to MobSF (Docker/REST API) → report's "Trackers" section (Exodus DB) |
| Android | apkid (packer/SDK) | `apkid app.apk` |
| iOS | embedded frameworks | `ls Payload/*.app/Frameworks/` + strings-grep below |

exodus matches class-name/URL signatures for 400+ trackers (Firebase Analytics, AppsFlyer, Adjust, Braze, Facebook SDK, session-replay like FullStory/Smartlook). For iOS there is no exodus equivalent — enumerate `.framework` bundles by hand:

```bash
ls -1 Payload/*.app/Frameworks/                       # AppsFlyerLib, FBSDKCoreKit, Sentry...
strings -a Payload/*.app/*  | grep -iE 'appsflyer|adjust|braze|amplitude|mixpanel|smartlook|fullstory|idfa|att'
```

Session-replay SDKs (screen recording of user sessions) and any tracker firing **before** a consent dialog are the headline privacy findings — flag AAID/IDFA reads, `ASIdentifierManager.advertisingIdentifier`, and ATT (`NSUserTrackingUsageDescription`) presence/absence.

## PII leakage channels (MASVS-PRIVACY-4, MASVS-STORAGE-2)

Static grep first, then confirm at runtime. Capture primitives come from the dynamic files — do not re-teach them here.

```bash
# Android runtime log leak (MASTG "Testing Logs"):
adb logcat -c && adb logcat | grep -iE 'token|password|jwt|email|pan|otp|lat=|lon='
# iOS unified log:
idevicesyslog -u <udid> | grep -iE 'token|password|email|otp'      # or: log stream --predicate ...
```

| Channel | Android probe | iOS probe | Notes |
|---------|---------------|-----------|-------|
| Logs | `adb logcat` grep | `idevicesyslog` / `log stream` | verbose analytics payloads leak PII to logcat |
| Clipboard | hook `ClipboardManager.setPrimaryClip` | hook `UIPasteboard.general` | auto-copied OTP/PAN readable by any app |
| Screenshot / backgrounding | absent `FLAG_SECURE`; check `/data/.../cache` | `Library/Caches/Snapshots/` PII | task-switcher thumbnail cache |
| Backups | `android:allowBackup="true"` in manifest | iTunes/iCloud backup class | PII in off-device backup |

Hook clipboard/pasteboard and screenshot paths with Frida — use the `Java.perform` / `ObjC.classes` and `Interceptor` primitives in [`../../reverse-engineering/reference/scenarios/dynamic-analysis/frida-hooking.md`](../../reverse-engineering/reference/scenarios/dynamic-analysis/frida-hooking.md); syscall-level file/clipboard writes via [`../../reverse-engineering/reference/scenarios/dynamic-analysis/ltrace-strace.md`](../../reverse-engineering/reference/scenarios/dynamic-analysis/ltrace-strace.md).

## Network egress capture (MASVS-PRIVACY-2/4)

Intercept all traffic and record **every third-party host** the app talks to, then attribute each to a purpose (crash, analytics, ad, attribution). Any egress of PII or a stable identifier to a host **not** covered by the privacy label is the divergence finding.

```bash
mitmdump -q -w flows.mitm --set block_global=false
mitmdump -nr flows.mitm --set flow_detail=1 | grep -iE 'Host:|token|email|adid|idfa'
```

TLS pinning will block capture — bypass it with the pinning-bypass recipes in [`android-dynamic-analysis.md`](android-dynamic-analysis.md) / [`ios-dynamic-analysis.md`](ios-dynamic-analysis.md) (Frida/objection unpinning), then re-capture. Flutter and RN pin differently: see [`flutter-aot-reversing.md`](flutter-aot-reversing.md) and [`scenarios/android/react-native-hermes.md`](scenarios/android/react-native-hermes.md); logic buried in a custom `.so` may hold the endpoint list — [`scenarios/android/native-lib-host-extraction.md`](scenarios/android/native-lib-host-extraction.md).

## Declared-vs-actual — the headline finding (MASVS-PRIVACY-2)

Build one table. Left = what the vendor **declares**; right = what the binary **does**. Each mismatched row is a finding.

```
| Data type / SDK        | Play Data Safety / Nutrition Label | Observed (perm+egress+SDK) | Verdict     |
|------------------------|------------------------------------|----------------------------|-------------|
| Precise location       | "Not collected"                    | ACCESS_FINE + egress→adj   | DIVERGENCE  |
| Advertising ID         | "Not shared"                       | AD_ID → adservice host     | DIVERGENCE  |
```

- **Android**: the Play listing's *Data Safety* section is the declaration; pull it from the store page for the exact `applicationId`.
- **iOS**: the App Store *Privacy* nutrition label plus the shipped `PrivacyInfo.xcprivacy` (and SDK-supplied ones under `Frameworks/*.bundle`).
- Any collected/shared category, tracker, or identifier present in the binary/egress but **absent or contradicted** in the label = MASVS-PRIVACY-2 (transparency) finding. This is the reportable headline; single-source it into the report skill, do not score inline.

## Regulatory framing (flag posture only — not legal advice)

Note the *posture*, cite the control, hand the legal call to the client. Consent-before-collection maps to GDPR Art.6/7 & DPDP consent; over-ask maps to GDPR Art.5(1)(c) minimization; undisclosed third-party sharing maps to CCPA "sale/share" + GDPR Art.13/14; session-replay of a data-entry screen is a high-risk processing flag. Record as observations with the MASVS-PRIVACY id; the report skill owns wording and severity.

## Anti-Patterns

- Reporting a permission as over-ask without grepping the dex for its actual use — a declared-but-unused grant is the finding; a used one is not.
- Concluding "no trackers" from exodus alone — it is signature-based; confirm with egress capture (a first-party proxy can front a tracker).
- Skipping the label diff and dumping a raw SDK list — the *divergence* against the declared label is what makes it reportable, not the inventory.
- Treating an empty `network_security_config.xml` as "captures everything" — the app may pin in code; unpin first (dynamic files) or you record zero egress falsely.
- Scoring severity or writing GDPR "violations" here — flag posture + MASVS id only; scoring lives in the report skill, validation in [`../../coordination/reference/VALIDATION.md`](../../coordination/reference/VALIDATION.md).

## Cross-references

- [`methodology.md`](methodology.md) — where the privacy pass sits in the overall mobile workflow.
- [`android-static-analysis.md`](android-static-analysis.md) / [`ios-static-analysis.md`](ios-static-analysis.md) — produce the decoded artifact + manifests this pass consumes.
- [`android-dynamic-analysis.md`](android-dynamic-analysis.md) / [`ios-dynamic-analysis.md`](ios-dynamic-analysis.md) — pinning bypass + runtime capture for egress/log/clipboard evidence.
- [`../../reverse-engineering/reference/scenarios/dynamic-analysis/frida-hooking.md`](../../reverse-engineering/reference/scenarios/dynamic-analysis/frida-hooking.md) — hook primitives (clipboard, pasteboard, screenshot, tracker init).
