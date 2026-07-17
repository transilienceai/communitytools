# iOS — Dynamic Analysis (DAST) & Runtime Instrumentation

Runtime instrumentation of an iOS app once the static pass (`ios-static-analysis.md`) has mapped classes, endpoints, pinning config, and Keychain access-control. Dynamic testing confirms what the binary *does*: pinning enforcement, biometric gating, jailbreak/anti-debug, storage/log leakage, deep-link handling. Frida/ObjC hooking primitives (spawn/attach, `Interceptor`, `Stalker`, `ObjC.classes`) are NOT re-taught here — see [../../reverse-engineering/reference/scenarios/dynamic-analysis/frida-hooking.md](../../reverse-engineering/reference/scenarios/dynamic-analysis/frida-hooking.md). This file is the **iOS device bring-up + mobile-specific hooks** delta.

## When to use

- Static analysis flagged a control (pinning, `LAContext`, jailbreak check, Keychain `kSecAttrAccessible*`) and you must prove enforcement at runtime.
- You need cleartext HTTP through Burp/mitmproxy but the app pins TLS.
- You suspect secrets in the Keychain, sandbox, snapshots, pasteboard, or unified log.
- Deep-link / Universal-Link parameter handling needs live observation.
- Skip when a static dump already answers the question — device bring-up is expensive; RoE/preflight lives in [../../coordination/reference/preflight-checklist.md](../../coordination/reference/preflight-checklist.md).

## Device options

| Option | Bring-up | Frida delivery | Trade-off |
|--------|----------|----------------|-----------|
| **Jailbroken** (checkm8 SoCs ≤ A11: checkra1n ≤ iOS 14, palera1n iOS 15–18) | tethered/semi-tethered boot | `frida-server` via Sileo/Cydia apt repo `https://build.frida.re` | Full power (any process, kernel-adjacent); JB itself trips detection — pair with a JB-hider. Both ride the checkm8 BootROM exploit (unpatchable, but A12+ SoCs are NOT checkm8-vulnerable — use Corellium there). |
| **Non-JB, patched IPA** | re-sign + sideload | `objection patchipa` embeds **frida-gadget** dylib | No JB, but needs a signing identity; gadget loads in-process only (that app). App Store apps must be decrypted first. |
| **Non-JB, manual gadget** | inject `FridaGadget.dylib`, `ldid -S` / `codesign`, sideload via **Sideloadly / AltStore** | frida-gadget (embedded) | 7-day free-cert expiry (AltStore auto-refresh); more control than objection. |
| **Corellium** | virtual iOS instance (web) | `frida-server` pre-integrated | No hardware, jailbroken by default, snapshots; paid, and some anti-VM/JB checks fire. |

```bash
# Jailbroken: install frida-server via apt repo, then over USB:
frida-ps -Uai                          # -a running apps, -i installed (get bundle id)
# Non-JB: patch a decrypted IPA to embed the gadget (objection >=1.11):
objection patchipa --source app.ipa --codesign-signature <TEAM_ID>
ios-deploy -b app-frida-codesigned.ipa # or Sideloadly/AltStore GUI
```

Decrypt App Store binaries first (encrypted `LC_ENCRYPTION_INFO`): `frida-ios-dump` (JB) or `bagbak`. See `ios-static-analysis.md` for decrypt + class-dump.

## Frida + objection (mobile delta)

```bash
pip3 install -U frida-tools objection          # objection PyPI name is stable; frida pin to server version
objection -g <bundle.id> explore               # gadget or frida-server, same REPL
```

| objection command | Purpose | MASVS / MASTG |
|-------------------|---------|---------------|
| `ios hooking list classes` / `... list class_methods <Cls>` | live class/selector map | MASTG-TECH runtime enum |
| `ios hooking search methods <kw>` | find auth/crypto selectors | — |
| `ios hooking watch method "-[Cls sel:]" --dump-args --dump-return --dump-backtrace` | trace a selector | — |
| `memory search "<hex/utf8>" --string` / `memory dump all <out>` | find/dump secrets in heap | MASVS-STORAGE-2 |
| `ios monitor pasteboard` | poll `UIPasteboard` | MASVS-PLATFORM-4 |

`frida-trace` on ObjC selectors is the fastest dynamic code-analysis lens (auto-generates editable JS stubs):

```bash
frida-trace -U -f <bundle.id> -m "-[NSURLSession * dataTaskWithRequest:*]" -m "-[* URLSession:didReceiveChallenge:*]"
frida-trace -U <bundle.id> -m "*[* * decrypt*]" -m "*[* * *token*]"
```

## TLS pinning bypass (MASVS-NETWORK-2, MASTG-TEST-0067)

Try in ascending effort:

```bash
objection -g <bundle.id> explore -s "ios sslpinning disable"   # covers NSURLSession, AFNetworking, TrustKit, BoringSSL
```

If custom pinning survives, hook the trust evaluation directly:

```javascript
// SecTrustEvaluateWithError -> force trusted
Interceptor.replace(Module.findExportByName('Security','SecTrustEvaluateWithError'),
  new NativeCallback(function(t, e){ return 1; }, 'int', ['pointer','pointer']));
```

Or override the challenge delegate (`URLSession:didReceiveChallenge:`) to call the completion handler with `NSURLSessionAuthChallengeUseCredential` + `serverTrust`. On a jailbroken device, **SSL Kill Switch 2/3** (tweak) patches `SecTrust*` globally — no per-app script. Static side: enumerate **TrustKit** `TSKConfiguration` and pinned SPKI-SHA256 hashes from the binary/`Info.plist` and feed them to `ios-static-analysis.md` (a stale/backup-pin gap is a static finding).

## Keychain dump + Data Protection (MASVS-STORAGE-1/2, MASTG-TEST-0053/0060)

```bash
objection -g <bundle.id> explore -s "ios keychain dump"        # items + accessibility class
# JB alternative: keychain-dumper (build from github.com/ptoomey3/Keychain-Dumper, re-sign the entitlements plist)
```

Correlate the `kSecAttrAccessible*` class with lock-state reachability — this is the whole point:

| Accessibility class | Readable when | Finding |
|---------------------|---------------|---------|
| `AlwaysThisDeviceOnly` (deprecated) | even locked | over-permissive; flag |
| `AfterFirstUnlock[ThisDeviceOnly]` | after one unlock until reboot | common; OK for background |
| `WhenUnlocked[ThisDeviceOnly]` | only while unlocked | preferred for secrets |
| `...WhenPasscodeSetThisDeviceOnly` | unlocked + passcode set | strongest |

Dumping a secret while the device is **locked** proves weak Data Protection. Also pull `NSFileProtection` on sandbox files (`ls -laO`, or `ios nsuserdefaults get`).

## Biometric / local-auth bypass (MASVS-AUTH-2, MASWE-0043, MASTG-TEST-0064)

```javascript
// Force LAContext.evaluatePolicy to succeed
var LAContext = ObjC.classes.LAContext;
Interceptor.attach(LAContext['- evaluatePolicy:localizedReason:reply:'].implementation, {
  onEnter(a){ var cb = new ObjC.Block(a[4]);
    var orig = cb.implementation;
    cb.implementation = function(success, err){ return orig(true, null); }; }
});
```

Distinguish the two designs — **only one is bypassable this way**:

- **Event-bound** (`evaluatePolicy` returns a bool, app branches on it): return-flip = full bypass. **Reportable.**
- **Key-bound**: the secret sits in a Keychain item guarded by `SecAccessControl` (`kSecAccessControlBiometryCurrentSet` / `...UserPresence`). LocalAuthentication gates key *release*, not an app-side bool — flipping the return does **not** decrypt it. Not bypassable by hooking; this is the secure pattern. Verify which one via the `ios keychain dump` access-control column + the `evaluatePolicy` hook not yielding the protected item.

## Jailbreak-detection & anti-debug bypass (MASVS-RESILIENCE-1/4, MASTG-TEST-0066)

```bash
objection -g <bundle.id> explore -s "ios jailbreak disable"
```

Tweaks: **Shadow**, **Liberty Lite**, **A-Bypass**. When bundled/custom, hook the primitives:

- File probes: `-[NSFileManager fileExistsAtPath:]` on `/Applications/Cydia.app`, `/bin/bash`, `/etc/apt`, `/var/jb` — return `false`.
- `stat`/`access`/`fork`/`system`/`getenv("DYLD_INSERT_LIBRARIES")` via `Interceptor.attach`.
- URL scheme: `-[UIApplication canOpenURL:]` on `cydia://` — return `false`.

Anti-debug (neutralize each):

| Mechanism | Detect | Neutralize |
|-----------|--------|-----------|
| `ptrace(PT_DENY_ATTACH=31)` | `svc` to `ptrace`/`syscall(26)` | `Interceptor.replace` → return 0; or hook `ptrace` export |
| `sysctl(KERN_PROC → P_TRACED)` | reads `kp_proc.p_flag & 0x800` | hook `sysctl`, clear the flag in the out-buffer |
| `getppid()!=1` / `dyld` image scan (`_dyld_image_count`, names) | counts injected dylibs | hook the enumerator to hide `FridaGadget`/`libfrida` |

## Runtime storage & log leakage (MASVS-STORAGE-1/2)

```bash
# after exercising sensitive flows, pull the sandbox:
objection -g <bundle.id> explore -s "env"          # shows Documents/Library/tmp paths
frida-ios-dump / ios-deploy --download             # or `ios plist cat`, `ios nsuserdefaults get`
# unified log (NSLog lands here) — grep live:
idevicesyslog -u <UDID> | grep -i <bundle.id>
log stream --predicate 'subsystem == "<bundle.id>"' --level debug   # on-device / Corellium
```

Flag PII/tokens/PAN in `NSUserDefaults` plist, WebKit caches, `Cache.db`, or the log. Realm/SQLite/Core Data unencrypted = MASVS-STORAGE-1.

## URL-scheme / Universal-Link drive (MASVS-PLATFORM-1/3, MASTG-TEST-0075)

```bash
xcrun simctl openurl booted "myapp://path?param=payload"   # Simulator
# device: type into Safari, or `frida`-invoke -[UIApplication openURL:]
```

Hook the handlers to observe raw parameter handling (auth-token-in-URL, unvalidated redirect, injection into a WebView):

```javascript
["- application:openURL:options:", "- application:continueUserActivity:restorationHandler:"]
  .forEach(s => { var m = ObjC.classes.AppDelegate[s]; if(m)
    Interceptor.attach(m.implementation, { onEnter(a){ console.log(s, new ObjC.Object(a[3])); } }); });
```

## Pasteboard & snapshot runtime (MASVS-STORAGE-2/PLATFORM-4, MASTG-TEST-0072)

```javascript
Interceptor.attach(ObjC.classes.UIPasteboard['- setString:'].implementation,
  { onEnter(a){ console.log('pasteboard <=', new ObjC.Object(a[2]).toString()); } });
```

Background a sensitive screen, then inspect `Library/Caches/Snapshots/<bundle.id>/` — iOS snapshots the last frame for the app-switcher; a card/PIN/token screen captured in cleartext is a finding (fix = blur/placeholder on `applicationDidEnterBackground`).

## Anti-Patterns

- Bringing up a device before static analysis narrows the target — hook lists are huge; know the class/selector first.
- Reporting a biometric "bypass" that only flipped an `evaluatePolicy` bool while the secret is `SecAccessControl` key-bound — that is the secure design, not a finding.
- Concluding "pinned, untestable" after only `objection sslpinning disable` — custom BoringSSL/`SecTrust` pinning needs the direct hook.
- Trusting an empty capture as "no traffic" when the app silently failed the pinned handshake — confirm the socket actually connected.
- Leaving jailbreak/anti-debug bypass on while testing a business flow, then blaming crashes on the app.
- Testing on Corellium and reporting anti-VM/JB triggers as app defects.

## Cross-references

- [methodology.md](methodology.md) — overall mobile engagement flow and where DAST sits.
- [ios-static-analysis.md](ios-static-analysis.md) — decrypt, class-dump, TrustKit/SPKI pins, `SecAccessControl` config that this file confirms at runtime.
- [../../reverse-engineering/reference/scenarios/dynamic-analysis/frida-hooking.md](../../reverse-engineering/reference/scenarios/dynamic-analysis/frida-hooking.md) — Frida primitives (`Interceptor`, `Stalker`, `ObjC`, spawn/attach) — not re-taught here.
- [../../reverse-engineering/reference/scenarios/dynamic-analysis/ltrace-strace.md](../../reverse-engineering/reference/scenarios/dynamic-analysis/ltrace-strace.md) — syscall/library-call tracing when reasoning about `ptrace`/`sysctl` anti-debug.
- [privacy-testing.md](privacy-testing.md) — pasteboard/log/tracking leakage from the privacy angle.
- [flutter-aot-reversing.md](flutter-aot-reversing.md) / [scenarios/android/react-native-hermes.md](scenarios/android/react-native-hermes.md) — cross-platform runtimes: hook the Dart/Hermes networking layer, not `NSURLSession`.
- [scenarios/android/native-lib-host-extraction.md](scenarios/android/native-lib-host-extraction.md) — when iOS logic sits in a bundled native lib you can extract host-side.
- API pivot once TLS is unpinned: [../../api-security/reference/scenarios/rest/owasp-bola-bopla.md](../../api-security/reference/scenarios/rest/owasp-bola-bopla.md) (BOLA/BFLA) and [../../api-security/reference/scenarios/rest/mass-assignment.md](../../api-security/reference/scenarios/rest/mass-assignment.md).
