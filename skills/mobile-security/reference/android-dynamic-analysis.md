# Android — Dynamic Analysis (DAST) & Runtime Instrumentation

Static-first is the house rule (see `android-static-analysis.md`), but some findings only exist at runtime: keys decrypted in memory, TLS traffic, IPC reachability, and RESILIENCE controls (MAS-L2 / MASA) that are only *real* if they survive an active bypass. This file is the runtime tier — device bring-up + the mobile-specific deltas. Frida primitives (Interceptor/Stalker/`Java.perform`/replace) are taught once in [`../../reverse-engineering/reference/scenarios/dynamic-analysis/frida-hooking.md`](../../reverse-engineering/reference/scenarios/dynamic-analysis/frida-hooking.md) — cross-link, don't re-teach. RoE/preflight → [`../../coordination/reference/preflight-checklist.md`](../../coordination/reference/preflight-checklist.md).

## When to use

- Static pass recovered *references* to secrets/keys but not the runtime value (derived/decrypted at use).
- You need real TLS traffic (Burp/mitmproxy) but the app pins or ignores the proxy.
- IPC surface (providers, activities, deep links, WebView bridges) needs reachability confirmation, not just manifest reading.
- The engagement is MAS-L2 / MASA-scoped — root/pinning/tamper detection must be *actively defeated*, not merely documented.

## Test environment

| Env | Root/CA path | Survives detection | Trade-off |
|-----|-------------|--------------------|-----------|
| Physical + **Magisk** + **Zygisk** | System CA via module; root via su | DenyList + **Shamiko** hide root from app | Play Integrity increasingly forces **hardware**-backed attestation → emulator fails, physical `MEETS_DEVICE` may still pass |
| **AVD** (Google **APIs**, not Play) `-writable-system` | `adb remount` → push CA to `/system/etc/security/cacerts` | Weak; many apps flag emulator (`ro.kernel.qemu`, sensors) | Free, scriptable, disposable; snapshot before each test |
| Genymotion / corp-cloud device | vendor root | varies | when Play Integrity `STRONG` is required |

```bash
adb root && adb remount            # emulator writable-system
# Magisk hide: DenyList the target pkg, enable Shamiko (Zygisk) for stronger hiding
```

## Frida bring-up (mobile delta only)

```bash
adb shell getprop ro.product.cpu.abi                     # match server ABI
V=$(frida --version)
curl -L https://github.com/frida/frida/releases/download/$V/frida-server-$V-android-arm64.xz -o fs.xz
unxz fs.xz && adb push fs /data/local/tmp/frida-server
adb shell "chmod 755 /data/local/tmp/frida-server && su -c /data/local/tmp/frida-server &"
frida-ps -Uai                                            # confirm link
frida -U -f com.pkg -l hook.js --no-pause                # SPAWN: pre-init checks (pinning/root run at startup)
frida -U -N com.pkg -l hook.js                           # ATTACH: app already running
```

Non-rooted device → inject **frida-gadget** by repackaging: `objection patchapk -s app.apk` (embeds gadget + smali loader, re-signs). Then `objection explore` / `frida -U -n Gadget`.

## Objection VAPT recipes

```bash
objection -g com.pkg explore
# in the REPL:
android hooking list activities
memory list modules
memory dump all /tmp/dump                 # then: strings/grep for runtime-decrypted keys the static pass missed
memory search "BEGIN RSA" --string        # MASVS-STORAGE-1 / MASVS-CRYPTO-2
android keystore list                     # confirm Keystore-backed vs. app-managed key
android sslpinning disable                # MASVS-NETWORK-1
android root disable                      # MASVS-RESILIENCE-1 (RootBeer/SafetyNet common hooks)
android hooking watch class_method com.pkg.Crypto.decrypt --dump-args --dump-return
```

## Traffic interception

Set device proxy (`Settings → Wi-Fi → proxy`, or `adb shell settings put global http_proxy host:8080`) to Burp/mitmproxy. **Android 7+**: apps ignore user-added CAs by default (`network_security_config` trusts `system` only). Three real workarounds:

1. **System-store CA** (best): rename Burp cert to subject-hash `openssl x509 -inform DER -subject_hash_old -in cacert.der` → `<hash>.0`, push to `/system/etc/security/cacerts` (writable-system emulator) or install as a **Magisk module** (`MoveCertificates` / cert-fixing module) so it survives on a physical device.
2. **Repackage NSC**: inject `<debug-overrides><trust-anchors><certificates src="user"/>` into `res/xml/network_security_config.xml`, `apktool b` → resign (see RESILIENCE below). Only works if the app is `debuggable` or you flip it.
3. **objection** `android sslpinning disable` (also relaxes trust for common stacks at runtime).

mitmproxy transparent mode when no in-app proxy setting: `adb shell iptables -t nat -A OUTPUT -p tcp --dport 443 -j REDIRECT --to-port 8080` + `mitmproxy --mode transparent`.

## Universal TLS-pinning bypass by stack

| Stack | Signal | Bypass |
|-------|--------|--------|
| JVM / OkHttp / Conscrypt / TrustKit | `CertificatePinner`, `okhttp3`, `network_security_config` `<pin-set>` | `objection android sslpinning disable`; or `frida -U -f pkg -l frida-multiple-unpinning.js` (akabe1) |
| **Flutter** (BoringSSL, statically linked) | `libflutter.so`, Dart ignores OkHttp hooks **and the system proxy** | Frida-hook `ssl_crypto_x509_session_verify_cert_chain` / `ssl_verify` in `libflutter.so`; **or** `reFlutter` to patch pins. Proxy-unaware → `reFlutter` proxy-inject **or** iptables REDIRECT to transparent mitmproxy |
| React Native | JS SPKI pins (`react-native-ssl-pinning`, TrustKit) | disable at JS layer or NSC; unpinning script still covers the native TrustKit path — see [`scenarios/android/react-native-hermes.md`](scenarios/android/react-native-hermes.md) |

Flutter's `libflutter.so` symbol offset drifts per version — locate `ssl_verify_cert_chain` with a BoringSSL byte-pattern scan (reFlutter and the `disable-flutter-tls.js` gists ship the current patterns). Flutter static teardown → [`flutter-aot-reversing.md`](flutter-aot-reversing.md).

## drozer — IPC runtime exploitation (MASVS-PLATFORM-1/2)

```bash
adb forward tcp:31415 tcp:31415 && drozer console connect
run app.package.attacksurface com.pkg
run app.provider.query content://com.pkg.provider/users --projection "* FROM sqlite_master--"  # projection SQLi
run app.provider.read content://com.pkg.provider/../../../databases/app.db                       # path traversal
run app.activity.start --component com.pkg com.pkg.AdminActivity                                 # exported/unauth screen
run app.provider.finduri com.pkg
# quick adb confirms without drozer:
adb shell content query --uri content://com.pkg.provider/users
adb shell am start -n com.pkg/.SecretActivity --es token x   # intent fuzzing: vary --es/--ei/-d
```

## Runtime storage & deep links / WebView

```bash
# exercise the flow first, THEN pull real artifacts (MASVS-STORAGE-1)
adb exec-out run-as com.pkg tar c ./ 2>/dev/null | tar xv -C ./data_dump   # debuggable
adb pull /data/data/com.pkg /dump                                          # rooted
sqlite3 /dump/databases/app.db .dump      # inspect real SharedPreferences XML + SQLite
# deep-link param injection (MASVS-PLATFORM-1):
adb shell am start -a android.intent.action.VIEW -d "app://open?redirect=https://evil/&next=//x"
```

Hook the WebView JS bridge to enumerate exposed methods: in `Java.perform`, hook `android.webkit.WebView.addJavascriptInterface` and log the object's class → any `@JavascriptInterface` method reachable from loaded content is MASVS-PLATFORM-2 exposure. `javaScriptEnabled` + `file://`/`content://` load = potential file exfil.

## RESILIENCE active bypass (MAS-L2 / MASA)

A control is only worth reporting as *present* if you tried to defeat it. Two paths:

- **smali return-flip**: patch the detector to `const/4 v0, 0x0; return v0` (root/emulator/debugger check), `apktool b`, resign.
- **Frida RootBeer/detector bypass** at runtime (`Java.perform` → force detector methods to `false`).

Tamper test — prove the integrity check (or its absence):

```bash
apktool b out -o mod.apk
zipalign -p -f 4 mod.apk aligned.apk
uber-apk-signer -a aligned.apk        # or: apksigner sign --ks debug.ks aligned.apk
adb install -r aligned.apk            # then run the PROTECTED flow and show it still works
```

If the repackaged, re-signed app runs the sensitive flow, anti-tamper (MASVS-RESILIENCE-2) is ineffective. **Attestation is only real if the SERVER verifies the Play Integrity verdict + nonce** — a client-only `integrity.token` call that never round-trips to a server that checks it is bypassable; confirm server-side verification before crediting the control (MASVS-RESILIENCE-1).

## Dynamic code analysis (decrypted branches / no-symbol compares)

```bash
frida-trace -U -f com.pkg -i 'lib*.so!*cmp*' -i 'lib*.so!*decrypt*'   # -i native, -j 'com.pkg.*!*' for Java
```

For inlined / no-PLT comparisons that `frida-trace` can't anchor, use **Stalker** to trace the decrypted branch and observe register values at the compare — see [`../../reverse-engineering/reference/scenarios/dynamic-analysis/frida-hooking.md`](../../reverse-engineering/reference/scenarios/dynamic-analysis/frida-hooking.md). Coarser syscall/libc view via [`../../reverse-engineering/reference/scenarios/dynamic-analysis/ltrace-strace.md`](../../reverse-engineering/reference/scenarios/dynamic-analysis/ltrace-strace.md). ELF symbol/offset work for hook targets → [`../../reverse-engineering/reference/scenarios/static-analysis/elf-analysis.md`](../../reverse-engineering/reference/scenarios/static-analysis/elf-analysis.md). Recovered API endpoints/params pivot to server-side authz testing: [`../../api-security/reference/scenarios/rest/owasp-bola-bopla.md`](../../api-security/reference/scenarios/rest/owasp-bola-bopla.md), [`../../api-security/reference/scenarios/rest/mass-assignment.md`](../../api-security/reference/scenarios/rest/mass-assignment.md).

## Anti-Patterns

- Reaching for a device before the static pass is exhausted — static-first is cheaper and often sufficient (see `methodology.md`).
- Installing the Burp cert to the **user** store on Android 7+ and concluding "no pinning" when the app simply ignores user CAs — use the system-store / NSC / objection path first.
- Testing a **Flutter** app through Burp and seeing zero traffic → not stealth, it's Dart ignoring the system proxy. Use iptables REDIRECT + reFlutter, not more Burp fiddling.
- Reporting root/pinning/tamper detection as a *strength* without an active bypass attempt — MAS-L2 requires you defeat it (or prove you can't).
- Crediting Play Integrity because the app *calls* it — worthless unless the server verifies the verdict + nonce.
- Passing a C++ `std::string`-typed function to a Frida/host hook — hook the underlying libc primitive; see [`scenarios/android/native-lib-host-extraction.md`](scenarios/android/native-lib-host-extraction.md).

## Cross-references

- [`methodology.md`](methodology.md) · [`android-static-analysis.md`](android-static-analysis.md) — the tiers this feeds from.
- [`scenarios/android/native-lib-host-extraction.md`](scenarios/android/native-lib-host-extraction.md) — no-device `strcmp`/`memcmp` extraction when Frida is blocked.
- [`scenarios/android/react-native-hermes.md`](scenarios/android/react-native-hermes.md) · [`flutter-aot-reversing.md`](flutter-aot-reversing.md) — stack-specific pinning/storage deltas.
- [`../../reverse-engineering/reference/scenarios/static-analysis/unity-il2cpp-recipe.md`](../../reverse-engineering/reference/scenarios/static-analysis/unity-il2cpp-recipe.md) · [`../../reverse-engineering/reference/scenarios/obfuscation/packed-binaries.md`](../../reverse-engineering/reference/scenarios/obfuscation/packed-binaries.md) — Unity dumps and packer/anti-debug handling for hook targets.
- Validation of runtime claims → [`../../coordination/reference/VALIDATION.md`](../../coordination/reference/VALIDATION.md); reporting → [`../../transilience-report-style/SKILL.md`](../../transilience-report-style/SKILL.md).
