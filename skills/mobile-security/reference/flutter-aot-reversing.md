# Mobile — Flutter AOT (Dart) Static Analysis

When a Mobile challenge or target ships a Flutter Android APK with `lib/arm64-v8a/libapp.so`, the application logic lives in the **Dart Ahead-Of-Time snapshot** inside that ELF. Native disassembly shows only Dart VM helpers; you need a Dart-aware decompiler.

## Toolchain selection

| Tool | When to use | Notes |
|------|-------------|-------|
| **blutter** (`https://github.com/worawit/blutter`) | Dart 3.x snapshots (Flutter 3.16+) | Builds the matching Dart VM from source against the SDK version. Best output quality (annotated ARM64 + class hierarchy). 5-10 min build. |
| **doldrums** (`https://github.com/rscloura/Doldrums`) | Dart 2.x snapshots only | Pure Python; broken on Dart 3.x. |
| **reFlutter** (`https://github.com/Impact-I/reFlutter`) | When you need to *modify* the APK to disable TLS pinning + enable Frida | `pip3 install reflutter` (a pip CLI, **not** Docker): inserts a patched Flutter engine → patched APK (Frida-gadget or built-in proxy/unpin mode); re-sign the output. |

## blutter recipe

```bash
# Identify the Dart/Flutter version — it is a semver "(stable)" string in the snapshot,
# NOT a 'Dart_' token ('Dart_' is the C-API symbol namespace, absent from snapshot data):
strings -a libapp.so | grep -Eo '[0-9]+\.[0-9]+\.[0-9]+ \(stable\)' | head   # e.g. "3.4.4 (stable)"

git clone https://github.com/worawit/blutter
cd blutter
python3 -m pip install -r scripts/requirements.txt
# Pass the arch dir that contains BOTH libapp.so AND libflutter.so — blutter reads the
# exact Dart VM version from libflutter.so and builds the matching VM to decompile.
python3 blutter.py /path/to/lib/arm64-v8a/ ./out/

# Output:
# out/asm/bank/api_service.dart.asm  - ARM64 + Dart-aware comments
# out/blutter_<arch>.so              - patched Dart VM
# out/<package>/                     - decompiled per-class structure
```

## Common envelope patterns to look for in the dumped Dart

The bank/payment/transfer apps typically wrap requests as:

1. **Custom HTTP envelope** with `Content-Type: text/plain` (skipping framework parsing).
2. **Headers** carry the symmetric key material: `KEY`, `IV`, `SALT`, `SIGNATURE` — each base64-encoded.
3. **Symmetric key wrapping**: `KEY = base64(RSA-OAEP(<aes_key_bytes>, server_pubkey))`. Default OAEP hash:
   - **fast_rsa Dart package**: SHA-**256** (NOT SHA-1!)
   - **pointycastle Dart package**: configurable, often SHA-256
4. **Body**: `base64(AES-256-CBC-PKCS7(jsonEncode(body), aes_key, aes_iv))`.

> **Report it, don't just replicate it.** This envelope is a *finding source*, not only a contract: AES-CBC with **no MAC** (non-AEAD) is malleable/padding-oracle-prone, and a **static or reused IV** (or `key == IV`) is a MASVS-CRYPTO-1 weakness (MASWE-020/021). Flag those while you reverse the contract — see [android-static-analysis.md](android-static-analysis.md) for the full crypto-primitive weakness pass.

**Common mistake**: Python `cryptography.hazmat.primitives.asymmetric.padding.OAEP` defaults to SHA-1. If your client uses SHA-1 against a fast_rsa server, every request returns 400 with no useful error.

## Worked example — banking-style Flutter app

When you encounter a Flutter 3.6.x AOT banking app: blutter dumps `package:<app>/*.dart`. Typical envelope is KEY/IV/SALT headers via fast_rsa OAEP-**SHA256** + body AES-256-CBC. Endpoints follow `/api/v1/user/{register,login,me}` and `/api/v1/transaction/{history,transfer}`. IDOR on `/transaction/transfer` is common: server does not verify ownership of `from_account`. Forge `from_account=<bank-internal-account>` to read its outgoing-transfer remark, which often contains the target string. Login returns JWT + an XOR-obfuscated PIN (e.g. `pin ^ 0xdead`).

## Anti-patterns

- Static dump first — don't reach for dynamic instrumentation while the snapshot answers the question. But Flutter is the case where dynamic is often *required*: Dart ships its own statically-linked BoringSSL and ignores the system proxy, so a plain Burp captures nothing and default OkHttp unpinning hooks miss it. When you need live traffic, go to [android-dynamic-analysis.md](android-dynamic-analysis.md) (reFlutter / `ssl_verify` hook / iptables REDIRECT).
- Don't assume OAEP-SHA1 in the Python client. Always check the source library's default.
- Don't ignore Dart symbol names that look "boring" — `_handlePinInput`, `_navigateToPinPage` often anchor the auth/business-logic functions.
- Don't run the APK in an emulator unless absolutely needed; static dump is faster and more reliable.

## Cross-references

- [android-static-analysis.md](android-static-analysis.md) — crypto-primitive weakness pass; manifest/IPC/storage surface around the Flutter app.
- [android-dynamic-analysis.md](android-dynamic-analysis.md) — Flutter BoringSSL pinning bypass + proxy-unaware traffic capture.
- [methodology.md](methodology.md) — where Flutter RE sits in the overall flow; the client→API pivot for any IDOR you find in the dumped Dart.
