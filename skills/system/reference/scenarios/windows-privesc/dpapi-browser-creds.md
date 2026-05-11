# DPAPI Browser Credential Extraction (In-Process)

## When this applies

- You have code execution (RCE, load_extension DLL, webshell) as a user account — typically a service account like `web`, `IIS APPPOOL\*`, or any non-admin local user.
- That user's profile contains a Chromium-family browser (Chrome, Edge, Brave, Opera).
- Goal: decrypt the browser's saved passwords for lateral-movement credentials.

## Why In-Process DPAPI Beats mimikatz Offline

DPAPI master keys are bound to the user's SID + password hash. To decrypt offline you need the master key blob **plus** the user's password (or machine DPAPI secret for SYSTEM context). In-process, calling `CryptUnprotectData` from code running as that user is transparent — Windows resolves the master key automatically. No key extraction, no password cracking, no mimikatz required.

## Chrome/Edge v10+ Password Format

```
file: %LOCALAPPDATA%\{Microsoft\Edge|Google\Chrome|BraveSoftware\Brave-Browser}\User Data\
  Local State         (JSON; contains "os_crypt.encrypted_key" — base64 "DPAPI"+DPAPI-blob)
  Default\Login Data  (SQLite; logins table; password_value = "v10"+IV(12)+ciphertext+tag(16))
```

Decrypt flow:

1. Read `Local State`, extract `encrypted_key`, base64-decode, strip 5-byte `DPAPI` prefix, pass remainder to `CryptUnprotectData` → 32-byte AES key.
2. Copy `Login Data` to a writable temp path (SQLite lock while browser runs), open read-only.
3. For each `logins` row: strip `v10` prefix; split remainder into `iv=[0:12]`, `tag=[-16:]`, `ciphertext=[12:-16]`. AES-256-GCM decrypt with the key from step 1.

## Minimal In-Process C (load_extension DLL)

```c
// Read Local State, find "encrypted_key":"...", base64-decode, strip "DPAPI" prefix
DATA_BLOB in = {dpapi_len, dpapi_blob}, out = {0};
CryptUnprotectData(&in, NULL, NULL, NULL, NULL, 0, &out);
// out.pbData / out.cbData = 32-byte AES-GCM key
// AES-GCM via BCrypt: BCRYPT_CHAIN_MODE_GCM + BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO (pbNonce=iv, pbTag=tag)
```

From Python (pywin32): `win32crypt.CryptUnprotectData(blob, None, None, None, 0)`.

## Workflow Tips

- Dump AES key first (one CryptUnprotectData call), exfil hex → decrypt `Login Data` offline. Avoids bundling BCrypt/AES-GCM into your DLL.
- Also check Firefox (`%APPDATA%\Mozilla\Firefox\Profiles\*\logins.json` + `key4.db` — NOT DPAPI; uses NSS) and Windows Credential Manager (`vaultcli`/`CredEnumerate`).
- Same technique decrypts browser cookies, autofill, credit cards — the AES key is universal for that profile.

## Verifying success

- The decrypted `Login Data` rows produce cleartext URL/username/password triplets.
- Recovered creds authenticate against the corresponding services.

## Detection/Defense

- Chrome "App-Bound Encryption" (2024+) wraps the AES key with an additional SYSTEM-only layer — requires SYSTEM or elevation to decrypt. Older Edge/Chrome profiles on the target remain v10-only.
- EDR may flag `CryptUnprotectData` invocations from non-browser processes.

## Common pitfalls

- `Login Data` SQLite is locked while the browser runs — copy to a temp path before opening.
- Chrome 2024+ "App-Bound Encryption" requires SYSTEM context — escalate first if target uses that build.

## Tools

- pywin32 (`win32crypt.CryptUnprotectData`)
- BCrypt (Windows native AES-GCM)
- SQLite reader (any)
