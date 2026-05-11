# API Endpoint Discovery

## When this applies

A web application exposes an API and the goal is to enumerate routes, methods, parameters, and authentication requirements. APIs may be REST, GraphQL, SOAP, or WebSocket. Discovery comes from documentation files, server-rendered hints, and client-side JavaScript.

## Technique

API surface lives in five places:

1. **Self-documenting endpoints** - swagger/openapi, GraphQL introspection, WSDL.
2. **Crawl-friendly metadata** - `robots.txt`, `sitemap.xml`, `.well-known/`.
3. **Client-side source** - JS bundles call API routes via `fetch()`, `axios`, or templated URLs.
4. **Mobile / native clients** - APK/IPA decompilation reveals routes that the web UI does not use.
5. **Brute force** - common API wordlists when the above fail.

Always check 1-3 before brute forcing; documented routes are higher fidelity than wordlist guesses.

## Steps

1. **Output structure and target**

   ```bash
   mkdir -p recon/{raw,inventory}
   BASE=https://api.example.tld
   ```

2. **Swagger / OpenAPI / Redoc paths**

   ```bash
   for p in /swagger /swagger.json /swagger/v1/swagger.json \
            /openapi.json /openapi.yaml /api-docs /api/docs \
            /v1/swagger.json /v2/api-docs /redoc /docs /api/swagger; do
     code=$(curl -sk -o /dev/null -w "%{http_code}" "${BASE}${p}")
     echo "${code} ${BASE}${p}"
   done | tee recon/raw/swagger-probe.txt
   ```

   When a swagger doc is found, save it and parse the routes:

   ```bash
   curl -sk "${BASE}/openapi.json" -o recon/raw/openapi.json
   jq -r '.paths | keys[]' recon/raw/openapi.json > recon/inventory/api-routes.txt
   ```

3. **GraphQL introspection**

   ```bash
   curl -sk -X POST -H "Content-Type: application/json" \
     -d '{"query":"{__schema{types{name fields{name args{name type{name}}}}}}"}' \
     "${BASE}/graphql" \
     | tee recon/raw/graphql-introspection.json | jq '.data.__schema.types[].name' \
     | head -50
   ```

   When introspection is disabled, attempt suggestion-based inference (e.g. `clairvoyance`) or grep client-side bundles for `gql`/`query` literals.

4. **robots.txt and sitemap**

   ```bash
   curl -sk "${BASE}/robots.txt"  | tee recon/raw/robots.txt
   curl -sk "${BASE}/sitemap.xml" | tee recon/raw/sitemap.xml
   curl -sk "${BASE}/.well-known/security.txt" | tee recon/raw/security.txt
   ```

   Disallowed paths in `robots.txt` are often the most interesting endpoints.

5. **JavaScript source review**

   ```bash
   # Pull every JS asset referenced from the front page
   curl -sk "${BASE}/" | grep -oE '/[^" ]+\.js' | sort -u \
     | while read js; do
         curl -sk "${BASE}${js}" -o "recon/raw/js$(echo ${js} | tr '/' '_')"
       done

   # Extract endpoint candidates from JS
   grep -hoE '"/(api|v[0-9]+)/[A-Za-z0-9_/{}.-]+"' recon/raw/js_*.js \
     | sort -u | tr -d '"' > recon/inventory/api-routes-from-js.txt

   # Extract fetch()/axios call patterns
   grep -hoE '(fetch|axios\.(get|post|put|delete|patch))\(["`][^"`]+["`]' \
     recon/raw/js_*.js | sort -u
   ```

   Tools like `linkfinder`, `getjs`, and `jsluice` automate this and handle webpack bundles.

6. **Common API path probes**

   ```bash
   for p in /api /api/v1 /api/v2 /api/v3 /v1 /v2 /rest /graphql \
            /api/users /api/admin /api/login /api/health /api/me; do
     code=$(curl -sk -o /dev/null -w "%{http_code}" "${BASE}${p}")
     echo "${code} ${p}"
   done
   ```

7. **Brute force with API-aware wordlists**

   ```bash
   WORDLIST=/usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt
   ffuf -u "${BASE}/FUZZ" -w ${WORDLIST} -mc 200,201,204,301,302,401,403,500 \
        -o recon/raw/api-ffuf.json -of json
   ```

8. **HTTP verb enumeration**

   Some routes only accept POST or PUT. Re-test interesting paths with multiple methods:

   ```bash
   for m in GET POST PUT PATCH DELETE OPTIONS; do
     code=$(curl -sk -o /dev/null -w "%{http_code}" -X ${m} "${BASE}/api/users")
     echo "${m} ${code}"
   done
   ```

9. **WebSocket discovery**

   ```bash
   grep -hoE '"(wss?://[^"]+)"' recon/raw/js_*.js | sort -u
   ```

   WebSocket endpoints often share base path with REST (e.g. `/ws`, `/socket.io`).

## Verifying success

- `recon/inventory/api-routes.txt` lists discovered routes deduplicated across sources.
- For each route: HTTP method, status without auth, status with auth (when credentials available).
- Swagger or GraphQL schema files saved when present.
- JS-extracted candidates are tagged with their source file in `recon/raw/js_*.js`.

## Common pitfalls

- Treating swagger UI 401 responses as "no docs" - the JSON spec is often at a sibling path.
- Skipping GraphQL because `/graphql` returned 400; many GraphQL endpoints reject GET but accept POST.
- Ignoring webpack chunk files (`*.chunk.js`) - they often hold the bulk of route literals.
- Brute forcing without method enumeration; many routes return 405 to GET but accept POST.
- Trusting 404 responses; APIs frequently use 404 as a generic error for both missing resources and missing routes. Test with auth tokens to disambiguate.

## Tools

- `linkfinder`, `getjs`, `jsluice` - JS endpoint extraction.
- `kiterunner` - API route brute force with method/auth awareness.
- `arjun`, `param-miner` - parameter discovery on known routes.
- `clairvoyance` - GraphQL schema reconstruction without introspection.
- `gau`, `waybackurls` - historical URL discovery from web archives.
- SecLists `Discovery/Web-Content/api/` - API-tuned wordlists.
