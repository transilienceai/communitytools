# Race Detection — PREDICT / PROBE / PROVE

## When this applies

- You're scoping a target and want to identify high-value race condition surfaces.
- You're triaging deviations between sequential and parallel runs.
- You need a structured workflow for race testing rather than ad-hoc Repeater attempts.

## Technique

Three phases:
1. **PREDICT** — enumerate endpoints with limit, single-use, state-change, or check-then-use semantics.
2. **PROBE** — establish baseline (sequential) behavior, then send parallel volleys, look for deviations in status, length, timing.
3. **PROVE** — repeat 10 times to estimate success rate; >50% = exploitable.

## Steps

### Phase 1: PREDICT

**Identify Vulnerable Endpoints:**
- Operations with limits (rate limits, quotas)
- Single-use resources (coupons, tokens)
- State-dependent actions (checkout, registration)
- Time-sensitive operations (password resets)
- File processing (upload, validation)
- Server-side sessions with verify→use gaps (two-step authorization: validate then re-read)

**Questions to Ask:**
- Does it check then use a resource?
- Is there a gap between validation and action?
- Does it enforce a limit?
- Is state stored server-side?
- Are operations atomic?

### Phase 2: PROBE

**Baseline Testing:**
```
1. Send request twice sequentially
2. Document expected behavior:
   - Response codes
   - Response lengths
   - Response times
   - Error messages
```

**Race Testing:**
```
1. Create 20 duplicate requests
2. Send in parallel (single-packet)
3. Look for deviations:
   - Multiple successes (expected: 1)
   - Different status codes
   - Different response lengths
   - Timing anomalies
```

**Deviation Examples:**
```
Sequential: 200, 409, 409, 409 (working as designed)
Parallel:   200, 200, 200, 409 (VULNERABLE!)

Sequential: All 3420 bytes
Parallel:   3420, 3567, 3567, 3420 (ANOMALY!)

Sequential: 150ms, 160ms, 155ms, 158ms
Parallel:   145ms, 145ms, 145ms, 145ms (SYNCHRONIZED!)
```

### Phase 3: PROVE

**Consistent Exploitation:**
```
1. Isolate minimal requests
2. Test 10 times
3. Success rate > 50% = exploitable
4. Document impact
5. Create PoC
```

### Response analysis

**Status Code Analysis:**
```
# Burp Repeater: Sort by status code
# Look for multiple successes when expecting one

Expected: [200, 409, 409, 409, 409]
Anomaly:  [200, 200, 200, 409, 409]
```

**Response Length Analysis:**
```
# Sort by length in Burp
# Different lengths indicate different responses

Expected: [3420, 3420, 3420, 3420]
Anomaly:  [3420, 3567, 3567, 3420]
```

**Timing Analysis:**
```
# Synchronized timing indicates simultaneous processing

Sequential: [150ms, 160ms, 155ms, 158ms]
Parallel:   [145ms, 145ms, 145ms, 145ms]
```

**Content Difference:**
```bash
# Save responses and diff
diff response1.txt response2.txt

# Look for:
- Different error messages
- Different data returned
- Different state reflected
```

### Burp Repeater quick testing

**Setup:**
```
1. Proxy → HTTP history → Right-click → Send to Repeater
2. Repeater → Right-click tab → Add to new tab group
3. Ctrl+Shift+D to duplicate (create 20 tabs)
4. Verify all tabs have same session cookie
5. Update CSRF tokens if needed
```

**Execute:**
```
1. Right-click tab group name
2. "Send group in parallel (single-packet attack)"
3. Analyze responses
4. Sort by: Status code, Length, Time
```

**Analysis:**
```bash
# Look for:
- Multiple 200 responses (expected: 1)
- Different response lengths
- Different error messages
- Timing patterns
```

### Python race condition tester

```python
import concurrent.futures
import requests

def test_race_condition(url, data, headers, num_requests=20):
    """
    Test endpoint for race conditions
    """
    results = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=num_requests) as executor:
        futures = [
            executor.submit(requests.post, url, data=data, headers=headers)
            for _ in range(num_requests)
        ]

        for future in concurrent.futures.as_completed(futures):
            try:
                response = future.result()
                results.append({
                    'status': response.status_code,
                    'length': len(response.content),
                    'time': response.elapsed.total_seconds()
                })
            except Exception as e:
                results.append({'error': str(e)})

    success_count = sum(1 for r in results if r.get('status') == 200)
    print(f"Success count: {success_count}/{num_requests}")

    if success_count > 1:
        print("POTENTIAL RACE CONDITION DETECTED")

    return results

url = "https://target.com/api/endpoint"
data = {"param": "value"}
headers = {"Cookie": "session=TOKEN"}

test_race_condition(url, data, headers)
```

### Bash race condition tester

```bash
#!/bin/bash

URL="https://target.com/api/endpoint"
COOKIE="session=TOKEN"
DATA="param=value"
REQUESTS=20

echo "Testing race condition..."

for i in $(seq 1 $REQUESTS); do
    curl -X POST "$URL" \
        -H "Cookie: $COOKIE" \
        -d "$DATA" \
        -s -o "response_$i.txt" \
        -w "%{http_code}\n" >> status_codes.txt &
done

wait

success_count=$(grep -c "200" status_codes.txt)
echo "Successful requests: $success_count/$REQUESTS"

if [ $success_count -gt 1 ]; then
    echo "POTENTIAL RACE CONDITION DETECTED"
fi

rm response_*.txt status_codes.txt
```

### Troubleshooting

**Problem: No Collision Detected**
- Using parallel sending (not sequential)?
- Same session cookie in all requests?
- Valid CSRF tokens?
- HTTP/2 enabled on target?
- Burp Suite 2023.9+?
- Enough requests (try 50-100)?

```python
engine = RequestEngine(
    concurrentConnections=10,
    requestsPerConnection=100
)
```

**Problem: Session Locking** — sequential processing despite parallel sending; use different sessions.

**Problem: Rate Limiting** — slow down between attempts:
```python
for i in range(20):
    engine.queue(req, gate=str(i))
    engine.openGate(str(i))
    time.sleep(1)
```

**Problem: CSRF Validation** — get fresh CSRF token from form, update all requests immediately, work quickly before expiration.

**Problem: Inconsistent Results** — add connection warming, increase volume.

## Verifying success

- Sequential baseline shows the expected enforcement (1 success, N rejections).
- Parallel run shows multiple successes / anomalous lengths / synchronized timings.
- 10-trial reproducibility >= 50%.

## Common pitfalls

- Treating a single anomalous run as proof — always retry 10× before claiming exploitability.
- Failing to record the baseline (you can't tell if a parallel response is anomalous without it).
- CSRF tokens expiring mid-test — automate token refresh.

## Tools

- Burp Turbo Intruder
- Burp Repeater (tab groups)
- Burp Logger++
- Burp Collaborator (out-of-band)
- Python `concurrent.futures.ThreadPoolExecutor`
