# HTTP Request Smuggling — CL.0 + Pause-Based Desync

## When this applies

- Back-end ignores `Content-Length` entirely (treats every request as having no body).
- Apache front-end / connection-timeout-bound back-end where partial body + pause causes desync.
- Goal: smuggle by exploiting the back-end's bodyless processing or by deliberately holding open the connection.

## Technique

CL.0: Send any valid POST with `Content-Length: N` pointing to a 404 path. The back-end ignores CL, treats body bytes as the start of a new request — second request returns 404, confirming.

Pause-based: Send headers + partial body, then pause 61 seconds. Apache front-end streams the entire body when complete; back-end has already moved on.

## Steps

### CL.0 detection

Send request with Content-Length pointing to a 404 path — if second request gets 404, CL.0 confirmed:

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 30

GET /404path HTTP/1.1
Host: target.com


```

### Pause-based (server-side desync / CL.0)

Exploit Apache's connection timeout — send partial body and pause 61 seconds. Front-end streams entire body; back-end maintains connection longer.

**Tool:** Burp's "Send with pauses" in Repeater with pause set after first headers.

### Response queue poisoning (H2.TE flavor)

**Mechanism:** Smuggle a complete HTTP/1.1 request that causes the back-end to respond TWICE, desynchronizing the response queue.

**Goal:** Steal another user's response (which may contain auth tokens or sensitive data).

The next HTTP request on that connection — even from a DIFFERENT user — receives the queued response.

## Verifying success

- CL.0: second request returns 404 / different response.
- Pause-based: time differential between request submission and final response confirms desync.
- Response queue: receive a response that doesn't match the request you sent (someone else's session content).

## Common pitfalls

- Pause-based requires the front-end to keep the connection open during the pause — modern keepalive timeouts are short. Apache 60s default is the canonical case.
- CL.0 detection is noisier than CL.TE — multiple 404s look like normal traffic.
- Response queue poisoning requires high traffic to capture another user's response — test at peak times.

## Tools

- Burp Suite Repeater + "Send with pauses"
- Burp HTTP Request Smuggler BApp
- Custom Python with raw socket + sleep
