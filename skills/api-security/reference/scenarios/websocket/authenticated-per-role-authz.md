# Authenticated WebSocket per-role authorization (relay + BOLA/BFLA over the socket)

Once a WebSocket is authenticated, the per-message authorization is frequently weaker than the REST equivalent — the server authenticates the *handshake* but then trusts message bodies. Testing it needs an authenticated relay that replays messages under different role tokens; that harness is easy to rebuild ad hoc and slow to get right. This scenario is the reusable playbook.

## Establish the authenticated socket

- Reuse the session artifact from `authenticated-session-acquisition` (cookies in `storageState` and/or a Bearer). WebSocket auth arrives one of three ways — identify which:
  1. **Cookie** on the `Upgrade` request (ambient) — a `storageState` cookie jar carries it.
  2. **Bearer in a query param** (`?token=…`) or the `Sec-WebSocket-Protocol` header (browsers can't set `Authorization` on WS).
  3. **First-message auth** — the socket opens unauthenticated and the client sends an `{"type":"auth","token":…}` frame.
- Capture the exact subscribe/first frames from the real client (DevTools → WS → Messages) — the message envelope (type, channel, id fields) is the attack surface.

## Per-role relay matrix (the core test)

Stand up two (or more) sockets — one per role/tenant (LOW-priv client, another client, an admin if available) — and cross-replay:

- **BOLA over the socket:** take a `{"type":"subscribe","channel":"account","id":<OWN>}` frame and replay it from the LOW-priv socket with `id:<VICTIM>` / a foreign tenant's object id. If the server streams the victim's data, per-object authz is missing on the socket even if the REST path enforces it.
- **BFLA over the socket:** replay a privileged message type (`{"type":"admin.broadcast",…}`, `{"type":"config.set",…}`) from the low-priv socket. A server that acts on it authenticates the connection but not the *action*.
- **Channel/topic authorization:** subscribe to channels you were never granted (`presence:<other-tenant>`, `admin:*`) — an unauthorized subscription that starts receiving events is the finding.
- **Mass-assignment in the frame:** add fields the client never sends (`"role":"admin"`, `"tenantId":<other>`) to a mutate frame.
- **Identity pinning:** does the server bind actions to the *handshake* identity, or to an `actorId`/`userId` in each message body? If the body value is trusted, spoof it.

`tools/auth_replay_harness.py` holds the per-role token store and can drive the relay + evidence logging (each cross-role frame → its response, with an `evidence_id`).

## Handshake & transport checks (pair with the siblings)

- Origin enforcement on `Upgrade` (CSWSH) → [`cswsh.md`](cswsh.md).
- Auth-bypass handshake tricks → [`auth-bypass-and-handshake-tricks.md`](auth-bypass-and-handshake-tricks.md).
- Unauth message injection / discovery → [`message-injection.md`](message-injection.md), [`discovery-and-handshake.md`](discovery-and-handshake.md).

## Verify & score

- A cross-tenant subscribe returning another tenant's live stream is a **High** BOLA — evidence = the replayed frame + the foreign data received on the low-priv socket.
- A privileged message-type accepted from a low-priv socket is a **High** BFLA.
- Run the full role×message-type matrix so a socket that correctly rejects every cross-role frame is an *evidenced* strong-negative, not an untested surface.
