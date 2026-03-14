# Business Logic Vulnerabilities - Quick Start Guide

> **Fast reference for rapid vulnerability identification and exploitation**
>
> Time to master: 5 minutes | Time to exploit: 2-30 minutes per lab

---

## Table of Contents

1. [1-Minute Vulnerability Identification](#1-minute-identification)
2. [Common Business Logic Flaws](#common-flaws)
3. [Quick Burp Suite Commands](#burp-commands)
4. [Rapid Exploitation Techniques](#rapid-exploitation)
5. [Speed-Run Strategies for All 11 Labs](#speed-run)

---

## 1-Minute Vulnerability Identification Checklist {#1-minute-identification}

### Quick Assessment Questions

Ask yourself these questions when testing any application:

#### Financial Operations
- [ ] Does the client send price data? (Check POST parameters)
- [ ] Can I send negative quantities or amounts?
- [ ] Are there maximum limits on quantities? What happens at the limit?
- [ ] Can I apply multiple discount codes?
- [ ] Do gift cards/vouchers work with discounts?

#### Workflow & State
- [ ] Can I skip steps in multi-step processes?
- [ ] Can I replay confirmation/success requests?
- [ ] Can I change my email/role without verification?
- [ ] Are state transitions validated?

#### Input Validation
- [ ] What happens with extreme values (0, -1, 999999, INT_MAX)?
- [ ] Are all numeric inputs validated for ranges?
- [ ] Can I manipulate client-side data that affects server logic?

#### Authentication & Authorization
- [ ] Can I change privileged attributes (email domain, role)?
- [ ] Are all authorization checks consistent?
- [ ] Can I access admin functions through direct URLs?

---

## Common Business Logic Flaws {#common-flaws}

### Priority-Based Testing Order

Test these in order from most common to least:

| Priority | Flaw Type | Time to Test | Success Rate |
|----------|-----------|--------------|--------------|
| **HIGH** | Client-side price/quantity trust | 30 seconds | 40% |
| **HIGH** | Negative quantity/price | 1 minute | 35% |
| **HIGH** | Workflow step skipping | 2 minutes | 30% |
| **MEDIUM** | Discount/coupon stacking | 3 minutes | 25% |
| **MEDIUM** | Email domain verification bypass | 5 minutes | 20% |
| **MEDIUM** | Inconsistent validation | 5 minutes | 15% |
| **LOW** | Integer overflow | 20 minutes | 10% |
| **LOW** | Gift card/voucher loops | 30 minutes | 5% |

---

## Quick Burp Suite Commands {#burp-commands}

### Essential Burp Suite Workflow

#### 1. Capture and Analyze (30 seconds)

```plaintext
Proxy → HTTP History → Filter by:
- Method: POST
- Search: "cart|checkout|price|quantity|coupon|email|order"
```

**Quick keyboard shortcuts:**
- `Ctrl+R` / `Cmd+R`: Send to Repeater
- `Ctrl+I` / `Cmd+I`: Send to Intruder
- `Ctrl+Shift+B` / `Cmd+Shift+B`: Base64 decode

#### 2. Rapid Parameter Testing in Repeater

**Test these parameter modifications immediately:**

```http
# Original request
POST /cart HTTP/1.1
productId=1&quantity=1&price=133700

# Test 1: Client-side price manipulation
productId=1&quantity=1&price=1

# Test 2: Negative quantity
productId=1&quantity=-100&price=133700

# Test 3: Extreme values
productId=1&quantity=999999&price=133700
productId=1&quantity=0&price=133700
```

#### 3. Intruder Speed Configurations

**For automated exploitation:**

```plaintext
Intruder → Resource Pool Settings:
- Maximum concurrent requests: 1 (for sequential operations)
- Delay between requests: 0ms
- Payload type: Null payloads (for repeating same request)
```

---

## Rapid Exploitation Techniques {#rapid-exploitation}

### Technique 1: Price Manipulation (2 minutes)

**Target:** Applications with client-side pricing

```plaintext
1. Burp → Find POST /cart request
2. Send to Repeater (Ctrl+R)
3. Change price=133700 to price=1
4. Send → Refresh browser cart
5. Checkout if total is affordable
```

**Success Indicators:**
- Modified price accepted
- Cart shows reduced total
- No server-side validation error

---

### Technique 2: Negative Quantity Attack (5 minutes)

**Target:** Applications accepting quantity values

```plaintext
1. Add expensive item (quantity=1) to cart
2. Burp → Find POST /cart for cheap item
3. Send to Repeater
4. Calculate: negative_qty = -(expensive_price / cheap_price)
5. Change quantity=1 to quantity=[negative_qty]
6. Send → Check cart total
7. Adjust until total < your credit
```

**Quick calculation example:**
```
Expensive: $1,337
Cheap: $10
Negative quantity needed: -($1,337 / $10) = -134
Result: $1,337 + ($10 × -134) = $1,337 - $1,340 = -$3
```

---

### Technique 3: Workflow Bypass (3 minutes)

**Target:** Multi-step processes (checkout, registration)

```plaintext
1. Complete legitimate workflow once
2. Burp → Find final confirmation request (GET /order-confirmation)
3. Send to Repeater
4. Clear cart → Add expensive item (DON'T checkout)
5. Replay confirmation request from Repeater
6. Order confirmed without payment!
```

---

### Technique 4: Coupon Stacking (5 minutes)

**Target:** Applications with multiple promo codes

```plaintext
1. Collect all available coupon codes
2. Apply coupon A → Try applying A again (should fail)
3. Apply coupon B → Try applying A again (may succeed!)
4. Pattern: A → B → A → B → A → B...
5. Repeat until total is affordable
```

**Burp automation:**
```plaintext
1. Send POST /cart/coupon to Repeater
2. Create 2 tabs: one for each coupon
3. Alternate sending requests: Tab1 → Tab2 → Tab1 → Tab2
```

---

### Technique 5: Email Domain Bypass (5 minutes)

**Target:** Role-based access via email domains

```plaintext
1. Register with any email (user@exploit-xxx.com)
2. Confirm registration
3. Login → Navigate to account settings
4. Change email to privileged domain (user@company.com)
5. Check if admin access granted (no verification required!)
```

---

### Technique 6: Integer Overflow (20 minutes)

**Target:** Applications with 32-bit integer arithmetic

```plaintext
1. Find expensive item price (e.g., $1,337 = 133,700 cents)
2. Calculate overflow point: 2,147,483,647 / 133,700 = ~16,064 items
3. Burp Intruder: Null payloads, Continue indefinitely
4. Resource pool: Max concurrent = 1 (CRITICAL!)
5. Monitor cart until negative value appears
6. Stop → Fine-tune to affordable positive value
```

**Quick reference:**
- 32-bit signed max: 2,147,483,647
- Overflow formula: `max_int / item_price = items_needed`

---

### Technique 7: Gift Card Loop (30 minutes)

**Target:** Gift card systems with discount codes

```plaintext
1. Get discount coupon (e.g., SIGNUP30 = 30% off)
2. Buy $10 gift card with coupon ($7 spent)
3. Redeem gift card ($10 gained)
4. Net profit: $3 per cycle
5. Automate with Burp Macro (see detailed guide)
```

---

## Speed-Run Strategies for All 11 Labs {#speed-run}

### Lab-by-Lab Quick Reference

| Lab | Difficulty | Time | Key Technique | Quick Win |
|-----|------------|------|---------------|-----------|
| **1. Excessive Trust in Client-Side Controls** | ⭐ | 2 min | Price manipulation | Change `price` param to 1 |
| **2. High-Level Logic Vulnerability** | ⭐ | 5 min | Negative quantity | Use `-124` quantity on cheap item |
| **3. Inconsistent Security Controls** | ⭐ | 5 min | Email change bypass | Change email to `@dontwannacry.com` |
| **4. Flawed Enforcement of Business Rules** | ⭐ | 5 min | Coupon stacking | Alternate NEWCUST5 & SIGNUP30 |
| **5. Insufficient Workflow Validation** | ⭐ | 3 min | Workflow skip | Replay confirmation URL |
| **6. Low-Level Logic Flaw** | ⭐⭐ | 20 min | Integer overflow | Burp Intruder with 323 requests |
| **7. Infinite Money Logic Flaw** | ⭐⭐ | 30 min | Gift card loop | Burp Macro automation |
| **8. Authentication Bypass via Flawed State Machine** | ⭐⭐ | 10 min | State manipulation | Role change without validation |
| **9. Flawed Domain Validation** | ⭐⭐ | 10 min | Subdomain bypass | Use attacker-controlled subdomain |
| **10. Inconsistent Handling of Exceptional Input** | ⭐⭐ | 15 min | Edge case testing | Test null, empty, extreme values |
| **11. Weak Isolation on Dual-Use Endpoint** | ⭐⭐⭐ | 20 min | Endpoint confusion | Access admin via user endpoint |

---

### Speed-Run Strategy by Time Available

#### If You Have 15 Minutes (Labs 1-5)

**Optimal order for maximum learning:**

1. **Lab 1** (2 min): Price manipulation basics
2. **Lab 5** (3 min): Workflow understanding
3. **Lab 2** (5 min): Negative values
4. **Lab 4** (5 min): Business rule flaws

**Total: 15 minutes, 4 labs complete**

---

#### If You Have 1 Hour (Labs 1-7)

**Include practitioner-level challenges:**

1. All Apprentice labs (20 min)
2. **Lab 6**: Integer overflow (20 min)
3. **Lab 7**: Gift card loop setup (20 min, let run in background)

**Total: 60 minutes, 7 labs complete**

---

#### If You Have 3 Hours (All 11 Labs)

**Complete mastery path:**

1. **Phase 1** (30 min): Labs 1-5 (Apprentice)
2. **Phase 2** (1 hour): Labs 6-7 (Practitioner arithmetic)
3. **Phase 3** (1.5 hours): Labs 8-11 (Advanced practitioner)

**Total: 3 hours, all 11 labs complete**

---

## Quick Reference Tables

### Common POST Parameters to Test

| Parameter | Test Values | Expected Behavior | Vulnerable If |
|-----------|-------------|-------------------|---------------|
| `price` | 1, 0, -1 | Reject modification | Accepts client value |
| `quantity` | -1, 0, 999999 | Reject invalid | Accepts negative/extreme |
| `productId` | Other IDs | No impact on price | Allows price override |
| `coupon` | Multiple codes | One per order | Allows stacking |
| `email` | Privileged domain | Require verification | No re-verification |
| `role` | admin, superuser | Authorization check | Direct modification works |

---

### Burp Intruder Payload Types Cheat Sheet

| Payload Type | Use Case | Configuration |
|--------------|----------|---------------|
| **Null payloads** | Repeat same request N times | Set count or "Continue indefinitely" |
| **Numbers** | Test numeric ranges | From: -999, To: 999999, Step: 1 |
| **Simple list** | Test multiple values | Custom list: 0, -1, 999999, NULL |
| **Character substitution** | Bypass filters | Replace chars in string |

---

### Critical Burp Settings for Business Logic Testing

```plaintext
Resource Pool:
✅ Maximum concurrent requests: 1 (for sequential logic)
✅ Delay between requests: 0ms (unless rate limited)

Intruder Attack Type:
✅ Sniper (single parameter testing)
✅ Pitchfork (parallel parameter lists)

Session Handling:
✅ Automatic CSRF token handling
✅ Cookie jar enabled
✅ Macros for complex workflows
```

---

## Exploitation Patterns

### Pattern 1: Arithmetic Manipulation

```plaintext
IDENTIFY: Numeric parameters (price, quantity, discount)
TEST: Negative, zero, extreme values
EXPLOIT: Find profitable calculation flaw
AUTOMATE: Burp Repeater or Intruder
```

---

### Pattern 2: State Machine Violation

```plaintext
IDENTIFY: Multi-step workflows
MAP: Document all steps and requests
TEST: Skip steps, replay out of order
EXPLOIT: Bypass validation or payment
```

---

### Pattern 3: Business Rule Abuse

```plaintext
IDENTIFY: Promotional features (coupons, gift cards)
TEST: Stacking, looping, combining
CALCULATE: Profit per cycle
AUTOMATE: Burp Macro for loops
```

---

### Pattern 4: Validation Inconsistencies

```plaintext
IDENTIFY: Input validation points
TEST: Different endpoints, different stages
FIND: Weak validation point
EXPLOIT: Route through weak point
```

---

## Time-Saving Tips

### Burp Suite Pro Features

If you have Burp Suite Professional:

1. **Scanner Audit Items**: Look for "input returned in response" (potential parameter extraction)
2. **Collaborator**: Test for out-of-band interactions
3. **Active Scan**: May catch some obvious validation issues

### Browser Extensions

Recommended for speed:

- **Wappalyzer**: Identify tech stack quickly
- **Cookie Editor**: Quickly modify session cookies
- **FoxyProxy**: Fast proxy switching

### Note-Taking Template

Quick notes format for each lab:

```markdown
## Lab X: [Name]
- **Vuln Type**: [Price/Quantity/Workflow/etc]
- **Key Request**: POST /cart
- **Exploit Param**: price=1
- **Time Taken**: 2 min
- **Notes**: Change price parameter, no validation
```

---

## Common Error Messages and What They Mean

| Error Message | Meaning | Next Step |
|---------------|---------|-----------|
| "Coupon already applied" | Duplicate prevention | Try different coupon |
| "Invalid quantity" | Range validation | Test boundary values |
| "Payment failed" | Price validation working | Try different approach |
| "Admin access only" | Authorization check | Find privilege escalation |
| "Invalid session" | Session expired | Re-login and retry |

---

## Keyboard Shortcuts for Speed

### Burp Suite

```plaintext
Ctrl+R (Cmd+R)       - Send to Repeater
Ctrl+I (Cmd+I)       - Send to Intruder
Ctrl+Shift+R         - Send to Repeater (new tab)
Ctrl+Space           - Send request in Repeater
Ctrl+U               - URL decode
Ctrl+Shift+U         - URL encode
Ctrl+B               - Base64 decode
Ctrl+Shift+B         - Base64 encode
```

### Browser (with Burp)

```plaintext
Ctrl+Shift+P         - Open private/incognito window
Ctrl+Shift+Delete    - Clear cache/cookies
F12                  - Open DevTools
Ctrl+R               - Refresh page
Ctrl+Shift+R         - Hard refresh (bypass cache)
```

---

## Quick Vulnerability Assessment Checklist

Print this and check off as you test:

```plaintext
FINANCIAL OPERATIONS:
[ ] Price manipulation (client-side)
[ ] Negative quantities/amounts
[ ] Integer overflow on totals
[ ] Coupon/discount stacking
[ ] Gift card/voucher loops

WORKFLOW & STATE:
[ ] Skip checkout/payment steps
[ ] Replay confirmation requests
[ ] Out-of-order step execution
[ ] State machine bypasses

INPUT VALIDATION:
[ ] Negative values accepted
[ ] Zero values accepted
[ ] Extreme values (999999, INT_MAX)
[ ] Null/empty values
[ ] Type confusion (string vs int)

AUTHENTICATION & AUTHORIZATION:
[ ] Email domain bypass
[ ] Role modification without validation
[ ] Direct URL access to admin functions
[ ] Session/token replay
[ ] Privilege escalation paths

BUSINESS RULES:
[ ] Promotional abuse
[ ] Rate limiting gaps
[ ] Maximum limit bypasses
[ ] Exclusive rule violations
```

---

## Final Speed Tips

### Before Starting Any Lab:

1. **Read objective** (10 seconds)
2. **Note credentials** (5 seconds)
3. **Enable Burp Proxy** (5 seconds)
4. **Login and explore** (30 seconds)
5. **Start testing** (immediately)

### While Testing:

1. **Test obvious first**: Price, quantity, negative values
2. **Use Repeater**: Faster than browser
3. **Monitor HTTP history**: Watch for patterns
4. **Take quick notes**: Document findings immediately

### When Stuck:

1. **Check HTTP history**: Look for missed requests
2. **Re-read objective**: Confirm what you're trying to achieve
3. **Try extreme values**: 0, -1, 999999, null
4. **Look for hidden parameters**: Check page source, JavaScript

---

## Success Metrics

Track your progress:

```plaintext
Beginner:    5+ labs in 2 hours
Intermediate: 8+ labs in 2 hours
Advanced:    11 labs in 2 hours
Expert:      11 labs in 1 hour
```

---

## Next Steps

After completing quick exploitation:

1. Review detailed lab guides for deeper understanding
2. Read the comprehensive cheat sheet for all payloads
3. Study the resources document for real-world applications
4. Practice on bug bounty programs
5. Build your own vulnerable app to understand defenses

---

**Ready to start?** Pick Lab 1 and go! Remember: Speed comes from pattern recognition, not rushing.

**Quick Start Command:**
```bash
# Start with the easiest lab
Navigate to: https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-excessive-trust-in-client-side-controls
Login: wiener:peter
Find: POST /cart request
Change: price=1
Win: Complete checkout
```

Good luck and happy hacking!
