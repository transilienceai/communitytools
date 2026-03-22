# Playwright Tool

Browser automation tool for pentest-executor agents. Enables client-side vulnerability testing including XSS, CSRF, clickjacking, and DOM-based attacks.

## Purpose

Provides headless browser automation for pentest-executor agents to:
- Navigate web applications and interact with elements
- Capture screenshots and videos as evidence
- Intercept and analyze network requests
- Execute JavaScript in browser context
- Test client-side vulnerabilities
- Bypass client-side validation

## Installation

```bash
./tools/playwright/install.sh
```

This will:
1. Install Node.js (if not present)
2. Install Playwright Python package
3. Install Playwright browsers (Chromium, Firefox, WebKit)
4. Install system dependencies (Linux only)
5. Create tool configuration

## Usage

### Verify Installation

```bash
./tools/playwright/run.sh
```

### Integration with Pentest-Executor

Pentest-executor agents automatically use Playwright via MCP tools:

```yaml
tools: [mcp__plugin_playwright_playwright__*, Bash, Read, Write]
```

### Available MCP Tools

**Navigation:**
- `browser_navigate` - Navigate to URL
- `browser_navigate_back` - Go back in history
- `browser_tabs` - Manage tabs (list, new, close, select)

**Interaction:**
- `browser_click` - Click elements (left, right, double-click)
- `browser_type` - Type text into editable elements
- `browser_fill_form` - Fill multiple form fields
- `browser_hover` - Hover over elements
- `browser_drag` - Drag and drop
- `browser_select_option` - Select dropdown options
- `browser_press_key` - Press keyboard keys
- `browser_file_upload` - Upload files

**Inspection:**
- `browser_snapshot` - Capture accessibility snapshot
- `browser_take_screenshot` - Take screenshots (full page or element)
- `browser_console_messages` - Get console output
- `browser_network_requests` - Get network activity

**Execution:**
- `browser_evaluate` - Execute JavaScript
- `browser_run_code` - Run Playwright code snippets

**Utilities:**
- `browser_wait_for` - Wait for text/events
- `browser_handle_dialog` - Handle alerts/confirms
- `browser_resize` - Resize browser window
- `browser_close` - Close browser

## Use Cases

### XSS Testing
```python
# Navigate to target
browser_navigate(url="https://target.com/search?q=test")

# Inject XSS payload
browser_type(ref="input#search", text="<script>alert(1)</script>")
browser_click(ref="button[type=submit]")

# Check for execution
browser_snapshot()
browser_console_messages(level="error")
```

### CSRF Testing
```python
# Navigate to attacker page
browser_navigate(url="file:///tmp/csrf_poc.html")

# Trigger CSRF
browser_click(ref="button#exploit")

# Verify action
browser_network_requests()
browser_take_screenshot(filename="csrf_proof.png")
```

### Clickjacking Testing
```python
# Load clickjacking PoC
browser_navigate(url="file:///tmp/clickjacking_poc.html")

# Verify iframe loads
browser_snapshot()

# Test frame busting bypass
browser_evaluate(function="() => { return window.top === window; }")
```

### Authentication Bypass
```python
# Test client-side validation bypass
browser_navigate(url="https://target.com/login")

# Modify form validation
browser_evaluate(
    element="login form",
    function="(form) => { form.removeAttribute('onsubmit'); }"
)

# Submit with invalid data
browser_fill_form(fields=[
    {"name": "username", "type": "textbox", "value": "admin", "ref": "input#user"},
    {"name": "password", "type": "textbox", "value": "' OR '1'='1", "ref": "input#pass"}
])
browser_click(ref="button[type=submit]")
```

## Capabilities

- **Browser Automation**: Full browser control (navigate, click, type, etc.)
- **Screenshot Capture**: Visual evidence of vulnerabilities
- **Network Interception**: Analyze requests/responses
- **JavaScript Execution**: Manipulate DOM and test client-side logic
- **Form Interaction**: Test input validation and submission
- **Multi-browser**: Chromium, Firefox, WebKit

## Attack Types Supported

- **Client-Side Injection**: XSS, DOM XSS, template injection
- **CSRF**: Cross-site request forgery testing
- **Clickjacking**: UI redressing attacks
- **Client-Side Validation**: Bypass validation logic
- **Session Management**: Test session handling
- **Authentication**: Test login flows and bypasses
- **Prototype Pollution**: JavaScript object manipulation

## Configuration

Located in `tools/playwright/config.json`:

```json
{
  "name": "playwright",
  "version": "1.x.x",
  "installed": true,
  "browsers": ["chromium", "firefox", "webkit"],
  "capabilities": [...],
  "mcp_integration": true,
  "use_cases": [...]
}
```

## Troubleshooting

### Browsers not installed
```bash
playwright install
```

### System dependencies missing (Linux)
```bash
playwright install-deps
```

### MCP integration not working
Check `.playwright-mcp/` directory exists and is configured correctly.

### Permission errors
Ensure scripts are executable:
```bash
chmod +x tools/playwright/*.sh
```

## References

- [Playwright Documentation](https://playwright.dev/python/)
- [Playwright MCP Integration](https://github.com/executeautomation/mcp-playwright)
- Pentest-executor agent: `.claude/agents/pentester-executor.md`
- XSS attack guide: `.claude/skills/pentest/attacks/client-side/xss/`
- CSRF attack guide: `.claude/skills/pentest/attacks/client-side/csrf/`
