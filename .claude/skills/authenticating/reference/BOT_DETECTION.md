# Bot Detection Evasion & Behavioral Biometrics

Comprehensive guide to testing bot detection systems and behavioral biometrics during authorized security assessments.

---

## Bot Detection Technologies (2026)

### 1. Behavioral Biometrics
- Mouse movement patterns
- Keystroke dynamics
- Touch interactions (mobile)
- Scroll behavior
- Timing analysis

### 2. Browser Fingerprinting
- Canvas fingerprinting
- WebGL fingerprinting
- Audio context fingerprinting
- Font detection
- Screen resolution/color depth

### 3. Automation Detection
- WebDriver detection
- Headless browser detection
- Browser automation flags
- JavaScript property checks

### 4. Network Analysis
- IP reputation
- Request patterns
- Header consistency
- TLS fingerprinting

### 5. AI/ML-Based Detection
- Real-time behavioral scoring
- Anomaly detection
- Pattern recognition
- Proof-of-human scores

---

## Testing Methodology

### Phase 1: Detection System Identification

```
Identify bot detection mechanisms:
1. Check for known services (PerimeterX, DataDome, Akamai, Cloudflare)
2. Analyze JavaScript for detection code
3. Monitor network requests for scoring endpoints
4. Test basic automation (will it trigger detection?)
5. Document detection triggers
```

---

## Evasion Techniques

## Technique 1: Behavioral Biometrics Simulation

### Mouse Movement Patterns

**Natural Movement Simulation**:

```javascript
/**
 * Generate natural mouse movement trajectory
 * Uses Bezier curves and randomness to simulate human movement
 */
function generateNaturalPath(startX, startY, endX, endY) {
    const points = [];
    const steps = 50 + Math.floor(Math.random() * 50);  // 50-100 steps

    for (let i = 0; i <= steps; i++) {
        const t = i / steps;

        // Bezier curve for smooth path
        const x = cubicBezier(startX, startX + (endX - startX) * 0.3, startX + (endX - startX) * 0.7, endX, t);
        const y = cubicBezier(startY, startY + (endY - startY) * 0.3, startY + (endY - startY) * 0.7, endY, t);

        // Add natural variance (micro-jitter)
        const jitterX = (Math.random() - 0.5) * 2;
        const jitterY = (Math.random() - 0.5) * 2;

        points.push({
            x: x + jitterX,
            y: y + jitterY,
            timestamp: Date.now() + (i * (10 + Math.random() * 5))  // Varied timing
        });
    }

    return points;
}

function cubicBezier(p0, p1, p2, p3, t) {
    const u = 1 - t;
    return u * u * u * p0 +
           3 * u * u * t * p1 +
           3 * u * t * t * p2 +
           t * t * t * p3;
}

// Easing function for natural acceleration/deceleration
function easeInOutQuad(t) {
    return t < 0.5 ? 2 * t * t : -1 + (4 - 2 * t) * t;
}
```

**Playwright Implementation**:

```javascript
// Move mouse naturally
async function moveMouseNaturally(page, startX, startY, endX, endY) {
    const path = generateNaturalPath(startX, startY, endX, endY);

    for (const point of path) {
        await page.mouse.move(point.x, point.y);
        await page.waitForTimeout(Math.random() * 5 + 5);  // 5-10ms per step
    }
}

// Usage
await moveMouseNaturally(page, 100, 100, 500, 300);
```

### Keystroke Dynamics

**Natural Typing Simulation**:

```javascript
/**
 * Simulate human typing with natural rhythm
 */
async function typeNaturally(page, selector, text) {
    const element = await page.$(selector);

    for (let i = 0; i < text.length; i++) {
        const char = text[i];

        // Variable delay between keystrokes (80-200ms)
        const baseDelay = 80 + Math.random() * 120;

        // Longer delay after space (word boundary)
        const delay = char === ' ' ? baseDelay * 1.5 : baseDelay;

        // Occasional longer pause (thinking)
        const thinkingPause = Math.random() < 0.1 ? Math.random() * 500 : 0;

        await element.type(char, { delay: delay + thinkingPause });

        // Occasional typo + correction
        if (Math.random() < 0.05) {  // 5% typo rate
            await page.keyboard.press('Backspace');
            await page.waitForTimeout(100 + Math.random() * 100);
            await element.type(char, { delay: baseDelay });
        }
    }
}

// Usage
await typeNaturally(page, '#username', 'testuser');
```

### Scroll Behavior

**Natural Scrolling**:

```javascript
/**
 * Simulate human scrolling with acceleration/deceleration
 */
async function scrollNaturally(page, targetY) {
    const currentY = await page.evaluate(() => window.scrollY);
    const distance = targetY - currentY;
    const steps = 30 + Math.floor(Math.random() * 20);

    for (let i = 0; i <= steps; i++) {
        const progress = i / steps;

        // Ease in-out for natural acceleration
        const eased = easeInOutCubic(progress);
        const scrollY = currentY + (distance * eased);

        await page.evaluate((y) => window.scrollTo(0, y), scrollY);

        // Variable delay (faster in middle, slower at start/end)
        const delay = progress < 0.2 || progress > 0.8 ? 30 : 15;
        await page.waitForTimeout(delay + Math.random() * 10);
    }

    // Micro-adjustment at end (overshoot slightly, then correct)
    if (Math.random() < 0.3) {
        const overshoot = (Math.random() - 0.5) * 50;
        await page.evaluate((y) => window.scrollTo(0, y), targetY + overshoot);
        await page.waitForTimeout(50);
        await page.evaluate((y) => window.scrollTo(0, y), targetY);
    }
}

function easeInOutCubic(t) {
    return t < 0.5 ? 4 * t * t * t : 1 - Math.pow(-2 * t + 2, 3) / 2;
}

// Usage
await scrollNaturally(page, 1000);  // Scroll to Y=1000
```

### Touch Interactions (Mobile)

**Natural Touch Simulation**:

```javascript
/**
 * Simulate natural touch events
 */
async function tapNaturally(page, x, y) {
    // Slight position variance (finger isn't perfectly accurate)
    const jitterX = (Math.random() - 0.5) * 10;
    const jitterY = (Math.random() - 0.5) * 10;

    const tapX = x + jitterX;
    const tapY = y + jitterY;

    // Touch down
    await page.touchscreen.tap(tapX, tapY);

    // Variable touch duration (100-300ms)
    await page.waitForTimeout(100 + Math.random() * 200);
}

async function swipeNaturally(page, startX, startY, endX, endY) {
    // Generate swipe path
    const path = generateNaturalPath(startX, startY, endX, endY);

    // Start touch
    await page.mouse.move(startX, startY);
    await page.mouse.down();

    // Move along path
    for (const point of path) {
        await page.mouse.move(point.x, point.y);
        await page.waitForTimeout(10 + Math.random() * 5);
    }

    // End touch
    await page.mouse.up();
}
```

---

## Technique 2: Browser Fingerprint Randomization

### Canvas Fingerprinting Evasion

```javascript
/**
 * Randomize canvas fingerprint
 */
async function randomizeCanvasFingerprint(page) {
    await page.evaluateOnNewDocument(() => {
        const originalGetContext = HTMLCanvasElement.prototype.getContext;

        HTMLCanvasElement.prototype.getContext = function(type, ...args) {
            const context = originalGetContext.apply(this, [type, ...args]);

            if (type === '2d') {
                const originalFillText = context.fillText;

                context.fillText = function(text, x, y, ...rest) {
                    // Add slight noise to canvas rendering
                    const noise = Math.random() * 0.01;
                    return originalFillText.apply(this, [text, x + noise, y + noise, ...rest]);
                };
            }

            return context;
        };
    });
}
```

### WebGL Fingerprinting Evasion

```javascript
/**
 * Randomize WebGL fingerprint
 */
async function randomizeWebGLFingerprint(page) {
    await page.evaluateOnNewDocument(() => {
        const originalGetParameter = WebGLRenderingContext.prototype.getParameter;

        WebGLRenderingContext.prototype.getParameter = function(parameter) {
            // Randomize specific WebGL parameters
            if (parameter === 37445) {  // UNMASKED_VENDOR_WEBGL
                return 'Intel Inc.';  // Or randomize
            }
            if (parameter === 37446) {  // UNMASKED_RENDERER_WEBGL
                return 'Intel Iris OpenGL Engine';  // Or randomize
            }

            return originalGetParameter.apply(this, [parameter]);
        };
    });
}
```

### User-Agent Rotation

```javascript
/**
 * Rotate User-Agent strings
 */
const userAgents = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15'
];

async function setRandomUserAgent(page) {
    const ua = userAgents[Math.floor(Math.random() * userAgents.length)];
    await page.setUserAgent(ua);
}
```

---

## Technique 3: WebDriver Detection Evasion

**Stealth Mode**:

```javascript
/**
 * Hide WebDriver/automation indicators
 */
async function enableStealth(page) {
    // Hide webdriver flag
    await page.evaluateOnNewDocument(() => {
        Object.defineProperty(navigator, 'webdriver', {
            get: () => undefined
        });
    });

    // Hide automation flags
    await page.evaluateOnNewDocument(() => {
        window.chrome = {
            runtime: {}
        };

        Object.defineProperty(navigator, 'plugins', {
            get: () => [1, 2, 3, 4, 5]
        });

        Object.defineProperty(navigator, 'languages', {
            get: () => ['en-US', 'en']
        });

        // Override permissions
        const originalQuery = window.navigator.permissions.query;
        window.navigator.permissions.query = (parameters) => (
            parameters.name === 'notifications' ?
                Promise.resolve({ state: Notification.permission }) :
                originalQuery(parameters)
        );
    });

    // Consistent window.chrome object
    await page.evaluateOnNewDocument(() => {
        window.chrome = {
            runtime: {},
            loadTimes: function() {},
            csi: function() {},
            app: {}
        };
    });
}
```

---

## Technique 4: Timing & Delays

**Human-Like Delays**:

```javascript
/**
 * Random delays that mimic human behavior
 */
async function humanDelay(min = 500, max = 2000) {
    const delay = min + Math.random() * (max - min);
    await new Promise(resolve => setTimeout(resolve, delay));
}

async function microDelay(min = 50, max = 150) {
    const delay = min + Math.random() * (max - min);
    await new Promise(resolve => setTimeout(resolve, delay));
}

async function thinkingPause() {
    // Occasional longer pause (2-5 seconds) simulating thinking
    if (Math.random() < 0.2) {  // 20% chance
        await humanDelay(2000, 5000);
    }
}

// Usage in workflow
await page.goto('https://target.com');
await humanDelay();  // Wait before interacting

await typeNaturally(page, '#username', 'test');
await microDelay();  // Small delay between fields

await thinkingPause();  // Occasional thinking pause

await typeNaturally(page, '#password', 'password');
await humanDelay();

await page.click('button[type="submit"]');
```

---

## Technique 5: Request Pattern Variation

**Natural Request Patterns**:

```javascript
/**
 * Add natural variance to requests
 */
async function addRequestVariance(page) {
    // Random page load delay
    await humanDelay(1000, 3000);

    // Simulate reading page content
    await scrollNaturally(page, 500);
    await humanDelay(2000, 4000);

    // Move mouse around (reading)
    for (let i = 0; i < 3; i++) {
        const x = 200 + Math.random() * 600;
        const y = 200 + Math.random() * 400;
        await moveMouseNaturally(page, 400, 300, x, y);
        await humanDelay(500, 1500);
    }

    // Occasional back/forward navigation
    if (Math.random() < 0.1) {
        await page.goBack();
        await humanDelay();
        await page.goForward();
        await humanDelay();
    }
}
```

---

## Complete Evasion Implementation

### Playwright Stealth Setup

```javascript
/**
 * Complete stealth configuration for Playwright
 */
async function setupStealthBrowser(playwright) {
    const browser = await playwright.chromium.launch({
        headless: false,  // Headless mode is more detectable
        args: [
            '--disable-blink-features=AutomationControlled',
            '--disable-dev-shm-usage',
            '--disable-setuid-sandbox',
            '--no-sandbox',
            '--disable-web-security',
            '--disable-features=IsolateOrigins,site-per-process',
            '--disable-site-isolation-trials'
        ]
    });

    const context = await browser.newContext({
        viewport: {
            width: 1920 + Math.floor(Math.random() * 100),
            height: 1080 + Math.floor(Math.random() * 100)
        },
        userAgent: userAgents[Math.floor(Math.random() * userAgents.length)],
        locale: 'en-US',
        timezoneId: 'America/New_York',
        permissions: ['geolocation', 'notifications'],
        geolocation: { latitude: 40.7128, longitude: -74.0060 },  // NYC
        deviceScaleFactor: 1 + (Math.random() * 0.5)
    });

    const page = await context.newPage();

    // Apply stealth techniques
    await enableStealth(page);
    await randomizeCanvasFingerprint(page);
    await randomizeWebGLFingerprint(page);

    return { browser, context, page };
}

// Usage
const { browser, context, page } = await setupStealthBrowser(playwright);

// Natural browsing
await page.goto('https://target.com');
await addRequestVariance(page);

// Human-like form interaction
await moveMouseNaturally(page, 100, 100, 300, 250);
await page.click('#username');
await typeNaturally(page, '#username', 'testuser');

await humanDelay();

await page.click('#password');
await typeNaturally(page, '#password', 'password123');

await thinkingPause();

await page.click('button[type="submit"]');
```

---

## Detection System Testing

### Test: Automation Detection

```javascript
/**
 * Check if automation is detected
 */
async function testAutomationDetection(page) {
    const results = await page.evaluate(() => {
        return {
            webdriver: navigator.webdriver,
            chrome: !!window.chrome,
            permissions: navigator.permissions,
            plugins: navigator.plugins.length,
            languages: navigator.languages
        };
    });

    console.log('Detection results:', results);

    if (results.webdriver === true) {
        console.warn('[!] WebDriver flag detected');
    }

    if (!results.chrome) {
        console.warn('[!] Missing window.chrome object');
    }

    return results;
}
```

### Test: Behavioral Scoring

```javascript
/**
 * Monitor behavioral scoring endpoints
 */
async function monitorBehavioralScoring(page) {
    page.on('response', async (response) => {
        const url = response.url();

        // Common bot detection services
        const detectionServices = [
            'perimeterx',
            'datadome',
            'px-cloud',
            'akamai',
            'cloudflare',
            'recaptcha',
            'hcaptcha'
        ];

        if (detectionServices.some(service => url.includes(service))) {
            console.log(`[*] Detection service request: ${url}`);

            try {
                const body = await response.json();
                console.log('[*] Response:', body);

                // Check for risk scores
                if (body.score || body.risk_score || body.bot_score) {
                    console.log(`[!] Risk score detected:`, body);
                }
            } catch (e) {
                // Not JSON
            }
        }
    });
}
```

---

## Testing Checklist

### Behavioral Biometrics

- [ ] Mouse movements are natural (curves, not straight lines)
- [ ] Keystroke timing varies realistically
- [ ] Scroll behavior includes acceleration/deceleration
- [ ] Random pauses simulate thinking/reading
- [ ] Touch interactions have position variance
- [ ] Page reading time is realistic

### Fingerprinting

- [ ] Canvas fingerprint randomized
- [ ] WebGL fingerprint randomized
- [ ] User-Agent varies across sessions
- [ ] Screen resolution varies slightly
- [ ] Timezone and locale set appropriately
- [ ] Plugins list appears legitimate

### Automation Detection

- [ ] navigator.webdriver is hidden/undefined
- [ ] window.chrome object present
- [ ] Permissions API behaves normally
- [ ] Plugins array populated
- [ ] Languages array realistic

### Request Patterns

- [ ] Delays between requests vary
- [ ] Request headers consistent with browser
- [ ] Navigation patterns realistic
- [ ] Resource loading order natural
- [ ] TLS fingerprint matches User-Agent

---

## Common Detection Triggers

**High Risk Indicators**:
- Constant timing between actions
- Perfectly straight mouse movements
- Instant typing (no keystroke delays)
- No scroll behavior
- WebDriver flag present
- Headless browser indicators
- Missing browser objects
- Inconsistent fingerprints

**Medium Risk Indicators**:
- Fast page navigation
- No mouse movement
- Unusual request patterns
- Known datacenter IPs
- Suspicious User-Agent

---

## Remediation Recommendations

**For Defenders** (Implementing Bot Detection):

```javascript
// Example: Behavioral biometrics scoring

class BehavioralBiometricsScorer {
    constructor() {
        this.mouseEvents = [];
        this.keyEvents = [];
        this.scrollEvents = [];
    }

    trackMouseMovement(event) {
        this.mouseEvents.push({
            x: event.clientX,
            y: event.clientY,
            timestamp: Date.now()
        });
    }

    calculateBotScore() {
        let score = 0;  // 0 = human, 100 = bot

        // Check mouse movement naturalness
        if (this.hasUnaturalMouseMovement()) {
            score += 30;
        }

        // Check keystroke patterns
        if (this.hasRoboticTyping()) {
            score += 25;
        }

        // Check for WebDriver
        if (navigator.webdriver) {
            score += 45;
        }

        // Check timing consistency
        if (this.hasConstantTiming()) {
            score += 20;
        }

        return Math.min(score, 100);
    }

    hasUnaturalMouseMovement() {
        if (this.mouseEvents.length < 10) return true;

        // Check for straight-line movements
        const straightLines = this.detectStraightLines(this.mouseEvents);
        return straightLines > 0.8;  // 80% straight lines = bot
    }

    hasRoboticTyping() {
        if (this.keyEvents.length < 5) return false;

        // Check keystroke timing variance
        const timings = [];
        for (let i = 1; i < this.keyEvents.length; i++) {
            timings.push(this.keyEvents[i].timestamp - this.keyEvents[i-1].timestamp);
        }

        const variance = this.calculateVariance(timings);
        return variance < 50;  // Low variance = robotic
    }
}
```

---

## Tools & Resources

**Browser Automation**:
- Playwright (with stealth)
- Puppeteer Stealth
- Selenium with undetected-chromedriver

**Fingerprint Tools**:
- BrowserLeaks.com
- AmIUnique
- Panopticlick

**References**:
- [Behavioral Biometrics Research](https://www.researchgate.net/publication/336270420_A_Deep_Learning_Approach_to_Web_Bot_Detection_Using_Mouse_Behavioral_Biometrics)
- [Roundtable Bot Detection 2026](https://www.biometricupdate.com/202508/roundtable-launches-system-to-detect-bots-using-behavioral-biometrics)
- [Bot Detection Deep Learning](https://dl.acm.org/doi/10.1145/3447815)
