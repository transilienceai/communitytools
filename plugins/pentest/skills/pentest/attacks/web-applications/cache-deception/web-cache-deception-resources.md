# Web Cache Deception - Comprehensive Resources

## Table of Contents
1. [Official Documentation](#official-documentation)
2. [Research Papers and Articles](#research-papers-and-articles)
3. [OWASP Resources](#owasp-resources)
4. [CVE Examples and Advisories](#cve-examples-and-advisories)
5. [Tools and Frameworks](#tools-and-frameworks)
6. [Video Tutorials and Walkthroughs](#video-tutorials-and-walkthroughs)
7. [Secure Coding Best Practices](#secure-coding-best-practices)
8. [CDN-Specific Documentation](#cdn-specific-documentation)
9. [Testing Methodologies](#testing-methodologies)
10. [Community Resources](#community-resources)

---

## Official Documentation

### PortSwigger Web Security Academy

**Main Topic Page:**
- URL: https://portswigger.net/web-security/web-cache-deception
- Comprehensive guide to web cache deception vulnerabilities
- Covers all attack vectors and exploitation techniques
- Includes interactive labs for hands-on practice

**Learning Path:**
- URL: https://portswigger.net/web-security/learning-paths/web-cache-deception
- Structured curriculum from beginner to advanced
- 4 deliberately vulnerable labs
- Progression: Apprentice → Practitioner levels

**Lab List:**
1. Exploiting path mapping for web cache deception
2. Exploiting path delimiters for web cache deception
3. Exploiting origin server normalization for web cache deception
4. Exploiting cache server normalization for web cache deception

**Delimiter Reference:**
- URL: https://portswigger.net/web-security/web-cache-deception/wcd-lab-delimiter-list
- Complete list of delimiters for testing
- Both raw and URL-encoded versions
- Essential for lab completion

**Request Smuggling + Cache Deception:**
- URL: https://portswigger.net/web-security/request-smuggling/exploiting/lab-perform-web-cache-deception
- Advanced lab combining two vulnerability classes
- CL.TE smuggling technique
- Demonstrates complex attack chains

---

## Research Papers and Articles

### "Gotta Cache 'em All: Bending the Rules of Web Cache Exploitation"

**Primary Research (2024):**
- URL: https://portswigger.net/research/gotta-cache-em-all
- Author: Martin Doyhenard, PortSwigger Research Team
- Presented: Black Hat USA 2024
- Last Updated: January 8, 2026

**Key Contributions:**
- Discovered new URL parsing discrepancies across frameworks
- Identified cache normalization vulnerabilities
- Documented CDN-specific behaviors
- Introduced cache-what-where attack chaining
- Demonstrated real-world impact on major platforms

**Technical Highlights:**
- Path mapping discrepancies in REST vs traditional routing
- Delimiter confusion across Java Spring, Rails, PHP frameworks
- Normalization inconsistencies in URL decoding
- Cache key manipulation techniques
- Combining with open redirects and XSS

---

### "Web Cache Deception Escalates!" (USENIX 2022)

**Academic Research:**
- URL: https://www.usenix.org/system/files/sec22-mirheidari.pdf
- Authors: Seyed Ali Mirheidari, et al.
- Conference: USENIX Security Symposium 2022

**Key Findings:**
- Systematic analysis of web cache deception attack surface
- Measurement study across 340 websites
- Identification of vulnerable patterns in popular CDNs
- Attack automation and detection methodologies
- Real-world exploitation case studies

**Impact Assessment:**
- 20% of tested sites vulnerable to basic attacks
- Financial, healthcare, and e-commerce sectors most affected
- Long-term cache poisoning implications
- User privacy and data exposure risks

---

### Original Web Cache Deception (2017)

**Seminal Research:**
- Author: Omer Gil
- First disclosed: 2017
- Initial attack vector discovery

**Original Technique:**
- Path confusion attack: `/profile/nonexistent.css`
- Static file extension caching exploitation
- Sensitive data exposure via caching

---

## OWASP Resources

### OWASP on Cache Poisoning and Deception

**Cache Poisoning Overview:**
- URL: https://owasp.org/www-community/attacks/Cache_Poisoning
- Distinguishes cache poisoning from cache deception
- Prevention guidelines
- Risk assessment frameworks

**Key Differences:**
| Aspect | Cache Poisoning | Cache Deception |
|--------|----------------|-----------------|
| Target | All users | Specific victim |
| Goal | Inject malicious content | Steal private data |
| Impact | Mass exploitation | Targeted data theft |
| Detection | Response analysis | Cache header analysis |

---

### OWASP ASVS (Application Security Verification Standard)

**Cache Security Requirements:**
- URL: https://github.com/OWASP/ASVS/issues/1560
- Issue tracking cache deception verification requirements
- Proposed ASVS additions for cache security
- Security control recommendations

**Proposed Controls:**
- V14.2.x: Verify sensitive responses include `Cache-Control: no-store, private`
- V14.3.x: Verify cache keys include relevant request components
- V14.4.x: Verify CDN configurations respect application cache headers

---

### OWASP Testing Guide

**Cache Testing Procedures:**
- Testing for cache deception vulnerabilities
- Identifying cache rules and behaviors
- Verifying cache control implementation
- Assessment methodologies

---

## CVE Examples and Advisories

### Cache Poisoning CVEs (Related)

**CVE-2020-4896:**
- **Vendor:** IBM Emptoris Sourcing
- **Versions:** 10.1.0, 10.1.1, 10.1.3
- **Vulnerability:** Web cache poisoning via improper input validation
- **Vector:** Modifying HTTP request headers
- **Impact:** Cache manipulation leading to data exposure

**CVE-2020-4828:**
- **Vendor:** IBM API Connect
- **Versions:** 10.0.0.0 through 10.0.1.0, 2018.4.1.0 through 2018.4.1.13
- **Vulnerability:** Web cache poisoning
- **Vector:** Improper header validation
- **Impact:** Malicious content caching

**CVE-2020-29022:**
- **Vendor:** GateManager
- **Vulnerability:** Host header poisoning leading to cache poisoning
- **Vector:** Unsanitized host header output
- **Impact:** Web cache poisoning attacks

**CVE-2020-28473:**
- **Package:** Bottle (Python)
- **Versions:** 0 through 0.12.18
- **Vulnerability:** Parameter cloaking leading to cache poisoning
- **Impact:** Cache manipulation via parameter confusion

**CVE-2021-27577:**
- **Vendor:** Apache Traffic Server
- **Vulnerability:** Cache poisoning via request smuggling
- **Impact:** Combined smuggling and cache exploitation

---

### Web Cache Deception-Specific Issues

**CVE-2020-15151:**
- Referenced in web cache deception detection research
- Parser discrepancy exploitation
- Cache rule bypass techniques

---

### Vendor Security Advisories

**Cloudflare:**
- Cache Deception Armor feature introduction
- Mitigates common cache deception vectors
- Content-Type validation enforcement

**Akamai:**
- Cache key normalization updates
- Enhanced cache rule validation
- Security advisory bulletins

**Fastly:**
- VCL security best practices
- Cache control implementation guides
- Vulnerability disclosure program

---

## Tools and Frameworks

### Burp Suite Extensions

#### 1. Web Cache Deception Scanner

**Official BApp:**
- **URL:** https://portswigger.net/bappstore/7c1ca94a61474d9e897d307c858d52f0
- **GitHub:** https://github.com/PortSwigger/web-cache-deception-scanner
- **Maintainer:** PortSwigger

**Features:**
- Context menu item: "Web Cache Deception Test"
- Active Scanner integration
- Automatic vulnerability detection
- Issue reporting with detailed explanations
- Works with Target sitemap and Proxy history

**Installation:**
1. Download JAR file from BApp Store
2. Extender → Extensions → Add
3. Select downloaded file
4. Extension loads automatically

**Usage:**
```
Right-click on request → Web Cache Deception Test
- Or -
Run Active Scanner on target
```

**Detection Capabilities:**
- Path mapping discrepancies
- Static extension caching
- Delimiter confusion
- Basic normalization issues

---

#### 2. Alternative WCD Scanner by Nowafen

**GitHub:** https://github.com/Nowafen/cache-deception-scanner

**Features:**
- Dedicated "WCD Scanner" tab in Burp
- Table view of vulnerable requests
- Highlights potential cache deception vectors
- Custom rule configuration

---

#### 3. HTTP Request Smuggler

**BApp Store URL:** https://portswigger.net/bappstore/aaaa60ef945341e8a450217a54a11646

**Relevance:**
- Essential for advanced cache deception via request smuggling
- Automatic CL.TE and TE.CL detection
- Payload generation for smuggling attacks
- Integration with Repeater and Scanner

**Usage for Cache Deception:**
1. Detect smuggling vulnerability
2. Craft smuggling payload targeting cache
3. Combine with cache rules to poison responses
4. Retrieve cached victim data

---

### Command-Line Tools

#### 1. PayloadsAllTheThings

**GitHub:** https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Web%20Cache%20Deception/README.md

**Contents:**
- Ready-to-use payload list
- Attack vector examples
- Methodology guides
- Real-world exploitation scenarios

**Example Payloads:**
```
/profile/test.css
/api/user;test.js
/resources/..%2fmy-account
/my-account%23%2f%2e%2e%2fresources
```

---

#### 2. Custom Testing Scripts

**Delimiter Discovery Script (Python):**
```python
import requests

delimiters = '; : . ? # $ @ ! % & * + , - = [ ] ^ _ ` { | } ~'.split()
target = "https://target.com/my-account"

for delim in delimiters:
    url = f"{target}{delim}test"
    response = requests.get(url)
    if response.status_code == 200:
        print(f"[+] Delimiter found: {delim}")
```

**Cache Testing Script:**
```python
import requests
import time

url = "https://target.com/my-account/test.js"

# First request
r1 = requests.get(url)
cache_status_1 = r1.headers.get('X-Cache', 'N/A')

# Wait a moment
time.sleep(1)

# Second request
r2 = requests.get(url)
cache_status_2 = r2.headers.get('X-Cache', 'N/A')

if cache_status_1 == 'miss' and cache_status_2 == 'hit':
    print("[+] Cache deception vulnerability detected!")
    print(f"[+] URL: {url}")
```

---

### Automated Scanners

#### OWASP ZAP

**Web Cache Deception Scan:**
- URL: https://www.zaproxy.org/docs/alerts/40039/
- Alert ID: 40039
- Detection capability for cache deception
- Integration with active scanning

**Configuration:**
- Enable passive and active scanners
- Configure custom payloads
- Set alert thresholds

---

#### Acunetix/Invicti

**Cache Deception Detection:**
- URL: https://www.invicti.com/web-vulnerability-scanner/vulnerabilities/web-cache-deception/
- Automated detection in web scans
- Vulnerability assessment reporting
- Remediation guidance

---

#### Nuclei Templates

**Community Templates:**
```yaml
id: web-cache-deception

info:
  name: Web Cache Deception
  severity: high

requests:
  - method: GET
    path:
      - "{{BaseURL}}/profile/test.js"
      - "{{BaseURL}}/api/user;test.js"

    matchers:
      - type: word
        words:
          - "X-Cache: hit"
```

---

## Video Tutorials and Walkthroughs

### Official PortSwigger Content

**Web Security Academy Videos:**
- Platform: YouTube, Web Security Academy
- Content: Lab walkthroughs and concept explanations
- Difficulty levels: Beginner to Advanced

---

### Conference Presentations

**Black Hat USA 2024:**
- **Title:** "Gotta Cache 'em All"
- **Speaker:** Martin Doyhenard
- **Duration:** 45 minutes
- **Content:** Original research presentation, new attack vectors, live demonstrations

**DEF CON Presentations:**
- Various talks on cache exploitation
- Community research sharing
- Tool demonstrations

---

### YouTube Walkthroughs

**Popular Channels:**
- Rana Khalil (PortSwigger Lab Solutions)
- Intigriti
- PwnFunction (Cache security concepts)
- LiveOverflow (Web security deep dives)

**Recommended Videos:**
- "Web Cache Deception Explained"
- "PortSwigger Cache Deception Labs Walkthrough"
- "How Caches Can Leak Your Data"

---

## Secure Coding Best Practices

### Prevention Guidelines

#### 1. Set Proper Cache-Control Headers

**For Dynamic, Sensitive Content:**
```http
Cache-Control: no-store, private, must-revalidate
Pragma: no-cache
```

**Implementation Examples:**

**Express.js (Node.js):**
```javascript
app.get('/my-account', (req, res) => {
  res.set({
    'Cache-Control': 'no-store, private',
    'Pragma': 'no-cache'
  });
  res.json({ apiKey: user.apiKey });
});
```

**Flask (Python):**
```python
@app.route('/my-account')
def my_account():
    response = jsonify({'apiKey': user.api_key})
    response.headers['Cache-Control'] = 'no-store, private'
    response.headers['Pragma'] = 'no-cache'
    return response
```

**Spring Boot (Java):**
```java
@GetMapping("/my-account")
public ResponseEntity<Account> getAccount() {
    return ResponseEntity.ok()
        .cacheControl(CacheControl.noStore())
        .header("Pragma", "no-cache")
        .body(account);
}
```

**ASP.NET:**
```csharp
[HttpGet("/my-account")]
public IActionResult GetAccount()
{
    Response.Headers["Cache-Control"] = "no-store, private";
    Response.Headers["Pragma"] = "no-cache";
    return Ok(account);
}
```

---

#### 2. Strict Path Validation

**Bad (Vulnerable):**
```python
# Path abstraction allows arbitrary suffixes
if request.path.startswith("/my-account"):
    return account_data()
```

**Good (Secure):**
```python
# Exact path matching
if request.path == "/my-account":
    return account_data()
else:
    return Response(status=404)
```

**Route Configuration:**

**Express.js:**
```javascript
// Vulnerable: matches /my-account/anything
app.get('/my-account*', handler);

// Secure: exact match only
app.get('/my-account', handler);
```

**Flask:**
```python
# Vulnerable: catches all sub-paths
@app.route('/my-account/', defaults={'path': ''})
@app.route('/my-account/<path:path>')

# Secure: exact route
@app.route('/my-account')
```

---

#### 3. Return Proper HTTP Status Codes

**Invalid Paths Should Return 404:**
```javascript
app.get('/my-account/:invalid', (req, res) => {
  res.status(404).send('Not Found');
});
```

**Not 200 with Default Content:**
```javascript
// BAD: Returns 200 for invalid paths
app.get('/my-account/*', (req, res) => {
  res.json(accountData); // Vulnerable!
});
```

---

#### 4. Content-Type Validation

**Ensure Response Matches Expected Type:**
```javascript
app.get('/api/data', (req, res) => {
  // If request expects JSON, return JSON
  res.type('application/json');
  res.json(data);
});

// Middleware to validate Content-Type
app.use((req, res, next) => {
  const ext = path.extname(req.path);
  const contentType = res.get('Content-Type');

  if (ext === '.js' && !contentType.includes('javascript')) {
    return res.status(404).send('Not Found');
  }
  next();
});
```

---

### Framework-Specific Best Practices

#### Java Spring

**Disable Matrix Variables on Sensitive Endpoints:**
```java
@Configuration
public class WebConfig implements WebMvcConfigurer {
    @Override
    public void configurePathMatch(PathMatchConfigurer configurer) {
        UrlPathHelper urlPathHelper = new UrlPathHelper();
        urlPathHelper.setRemoveSemicolonContent(true); // Remove ;params
        configurer.setUrlPathHelper(urlPathHelper);
    }
}
```

**Set Cache Headers:**
```java
@GetMapping("/api/user")
@CacheControl(noStore = true, maxAge = 0)
public User getUser() {
    return userService.getCurrentUser();
}
```

---

#### Ruby on Rails

**Disable Format Extensions on Sensitive Routes:**
```ruby
# config/routes.rb
get '/my-account', to: 'accounts#show', format: false
```

**Set Cache Headers:**
```ruby
class AccountsController < ApplicationController
  def show
    response.headers['Cache-Control'] = 'no-store, private'
    render json: @account
  end
end
```

---

#### PHP

**Strict Path Checking:**
```php
<?php
// Validate exact path
if ($_SERVER['REQUEST_URI'] !== '/my-account') {
    http_response_code(404);
    exit('Not Found');
}

// Set cache headers
header('Cache-Control: no-store, private');
header('Pragma: no-cache');
```

---

## CDN-Specific Documentation

### Cloudflare

**Cache Deception Armor:**
- **URL:** https://developers.cloudflare.com/cache/cache-security/cache-deception-armor/
- **Feature:** Validates file extension matches Content-Type
- **Configuration:** Enable in Cache settings

**How It Works:**
```
Request: /my-account/test.js
Response Content-Type: text/html
Action: Do not cache (mismatch detected)
```

**Enable:**
1. Dashboard → Caching → Configuration
2. Toggle "Cache Deception Armor" to ON
3. Save changes

**Limitations:**
- Only checks extension/Content-Type match
- Doesn't prevent all deception vectors
- Should be combined with proper Cache-Control headers

---

**Custom Cache Rules:**
```javascript
// Page Rule example
Cache-Control: no-store
URL: *my-account*
```

**Workers for Advanced Protection:**
```javascript
addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request))
})

async function handleRequest(request) {
  const url = new URL(request.url)

  // Prevent cache deception on sensitive paths
  if (url.pathname.includes('/my-account')) {
    const response = await fetch(request)
    const newResponse = new Response(response.body, response)
    newResponse.headers.set('Cache-Control', 'no-store, private')
    return newResponse
  }

  return fetch(request)
}
```

---

### Akamai

**Cache Key Configuration:**
- Include relevant headers in cache key
- Normalize paths before caching
- Validate Content-Type matching

**Property Manager Rules:**
```json
{
  "name": "Prevent Cache Deception",
  "criteria": [
    {
      "name": "path",
      "options": {
        "matchOperator": "MATCHES_ONE_OF",
        "values": ["/my-account/*", "/api/user/*"]
      }
    }
  ],
  "behaviors": [
    {
      "name": "caching",
      "options": {
        "behavior": "NO_STORE"
      }
    }
  ]
}
```

---

### AWS CloudFront

**Cache Policy:**
```json
{
  "CachePolicyConfig": {
    "Name": "Secure-Sensitive-Content",
    "MinTTL": 0,
    "MaxTTL": 0,
    "DefaultTTL": 0,
    "ParametersInCacheKeyAndForwardedToOrigin": {
      "EnableAcceptEncodingGzip": false,
      "HeadersConfig": {
        "HeaderBehavior": "whitelist",
        "Headers": ["Authorization", "Cookie"]
      }
    }
  }
}
```

**Lambda@Edge for Protection:**
```javascript
exports.handler = async (event) => {
  const request = event.Records[0].cf.request;
  const response = event.Records[0].cf.response;

  // Check for sensitive paths
  if (request.uri.includes('/my-account')) {
    response.headers['cache-control'] = [{
      key: 'Cache-Control',
      value: 'no-store, private'
    }];
  }

  return response;
};
```

---

### Fastly

**VCL (Varnish Configuration Language):**
```vcl
sub vcl_recv {
  # Prevent caching on sensitive paths
  if (req.url ~ "^/my-account" || req.url ~ "^/api/user") {
    return (pass);
  }
}

sub vcl_backend_response {
  # Respect Cache-Control headers
  if (beresp.http.Cache-Control ~ "no-store") {
    set beresp.ttl = 0s;
    set beresp.uncacheable = true;
    return (deliver);
  }
}
```

---

## Testing Methodologies

### Manual Testing Process

#### Phase 1: Information Gathering
1. Map application endpoints
2. Identify authenticated areas
3. Locate sensitive data responses
4. Check for cache headers

#### Phase 2: Vulnerability Discovery
1. Test path abstraction
2. Discover delimiters (automated)
3. Test normalization behaviors
4. Identify cache rules

#### Phase 3: Exploitation
1. Craft working payloads
2. Verify caching behavior
3. Test with unique identifiers
4. Retrieve cached data

#### Phase 4: Validation
1. Confirm data exposure
2. Test impact scenarios
3. Document findings
4. Verify remediation

---

### Automated Testing

**Burp Suite Active Scan:**
1. Configure scan settings
2. Add Web Cache Deception Scanner extension
3. Run active scan on target
4. Review Issues for cache deception findings

**OWASP ZAP:**
1. Proxy application traffic
2. Enable cache deception scan rules
3. Run active scan
4. Review alerts (ID: 40039)

**Nuclei:**
```bash
nuclei -u https://target.com -t cache-deception-template.yaml
```

---

### Continuous Security Testing

**Integration with CI/CD:**
```yaml
# .gitlab-ci.yml
security_scan:
  stage: test
  script:
    - nuclei -u $TARGET_URL -t cache-deception
    - zap-cli active-scan $TARGET_URL
  only:
    - merge_requests
```

**Pre-Production Checks:**
- Automated cache header verification
- Path validation testing
- CDN configuration audits
- Regular penetration testing

---

## Community Resources

### Bug Bounty Platforms

**HackerOne:**
- Search: "web cache deception"
- Disclosed reports with detailed exploitation
- Remediation examples
- Bounty amounts and impact assessment

**Bugcrowd:**
- Cache deception vulnerability disclosures
- Researcher write-ups
- Best practices from security teams

**Intigriti:**
- European bug bounty platform
- Cache security challenges
- Community discussions

---

### Security Blogs and Write-Ups

**Medium Collections:**
- URL: https://medium.com/@hanzalaghayasabbasi01/list/web-cache-deception-all-labs-portswigger-81275857ce61
- Community lab solutions
- Real-world exploitation scenarios
- Learning resources

**InfoSec Write-Ups:**
- URL: https://infosecwriteups.com/mastering-web-cache-deception-vulnerabilities-an-advanced-bug-hunters-guide-b7b500b482e3
- Advanced exploitation techniques
- Bug hunter's perspective
- Automation and tooling

---

### GitHub Repositories

**Awesome Burp Extensions:**
- URL: https://github.com/snoopysecurity/awesome-burp-extensions
- Curated list of security extensions
- Cache deception testing tools
- Community recommendations

**PayloadsAllTheThings:**
- URL: https://github.com/swisskyrepo/PayloadsAllTheThings
- Comprehensive payload repository
- Cache deception section
- Regular updates from community

---

### Conferences and Events

**Black Hat:**
- Annual security conference
- Research presentations
- Tool releases
- Networking opportunities

**DEF CON:**
- Hacker conference
- Village talks (Web Hacking Village)
- Workshops and training
- Community engagement

**OWASP AppSec:**
- Application security focus
- Cache security talks
- Best practices sharing
- Global events

---

### Forums and Discussion

**PortSwigger Forum:**
- Official community forum
- Lab discussions
- Technique sharing
- Expert guidance

**Reddit:**
- r/netsec
- r/websecurity
- r/bugbounty
- Cache deception discussions

**Discord Servers:**
- Bug Bounty Hunter communities
- Security research channels
- Real-time discussions
- Collaboration opportunities

---

## Academic and Industry Research

### Research Papers

**Key Publications:**
1. "Web Cache Deception Escalates!" (USENIX Security 2022)
2. "Gotta Cache 'em All" (Black Hat USA 2024)
3. "A Methodology for Web Cache Deception Vulnerability Discovery" (CLOSER 2024)

**Access:**
- IEEE Xplore
- ACM Digital Library
- USENIX proceedings
- arXiv preprints

---

### Industry Reports

**Tenable Blog:**
- URL: https://www.tenable.com/blog/identifying-web-cache-poisoning-and-web-cache-deception-how-tenable-web-app-scanning-can-help
- Detection methodologies
- Scanner capabilities
- Real-world findings

**Beagle Security:**
- URL: https://beaglesecurity.com/blog/article/web-cache-deception.html
- Vulnerability assessment
- Testing approaches
- Mitigation strategies

---

### Standards and Guidelines

**NIST Cybersecurity Framework:**
- Cache security considerations
- Risk management
- Implementation guidance

**CWE (Common Weakness Enumeration):**
- Related weakness categories
- Taxonomy and classification
- Mitigation strategies

**PCI DSS:**
- Cache control requirements
- Sensitive data handling
- Compliance considerations

---

## Training and Certification

### Online Platforms

**PortSwigger Web Security Academy:**
- Free online training
- Interactive labs
- Certification available
- Self-paced learning

**PentesterLab:**
- Hands-on exercises
- Cache deception modules
- Subscription-based
- Badge system

**HackTheBox:**
- Virtual machines with vulnerabilities
- Cache-related challenges
- CTF competitions
- Community solutions

---

### Professional Certifications

**Offensive Security (OSWE):**
- Web application penetration testing
- Advanced exploitation techniques
- Includes cache-related attacks

**GIAC (GWAPT):**
- Web application penetration testing
- Cache security testing
- Industry-recognized

**eLearnSecurity (eWPT/eWPTX):**
- Web penetration testing
- Practical exam
- Cache vulnerability coverage

---

## Vendor-Specific Resources

### StackHawk

**Documentation:**
- URL: https://docs.stackhawk.com/vulnerabilities/40039/
- Cache deception detection
- CI/CD integration
- Automated testing

---

### Lisandre Pentest Resources

**URL:** https://lisandre.com/pentest/web/web-cache-deception
- Practical exploitation guides
- Testing methodologies
- Real-world examples

---

## Summary

### Essential Resources Checklist

**Beginners:**
- [ ] PortSwigger Web Security Academy
- [ ] Web Cache Deception Quick Start Guide
- [ ] Basic lab walkthroughs (YouTube)
- [ ] PayloadsAllTheThings repository

**Intermediate:**
- [ ] "Gotta Cache 'em All" research paper
- [ ] All PortSwigger labs completed
- [ ] Burp Suite extensions configured
- [ ] Bug bounty write-ups reviewed

**Advanced:**
- [ ] USENIX research paper
- [ ] Custom tool development
- [ ] Conference presentations watched
- [ ] Contributing to community research

---

### Quick Access Links

**Must-Visit URLs:**
1. https://portswigger.net/web-security/web-cache-deception
2. https://portswigger.net/research/gotta-cache-em-all
3. https://github.com/PortSwigger/web-cache-deception-scanner
4. https://developers.cloudflare.com/cache/cache-security/cache-deception-armor/
5. https://github.com/swisskyrepo/PayloadsAllTheThings

---

## Staying Updated

### Follow These Sources

**Twitter/X:**
- @PortSwiggerRes (PortSwigger Research)
- @albinowax (James Kettle)
- @orange_8361 (Orange Tsai)
- @filedescriptor
- @InsiderPhD

**Blogs:**
- PortSwigger Research Blog
- Web Security Academy updates
- HackerOne Hacktivity
- Medium InfoSec Write-ups

**Mailing Lists:**
- Bugtraq
- Full Disclosure
- OWASP mailing lists
- Vendor security advisories

**RSS Feeds:**
- PortSwigger research feed
- OWASP blog feed
- CVE feeds
- Security conference proceedings

---

This comprehensive resource guide provides everything needed to master web cache deception from basic understanding to advanced exploitation and defense techniques.
