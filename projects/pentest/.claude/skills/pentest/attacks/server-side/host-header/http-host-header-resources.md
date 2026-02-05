# HTTP Host Header Attacks - Comprehensive Resources

Complete reference guide covering standards, research, tools, CVEs, and best practices for HTTP Host header security.

## Table of Contents

1. [OWASP Guidelines](#owasp-guidelines)
2. [Security Standards](#security-standards)
3. [CVE Examples](#cve-examples)
4. [Research Papers](#research-papers)
5. [Tools and Frameworks](#tools-and-frameworks)
6. [Secure Coding Practices](#secure-coding-practices)
7. [Detection and Monitoring](#detection-and-monitoring)
8. [Real-World Case Studies](#real-world-case-studies)
9. [Additional Resources](#additional-resources)

---

## OWASP Guidelines

### OWASP Web Security Testing Guide

**Testing for Host Header Injection**
- **Location:** OWASP WSTG v4.2 - Section 4.7.17
- **URL:** https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/17-Testing_for_Host_Header_Injection

**Key Points:**
- Host header should be treated as untrusted user input
- Web servers dispatch requests based on Host header value
- Without proper validation, attackers can manipulate application behavior
- Can lead to password reset poisoning, cache poisoning, SSRF, and authentication bypass

**Testing Methodology:**
1. Supply invalid Host headers
2. Test with X-Forwarded-Host header
3. Analyze response for reflection
4. Test password reset functionality
5. Attempt cache poisoning
6. Check for SSRF vulnerabilities

**Remediation:**
- Validate Host header against whitelist
- Use absolute paths instead of dynamically generated URLs
- Disable support for X-Forwarded-Host if not needed
- Implement proper input validation

### OWASP HTTP Headers Cheat Sheet

**URL:** https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html

**Security Headers Related to Host:**
- Host header validation
- Strict-Transport-Security (HSTS)
- Content-Security-Policy (CSP)

**Best Practices:**
- Never trust HTTP headers for security decisions
- Validate all incoming headers
- Use configuration-based values for critical operations

### OWASP Injection Prevention

**URL:** https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html

**Host Header Context:**
- Treat Host header as injection vector
- Validate and sanitize all header values
- Use parameterized/typed interfaces
- Implement defense in depth

### OWASP Top 10:2021 - A03:2021 Injection

**URL:** https://owasp.org/Top10/2021/A03_2021-Injection/

**Relevant Context:**
- Host header injection falls under broader injection category
- Applications vulnerable when they don't validate, filter, or sanitize user-supplied data
- Can lead to data loss, corruption, or disclosure

---

## Security Standards

### HTTP/1.1 Specification (RFC 7230)

**Section 5.4 - Host Header Field**
- **RFC:** 7230
- **URL:** https://tools.ietf.org/html/rfc7230#section-5.4

**Key Requirements:**
- Host header field MUST be sent in all HTTP/1.1 request messages
- If no Host header, server SHOULD respond with 400 (Bad Request)
- Host field value comprises the authority component of the request URI

**Security Considerations:**
- Host header determines which virtual host handles the request
- Security policies should not rely solely on Host header
- Servers should validate Host against expected values

### Forwarded HTTP Extension (RFC 7239)

**URL:** https://tools.ietf.org/html/rfc7239

**Standard Headers:**
```http
Forwarded: for=192.0.2.60;proto=http;by=203.0.113.43;host=example.com
```

**Security Implications:**
- Provides standard way to disclose proxy information
- Replaces non-standard X-Forwarded-* headers
- Applications must validate forwarded host information

### HTTP/2 and HTTP/3

**:authority Pseudo-Header:**
- Replaces Host header in HTTP/2 and HTTP/3
- Same security considerations apply
- Must be validated like Host header

---

## CVE Examples

### CVE-2022-34362 - IBM Sterling Secure Proxy

**Severity:** Medium (CVSS 6.1)
**Published:** 2022-09-09

**Description:**
IBM Sterling Secure Proxy 6.0.3 is vulnerable to HTTP header injection through improper validation of HOST headers, which could allow cross-site scripting, cache poisoning, or session hijacking.

**Impact:**
- Cross-site scripting (XSS)
- Web cache poisoning
- Session hijacking

**Affected Versions:** IBM Sterling Secure Proxy 6.0.3

**Remediation:** Apply vendor patch, validate all Host header values

### CVE-2022-34306 - IBM CICS TX

**Severity:** Medium (CVSS 6.1)
**Published:** 2022-09-09

**Description:**
IBM CICS TX Standard and Advanced 11.1 is vulnerable to HTTP header injection caused by improper validation of input by the HOST headers.

**Impact:**
- Cache poisoning
- XSS attacks
- Request routing manipulation

**Affected Versions:** IBM CICS TX 11.1

**Remediation:** Implement strict Host header validation

### CVE-2022-34165 - IBM WebSphere Application Server

**Severity:** Medium (CVSS 6.1)
**Published:** 2022-08-31

**Description:**
IBM WebSphere Application Server versions 7.0, 8.0, 8.5, and 9.0, and IBM WebSphere Application Server Liberty are vulnerable to HTTP header injection, which could allow cache poisoning and cross-site scripting.

**Impact:**
- Web cache poisoning affecting multiple users
- Persistent XSS attacks
- Malicious content injection

**Affected Versions:**
- WebSphere Application Server 7.0, 8.0, 8.5, 9.0
- WebSphere Application Server Liberty

**Remediation:** Update to patched versions, implement Host validation

### CVE-2022-29933 - Craft CMS

**Severity:** Medium (CVSS 5.4)
**Published:** 2022-05-18

**Description:**
Craft CMS vulnerable to password reset poisoning via X-Forwarded-Host header manipulation, allowing attackers to generate password reset links pointing to attacker-controlled domains.

**Impact:**
- Account takeover
- Password reset token theft
- User credential compromise

**Attack Vector:**
```http
POST /index.php?p=admin/actions/users/send-password-reset-email HTTP/1.1
Host: legitimate-site.com
X-Forwarded-Host: attacker-controlled.com
Content-Type: application/x-www-form-urlencoded

loginName=victim@example.com
```

**Affected Versions:** Craft CMS < 3.7.36, < 4.0.0-RC2

**Remediation:** Update to Craft CMS 3.7.36+ or 4.0.0-RC2+, disable X-Forwarded-Host trust

### CVE-2022-22344 - IBM Spectrum Copy Data Management

**Severity:** Medium (CVSS 6.1)
**Published:** 2022-04-18

**Description:**
IBM Spectrum Copy Data Management 2.2.0.0 through 2.2.15.3 vulnerable to HTTP header injection causing cross-site scripting, cache poisoning, or session hijacking.

**Impact:**
- XSS exploitation
- Session token theft
- Cache poisoning attacks

**Affected Versions:** IBM Spectrum Copy Data Management 2.2.0.0 - 2.2.15.3

### CVE-2021-21972 - VMware vCenter Server

**Severity:** Critical (CVSS 9.8)
**Published:** 2021-02-23

**Description:**
VMware vCenter Server vSphere Client (HTML5) contains a remote code execution vulnerability due to lack of input validation in the vCenter Server plug-in. Exploitable via Host header manipulation for SSRF leading to RCE.

**Impact:**
- Remote code execution without authentication
- Full system compromise
- Internal network pivoting

**Attack Vector:**
- SSRF via Host header manipulation
- Access to internal vCenter services
- Unauthenticated exploitation

**Affected Versions:**
- vCenter Server 6.5 (all versions)
- vCenter Server 6.7 (prior to 6.7 U3l)
- vCenter Server 7.0 (prior to 7.0 U1c)

**Remediation:** Apply VMware security patches immediately

**Real-World Impact:** Widely exploited in the wild, multiple ransomware campaigns

### CVE-2019-11581 - Atlassian Jira

**Severity:** Critical (CVSS 9.8)
**Published:** 2019-05-30

**Description:**
Atlassian Jira Server and Data Center vulnerable to server-side template injection via Host header manipulation in velocity templates.

**Impact:**
- Remote code execution
- Server compromise
- Data theft

**Affected Versions:** Jira Server/Data Center < 7.13.3, 8.0.0 - 8.0.3, 8.1.0 - 8.1.1

### Additional Notable CVEs

**CVE-2018-8026 - Apache Tomcat**
- Host header not validated in certain configurations
- Could lead to cache poisoning and request smuggling

**CVE-2016-5385 - HTTPoxy**
- HTTP_PROXY environment variable contamination
- Related to improper header handling
- Affects multiple languages and frameworks

---

## Research Papers

### 1. "Host Header Injection Detection Tool for Enhanced Web Security"

**Authors:** International Journal of Scientific Development and Research (IJSDR)
**Year:** 2024
**URL:** https://ijsdr.org/papers/IJSDR2412040.pdf

**Abstract:**
Presents a novel automated tool for detecting Host Header Injection vulnerabilities by simulating various attack vectors. The methodology combines payload generation, robust request execution, and response analysis to detect misconfigurations and potential attack vectors.

**Key Findings:**
- Automated detection of SSRF via Host headers
- Cache poisoning identification
- XSS through Host reflection
- Framework for systematic testing

**Methodology:**
1. Payload generation for common attack patterns
2. HTTP request execution with modified headers
3. Response analysis for vulnerability indicators
4. Reporting and classification

### 2. "HTTP Security Headers Analysis of Top One Million Websites"

**Authors:** Various
**Published:** ResearchGate, 2018
**URL:** https://www.researchgate.net/publication/326280169

**Abstract:**
Large-scale study analyzing HTTP security header adoption across top one million websites using a Java-based web crawler.

**Key Findings:**
- Low adoption of security headers across major websites
- Host header validation rarely implemented
- Inconsistent security practices across different hosting providers

**Relevance to Host Header Attacks:**
- Demonstrates widespread lack of header validation
- Highlights need for better security practices
- Shows correlation between missing headers and vulnerabilities

### 3. "Uncovering HTTP Header Inconsistencies and Impact on Desktop/Mobile Websites"

**Authors:** ACM Digital Library
**Year:** 2018
**URL:** https://dl.acm.org/doi/fullHtml/10.1145/3178876.3186091

**Abstract:**
Research exploring subtle inconsistencies of HTTP security headers between desktop and mobile website implementations.

**Key Findings:**
- Mobile and desktop versions often handle headers differently
- Inconsistencies reduce efficacy of security defenses
- Host header processing varies between platforms

**Security Implications:**
- Attackers can exploit platform-specific differences
- Mobile applications may be more vulnerable
- Need for consistent header handling across platforms

### 4. "Studying the Manipulation of Security Headers in Browser Extensions"

**Authors:** CISPA (Saarland Informatics Campus)
**Year:** 2021
**URL:** https://swag.cispa.saarland/papers/agarwal2021extensions.pdf

**Abstract:**
Analyzes browser extensions that intercept, inject, drop, or modify HTTP security headers.

**Findings:**
- Many extensions modify security-critical headers
- Can introduce vulnerabilities through header manipulation
- Host header among frequently modified headers

**Relevance:**
- Understanding header manipulation vectors
- Browser extensions as attack surface
- Need for extension security reviews

### 5. "Securing the Web: Analysis of HTTP Security Headers in Popular Global Websites"

**Authors:** SpringerLink
**Year:** 2024
**URL:** https://link.springer.com/chapter/10.1007/978-3-031-80020-7_5

**Abstract:**
Study analyzing HTTP security headers across 3,195 globally popular websites, revealing security implementation weaknesses.

**Key Statistics:**
- 55.66% of sites received security grade 'F'
- Weak HTTP header implementation widespread
- Host header validation largely absent

**Recommendations:**
- Implement comprehensive header validation
- Use automated security testing
- Follow security best practices consistently

### 6. "HTTP Security Headers" (Invicti White Paper)

**Publisher:** Invicti (formerly Netsparker)
**URL:** https://www.invicti.com/white-papers/whitepaper-http-security-headers

**Contents:**
- Comprehensive overview of security headers
- Implementation guidance
- Real-world examples
- Best practices for Host header handling

**Topics Covered:**
- Host header injection risks
- Prevention techniques
- Testing methodologies
- Integration with security tools

---

## Tools and Frameworks

### Burp Suite Professional

**Developer:** PortSwigger
**URL:** https://portswigger.net/burp

**Key Features for Host Header Testing:**

**1. Repeater**
- Manual request modification
- Host header manipulation
- Response analysis

**2. Intruder**
- Automated fuzzing
- Internal network scanning
- Payload generation
- Numbers payload type for IP scanning

**3. Collaborator**
- Out-of-band interaction detection
- SSRF validation
- DNS/HTTP interaction logging

**4. Scanner**
- Automated vulnerability detection
- Host header injection checks
- Cache poisoning detection

**5. Extensions:**
- **Param Miner**: Discovers hidden parameters and headers
- **Collaborator Everywhere**: Automated out-of-band testing
- **Turbo Intruder**: High-speed testing with custom scripts
- **Host Header Injection Checker**: Specialized testing

**Configuration Tips:**
```
Target > Repeater options:
☑ Update Host header to match target (disable for SSRF testing)

Intruder > Options:
☐ Update Host header to match target (disable for scanning)
```

### OWASP ZAP

**Developer:** OWASP Foundation
**URL:** https://www.zaproxy.org/

**Host Header Testing Features:**
- Active scanning for header injection
- Fuzzing capabilities
- Custom header injection
- Scripting for automated testing

**Add-ons:**
- Custom Payloads
- Advanced SQLInjection Scanner
- FuzzDB Files

### Custom Testing Scripts

**Python Example:**
```python
import requests

def test_host_header_injection(target_url):
    """Test for Host header injection vulnerabilities"""

    test_hosts = [
        'localhost',
        '127.0.0.1',
        'attacker-controlled.com',
        '192.168.0.1',
        '169.254.169.254',
    ]

    results = []

    for test_host in test_hosts:
        headers = {'Host': test_host}

        try:
            response = requests.get(target_url, headers=headers, timeout=5)

            # Check for reflection
            if test_host in response.text:
                results.append({
                    'host': test_host,
                    'status': 'REFLECTED',
                    'status_code': response.status_code
                })

            # Check for different responses
            elif response.status_code != 200:
                results.append({
                    'host': test_host,
                    'status': 'DIFFERENT_RESPONSE',
                    'status_code': response.status_code
                })

        except Exception as e:
            results.append({
                'host': test_host,
                'status': 'ERROR',
                'error': str(e)
            })

    return results

# Usage
results = test_host_header_injection('https://target-site.com')
for result in results:
    print(f"Host: {result['host']} - Status: {result['status']}")
```

**Ruby Example (for Metasploit):**
```ruby
# Metasploit auxiliary module structure
class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient

  def run
    test_hosts = ['localhost', '127.0.0.1', datastore['RHOST']]

    test_hosts.each do |host|
      res = send_request_cgi(
        'method' => 'GET',
        'uri' => normalize_uri(target_uri.path),
        'headers' => {
          'Host' => host
        }
      )

      if res && res.code == 200
        print_good("Host header accepted: #{host}")
        if res.body.include?(host)
          print_warning("Host header reflected in response!")
        end
      end
    end
  end
end
```

### Nuclei Templates

**Developer:** ProjectDiscovery
**URL:** https://github.com/projectdiscovery/nuclei-templates

**Host Header Templates:**
```yaml
id: host-header-injection

info:
  name: Host Header Injection Detection
  author: pdteam
  severity: medium
  description: Detects Host header injection vulnerabilities

requests:
  - method: GET
    path:
      - "{{BaseURL}}"

    headers:
      Host: "{{Hostname}}.attacker.com"

    matchers:
      - type: word
        words:
          - "{{Hostname}}.attacker.com"
        part: body
```

### ffuf (Fuzz Faster U Fool)

**Developer:** Community
**URL:** https://github.com/ffuf/ffuf

**Host Header Fuzzing:**
```bash
# Fuzz Host header values
ffuf -u https://target.com -H "Host: FUZZ" -w hostnames.txt

# Fuzz internal IPs
ffuf -u https://target.com -H "Host: 192.168.0.FUZZ" -w numbers.txt

# Multiple header fuzzing
ffuf -u https://target.com \
  -H "Host: FUZZ1" \
  -H "X-Forwarded-Host: FUZZ2" \
  -w wordlist1.txt:FUZZ1 \
  -w wordlist2.txt:FUZZ2
```

### Custom Burp Extensions

**Host Header Scanner Extension:**
```java
public class HostHeaderScanner implements IScannerCheck {

    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
        // Analyze responses for Host header reflection
        byte[] response = baseRequestResponse.getResponse();
        IResponseInfo responseInfo = helpers.analyzeResponse(response);

        String responseStr = new String(response);
        byte[] request = baseRequestResponse.getRequest();
        IRequestInfo requestInfo = helpers.analyzeRequest(request);

        // Extract Host header
        for (String header : requestInfo.getHeaders()) {
            if (header.toLowerCase().startsWith("host:")) {
                String hostValue = header.substring(5).trim();
                if (responseStr.contains(hostValue)) {
                    // Found reflection - report issue
                    return Collections.singletonList(
                        new CustomScanIssue(
                            baseRequestResponse.getHttpService(),
                            helpers.analyzeRequest(baseRequestResponse).getUrl(),
                            new IHttpRequestResponse[] { baseRequestResponse },
                            "Host Header Reflection Detected",
                            "The Host header value is reflected in the response",
                            "Medium"
                        )
                    );
                }
            }
        }

        return null;
    }

    @Override
    public List<IScanIssue> doActiveScan(
        IHttpRequestResponse baseRequestResponse,
        IScannerInsertionPoint insertionPoint
    ) {
        // Active scanning logic
        if (!insertionPoint.getInsertionPointName().equals("Host header")) {
            return null;
        }

        // Test various payloads
        String[] testPayloads = {
            "localhost",
            "127.0.0.1",
            "attacker-controlled.com",
            "192.168.0.1"
        };

        List<IScanIssue> issues = new ArrayList<>();

        for (String payload : testPayloads) {
            byte[] checkRequest = insertionPoint.buildRequest(
                payload.getBytes()
            );
            IHttpRequestResponse checkRequestResponse = callbacks
                .makeHttpRequest(
                    baseRequestResponse.getHttpService(),
                    checkRequest
                );

            // Analyze response for vulnerabilities
            // Add issues as found
        }

        return issues;
    }
}
```

### Docker Testing Environment

**Setup isolated testing environment:**
```dockerfile
FROM nginx:alpine

# Configure multiple virtual hosts
COPY nginx.conf /etc/nginx/nginx.conf
COPY vulnerable-app /usr/share/nginx/html

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
```

**nginx.conf (Vulnerable Configuration):**
```nginx
server {
    listen 80;
    server_name _;

    location / {
        root /usr/share/nginx/html;
        index index.html;
    }

    # Vulnerable password reset endpoint
    location /reset-password {
        proxy_pass http://backend;
        proxy_set_header Host $http_host;  # Vulnerable!
    }
}
```

---

## Secure Coding Practices

### General Principles

**1. Never Trust the Host Header**
```python
# ❌ VULNERABLE
reset_url = f"https://{request.headers.get('Host')}/reset?token={token}"

# ✓ SECURE
SITE_DOMAIN = config.get('SITE_DOMAIN')  # From configuration
reset_url = f"https://{SITE_DOMAIN}/reset?token={token}"
```

**2. Validate Against Whitelist**
```python
# ✓ SECURE
ALLOWED_HOSTS = ['example.com', 'www.example.com', 'api.example.com']

def validate_host(host):
    # Remove port if present
    host_without_port = host.split(':')[0]

    if host_without_port not in ALLOWED_HOSTS:
        raise ValueError('Invalid Host header')

    return host_without_port
```

**3. Use Relative URLs**
```python
# ❌ VULNERABLE
redirect_url = f"https://{request.headers.get('Host')}/dashboard"

# ✓ SECURE
redirect_url = "/dashboard"  # Relative URL
```

### Language-Specific Examples

#### Python (Django)

```python
# settings.py
ALLOWED_HOSTS = [
    'example.com',
    'www.example.com',
    '.example.com',  # Wildcard for subdomains
]

# Django automatically validates Host header against ALLOWED_HOSTS
# Requests with invalid Host return HTTP 400

# For password resets
from django.conf import settings

def send_password_reset(user):
    # ✓ SECURE: Use Site framework or settings
    domain = settings.SITE_DOMAIN
    reset_url = f"https://{domain}/reset/{user.token}/"

    # Don't use request.get_host() for security-critical URLs
```

#### Python (Flask)

```python
from flask import Flask, request, abort

app = Flask(__name__)

# Configuration
ALLOWED_HOSTS = {'example.com', 'www.example.com'}

@app.before_request
def validate_host():
    """Validate Host header before processing any request"""
    host = request.host.split(':')[0]  # Remove port

    if host not in ALLOWED_HOSTS:
        abort(400, description="Invalid Host header")

@app.route('/reset-password', methods=['POST'])
def reset_password():
    # ✓ SECURE: Use configured domain
    domain = app.config['SITE_DOMAIN']
    reset_url = f"https://{domain}/reset/{generate_token()}"

    send_email(reset_url)
    return "Reset email sent"
```

#### Node.js (Express)

```javascript
const express = require('express');
const app = express();

// Middleware to validate Host header
const allowedHosts = ['example.com', 'www.example.com'];

app.use((req, res, next) => {
  const host = req.get('host').split(':')[0];

  if (!allowedHosts.includes(host)) {
    return res.status(400).send('Invalid Host header');
  }

  next();
});

// Password reset endpoint
app.post('/reset-password', (req, res) => {
  // ✓ SECURE: Use environment variable
  const domain = process.env.SITE_DOMAIN;
  const resetUrl = `https://${domain}/reset/${generateToken()}`;

  sendEmail(resetUrl);
  res.send('Reset email sent');
});
```

#### PHP

```php
<?php
// config.php
$allowedHosts = ['example.com', 'www.example.com'];

function validateHost() {
    global $allowedHosts;

    $host = $_SERVER['HTTP_HOST'];
    $hostWithoutPort = explode(':', $host)[0];

    if (!in_array($hostWithoutPort, $allowedHosts)) {
        http_response_code(400);
        die('Invalid Host header');
    }
}

// Call at application entry point
validateHost();

// Password reset
function sendPasswordReset($email) {
    // ✓ SECURE: Use configured domain
    $domain = getenv('SITE_DOMAIN');
    $token = generateToken();
    $resetUrl = "https://$domain/reset.php?token=$token";

    sendEmail($email, $resetUrl);
}
?>
```

#### Java (Spring Boot)

```java
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import javax.servlet.*;
import javax.servlet.http.*;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;

// Host validation filter
@Component
public class HostHeaderValidationFilter implements Filter {

    @Value("${app.allowed.hosts}")
    private String allowedHostsConfig;

    @Override
    public void doFilter(ServletRequest request, ServletResponse response,
                        FilterChain chain) throws IOException, ServletException {

        HttpServletRequest httpRequest = (HttpServletRequest) request;
        String host = httpRequest.getHeader("Host");

        if (host != null) {
            String hostWithoutPort = host.split(":")[0];
            List<String> allowedHosts = Arrays.asList(
                allowedHostsConfig.split(",")
            );

            if (!allowedHosts.contains(hostWithoutPort)) {
                HttpServletResponse httpResponse = (HttpServletResponse) response;
                httpResponse.sendError(HttpServletResponse.SC_BAD_REQUEST,
                                     "Invalid Host header");
                return;
            }
        }

        chain.doFilter(request, response);
    }
}

// Service for password reset
@Service
public class PasswordResetService {

    @Value("${app.site.domain}")
    private String siteDomain;

    public void sendPasswordReset(String email) {
        // ✓ SECURE: Use configured domain
        String token = generateToken();
        String resetUrl = String.format("https://%s/reset?token=%s",
                                       siteDomain, token);

        emailService.send(email, resetUrl);
    }
}
```

#### Ruby (Rails)

```ruby
# config/application.rb
module YourApp
  class Application < Rails::Application
    # Host authorization
    config.hosts = [
      "example.com",
      "www.example.com",
      /.*\.example\.com/  # Subdomain wildcard
    ]

    # Rails 6+ automatically validates Host header
    # Invalid hosts receive 403 Forbidden
  end
end

# app/controllers/password_resets_controller.rb
class PasswordResetsController < ApplicationController
  def create
    user = User.find_by(email: params[:email])

    if user
      # ✓ SECURE: Use configured domain
      domain = Rails.application.config.site_domain
      reset_url = "https://#{domain}/reset/#{user.generate_token}"

      UserMailer.password_reset(user.email, reset_url).deliver_now
    end

    render json: { message: 'Reset email sent' }
  end
end
```

### Infrastructure Configuration

#### Nginx

```nginx
# nginx.conf

# ✓ SECURE: Strict Host validation
server {
    listen 80;
    server_name example.com www.example.com;

    # Reject requests with invalid Host header
    if ($host !~ ^(example\.com|www\.example\.com)$) {
        return 444;  # Close connection without response
    }

    location / {
        proxy_pass http://backend;

        # ✓ SECURE: Use explicit host, not $http_host
        proxy_set_header Host example.com;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;

        # Only set X-Forwarded-Host if needed and validated
        # proxy_set_header X-Forwarded-Host example.com;
    }
}

# Catch-all server block for invalid hosts
server {
    listen 80 default_server;
    server_name _;
    return 444;  # Drop invalid requests
}
```

#### Apache

```apache
# httpd.conf or .htaccess

# ✓ SECURE: Host validation
<VirtualHost *:80>
    ServerName example.com
    ServerAlias www.example.com

    # Use server name, not Host header
    UseCanonicalName On

    # Optional: Reject invalid Host headers
    RewriteEngine On
    RewriteCond %{HTTP_HOST} !^(example\.com|www\.example\.com)$ [NC]
    RewriteRule ^ - [F,L]

    ProxyPass / http://backend/
    ProxyPassReverse / http://backend/

    # ✓ SECURE: Use canonical name
    RequestHeader set Host "example.com"
</VirtualHost>

# Default virtualhost for invalid hosts
<VirtualHost *:80>
    ServerName default
    DocumentRoot /var/www/default

    # Return error for any request
    <Location />
        Require all denied
    </Location>
</VirtualHost>
```

#### HAProxy

```haproxy
# haproxy.cfg

frontend http-in
    bind *:80

    # ✓ SECURE: Validate Host header
    acl valid_host hdr(host) -i example.com
    acl valid_host hdr(host) -i www.example.com

    # Reject invalid hosts
    http-request deny if !valid_host

    # Remove potentially malicious headers
    http-request del-header X-Forwarded-Host
    http-request del-header X-Host

    # Set explicit Host header for backend
    http-request set-header Host example.com

    default_backend app-servers

backend app-servers
    balance roundrobin
    server app1 192.168.1.10:8080 check
    server app2 192.168.1.11:8080 check
```

---

## Detection and Monitoring

### Log Analysis

**Suspicious Patterns to Monitor:**

```bash
# Grep for suspicious Host headers
grep -E "Host: (localhost|127\.0\.0\.1|192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)" access.log

# Look for unusual domains
grep -E "Host: [^.]+\.(tk|ml|ga|cf|gq)" access.log

# Detect multiple Host headers (if logged)
grep -c "Host:" request.log | awk '$1 > 1 {print}'

# Monitor for port injection attempts
grep -E "Host: .*:[^0-9]" access.log

# Check for override headers
grep -E "(X-Forwarded-Host|X-Host|X-HTTP-Host-Override)" access.log
```

### SIEM Rules

**Splunk Query:**
```spl
index=web sourcetype=access_combined
| rex field=_raw "Host: (?<host_header>[^\s]+)"
| where match(host_header, "(localhost|127\.0\.0\.1|192\.168\.|10\.|169\.254\.)")
| stats count by host_header, src_ip, uri
| where count > 5
| sort -count
```

**ELK Stack (Elasticsearch Query):**
```json
{
  "query": {
    "bool": {
      "should": [
        { "match": { "request.headers.host": "localhost" }},
        { "match": { "request.headers.host": "127.0.0.1" }},
        { "regexp": { "request.headers.host": "192\\.168\\..*" }},
        { "regexp": { "request.headers.host": "10\\..*" }},
        { "exists": { "field": "request.headers.x-forwarded-host" }}
      ],
      "minimum_should_match": 1
    }
  },
  "aggs": {
    "by_host": {
      "terms": { "field": "request.headers.host" }
    }
  }
}
```

### WAF Rules

**ModSecurity Rules:**
```apache
# Block localhost access attempts
SecRule REQUEST_HEADERS:Host "@rx ^(localhost|127\.0\.0\.1|0\.0\.0\.0)" \
    "id:100001,phase:1,deny,status:403,msg:'Invalid Host header'"

# Block internal IP ranges
SecRule REQUEST_HEADERS:Host "@rx ^(192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)" \
    "id:100002,phase:1,deny,status:403,msg:'Internal IP in Host header'"

# Detect Host header injection attempts
SecRule REQUEST_HEADERS:Host "@rx [<>'\"]" \
    "id:100003,phase:1,deny,status:403,msg:'Suspicious characters in Host header'"

# Block cloud metadata attempts
SecRule REQUEST_HEADERS:Host "@rx (169\.254\.169\.254|metadata\.google\.internal)" \
    "id:100004,phase:1,deny,status:403,msg:'Cloud metadata access attempt'"

# Detect port injection
SecRule REQUEST_HEADERS:Host "@rx :[^0-9]" \
    "id:100005,phase:1,deny,status:403,msg:'Non-numeric port in Host header'"

# Validate against whitelist
SecRule REQUEST_HEADERS:Host "!@rx ^(example\.com|www\.example\.com)(:[0-9]+)?$" \
    "id:100006,phase:1,deny,status:403,msg:'Host not in whitelist'"
```

**AWS WAF Rule:**
```json
{
  "Name": "BlockInvalidHostHeader",
  "Priority": 1,
  "Statement": {
    "OrStatement": {
      "Statements": [
        {
          "ByteMatchStatement": {
            "SearchString": "localhost",
            "FieldToMatch": {
              "SingleHeader": { "Name": "host" }
            },
            "TextTransformations": [
              { "Priority": 0, "Type": "LOWERCASE" }
            ],
            "PositionalConstraint": "CONTAINS"
          }
        },
        {
          "ByteMatchStatement": {
            "SearchString": "127.0.0.1",
            "FieldToMatch": {
              "SingleHeader": { "Name": "host" }
            },
            "TextTransformations": [
              { "Priority": 0, "Type": "NONE" }
            ],
            "PositionalConstraint": "CONTAINS"
          }
        }
      ]
    }
  },
  "Action": { "Block": {} }
}
```

### Monitoring Dashboards

**Key Metrics:**
- Unique Host header values per hour
- Requests with internal IP addresses in Host header
- Presence of override headers (X-Forwarded-Host)
- Password reset requests with non-standard Host headers
- Cache poisoning attempts (duplicate headers)
- Connection patterns (for state attacks)

**Alert Thresholds:**
- Alert on any internal IP in Host header from external source
- Alert on localhost/127.0.0.1 in Host header
- Alert on cloud metadata IP (169.254.169.254)
- Alert on override headers from untrusted sources
- Alert on unusual Host header patterns

---

## Real-World Case Studies

### Case Study 1: Capital One Data Breach (2019)

**Incident:** SSRF via misconfigured Web Application Firewall

**Attack Vector:**
- Exploited SSRF vulnerability in web application
- Used to access AWS EC2 instance metadata
- Retrieved IAM role credentials from metadata service

**Host Header Role:**
```http
GET / HTTP/1.1
Host: 169.254.169.254

# Accessed AWS metadata:
GET /latest/meta-data/iam/security-credentials/role-name HTTP/1.1
Host: 169.254.169.254
```

**Impact:**
- 106 million customer records compromised
- Personal information including SSNs exposed
- $80 million fine from regulators
- Significant reputational damage

**Lessons Learned:**
- Validate and restrict Host header values
- Implement egress filtering
- Block access to metadata services from application layer
- Use IMDSv2 for AWS metadata (requires token)

### Case Study 2: Practical HTTP Host Header Attacks (James Kettle, 2015)

**Researcher:** James Kettle (PortSwigger)
**Publication:** Black Hat USA 2015

**Key Findings:**
- Widespread Host header vulnerabilities in major applications
- Password reset poisoning affecting multiple platforms
- Cache poisoning through Host header manipulation
- SSRF through routing-based attacks

**Notable Targets:**
- Popular CMS platforms
- E-commerce applications
- Banking websites
- Government portals

**Impact:**
- Raised awareness of Host header security
- Led to patches in major frameworks
- Established testing methodologies
- Created industry best practices

### Case Study 3: VMware vCenter SSRF (CVE-2021-21972)

**Vulnerability:** Critical SSRF in vSphere Client

**Attack Mechanism:**
```http
POST /ui/vropspluginui/rest/services/uploadova HTTP/1.1
Host: 192.168.100.1
Content-Type: application/json

{
  "uploadFile": "file:///etc/passwd"
}
```

**Exploitation:**
- Host header manipulation for internal routing
- SSRF to access internal services
- Remote code execution without authentication
- Ransomware deployment via exploitation

**Impact:**
- CVSS Score: 9.8 (Critical)
- Widespread exploitation by ransomware groups
- Emergency patches required
- Affected thousands of organizations

**Mitigation:**
- Apply VMware security patches
- Segment vCenter from internet
- Implement strict Host header validation
- Monitor for exploitation attempts

### Case Study 4: Web Cache Poisoning in the Wild

**Target:** Major CDN provider (anonymized)

**Attack:**
```http
GET / HTTP/1.1
Host: legitimate-site.com
Host: attacker-controlled.com
```

**Process:**
1. CDN cached response based on first Host header
2. Backend generated URLs using second Host header
3. Cached response contained attacker's domain
4. All users received poisoned cached content

**Impact:**
- JavaScript malware served to thousands of users
- Credential theft through injected login forms
- Persistent XSS affecting cached pages
- CDN provider updated architecture

**Defense:**
- Include Host in cache key
- Reject duplicate headers
- Validate headers at all layers
- Implement cache poisoning detection

---

## Additional Resources

### Training and Certification

**PortSwigger Web Security Academy**
- URL: https://portswigger.net/web-security
- Free training on Host header attacks
- 7 hands-on labs with varying difficulty
- Video walkthroughs and documentation

**SANS SEC542: Web App Penetration Testing**
- Comprehensive web security training
- Includes Host header attack techniques
- Hands-on labs and real-world scenarios

**Offensive Security OSWE**
- Advanced web exploitation certification
- Covers Host header vulnerabilities
- Practical exploitation focus

### Books and Publications

**"The Web Application Hacker's Handbook" (2nd Edition)**
- Authors: Dafydd Stuttard, Marcus Pinto
- Chapter on header-based attacks
- Foundational web security knowledge

**"Real-World Bug Hunting: A Field Guide to Web Hacking"**
- Author: Peter Yaworski
- Real bug bounty examples
- Practical exploitation techniques

**"Web Security Testing Cookbook"**
- Practical testing recipes
- Including Host header tests
- Tool usage and automation

### Bug Bounty Platforms

**HackerOne**
- URL: https://www.hackerone.com
- Reports of Host header vulnerabilities
- Disclosed vulnerabilities with write-ups

**Bugcrowd**
- URL: https://www.bugcrowd.com
- Vulnerability disclosure programs
- Host header bounty examples

**Intigriti**
- URL: https://www.intigriti.com
- European bug bounty platform
- Host header related reports

### Community Resources

**OWASP Community**
- Mailing lists and forums
- Local chapter meetings
- Annual conferences (AppSec)

**PortSwigger Research**
- URL: https://portswigger.net/research
- Latest vulnerability research
- White papers and tools

**Security Conferences**
- Black Hat USA/Europe/Asia
- DEF CON
- OWASP AppSec conferences
- BSides events worldwide

### Online Communities

**Reddit:**
- /r/netsec
- /r/websecurity
- /r/bugbounty
- /r/AskNetsec

**Twitter:**
- @PortSwiggerRes (PortSwigger Research)
- @albinowax (James Kettle - Host header research)
- @nahamsec (Bug bounty insights)
- @InsiderPhD (Web security education)

**Discord/Slack Communities:**
- Bugcrowd Discord
- HackerOne community
- InfoSec Prep Discord

### Vendor Documentation

**Framework-Specific Guides:**

**Django:**
- https://docs.djangoproject.com/en/stable/ref/settings/#allowed-hosts
- ALLOWED_HOSTS configuration
- Security best practices

**Ruby on Rails:**
- https://guides.rubyonrails.org/security.html
- Host authorization middleware
- Security configuration

**Spring Boot:**
- https://spring.io/guides/topicals/spring-security-architecture/
- Security headers configuration
- Filter implementation

**Laravel:**
- https://laravel.com/docs/master/requests#trusted-proxies
- Trusted proxies configuration
- Host validation

### Video Tutorials

**PortSwigger YouTube Channel**
- Lab walkthroughs
- Vulnerability explanations
- Tool demonstrations

**OWASP Chapter Recordings**
- Conference presentations
- Technical deep-dives
- Expert panels

**Bug Bounty Hunters on YouTube:**
- NahamSec
- STÖKfredrik
- InsiderPhD
- PwnFunction

---

## Summary

HTTP Host header attacks represent a significant security risk due to:

1. **Widespread Vulnerability**: Many applications implicitly trust the Host header
2. **High Impact**: Can lead to account takeover, data theft, and system compromise
3. **Easy Exploitation**: Simple to test and exploit with basic tools
4. **Multiple Attack Vectors**: Password resets, auth bypass, cache poisoning, SSRF

**Key Protection Principles:**
- Never trust user-controllable headers
- Validate Host against whitelists
- Use configuration-based domains
- Implement defense in depth
- Monitor for suspicious patterns

**Essential Resources:**
- OWASP Testing Guide and Cheat Sheets
- PortSwigger Web Security Academy
- CVE databases for real-world examples
- Security tools (Burp Suite, OWASP ZAP)
- Framework-specific security documentation

**Continuous Learning:**
- Practice with PortSwigger labs
- Stay updated on CVEs
- Participate in bug bounty programs
- Engage with security community
- Implement secure coding practices

---

*This resource guide provides comprehensive information for understanding, testing, and defending against HTTP Host header attacks. Regular updates recommended as new vulnerabilities and techniques emerge.*
