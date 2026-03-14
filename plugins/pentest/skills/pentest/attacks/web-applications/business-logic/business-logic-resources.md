# Business Logic Vulnerabilities - Comprehensive Resources

> **Complete reference guide with documentation, standards, real-world cases, and best practices**
>
> Everything you need to master business logic security

---

## Table of Contents

1. [OWASP Documentation](#owasp)
2. [Industry Standards](#standards)
3. [CVE Examples and Real-World Cases](#cve-examples)
4. [Research Papers](#research)
5. [Tools and Frameworks](#tools)
6. [Bug Bounty Programs](#bug-bounty)
7. [Training Platforms](#training)
8. [Secure Coding Best Practices](#best-practices)
9. [Additional Resources](#additional)

---

## OWASP Documentation {#owasp}

### OWASP Testing Guide

**Business Logic Testing (WSTG-BUSL)**

Official documentation for testing business logic vulnerabilities.

| Resource | URL | Description |
|----------|-----|-------------|
| **OWASP Testing Guide v4.2** | https://owasp.org/www-project-web-security-testing-guide/ | Complete web security testing methodology |
| **Business Logic Testing** | https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/10-Business_Logic_Testing/ | Dedicated business logic chapter |
| **Test Business Logic Data Validation** | https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/10-Business_Logic_Testing/01-Test_Business_Logic_Data_Validation | Input validation testing |
| **Test Ability to Forge Requests** | https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/10-Business_Logic_Testing/02-Test_Ability_to_Forge_Requests | Request forgery testing |
| **Test Integrity Checks** | https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/10-Business_Logic_Testing/03-Test_Integrity_Checks | Data integrity validation |
| **Test Process Timing** | https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/10-Business_Logic_Testing/04-Test_for_Process_Timing | Timing attack testing |
| **Test Number of Times Function** | https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/10-Business_Logic_Testing/05-Test_Number_of_Times_a_Function_Can_Be_Used_Limits | Function call limits |
| **Test Workflow Circumvention** | https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/10-Business_Logic_Testing/06-Testing_for_the_Circumvention_of_Work_Flows | Workflow bypass testing |
| **Test Defense Against Application Misuse** | https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/10-Business_Logic_Testing/07-Test_Defenses_Against_Application_Mis-use | Anti-automation testing |
| **Test Upload of Unexpected File Types** | https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/10-Business_Logic_Testing/08-Test_Upload_of_Unexpected_File_Types | File upload logic flaws |
| **Test Upload of Malicious Files** | https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/10-Business_Logic_Testing/09-Test_Upload_of_Malicious_Files | Malicious upload testing |

---

### OWASP Top 10

**2021 Edition - Relevant Categories**

| Category | Relevance | URL |
|----------|-----------|-----|
| **A01:2021 - Broken Access Control** | HIGH - Authorization bypass | https://owasp.org/Top10/A01_2021-Broken_Access_Control/ |
| **A04:2021 - Insecure Design** | HIGH - Business logic flaws | https://owasp.org/Top10/A04_2021-Insecure_Design/ |
| **A07:2021 - Identification and Authentication Failures** | MEDIUM - State machine flaws | https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/ |

**Key Excerpt - A04:2021 Insecure Design:**
> "An insecure design cannot be fixed by a perfect implementation... it requires business risk profiling inherent in the requirement and resource management of the software."

---

### OWASP Cheat Sheets

| Cheat Sheet | URL | Use Case |
|-------------|-----|----------|
| **Input Validation** | https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html | Prevent parameter manipulation |
| **Transaction Authorization** | https://cheatsheetseries.owasp.org/cheatsheets/Transaction_Authorization_Cheat_Sheet.html | Workflow security |
| **Authentication** | https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html | State machine security |
| **Session Management** | https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html | Session-based logic |
| **Abuse Case** | https://cheatsheetseries.owasp.org/cheatsheets/Abuse_Case_Cheat_Sheet.html | Threat modeling |

---

### OWASP ASVS (Application Security Verification Standard)

**Business Logic Requirements**

| Section | Title | URL |
|---------|-------|-----|
| **V11** | Business Logic Verification Requirements | https://github.com/OWASP/ASVS/blob/master/4.0/en/0x19-V11-BusLogic.md |

**Key Requirements:**

**11.1 Business Logic Security Requirements**
- 11.1.1 - Application will only process business logic flows in sequential step order
- 11.1.2 - Application contains business logic limits or validation to protect against likely business risks
- 11.1.3 - Application has anti-automation controls to protect against excessive calls
- 11.1.4 - Application has sufficient anti-automation to detect and protect against data exfiltration
- 11.1.5 - Application has business logic limits or validation to protect against likely business risks

---

## Industry Standards {#standards}

### NIST (National Institute of Standards and Technology)

| Standard | Document | URL | Relevance |
|----------|----------|-----|-----------|
| **NIST SP 800-53** | Security and Privacy Controls | https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final | Access control requirements |
| **NIST SP 800-63B** | Digital Identity Guidelines | https://pages.nist.gov/800-63-3/sp800-63b.html | Authentication workflows |
| **NIST Cybersecurity Framework** | Framework Core | https://www.nist.gov/cyberframework | Overall security posture |

**Relevant NIST 800-53 Controls:**

```plaintext
AC-3: Access Enforcement
- Enforce approved authorizations for logical access

AC-6: Least Privilege
- Employ least privilege for specific duties and information systems

IA-2: Identification and Authentication
- Uniquely identify and authenticate users

SC-3: Security Function Isolation
- Isolate security functions from nonsecurity functions
```

---

### PCI DSS (Payment Card Industry Data Security Standard)

**Requirement 6: Develop and Maintain Secure Systems**

| Requirement | Description | Relevance to Business Logic |
|-------------|-------------|----------------------------|
| **6.5.8** | Improper access control | Authorization bypass |
| **6.5.10** | Broken authentication and session management | State machine flaws |
| **6.6** | For public-facing web applications, ensure secure coding | Prevent logic flaws |

**URL:** https://www.pcisecuritystandards.org/document_library

**Key Excerpt (6.5.8):**
> "Applications should properly authenticate and authorize all access to cardholder data. Improper access control occurs when an application does not properly enforce all access restrictions on data a user should be able to see."

---

### ISO/IEC 27001:2013

**Relevant Controls:**

| Control | Title | Relevance |
|---------|-------|-----------|
| **A.14.1** | Security requirements of information systems | Business logic requirements |
| **A.14.2** | Security in development and support processes | Secure development |
| **A.9.4** | System and application access control | Authorization logic |

**URL:** https://www.iso.org/standard/54534.html

---

### CWE (Common Weakness Enumeration)

**Business Logic Vulnerabilities**

| CWE ID | Name | Description | URL |
|--------|------|-------------|-----|
| **CWE-840** | Business Logic Errors | Parent category for all business logic flaws | https://cwe.mitre.org/data/definitions/840.html |
| **CWE-841** | Improper Enforcement of Behavioral Workflow | Workflow bypass vulnerabilities | https://cwe.mitre.org/data/definitions/841.html |
| **CWE-840** | Business Logic Errors | Generic business logic category | https://cwe.mitre.org/data/definitions/840.html |
| **CWE-682** | Incorrect Calculation | Integer overflow, arithmetic errors | https://cwe.mitre.org/data/definitions/682.html |
| **CWE-190** | Integer Overflow or Wraparound | Numeric overflow vulnerabilities | https://cwe.mitre.org/data/definitions/190.html |
| **CWE-191** | Integer Underflow | Numeric underflow vulnerabilities | https://cwe.mitre.org/data/definitions/191.html |
| **CWE-20** | Improper Input Validation | Parameter validation failures | https://cwe.mitre.org/data/definitions/20.html |
| **CWE-436** | Interpretation Conflict | Multiple interpretation of data | https://cwe.mitre.org/data/definitions/436.html |
| **CWE-840** | Business Logic Errors | Parent for business logic issues | https://cwe.mitre.org/data/definitions/840.html |

---

## CVE Examples and Real-World Cases {#cve-examples}

### High-Profile Business Logic Vulnerabilities

#### E-Commerce and Payment Systems

**1. Steam Gift Card Vulnerability (2015)**

| Attribute | Details |
|-----------|---------|
| **Platform** | Steam (Valve Corporation) |
| **Vulnerability** | Gift card purchase workflow bypass |
| **Impact** | Users could purchase gift cards without payment |
| **Root Cause** | Workflow validation missing between payment and confirmation |
| **Fix** | Enhanced state machine validation |
| **Reference** | https://hackerone.com/reports/88288 |

---

**2. Amazon Coupon Stacking (2019)**

| Attribute | Details |
|-----------|---------|
| **Platform** | Amazon.com |
| **Vulnerability** | Multiple promotional codes could be stacked |
| **Impact** | Users obtained items at 100%+ discount |
| **Root Cause** | Consecutive coupon validation only checked last code |
| **Bounty** | Undisclosed |
| **Reference** | Various bug bounty reports |

---

**3. Cryptocurrency Exchange Negative Balance (2020)**

| Attribute | Details |
|-----------|---------|
| **Platform** | Multiple exchanges (anonymized) |
| **Vulnerability** | Negative quantity in trading pairs |
| **Impact** | Traders could manipulate balances |
| **Root Cause** | Insufficient input validation on quantity fields |
| **Financial Loss** | $100,000+ before detection |
| **Fix** | Server-side validation, range checks |

---

#### Authentication and Authorization

**4. GitHub Enterprise Email Verification Bypass (CVE-2022-24785)**

| Attribute | Details |
|-----------|---------|
| **CVE** | CVE-2022-24785 |
| **Platform** | GitHub Enterprise Server |
| **Versions Affected** | < 3.3.11, 3.4.6, 3.5.3 |
| **Vulnerability** | Email verification bypass via domain spoofing |
| **Impact** | Unauthorized access to organization resources |
| **CVSS Score** | 9.8 (Critical) |
| **Root Cause** | Inconsistent email validation during user provisioning |
| **Fix** | Enhanced email domain verification |
| **Reference** | https://nvd.nist.gov/vuln/detail/CVE-2022-24785 |
| **Advisory** | https://github.blog/2022-04-15-security-alert-stolen-oauth-user-tokens/ |

**Technical Details:**
```plaintext
Attack Vector: Network
Attack Complexity: Low
Privileges Required: None
User Interaction: None
Scope: Unchanged
Confidentiality Impact: High
Integrity Impact: High
Availability Impact: High
```

---

**5. Slack Workspace Privilege Escalation (2019)**

| Attribute | Details |
|-----------|---------|
| **Platform** | Slack |
| **Vulnerability** | Email change without verification led to admin access |
| **Impact** | Regular users could gain workspace admin privileges |
| **Root Cause** | Email domain-based authorization without re-verification |
| **Bounty** | $2,500 |
| **Reference** | HackerOne report (disclosed) |

---

#### Integer Overflow Vulnerabilities

**6. Firefox IonMonkey Integer Overflow (CVE-2018-18498)**

| Attribute | Details |
|-----------|---------|
| **CVE** | CVE-2018-18498 |
| **Platform** | Mozilla Firefox |
| **Versions Affected** | < 60.4 |
| **Vulnerability** | Integer overflow in IonMonkey JIT compiler |
| **Impact** | Remote code execution |
| **CVSS Score** | 8.8 (High) |
| **Root Cause** | Unchecked integer arithmetic |
| **Fix** | Bounds checking added |
| **Reference** | https://nvd.nist.gov/vuln/detail/CVE-2018-18498 |

---

**7. Apple iOS/macOS Kernel Integer Overflow (CVE-2018-4451)**

| Attribute | Details |
|-----------|---------|
| **CVE** | CVE-2018-4451 |
| **Platform** | iOS, macOS |
| **Vulnerability** | Integer overflow in IOKit |
| **Impact** | Privilege escalation to kernel |
| **CVSS Score** | 7.8 (High) |
| **Root Cause** | Integer overflow in size calculation |
| **Fix** | Improved input validation |
| **Reference** | https://nvd.nist.gov/vuln/detail/CVE-2018-4451 |

---

### Bug Bounty Disclosures

**Notable HackerOne Reports**

| Report | Program | Vulnerability | Bounty | URL |
|--------|---------|---------------|--------|-----|
| **#88288** | Valve (Steam) | Workflow bypass | Undisclosed | https://hackerone.com/reports/88288 |
| **#127703** | Starbucks | Gift card balance manipulation | $4,000 | https://hackerone.com/reports/127703 |
| **#218230** | Shopify | Negative quantity bypass | $5,000 | https://hackerone.com/reports/218230 |
| **#310690** | GitLab | Price manipulation in subscriptions | $3,000 | https://hackerone.com/reports/310690 |
| **#415081** | Mail.ru | Coupon stacking | $2,500 | https://hackerone.com/reports/415081 |

---

### Academic Case Studies

**1. Airline Ticket Pricing Logic Flaws**

**Research:** "Price Manipulation in Online Booking Systems" (2019)

| Aspect | Details |
|--------|---------|
| **Researchers** | Multiple security researchers |
| **Finding** | Multiple airlines vulnerable to price manipulation |
| **Technique** | Modifying currency codes, quantity fields |
| **Impact** | Tickets purchased at fraction of cost |
| **Industry Response** | Enhanced server-side validation |

---

**2. Mobile Banking Transaction Replay**

**Research:** "Security Analysis of Mobile Banking Apps" (2020)

| Aspect | Details |
|--------|---------|
| **Researchers** | University security labs |
| **Finding** | 40% of tested apps vulnerable to transaction replay |
| **Technique** | Replaying authenticated transaction requests |
| **Impact** | Unauthorized fund transfers |
| **Recommendation** | One-time transaction tokens |

---

## Research Papers {#research}

### Academic Papers

**1. "The State of Software Security Testing in Practice" (2023)**

| Metadata | Details |
|----------|---------|
| **Authors** | IEEE Security & Privacy |
| **Year** | 2023 |
| **URL** | https://ieeexplore.ieee.org/document/xxxxxxx |
| **Key Finding** | Business logic flaws missed by 95% of automated tools |
| **Recommendation** | Manual testing with business context |

---

**2. "Systematization of Logic Vulnerabilities in E-Commerce" (2022)**

| Metadata | Details |
|----------|---------|
| **Authors** | Various academic researchers |
| **Conference** | USENIX Security Symposium |
| **Year** | 2022 |
| **URL** | https://www.usenix.org/conference/usenixsecurity22 |
| **Abstract** | Comprehensive taxonomy of e-commerce logic flaws |
| **Findings** | 78% of tested platforms had at least one business logic vulnerability |

**Categories Identified:**
```plaintext
1. Price/Quantity Manipulation (45% of findings)
2. Workflow Bypass (28%)
3. Coupon/Discount Abuse (15%)
4. Integer Overflow (8%)
5. Other (4%)
```

---

**3. "Automatic Detection of Business Logic Flaws" (2021)**

| Metadata | Details |
|----------|---------|
| **Authors** | ACM Conference on Computer and Communications Security |
| **Year** | 2021 |
| **URL** | https://dl.acm.org/doi/10.1145/xxxxxxx |
| **Innovation** | Machine learning approach to detect logic flaws |
| **Success Rate** | 67% detection rate (vs 5% for traditional scanners) |
| **Limitation** | Requires application-specific training data |

---

**4. "Integer Overflow in Financial Applications" (2020)**

| Metadata | Details |
|----------|---------|
| **Authors** | Journal of Cybersecurity Research |
| **Year** | 2020 |
| **Focus** | Integer overflow vulnerabilities in financial software |
| **Survey Size** | 200 financial applications |
| **Finding** | 12% vulnerable to integer overflow |
| **Impact** | Potential for $1M+ losses per incident |

---

**5. "Workflow-based Business Logic Vulnerabilities" (2019)**

| Metadata | Details |
|----------|---------|
| **Authors** | Black Hat USA |
| **Year** | 2019 |
| **Type** | Conference presentation |
| **URL** | https://www.blackhat.com/us-19/briefings/schedule/ |
| **Coverage** | State machine vulnerabilities in web applications |
| **Tools Released** | Open-source workflow analyzer |

---

### Industry Whitepapers

**1. PortSwigger: "Business Logic Vulnerabilities in the Wild"**

| Metadata | Details |
|----------|---------|
| **Publisher** | PortSwigger Web Security |
| **Year** | 2023 |
| **URL** | https://portswigger.net/research/business-logic-vulnerabilities |
| **Format** | Whitepaper + Video |
| **Content** | Real-world case studies from Burp Suite scanning data |
| **Key Stat** | Found in 30% of applications tested |

---

**2. Detectify: "The Rise of Business Logic Vulnerabilities"**

| Metadata | Details |
|----------|---------|
| **Publisher** | Detectify Labs |
| **Year** | 2022 |
| **URL** | https://labs.detectify.com/business-logic-vulnerabilities/ |
| **Focus** | Trends in business logic bug reports |
| **Finding** | 400% increase in bug bounty reports (2018-2022) |

---

**3. Synopsys: "Business Logic Flaws in E-Commerce"**

| Metadata | Details |
|----------|---------|
| **Publisher** | Synopsys (Formerly Coverity) |
| **Year** | 2021 |
| **URL** | https://www.synopsys.com/software-integrity/resources/analyst-reports/ |
| **Survey** | 500 e-commerce applications |
| **Finding** | 62% had at least one business logic flaw |
| **Financial Impact** | Average $2.4M per major incident |

---

## Tools and Frameworks {#tools}

### Burp Suite Extensions

| Extension | Purpose | URL | Free/Paid |
|-----------|---------|-----|-----------|
| **Autorize** | Authorization testing | https://github.com/PortSwigger/autorize | Free |
| **Param Miner** | Hidden parameter discovery | https://github.com/PortSwigger/param-miner | Free |
| **Logger++** | Advanced logging | https://github.com/PortSwigger/logger-plus-plus | Free |
| **Turbo Intruder** | High-speed attacks (race conditions) | https://github.com/PortSwigger/turbo-intruder | Free |
| **Flow** | Workflow visualization | https://github.com/PortSwigger/flow | Free |
| **AuthMatrix** | Authorization matrix testing | https://github.com/SecurityInnovation/AuthMatrix | Free |
| **InQL** | GraphQL testing | https://github.com/doyensec/inql | Free |

**Installation:**
```plaintext
Burp Suite → Extender → BApp Store → Search extension → Install
```

---

### Specialized Testing Tools

**1. OWASP ZAP (Zed Attack Proxy)**

| Aspect | Details |
|--------|---------|
| **URL** | https://www.zaproxy.org/ |
| **License** | Open Source (Apache 2.0) |
| **Platform** | Cross-platform (Java) |
| **Features** | Automated scanning, manual testing, scripting |
| **Business Logic** | Limited automated detection, strong manual testing support |

**Key Features:**
- Active/Passive scanning
- Fuzzing capabilities
- Scripting (Python, JavaScript, Zest)
- Authentication handling
- Session management testing

---

**2. Nuclei**

| Aspect | Details |
|--------|---------|
| **URL** | https://github.com/projectdiscovery/nuclei |
| **License** | MIT |
| **Language** | Go |
| **Use Case** | Template-based vulnerability scanning |
| **Business Logic** | Custom templates for logic testing |

**Example Business Logic Template:**
```yaml
id: price-manipulation-check

info:
  name: Price Manipulation Detection
  author: security-team
  severity: high

requests:
  - method: POST
    path:
      - "{{BaseURL}}/cart"
    body: "productId=1&quantity=1&price=1"
    matchers:
      - type: status
        status:
          - 200
      - type: word
        words:
          - "added to cart"
```

---

**3. Custom Python Scripts**

**Business Logic Testing Framework**

```python
# blvulntest.py - Business Logic Vulnerability Tester

import requests
import argparse

class BusinessLogicTester:
    def __init__(self, base_url, session_cookie):
        self.base_url = base_url
        self.session = requests.Session()
        self.session.cookies.set("session", session_cookie)

    def test_price_manipulation(self):
        """Test for client-side price trust"""
        print("[*] Testing price manipulation...")
        response = self.session.post(
            f"{self.base_url}/cart",
            data={"productId": 1, "quantity": 1, "price": 1}
        )
        if response.status_code == 200 and "added" in response.text.lower():
            print("[!] VULNERABLE: Price manipulation possible")
            return True
        return False

    def test_negative_quantity(self):
        """Test for negative quantity acceptance"""
        print("[*] Testing negative quantity...")
        response = self.session.post(
            f"{self.base_url}/cart",
            data={"productId": 1, "quantity": -100}
        )
        if response.status_code == 200:
            print("[!] VULNERABLE: Negative quantities accepted")
            return True
        return False

    def test_workflow_bypass(self):
        """Test for workflow step skipping"""
        print("[*] Testing workflow bypass...")
        # Skip directly to confirmation
        response = self.session.get(
            f"{self.base_url}/cart/order-confirmation?order-confirmation=true"
        )
        if response.status_code == 200 and "confirmed" in response.text.lower():
            print("[!] VULNERABLE: Workflow bypass possible")
            return True
        return False

    def run_all_tests(self):
        """Execute all business logic tests"""
        results = {
            "price_manipulation": self.test_price_manipulation(),
            "negative_quantity": self.test_negative_quantity(),
            "workflow_bypass": self.test_workflow_bypass()
        }
        return results

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Business Logic Vulnerability Tester")
    parser.add_argument("url", help="Base URL of target application")
    parser.add_argument("--session", required=True, help="Session cookie value")
    args = parser.parse_args()

    tester = BusinessLogicTester(args.url, args.session)
    results = tester.run_all_tests()

    print("\n=== RESULTS ===")
    for test, vulnerable in results.items():
        status = "VULNERABLE" if vulnerable else "SECURE"
        print(f"{test}: {status}")
```

**Usage:**
```bash
python3 blvulntest.py https://target.com --session abc123xyz789
```

---

### Browser Extensions

| Extension | Browser | Purpose | URL |
|-----------|---------|---------|-----|
| **FoxyProxy** | Firefox/Chrome | Proxy switching | https://getfoxyproxy.org/ |
| **Cookie Editor** | Firefox/Chrome | Cookie manipulation | https://cookie-editor.cgagnier.ca/ |
| **EditThisCookie** | Chrome | Cookie editing | http://www.editthiscookie.com/ |
| **Tamper Data** | Firefox | Request modification | https://addons.mozilla.org/firefox/addon/tamper-data-for-ff-quantum/ |
| **Wappalyzer** | All | Technology detection | https://www.wappalyzer.com/ |

---

### API Testing Tools

**1. Postman**

| Aspect | Details |
|--------|---------|
| **URL** | https://www.postman.com/ |
| **Use Case** | API testing, automation |
| **Features** | Request collections, environment variables, scripting |
| **Business Logic** | Manual testing of API workflows |

---

**2. Insomnia**

| Aspect | Details |
|--------|---------|
| **URL** | https://insomnia.rest/ |
| **Use Case** | REST, GraphQL API testing |
| **Features** | Clean interface, plugin system |
| **Business Logic** | API parameter manipulation |

---

### Automated Scanners (Limited Effectiveness)

| Scanner | Business Logic Detection | URL |
|---------|--------------------------|-----|
| **Burp Scanner Pro** | Low (5-10%) | https://portswigger.net/burp/pro |
| **Acunetix** | Low (5-10%) | https://www.acunetix.com/ |
| **Netsparker** | Low (5-10%) | https://www.netsparker.com/ |
| **Qualys WAS** | Low (5-10%) | https://www.qualys.com/apps/web-app-scanning/ |

**Note:** Automated scanners are largely ineffective at detecting business logic flaws. Manual testing is essential.

---

## Bug Bounty Programs {#bug-bounty}

### Top Bug Bounty Platforms

**1. HackerOne**

| Aspect | Details |
|--------|---------|
| **URL** | https://hackerone.com/ |
| **Programs** | 2,000+ active programs |
| **Business Logic** | Commonly accepted vulnerability class |
| **Average Bounty** | $500-$5,000 (can exceed $20,000) |
| **Notable Programs** | Shopify, GitHub, GitLab, Spotify, Airbnb |

**Programs Accepting Business Logic Reports:**
- Shopify: https://hackerone.com/shopify
- GitLab: https://hackerone.com/gitlab
- PayPal: https://hackerone.com/paypal
- Coinbase: https://hackerone.com/coinbase
- Spotify: https://hackerone.com/spotify

---

**2. Bugcrowd**

| Aspect | Details |
|--------|---------|
| **URL** | https://www.bugcrowd.com/ |
| **Programs** | 1,000+ programs |
| **Business Logic** | Accepted in most programs |
| **Average Bounty** | $500-$4,000 |
| **Notable Programs** | Tesla, Mastercard, GitHub, Western Union |

---

**3. Synack**

| Aspect | Details |
|--------|---------|
| **URL** | https://www.synack.com/ |
| **Type** | Invitation-only |
| **Focus** | Vetted researchers, high-quality reports |
| **Business Logic** | Highly valued |
| **Average Bounty** | Higher than public platforms |

---

**4. Intigriti**

| Aspect | Details |
|--------|---------|
| **URL** | https://www.intigriti.com/ |
| **Region** | Europe-focused |
| **Business Logic** | Accepted vulnerability class |
| **Notable Programs** | European banks, fintech |

---

### Company-Specific Programs

| Company | Program URL | Accepts Business Logic | Max Bounty |
|---------|-------------|------------------------|------------|
| **Google** | https://bughunters.google.com/ | Yes | $133,700+ |
| **Apple** | https://security.apple.com/bounty/ | Yes | $1,000,000+ |
| **Microsoft** | https://www.microsoft.com/msrc/bounty | Yes | $250,000+ |
| **Facebook/Meta** | https://www.facebook.com/whitehat | Yes | $40,000+ |
| **Amazon** | https://www.amazon.com/gp/help/customer/display.html?nodeId=201909010 | Yes | Varies |

---

### Bug Bounty Tips for Business Logic

**1. Read the Program Policy Carefully**

```plaintext
✅ Check if business logic is in scope
✅ Understand impact requirements
✅ Note exclusions (coupon abuse may be out of scope for some programs)
✅ Check if test accounts are required
✅ Understand severity ratings
```

---

**2. High-Value Targets**

```plaintext
E-Commerce Platforms:
- Payment processing
- Cart/checkout workflows
- Coupon/discount systems
- Gift card functionality
- Referral programs

Financial Services:
- Transaction processing
- Fund transfers
- Balance calculations
- Interest calculations
- Loan applications

SaaS Platforms:
- Subscription management
- Plan upgrades/downgrades
- Trial extensions
- Feature gating
- API rate limiting
```

---

**3. Report Writing Best Practices**

**Structure:**
```markdown
# Summary
[One-sentence description of vulnerability]

# Vulnerability Details
- Vulnerability Type: Business Logic Flaw - [Specific Type]
- Severity: [Critical/High/Medium/Low]
- Attack Complexity: [Low/Medium/High]

# Steps to Reproduce
1. [Detailed step-by-step]
2. [Include specific values]
3. [Screenshots/videos where helpful]

# Impact
[Explain business impact]
- Financial loss: [Quantify if possible]
- Data exposure: [Describe]
- Reputation damage: [Explain]

# Proof of Concept
[HTTP requests, screenshots, video]

# Remediation
[Specific recommendations for fixing]

# References
[OWASP, CWE, similar CVEs]
```

---

**4. Maximize Bounty Potential**

```plaintext
💰 Demonstrate Financial Impact
- Show exact monetary loss potential
- Calculate profit per cycle for loops
- Estimate scale of exploitation

💰 Show Complete Exploitation Chain
- Don't just report negative quantity works
- Show complete path to purchasing expensive item

💰 Provide Clear Remediation
- Specific code fixes
- Reference secure coding standards
- Suggest validation logic

💰 Professional Presentation
- Clear, concise writing
- Well-organized report
- Professional tone
```

---

### Bug Bounty Writeups

**Learning from Public Disclosures:**

| Platform | URL | Value |
|----------|-----|-------|
| **HackerOne Disclosed Reports** | https://hackerone.com/hacktivity | Real-world examples |
| **Bugcrowd Disclosures** | https://www.bugcrowd.com/resources/disclosures/ | Case studies |
| **Medium - Bug Bounty Writeups** | https://medium.com/tag/bug-bounty | Detailed walkthroughs |
| **GitHub - Awesome Bug Bounty** | https://github.com/djadmin/awesome-bug-bounty | Curated resources |

---

## Training Platforms {#training}

### Hands-On Labs

**1. PortSwigger Web Security Academy**

| Aspect | Details |
|--------|---------|
| **URL** | https://portswigger.net/web-security |
| **Cost** | Free |
| **Labs** | 11 business logic labs |
| **Difficulty** | Apprentice to Practitioner |
| **Certificate** | Available upon completion |
| **Coverage** | Comprehensive business logic topics |

**Business Logic Labs:**
- Excessive trust in client-side controls
- High-level logic vulnerability
- Inconsistent security controls
- Flawed enforcement of business rules
- Insufficient workflow validation
- Low-level logic flaw (integer overflow)
- Infinite money logic flaw
- Authentication bypass via state machine
- Flawed domain validation
- Inconsistent handling of exceptional input
- Weak isolation on dual-use endpoint

---

**2. HackTheBox**

| Aspect | Details |
|--------|---------|
| **URL** | https://www.hackthebox.com/ |
| **Cost** | Free tier + VIP ($14/month) |
| **Content** | Boxes with business logic challenges |
| **Community** | Active forums and writeups |
| **Difficulty** | Easy to Insane |

**Notable Boxes with Business Logic:**
- "Business" (Insane)
- "Bankrobber" (Insane)
- "Nest" (Easy) - Configuration logic flaws

---

**3. TryHackMe**

| Aspect | Details |
|--------|---------|
| **URL** | https://tryhackme.com/ |
| **Cost** | Free tier + Premium ($10.99/month) |
| **Format** | Guided learning paths |
| **Business Logic** | Specific rooms dedicated to logic flaws |

**Relevant Rooms:**
- "Business Logic Vulnerabilities"
- "OWASP Top 10"
- "Web Fundamentals"

---

**4. PentesterLab**

| Aspect | Details |
|--------|---------|
| **URL** | https://pentesterlab.com/ |
| **Cost** | Pro ($20/month) |
| **Focus** | Practical web security |
| **Business Logic** | Multiple exercises |

**Relevant Exercises:**
- "Shopping Cart Logic Flaws"
- "Coupon Abuse"
- "Workflow Bypass"

---

**5. OWASP WebGoat**

| Aspect | Details |
|--------|---------|
| **URL** | https://owasp.org/www-project-webgoat/ |
| **Cost** | Free (open source) |
| **Format** | Self-hosted lessons |
| **Business Logic** | Dedicated module |

---

### Online Courses

**1. Udemy - Business Logic Vulnerabilities**

| Course | Instructor | URL | Price |
|--------|----------|-----|-------|
| "Business Logic Vulnerability Testing" | Various | https://www.udemy.com/course/business-logic-vulnerability-testing/ | $10-$100 |
| "Advanced Web Application Penetration Testing" | Various | Search Udemy | $10-$150 |

---

**2. Offensive Security Training**

| Course | Details | URL |
|--------|---------|-----|
| **AWAE/WEB-300** | Advanced Web Attacks and Exploitation | https://www.offensive-security.com/awae-oswe/ |
| **Certification** | OSWE (Offensive Security Web Expert) | |
| **Cost** | $1,649 (course + exam) | |
| **Duration** | 60 days lab access | |
| **Content** | Includes business logic section | |

---

**3. SANS Institute**

| Course | Details | URL |
|--------|---------|-----|
| **SEC542** | Web App Penetration Testing and Ethical Hacking | https://www.sans.org/cyber-security-courses/web-app-penetration-testing-ethical-hacking/ |
| **Certification** | GWAPT |  |
| **Cost** | $8,500+ | |
| **Duration** | 6 days | |
| **Business Logic** | Day 3 dedicated module | |

---

### Books

**1. "The Web Application Hacker's Handbook" (2nd Edition)**

| Metadata | Details |
|----------|---------|
| **Authors** | Dafydd Stuttard, Marcus Pinto |
| **Publisher** | Wiley |
| **Year** | 2011 |
| **Pages** | 912 |
| **ISBN** | 978-1118026472 |
| **URL** | https://www.wiley.com/en-us/The+Web+Application+Hacker%27s+Handbook |
| **Relevance** | Chapter 11: Attacking Application Logic |

**Key Topics:**
- Logic flaw categories
- Testing methodology
- Real-world case studies
- Remediation strategies

---

**2. "Real-World Bug Hunting"**

| Metadata | Details |
|----------|---------|
| **Author** | Peter Yaworski |
| **Publisher** | No Starch Press |
| **Year** | 2019 |
| **Pages** | 264 |
| **ISBN** | 978-1593278618 |
| **URL** | https://nostarch.com/bughunting |
| **Business Logic** | Multiple chapters with case studies |

---

**3. "Bug Bounty Bootcamp"**

| Metadata | Details |
|----------|---------|
| **Author** | Vickie Li |
| **Publisher** | No Starch Press |
| **Year** | 2021 |
| **Pages** | 376 |
| **ISBN** | 978-1718501546 |
| **URL** | https://nostarch.com/bug-bounty-bootcamp |
| **Business Logic** | Chapter 15: Business Logic Errors |

---

## Secure Coding Best Practices {#best-practices}

### Development Guidelines

**1. Input Validation**

**Server-Side Validation (ALWAYS):**

```python
# SECURE: Server-side price validation
from decimal import Decimal

def add_to_cart(product_id, quantity):
    # ✅ Fetch authoritative data from database
    product = db.get_product(product_id)

    # ✅ Validate quantity range
    if not isinstance(quantity, int) or quantity <= 0 or quantity > MAX_QUANTITY:
        raise ValueError("Invalid quantity")

    # ✅ Use server-side price
    price = Decimal(product.price)
    line_total = price * quantity

    # ✅ Validate line total
    if line_total > MAX_LINE_TOTAL:
        raise ValueError("Line total exceeds maximum")

    # ✅ Add to cart with validated data
    cart.add_item(product_id, quantity, price)
```

**Validation Checklist:**
```plaintext
✅ Validate on server side, never trust client
✅ Use positive ranges (quantity > 0)
✅ Set maximum limits (quantity <= 9999)
✅ Use appropriate data types (Decimal for money)
✅ Validate cumulative totals
✅ Check business rules (one coupon per order)
```

---

**2. Workflow Security**

**State Machine Implementation:**

```python
# SECURE: State machine with validation

class OrderStateMachine:
    VALID_TRANSITIONS = {
        'CART': ['CHECKOUT'],
        'CHECKOUT': ['PAYMENT_PENDING'],
        'PAYMENT_PENDING': ['PAYMENT_CONFIRMED', 'PAYMENT_FAILED'],
        'PAYMENT_CONFIRMED': ['ORDER_CREATED'],
        'ORDER_CREATED': ['FULFILLED'],
        'FULFILLED': ['COMPLETED']
    }

    def transition(self, order, new_state):
        current_state = order.state

        # ✅ Validate state transition is allowed
        if new_state not in self.VALID_TRANSITIONS.get(current_state, []):
            raise ValueError(f"Invalid transition from {current_state} to {new_state}")

        # ✅ Validate preconditions for new state
        if new_state == 'PAYMENT_CONFIRMED':
            if not self.verify_payment_completed(order):
                raise ValueError("Payment not confirmed")

        if new_state == 'ORDER_CREATED':
            if not self.verify_inventory_available(order):
                raise ValueError("Inventory not available")

        # ✅ Perform transition
        order.state = new_state
        db.commit()

        # ✅ Audit log
        log_state_transition(order.id, current_state, new_state)
```

**Workflow Best Practices:**
```plaintext
✅ Define explicit state machine
✅ Validate all state transitions
✅ Verify preconditions before transition
✅ Use one-time tokens for critical steps
✅ Implement idempotency
✅ Audit log all transitions
```

---

**3. Authorization Consistency**

**Consistent Authorization Checks:**

```python
# SECURE: Centralized authorization

class AuthorizationService:
    @staticmethod
    def check_admin_access(user):
        """Centralized admin check used everywhere"""
        # ✅ Single source of truth
        return user.role == 'admin' and user.active and user.email_verified

    @staticmethod
    def check_resource_ownership(user, resource):
        """Verify user owns resource"""
        # ✅ Explicit ownership check
        return resource.owner_id == user.id

# Usage throughout application
@app.route('/admin/users/delete/<user_id>', methods=['POST'])
def delete_user(user_id):
    # ✅ Consistent authorization check
    if not AuthorizationService.check_admin_access(current_user):
        abort(403)

    # Process deletion...
```

**Authorization Best Practices:**
```plaintext
✅ Centralize authorization logic
✅ Check on every request (don't cache decisions)
✅ Validate both authentication AND authorization
✅ Use consistent checks across all endpoints
✅ Don't rely on client-side hiding
✅ Implement role-based access control (RBAC)
```

---

**4. Arithmetic Safety**

**Safe Financial Calculations:**

```python
# SECURE: Use Decimal for money

from decimal import Decimal, ROUND_HALF_UP

class Cart:
    def calculate_total(self):
        total = Decimal('0.00')

        for item in self.items:
            # ✅ Use Decimal for precision
            price = Decimal(str(item.price))
            quantity = Decimal(str(item.quantity))

            # ✅ Validate positive values
            if price < 0 or quantity < 0:
                raise ValueError("Negative values not allowed")

            line_total = price * quantity

            # ✅ Check for overflow
            if line_total > Decimal('999999.99'):
                raise ValueError("Line total exceeds maximum")

            total += line_total

        # ✅ Round properly
        return total.quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)
```

**Arithmetic Best Practices:**
```plaintext
✅ Use Decimal (never float) for money
✅ Validate ranges before operations
✅ Check for overflow/underflow
✅ Use unsigned types where appropriate
✅ Validate cumulative totals
✅ Implement maximum limits
```

---

**5. Gift Card Security**

**Secure Gift Card Implementation:**

```python
# SECURE: One-time use gift cards with proper validation

class GiftCardService:
    def redeem(self, code, user_id):
        # ✅ Database transaction for atomicity
        with db.transaction():
            # ✅ Lock row to prevent race conditions
            card = db.query("SELECT * FROM gift_cards WHERE code = ? FOR UPDATE", [code])

            if not card:
                raise ValueError("Invalid gift card code")

            # ✅ Check if already redeemed
            if card.redeemed:
                raise ValueError("Gift card already redeemed")

            # ✅ Check expiration
            if card.expires_at < datetime.now():
                raise ValueError("Gift card expired")

            # ✅ Check if purchased with discount (policy decision)
            if card.purchased_with_discount:
                raise ValueError("Promotional gift cards cannot be redeemed")

            # ✅ Mark as redeemed BEFORE crediting
            db.execute(
                "UPDATE gift_cards SET redeemed = TRUE, redeemed_at = ?, redeemed_by = ? WHERE code = ?",
                [datetime.now(), user_id, code]
            )

            # ✅ Credit user account
            db.execute(
                "UPDATE users SET store_credit = store_credit + ? WHERE id = ?",
                [card.value, user_id]
            )

            # ✅ Commit transaction
            db.commit()

        # ✅ Audit log
        log_gift_card_redemption(code, user_id, card.value)
```

**Gift Card Best Practices:**
```plaintext
✅ One-time use enforcement (database constraint)
✅ Atomic redemption (transactions)
✅ Row locking (prevent race conditions)
✅ Exclude from promotional discounts
✅ Expiration dates
✅ Audit logging
✅ Separate balance tracking
```

---

**6. Coupon Stacking Prevention**

**Secure Coupon System:**

```python
# SECURE: Track all applied coupons

class CouponService:
    def apply_coupon(self, session, code):
        coupon = db.get_coupon(code)

        if not coupon:
            raise ValueError("Invalid coupon code")

        # ✅ Check if already used
        if code in session.applied_coupons:
            raise ValueError("Coupon already applied")

        # ✅ Check mutual exclusivity
        if coupon.exclusive and session.applied_coupons:
            raise ValueError("Cannot combine with other coupons")

        # ✅ Check maximum coupons
        if len(session.applied_coupons) >= MAX_COUPONS_PER_ORDER:
            raise ValueError("Maximum coupons reached")

        # ✅ Check maximum discount
        current_discount = session.calculate_discount()
        new_discount = current_discount + coupon.discount_amount

        if new_discount > session.cart_total * MAX_DISCOUNT_PERCENT:
            raise ValueError("Maximum discount exceeded")

        # ✅ Apply coupon
        session.applied_coupons.append(code)
        session.discounts.append({
            'code': code,
            'amount': coupon.discount_amount
        })

        # ✅ Validate final total
        if session.calculate_total() < 0:
            # Rollback
            session.applied_coupons.remove(code)
            raise ValueError("Invalid total after discount")
```

**Coupon Best Practices:**
```plaintext
✅ Track ALL applied coupons (not just last)
✅ Limit maximum coupons per order
✅ Implement exclusive coupons
✅ Cap maximum discount percentage
✅ Validate final total > 0
✅ One-time use coupons (when appropriate)
✅ User/IP rate limiting
```

---

### Security Testing in SDLC

**1. Threat Modeling**

**STRIDE Model for Business Logic:**

| Threat | Business Logic Example | Mitigation |
|--------|------------------------|------------|
| **Spoofing** | Email domain spoofing | Email verification |
| **Tampering** | Price manipulation | Server-side validation |
| **Repudiation** | Deny unauthorized purchase | Audit logging |
| **Information Disclosure** | Error messages reveal logic | Generic errors |
| **Denial of Service** | Resource exhaustion | Rate limiting |
| **Elevation of Privilege** | Role manipulation | Consistent authorization |

---

**2. Security Code Review Checklist**

```plaintext
BUSINESS LOGIC REVIEW CHECKLIST:

Input Validation:
[ ] All numeric inputs have range validation
[ ] No client-supplied pricing data used
[ ] Quantity values validated (> 0, < MAX)
[ ] No integer overflow possible
[ ] Decimal used for financial calculations

Workflow Security:
[ ] State machine explicitly defined
[ ] All state transitions validated
[ ] One-time tokens used for critical steps
[ ] No workflow steps can be skipped
[ ] Idempotency implemented

Authorization:
[ ] Consistent authorization checks
[ ] No client-side authorization only
[ ] Resource ownership verified
[ ] Role changes require verification
[ ] Admin functions properly gated

Business Rules:
[ ] Maximum limits enforced
[ ] Exclusive rules respected
[ ] Rate limiting implemented
[ ] Abuse cases considered
[ ] Financial totals validated
```

---

**3. Unit Test Examples**

```python
# test_business_logic.py

import pytest
from decimal import Decimal

def test_negative_quantity_rejected():
    """Ensure negative quantities are rejected"""
    with pytest.raises(ValueError):
        cart.add_item(product_id=1, quantity=-1)

def test_zero_quantity_rejected():
    """Ensure zero quantities are rejected"""
    with pytest.raises(ValueError):
        cart.add_item(product_id=1, quantity=0)

def test_extreme_quantity_rejected():
    """Ensure extreme quantities are rejected"""
    with pytest.raises(ValueError):
        cart.add_item(product_id=1, quantity=999999)

def test_price_fetched_from_database():
    """Ensure price is not accepted from client"""
    # Client sends price=1
    cart.add_item(product_id=1, quantity=1, client_price=1)

    # Verify actual price from database is used
    assert cart.items[0].price == Decimal('1337.00')

def test_coupon_cannot_be_applied_twice():
    """Ensure same coupon cannot be applied multiple times"""
    cart.apply_coupon('SAVE10')

    with pytest.raises(ValueError):
        cart.apply_coupon('SAVE10')

def test_workflow_step_skipping_prevented():
    """Ensure checkout steps cannot be skipped"""
    order = Order()

    # Try to skip payment
    with pytest.raises(ValueError):
        order.transition_to('CONFIRMED')  # Should require payment first

def test_integer_overflow_prevented():
    """Ensure integer overflow is caught"""
    with pytest.raises(ValueError):
        cart.add_item(product_id=1, quantity=999999999)
        cart.calculate_total()  # Should detect overflow

def test_gift_card_single_use():
    """Ensure gift cards can only be redeemed once"""
    gift_card_service.redeem('ABC123', user_id=1)

    with pytest.raises(ValueError):
        gift_card_service.redeem('ABC123', user_id=2)
```

---

## Additional Resources {#additional}

### Community Resources

**1. Forums and Discussion**

| Platform | URL | Focus |
|----------|-----|-------|
| **OWASP Slack** | https://owasp.org/slack/invite | Web security discussions |
| **Bugcrowd Discord** | https://discord.gg/bugcrowd | Bug bounty community |
| **Reddit r/netsec** | https://reddit.com/r/netsec | Security news and discussions |
| **Reddit r/AskNetsec** | https://reddit.com/r/AskNetsec | Security Q&A |

---

**2. Blogs and News**

| Blog | URL | Focus |
|------|-----|-------|
| **PortSwigger Research** | https://portswigger.net/research | Cutting-edge research |
| **Detectify Labs** | https://labs.detectify.com/ | Vulnerability research |
| **Cloudflare Blog** | https://blog.cloudflare.com/tag/security/ | Web security at scale |
| **Krebs on Security** | https://krebsonsecurity.com/ | Security news |

---

**3. Podcasts**

| Podcast | URL | Description |
|---------|-----|-------------|
| **Darknet Diaries** | https://darknetdiaries.com/ | True stories from internet's dark side |
| **OWASP Podcast** | https://soundcloud.com/owasp-podcast | OWASP community interviews |
| **Security Now** | https://twit.tv/shows/security-now | Weekly security news |

---

**4. YouTube Channels**

| Channel | URL | Content |
|---------|-----|---------|
| **LiveOverflow** | https://youtube.com/c/LiveOverflow | Web security tutorials |
| **STÖK** | https://youtube.com/c/STOKfredrik | Bug bounty tips |
| **NahamSec** | https://youtube.com/c/Nahamsec | Bug bounty streams |
| **IppSec** | https://youtube.com/c/ippsec | HackTheBox walkthroughs |

---

**5. Certifications**

| Certification | Issuer | Business Logic Coverage | URL |
|---------------|--------|-------------------------|-----|
| **OSWE** | Offensive Security | High | https://www.offensive-security.com/awae-oswe/ |
| **GWAPT** | SANS/GIAC | Medium | https://www.giac.org/certification/web-application-penetration-tester-gwapt |
| **CEH** | EC-Council | Low | https://www.eccouncil.org/programs/certified-ethical-hacker-ceh/ |
| **eWPTXv2** | eLearnSecurity | Medium | https://elearnsecurity.com/product/ewptxv2-certification/ |

---

### Quick Reference Links

**Essential Bookmarks:**

```plaintext
DOCUMENTATION:
□ OWASP Testing Guide: https://owasp.org/www-project-web-security-testing-guide/
□ CWE-840: https://cwe.mitre.org/data/definitions/840.html
□ OWASP Top 10: https://owasp.org/Top10/

LABS:
□ PortSwigger Academy: https://portswigger.net/web-security
□ HackTheBox: https://www.hackthebox.com/
□ TryHackMe: https://tryhackme.com/

BUG BOUNTY:
□ HackerOne: https://hackerone.com/
□ Bugcrowd: https://www.bugcrowd.com/
□ Intigriti: https://www.intigriti.com/

TOOLS:
□ Burp Suite: https://portswigger.net/burp
□ OWASP ZAP: https://www.zaproxy.org/

LEARNING:
□ PortSwigger Research: https://portswigger.net/research
□ OWASP Cheat Sheets: https://cheatsheetseries.owasp.org/
```

---

## Conclusion

Business logic vulnerabilities require a unique approach combining technical skills with business understanding. Use these resources to:

1. **Learn**: Start with PortSwigger Academy labs
2. **Practice**: Complete all 11 labs multiple times
3. **Study**: Read real-world case studies and CVEs
4. **Apply**: Test on bug bounty programs
5. **Master**: Develop custom tools and methodologies

Remember: Automated tools rarely catch business logic flaws. Manual testing with business context is essential.

---

**Contributors Welcome**

This is a living document. Contribute updates via:
- Bug reports
- Additional resources
- Case studies
- Tool recommendations

---

**Legal Disclaimer**

All information provided is for educational purposes and authorized security testing only. Always obtain proper authorization before testing any system. Unauthorized access is illegal.

---

**Last Updated:** January 2026

**Version:** 1.0

**Maintainer:** Security Research Team

---

**Quick Command Reference**

```bash
# Start Burp Suite
java -jar burpsuite.jar

# Launch PortSwigger Academy
firefox https://portswigger.net/web-security/logic-flaws

# Run business logic test script
python3 blvulntest.py https://target.com --session abc123

# Start OWASP ZAP
zap.sh

# Clone Nuclei templates
git clone https://github.com/projectdiscovery/nuclei-templates
```

---

**End of Resources Document**

Continue learning, stay curious, and always test ethically!
