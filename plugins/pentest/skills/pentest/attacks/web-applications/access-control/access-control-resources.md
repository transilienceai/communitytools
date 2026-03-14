# Access Control Vulnerabilities - Complete Resource Guide

**Comprehensive resources for mastering access control security testing**

---

## Table of Contents

- [OWASP Resources](#owasp-resources)
- [Industry Standards](#industry-standards)
- [CVE Examples](#cve-examples)
- [Tools and Frameworks](#tools-and-frameworks)
- [Research Papers](#research-papers)
- [Secure Coding Practices](#secure-coding-practices)
- [Training Platforms](#training-platforms)
- [Bug Bounty Programs](#bug-bounty-programs)
- [Books and Guides](#books-and-guides)
- [Community Resources](#community-resources)

---

## OWASP Resources

### OWASP Top 10

**A01:2021 - Broken Access Control**
- **URL:** https://owasp.org/Top10/A01_2021-Broken_Access_Control/
- **Description:** #1 ranked vulnerability in OWASP Top 10:2021
- **Key Points:**
  - 3.81% of applications tested had access control vulnerabilities
  - 318,000+ occurrences identified
  - 40 CWEs mapped to this category
  - Average of 3.73% incidence rate with notable common weakness enumerations

**Content Includes:**
- Overview of access control failures
- Common vulnerability patterns
- Prevention strategies
- Example attack scenarios
- References to CWE mappings

---

### OWASP Testing Guide

**Authorization Testing (WSTG-ATHZ)**
- **URL:** https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/
- **Sections:**
  - WSTG-ATHZ-01: Testing Directory Traversal File Include
  - WSTG-ATHZ-02: Testing for Bypassing Authorization Schema
  - WSTG-ATHZ-03: Testing for Privilege Escalation
  - WSTG-ATHZ-04: Testing for Insecure Direct Object References

**Key Content:**
- Detailed testing methodologies
- Tools and techniques
- Expected results
- Remediation guidance

---

### OWASP Cheat Sheets

**Authorization Cheat Sheet**
- **URL:** https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html
- **Topics:**
  - Access control principles
  - Centralized authorization
  - Enforce authorization on every request
  - Default deny approach
  - Role-based access control (RBAC)
  - Permission design patterns

**Access Control Cheat Sheet**
- **URL:** https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html
- **Content:**
  - Common pitfalls
  - Best practices
  - Implementation patterns
  - Framework-specific guidance

---

### OWASP Projects

**OWASP Access Control Community**
- **URL:** https://owasp.org/www-community/Access_Control
- **Resources:**
  - Vulnerability descriptions
  - Risk assessments
  - Technical impacts
  - Examples
  - Prevention strategies

**OWASP Secure Coding Practices**
- **URL:** https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/
- **Section 5:** Access Control
  - Enforce authorization checks
  - Segregate privileged logic
  - Restrict file access
  - Validate indirect references

---

## Industry Standards

### NIST (National Institute of Standards and Technology)

**NIST SP 800-53 - Security and Privacy Controls**
- **Access Control Family (AC):**
  - AC-1: Policy and Procedures
  - AC-2: Account Management
  - AC-3: Access Enforcement
  - AC-4: Information Flow Enforcement
  - AC-5: Separation of Duties
  - AC-6: Least Privilege
  - AC-17: Remote Access

**NIST SP 800-63 - Digital Identity Guidelines**
- Authentication and lifecycle management
- Federation and assertions
- Authorization principles

**URL:** https://csrc.nist.gov/publications

---

### PCI DSS (Payment Card Industry Data Security Standard)

**Requirement 6.5 - Secure Coding**
- **6.5.8:** Improper access control
- Validate authorization
- Prevent unauthorized access to data
- Secure coding training requirements

**Requirement 7 - Restrict Access**
- Role-based access control
- Least privilege principle
- Access control systems
- Review access rights regularly

**URL:** https://www.pcisecuritystandards.org/

---

### ISO/IEC 27001

**Annex A.9 - Access Control**
- A.9.1: Business requirements for access control
- A.9.2: User access management
- A.9.3: User responsibilities
- A.9.4: System and application access control

**Best Practices:**
- Formal access control policy
- User registration and de-registration
- Privilege management
- Password management
- Access to source code restriction

**URL:** https://www.iso.org/isoiec-27001-information-security.html

---

### MITRE Frameworks

**MITRE ATT&CK**
- **Tactic:** TA0004 - Privilege Escalation
- **Techniques:**
  - T1068: Exploitation for Privilege Escalation
  - T1078: Valid Accounts
  - T1548: Abuse Elevation Control Mechanism

**URL:** https://attack.mitre.org/

**MITRE CWE (Common Weakness Enumeration)**
- CWE-22: Path Traversal
- CWE-284: Improper Access Control
- CWE-285: Improper Authorization
- CWE-639: Authorization Bypass Through User-Controlled Key
- CWE-862: Missing Authorization
- CWE-863: Incorrect Authorization

**URL:** https://cwe.mitre.org/

**MITRE CAPEC (Common Attack Pattern Enumeration)**
- CAPEC-87: Forceful Browsing
- CAPEC-126: Path Traversal
- CAPEC-127: Directory Indexing
- CAPEC-402: Bypassing ACS through Pattern Recognition

**URL:** https://capec.mitre.org/

---

## CVE Examples

### Recent Critical Access Control CVEs

#### 2025 CVEs

**CVE-2025-67875 - RAGFlow IDOR & Broken Access Control**
- **CVSS Score:** 8.1 (High)
- **Vulnerability:** Cross-tenant access via IDOR
- **Description:** Combination of IDOR allowing any user to view other profiles, plus broken access control allowing general edit permissions to modify any user record
- **Impact:** Unauthorized data access and modification
- **Reference:** https://www.tenable.com/cve/CVE-2025-67875

**CVE-2025-27507 - ZITADEL IDOR Chain**
- **CVSS Score:** 9.0 (Critical)
- **Vulnerability:** IDOR in administration interface
- **Description:** Critical IDOR vulnerability chain allowing unauthorized administrative access
- **Impact:** Complete compromise of multi-tenant authentication system
- **Reference:** ZITADEL Security Advisory

**CVE-2025-32463 - sudo Privilege Escalation**
- **CVSS Score:** 9.8 (Critical)
- **Disclosure Date:** June 30, 2025
- **Vulnerability:** Privilege escalation in sudo
- **Description:** Local low-privileged users can escalate to root privileges
- **Impact:** Complete system compromise on virtually every Linux/Unix system
- **Reference:** sudo Security Advisory

---

#### 2024 CVEs

**CVE-2024-46528 - KubeSphere IDOR**
- **CVSS Score:** 8.8 (High)
- **Vulnerability:** Insecure direct object reference
- **Description:** Unauthorized access to resources via IDOR
- **Impact:** Cross-tenant data access
- **Reference:** KubeSphere GitHub Security Advisory

**CVE-2024-55471 - Oqtane Framework IDOR**
- **CVSS Score:** 7.5 (High)
- **Vulnerability:** IDOR in file management
- **Description:** Users can access files belonging to other users
- **Impact:** Unauthorized file access
- **Reference:** Oqtane Security Advisory

**CVE-2024-48899 - Moodle Course Badges IDOR**
- **CVSS Score:** 6.5 (Medium)
- **Vulnerability:** IDOR in badge system
- **Description:** Access to other users' badge information
- **Impact:** Information disclosure
- **Reference:** Moodle Security Announcements

**CVE-2024-3400 - Palo Alto PAN-OS Command Injection**
- **CVSS Score:** 10.0 (Critical)
- **Vulnerability:** OS command injection leading to RCE
- **Description:** Unauthenticated remote code execution
- **Impact:** Complete device compromise
- **Reference:** Palo Alto Security Advisory

**CVE-2024-4577 - PHP-CGI Windows Argument Injection**
- **CVSS Score:** 9.8 (Critical)
- **Vulnerability:** Argument injection vulnerability
- **Description:** Remote code execution on Windows systems
- **Impact:** Complete server compromise
- **Reference:** PHP Security Advisory

---

#### Notable Historical CVEs

**CVE-2021-22205 - GitLab Path Traversal & RCE**
- **CVSS Score:** 10.0 (Critical)
- **Vulnerability:** Unauthenticated file read via path traversal
- **Description:** Combined with image processing vulnerability for RCE
- **Impact:** Remote code execution as git user
- **Lesson:** Access control bypass + other vulns = critical impact
- **Reference:** GitLab Security Release

**CVE-2019-5418 - Ruby on Rails Path Traversal**
- **CVSS Score:** 7.5 (High)
- **Vulnerability:** File content disclosure via path traversal
- **Description:** Arbitrary file read through Accept header manipulation
- **Impact:** Source code and configuration disclosure
- **Reference:** Ruby on Rails Security Advisory

**CVE-2018-18314 - Grafana IDOR**
- **CVSS Score:** 6.5 (Medium)
- **Vulnerability:** API access control bypass
- **Description:** Users could access other organizations' data
- **Impact:** Unauthorized data access
- **Reference:** Grafana Security Advisory

**CVE-2019-8446 - Apache Airflow SSTI + Access Control**
- **CVSS Score:** 9.8 (Critical)
- **Vulnerability:** Server-side template injection
- **Description:** Combined with weak access controls for RCE
- **Impact:** Complete server compromise
- **Reference:** Apache Airflow Security Advisory

---

### Real-World Breach Examples

**Capital One Data Breach (2019)**
- **Vulnerability:** SSRF leading to AWS metadata access
- **Root Cause:** Broken access control in WAF configuration
- **Impact:** 100 million customer records exposed
- **Cost:** $80 million in fines
- **Lesson:** Cloud metadata endpoints need proper access controls

**Facebook IDOR Vulnerabilities**
- **Various instances:** Photo access, profile data, private information
- **Bug Bounty Payouts:** Multiple $10k-$40k rewards
- **Lesson:** Even with security teams, IDOR remains common

**Uber Trip Data Exposure**
- **Vulnerability:** IDOR allowing access to any rider's trip details
- **Impact:** Privacy violation, location tracking
- **Discovery:** Security researcher via bug bounty
- **Lesson:** Test all user-specific API endpoints

**British Airways Data Breach (2018)**
- **Vulnerability:** Cross-site scripting leading to payment data theft
- **Contributing Factor:** Weak access controls on payment scripts
- **Impact:** 380,000 payment card details stolen
- **Cost:** £20 million GDPR fine
- **Lesson:** Defense in depth for sensitive operations

---

## Tools and Frameworks

### Automated Testing Tools

#### Burp Suite Professional
- **URL:** https://portswigger.net/burp/pro
- **Features:**
  - Automated access control testing
  - Scanner for authorization flaws
  - Burp Collaborator for out-of-band testing
  - Extensive API for custom extensions
- **Extensions for Access Control:**
  - **Autorize:** Automated authorization testing
  - **AuthMatrix:** Role-based testing matrix
  - **Auth Analyzer:** Monitors session tokens
  - **Auto Repeater:** Automated request manipulation
- **Cost:** Commercial ($449/year per user)

#### OWASP ZAP (Zed Attack Proxy)
- **URL:** https://www.zaproxy.org/
- **Features:**
  - Free and open-source
  - Active and passive scanning
  - Access control testing add-ons
  - API for automation
- **Add-ons:**
  - Access Control Testing
  - Authentication Tester
  - Authorization Testing
- **Cost:** Free

#### Nuclei
- **URL:** https://github.com/projectdiscovery/nuclei
- **Features:**
  - Template-based vulnerability scanning
  - Community-contributed templates
  - Fast and efficient
  - CI/CD integration
- **Access Control Templates:**
  - IDOR detection
  - Admin panel discovery
  - Authorization bypass
- **Cost:** Free (open-source)

---

### Testing Frameworks

#### Metasploit Framework
- **URL:** https://www.metasploit.com/
- **Modules:**
  - Auxiliary modules for testing
  - Post-exploitation for privilege escalation
  - Integration with other tools
- **Cost:** Free (community), Commercial (Pro)

#### Postman
- **URL:** https://www.postman.com/
- **Features:**
  - API testing and automation
  - Collection runner for batch testing
  - Environment variables for multi-user testing
  - Scripting for authorization testing
- **Cost:** Free tier available, paid plans for teams

#### OWASP Amass
- **URL:** https://github.com/OWASP/Amass
- **Purpose:** Network mapping and attack surface discovery
- **Use Case:** Find hidden admin subdomains and interfaces
- **Cost:** Free (open-source)

---

### Custom Testing Tools

#### Python Libraries

**requests**
```python
import requests

# IDOR testing
for user_id in range(1, 1000):
    r = requests.get(
        f"https://api.example.com/user/{user_id}",
        headers={"Authorization": f"Bearer {token}"}
    )
    if r.status_code == 200:
        print(f"User {user_id} accessible")
```

**httpx (async requests)**
```python
import httpx
import asyncio

async def test_idor(session, user_id):
    async with session:
        r = await session.get(f"/user/{user_id}")
        return user_id, r.status_code

# Concurrent testing
```

---

#### Command-Line Tools

**curl**
```bash
# Basic access control testing
curl https://target.com/admin \
  -H "Cookie: session=abc123" \
  -v
```

**ffuf (Fast web fuzzer)**
```bash
# IDOR enumeration
ffuf -u https://target.com/api/user/FUZZ \
  -w numbers.txt \
  -H "Authorization: Bearer token" \
  -mc 200
```

**httpie**
```bash
# User-friendly HTTP client
http GET https://target.com/admin \
  Cookie:session=abc123 \
  --print=HhBb
```

---

### Browser Extensions

**Cookie-Editor**
- Quick cookie manipulation
- Export/import capabilities
- Available for Chrome, Firefox

**EditThisCookie**
- Edit cookies in-browser
- Search and filter
- Block/delete capabilities

**ModHeader**
- Modify HTTP headers
- Add custom headers (X-Original-URL, etc.)
- Profile switching

---

### Specialized Tools

#### Commix (Command Injection Exploiter)
- **URL:** https://github.com/commixproject/commix
- **Purpose:** OS command injection testing
- **Features:** Automated exploitation, various bypass techniques
- **Cost:** Free (open-source)

#### dotdotpwn
- **Purpose:** Path traversal fuzzing
- **Features:** Multiple protocols, encoding options
- **Use Case:** Test file access controls
- **Cost:** Free (open-source)

#### GitTools
- **URL:** https://github.com/internetwache/GitTools
- **Purpose:** Discover and extract .git directories
- **Use Case:** Find exposed source code revealing access control logic
- **Cost:** Free (open-source)

---

## Research Papers and Articles

### Foundational Research

**"Privilege Escalation Attacks on Android" (2010)**
- **Authors:** Davi et al.
- **Key Concepts:** Permission-based access control failures
- **Relevance:** Mobile app authorization patterns

**"An Empirical Study of Web Vulnerabilities" (2012)**
- **Authors:** Martin et al.
- **Findings:** Access control flaws in 8% of studied applications
- **Impact:** Statistical analysis of prevalence

**"Broken Object Level Authorization" (2019)**
- **Source:** OWASP API Security Top 10
- **Focus:** IDOR in modern APIs
- **Examples:** Real-world case studies

---

### Modern Research

**"Systematization of Access Control Vulnerabilities" (2023)**
- **Focus:** Categorization of access control flaws
- **Methodology:** Analysis of CVE database
- **Findings:** Common patterns across frameworks

**"Automated Detection of Authorization Bugs in Web Applications" (2022)**
- **Authors:** University research teams
- **Contribution:** Machine learning for detection
- **Tools:** Prototype static analysis tools

**"The State of Access Control in Modern Web Frameworks" (2024)**
- **Analysis:** Security features in popular frameworks
- **Comparison:** Django, Rails, Express, Spring
- **Recommendations:** Best practices per framework

---

### Industry Reports

**Verizon Data Breach Investigations Report (Annual)**
- **URL:** https://www.verizon.com/business/resources/reports/dbir/
- **Content:** Real-world breach statistics
- **Access Control Data:** Privilege misuse patterns

**OWASP Top 10 Report**
- **Latest:** 2021 (updated periodically)
- **URL:** https://owasp.org/Top10/
- **Focus:** Most critical security risks

**Synopsys Software Vulnerability Snapshot**
- **Annual:** Open-source audit results
- **Statistics:** Vulnerability prevalence
- **Trends:** Year-over-year changes

---

### Blog Posts and Writeups

**PortSwigger Research Blog**
- **URL:** https://portswigger.net/research
- **Topics:** Web security research, new techniques
- **Authors:** James Kettle, Gareth Heyes, others

**Orange Tsai's Blog**
- **URL:** https://blog.orange.tw/
- **Focus:** Advanced exploitation techniques
- **Notable:** Breaking Parser Logic research

**Sam Curry's Blog**
- **URL:** https://samcurry.net/
- **Content:** Bug bounty writeups
- **Examples:** Real-world IDOR and access control bypasses

**Detectify Labs**
- **URL:** https://labs.detectify.com/
- **Topics:** Web security vulnerabilities
- **Research:** Access control bypass techniques

---

## Secure Coding Practices

### Language-Specific Guidance

#### Python (Django)

**Built-in Protections:**
```python
from django.contrib.auth.decorators import login_required, permission_required
from django.contrib.auth.mixins import LoginRequiredMixin, PermissionRequiredMixin

# Function-based view
@login_required
@permission_required('app.delete_user', raise_exception=True)
def delete_user(request, user_id):
    user = get_object_or_404(User, id=user_id)
    # Verify requesting user owns resource
    if request.user != user and not request.user.is_staff:
        raise PermissionDenied
    user.delete()
    return redirect('user_list')

# Class-based view
class UserDeleteView(LoginRequiredMixin, PermissionRequiredMixin, DeleteView):
    permission_required = 'app.delete_user'
    model = User

    def get_object(self):
        obj = super().get_object()
        if self.request.user != obj and not self.request.user.is_staff:
            raise PermissionDenied
        return obj
```

**Best Practices:**
- Use Django's built-in permissions system
- Implement custom permission classes
- Use get_object_or_404 for IDOR protection
- Enable CSRF protection (default)

**Resources:**
- Django Security Documentation: https://docs.djangoproject.com/en/stable/topics/security/
- Django Permission System: https://docs.djangoproject.com/en/stable/topics/auth/

---

#### JavaScript (Node.js/Express)

**Middleware Pattern:**
```javascript
const express = require('express');
const app = express();

// Authorization middleware
function requireAdmin(req, res, next) {
    if (!req.user || !req.user.isAdmin) {
        return res.status(403).json({ error: 'Forbidden' });
    }
    next();
}

function requireOwnership(req, res, next) {
    const resourceUserId = req.params.userId;
    if (req.user.id !== resourceUserId && !req.user.isAdmin) {
        return res.status(403).json({ error: 'Forbidden' });
    }
    next();
}

// Apply middleware
app.delete('/admin/users/:id', requireAdmin, deleteUser);
app.get('/users/:userId/profile', requireOwnership, getProfile);
```

**Best Practices:**
- Use middleware for authorization checks
- Implement role-based access control (RBAC)
- Validate object ownership
- Use authentication libraries (Passport.js, jsonwebtoken)

**Resources:**
- Express Security Best Practices: https://expressjs.com/en/advanced/best-practice-security.html
- Helmet.js for security headers: https://helmetjs.github.io/

---

#### Java (Spring)

**Method Security:**
```java
@Configuration
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig {
    // Configuration
}

@RestController
@RequestMapping("/api")
public class UserController {

    @PreAuthorize("hasRole('ADMIN')")
    @DeleteMapping("/users/{id}")
    public ResponseEntity<?> deleteUser(@PathVariable Long id) {
        // Business logic
        return ResponseEntity.ok().build();
    }

    @PreAuthorize("#id == authentication.principal.id or hasRole('ADMIN')")
    @GetMapping("/users/{id}/profile")
    public ResponseEntity<User> getProfile(@PathVariable Long id) {
        User user = userService.findById(id)
            .orElseThrow(() -> new ResourceNotFoundException());
        return ResponseEntity.ok(user);
    }
}
```

**Best Practices:**
- Use Spring Security's annotations
- Implement expression-based access control
- Configure HTTP security
- Use method-level authorization

**Resources:**
- Spring Security Reference: https://docs.spring.io/spring-security/reference/
- Spring Security Architecture: https://spring.io/guides/topicals/spring-security-architecture/

---

#### PHP (Laravel)

**Middleware and Policies:**
```php
// Middleware
class EnsureUserIsAdmin {
    public function handle($request, Closure $next) {
        if (!Auth::user()->isAdmin()) {
            abort(403);
        }
        return $next($request);
    }
}

// Policy
class UserPolicy {
    public function view(User $authUser, User $user) {
        return $authUser->id === $user->id || $authUser->isAdmin();
    }

    public function delete(User $authUser, User $user) {
        return $authUser->isAdmin();
    }
}

// Controller
class UserController extends Controller {
    public function show(User $user) {
        $this->authorize('view', $user);
        return view('users.show', compact('user'));
    }

    public function destroy(User $user) {
        $this->authorize('delete', $user);
        $user->delete();
        return redirect()->route('users.index');
    }
}
```

**Best Practices:**
- Use Laravel's authorization features
- Define policies for models
- Use middleware for route protection
- Implement gates for custom logic

**Resources:**
- Laravel Authorization: https://laravel.com/docs/authorization
- Laravel Security: https://laravel.com/docs/security

---

### General Secure Coding Principles

#### 1. Centralized Authorization

**Bad:**
```javascript
// Authorization logic scattered across codebase
if (user.role === 'admin') { /* ... */ }
if (user.permissions.includes('delete')) { /* ... */ }
```

**Good:**
```javascript
// Centralized authorization service
class AuthorizationService {
    canDeleteUser(user, targetUser) {
        return user.isAdmin || user.id === targetUser.id;
    }

    canViewResource(user, resource) {
        return resource.ownerId === user.id || user.isAdmin;
    }
}

// Use throughout application
if (authService.canDeleteUser(currentUser, targetUser)) {
    // Perform deletion
}
```

---

#### 2. Server-Side Validation

**Bad:**
```javascript
// Client-side only
if (document.cookie.includes('admin=true')) {
    showAdminPanel();
}
```

**Good:**
```javascript
// Server-side validation
app.get('/admin', async (req, res) => {
    const user = await getUserFromSession(req.session.id);
    if (!user || !user.isAdmin) {
        return res.status(403).send('Forbidden');
    }
    res.render('admin-panel');
});
```

---

#### 3. Deny by Default

**Bad:**
```javascript
// Allow unless explicitly denied
function canAccess(user, resource) {
    if (resource.isDenied(user)) return false;
    return true; // Allows by default
}
```

**Good:**
```javascript
// Deny unless explicitly allowed
function canAccess(user, resource) {
    if (resource.isAllowed(user)) return true;
    return false; // Denies by default
}
```

---

#### 4. Indirect Object References

**Bad:**
```javascript
// Direct reference
app.get('/download/:filename', (req, res) => {
    const filepath = `/files/${req.params.filename}`;
    res.sendFile(filepath); // Vulnerable to path traversal
});
```

**Good:**
```javascript
// Indirect reference
const fileMapping = {
    'abc123': '/secure/path/file1.pdf',
    'def456': '/secure/path/file2.pdf'
};

app.get('/download/:fileId', (req, res) => {
    const filepath = fileMapping[req.params.fileId];
    if (!filepath) return res.status(404).send('Not found');

    // Verify user has access to this file ID
    if (!userHasAccessToFile(req.user, req.params.fileId)) {
        return res.status(403).send('Forbidden');
    }

    res.sendFile(filepath);
});
```

---

#### 5. Comprehensive Validation

**Bad:**
```javascript
// Only checking authentication
app.delete('/users/:id', isAuthenticated, deleteUser);
```

**Good:**
```javascript
// Checking authentication AND authorization
app.delete('/users/:id',
    isAuthenticated,
    requireAdmin,
    preventSelfDeletion,
    validateUserExists,
    deleteUser
);
```

---

### Framework Security Features

#### Enable Built-in Protections

**Django:**
```python
# settings.py
SECURE_SSL_REDIRECT = True
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
X_FRAME_OPTIONS = 'DENY'
SECURE_CONTENT_TYPE_NOSNIFF = True
```

**Express:**
```javascript
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

app.use(helmet());
app.use(rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100
}));
```

**Spring:**
```java
@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
            .and()
            .headers()
                .frameOptions().deny()
                .contentSecurityPolicy("default-src 'self'");
    }
}
```

---

## Training Platforms

### Hands-On Labs

#### PortSwigger Web Security Academy
- **URL:** https://portswigger.net/web-security
- **Access Control Labs:** 13 labs (Apprentice to Practitioner)
- **Features:**
  - Interactive labs
  - Detailed solutions
  - Progress tracking
  - Free access
- **Topics:**
  - Unprotected functionality
  - Parameter-based access control
  - IDOR vulnerabilities
  - Method-based bypasses
  - Multi-step process flaws

#### HackTheBox
- **URL:** https://www.hackthebox.com/
- **Content:**
  - Machines with access control vulnerabilities
  - Web challenges focused on authorization
  - Pro Labs for advanced scenarios
- **Cost:** Free tier + VIP ($20/month)

#### TryHackMe
- **URL:** https://tryhackme.com/
- **Rooms:**
  - OWASP Top 10 (Access Control section)
  - IDOR Vulnerabilities
  - Privilege Escalation paths
  - API Security
- **Features:**
  - Guided learning paths
  - Certificates
  - Active community
- **Cost:** Free tier + Premium ($10.99/month)

#### PentesterLab
- **URL:** https://pentesterlab.com/
- **Exercises:**
  - Access control bypass techniques
  - IDOR exploitation
  - Privilege escalation
- **Features:**
  - Hands-on vulnerable environments
  - Progressive difficulty
- **Cost:** $20/month

---

### Online Courses

#### Offensive Security (OffSec)
- **Web-200 (OSWA):** Web application security
- **PEN-200 (OSCP):** Penetration testing with access control focus
- **URL:** https://www.offensive-security.com/
- **Cost:** $999-$1,649 per course

#### SANS Institute
- **SEC542:** Web App Penetration Testing
- **SEC504:** Hacker Tools, Techniques, Exploits
- **URL:** https://www.sans.org/
- **Cost:** $8,500+ per course

#### Pluralsight
- **Path:** Ethical Hacking: Web Applications
- **Courses:** Authorization and authentication security
- **URL:** https://www.pluralsight.com/
- **Cost:** $29-$45/month

#### Udemy
- **Courses:**
  - Web Security & Bug Bounty: Learn Penetration Testing
  - OWASP Top 10 Vulnerabilities
- **URL:** https://www.udemy.com/
- **Cost:** $10-$200 per course (frequent sales)

---

### Certifications

#### OSWA (Offensive Security Web Assessor)
- **Focus:** Web application security
- **Exam:** 24-hour practical exam
- **URL:** https://www.offensive-security.com/awae-oswa/

#### OSCP (Offensive Security Certified Professional)
- **Focus:** Penetration testing (includes web)
- **Exam:** 24-hour practical exam
- **URL:** https://www.offensive-security.com/pwk-oscp/

#### CEH (Certified Ethical Hacker)
- **Focus:** Ethical hacking fundamentals
- **Exam:** Multiple choice + practical
- **URL:** https://www.eccouncil.org/programs/certified-ethical-hacker-ceh/

#### GWAPT (GIAC Web Application Penetration Tester)
- **Focus:** Web application security testing
- **Exam:** Proctored, open-book
- **URL:** https://www.giac.org/certification/web-application-penetration-tester-gwapt

---

## Bug Bounty Programs

### Major Platforms

#### HackerOne
- **URL:** https://www.hackerone.com/
- **Programs:** 2,000+ active programs
- **Notable:** GitLab, GitHub, Shopify, U.S. Dept of Defense
- **Access Control Scope:** Most programs include authorization testing
- **Payouts:** $500-$50,000+ for critical access control issues
- **Statistics:** Broken access control in top 10 vulnerability types

#### Bugcrowd
- **URL:** https://www.bugcrowd.com/
- **Programs:** 500+ programs
- **Notable:** Tesla, Atlassian, Western Union
- **Focus:** Web and mobile app vulnerabilities
- **Payouts:** Varies by severity and program

#### Intigriti
- **URL:** https://www.intigriti.com/
- **Programs:** European focus
- **Notable:** European companies and governments
- **Community:** Active Discord for collaboration

#### Synack
- **URL:** https://www.synack.com/
- **Model:** Invite-only platform
- **Focus:** Continuous pentesting
- **Vetting:** Application process for researchers

---

### Bug Bounty Tips for Access Control

**High-Value Targets:**
- Admin panel access bypasses
- IDOR in sensitive data (PII, financial)
- Privilege escalation to admin
- Cross-tenant data access (for SaaS)
- Payment/billing data access

**Reporting Tips:**
1. Clear impact demonstration
2. Reproduction steps with screenshots
3. Affected user roles
4. Business impact assessment
5. Recommended remediation

**Common Payouts:**
- **Low:** $100-$500 (information disclosure)
- **Medium:** $500-$2,000 (user data access)
- **High:** $2,000-$10,000 (privilege escalation)
- **Critical:** $10,000-$50,000+ (admin access, mass data breach)

---

### Notable Bug Bounty Findings

**Facebook IDOR - $31,500**
- Vulnerability: Access to deleted photos via IDOR
- Researcher: Multiple instances
- Impact: Privacy violation

**Uber IDOR - $5,000**
- Vulnerability: Access to trip details of any rider
- Researcher: Vulnerability Lab
- Impact: Location tracking, privacy breach

**GitHub API IDOR - $10,000**
- Vulnerability: Access to private repository data
- Researcher: Security researcher community
- Impact: Intellectual property exposure

**Shopify Privilege Escalation - $25,000**
- Vulnerability: Staff account takeover
- Researcher: Top HackerOne researcher
- Impact: Store compromise

---

## Books and Guides

### Essential Reading

#### "The Web Application Hacker's Handbook" (2nd Edition)
- **Authors:** Dafydd Stuttard, Marcus Pinto
- **Publisher:** Wiley
- **ISBN:** 978-1118026472
- **Content:**
  - Chapter 8: Attacking Access Controls
  - Comprehensive methodology
  - Real-world examples
- **Level:** Intermediate to Advanced

#### "Web Security Testing Cookbook"
- **Author:** Paco Hope, Ben Walther
- **Publisher:** O'Reilly
- **ISBN:** 978-0596514839
- **Content:**
  - Practical recipes for testing
  - Authorization testing techniques
  - Tool usage examples
- **Level:** Beginner to Intermediate

#### "Real-World Bug Hunting"
- **Author:** Peter Yaworski
- **Publisher:** No Starch Press
- **ISBN:** 978-1593278618
- **Content:**
  - Bug bounty approach
  - Real vulnerability case studies
  - Access control examples
- **Level:** Beginner to Intermediate

#### "Hacking APIs"
- **Author:** Corey Ball
- **Publisher:** No Starch Press
- **ISBN:** 978-1718502444
- **Content:**
  - API security testing
  - Authorization in APIs
  - BOLA/IDOR techniques
- **Level:** Intermediate

---

### Technical References

#### "OWASP Testing Guide v4.2"
- **Format:** Free PDF/Online
- **URL:** https://owasp.org/www-project-web-security-testing-guide/
- **Content:**
  - Authorization testing methodology
  - Comprehensive test cases
  - Tool recommendations

#### "PCI DSS Quick Reference Guide"
- **Format:** Free PDF
- **URL:** https://www.pcisecuritystandards.org/
- **Relevance:** Access control requirements for payment systems
- **Use Case:** Compliance-focused testing

#### "NIST SP 800-53 Rev. 5"
- **Format:** Free PDF
- **URL:** https://csrc.nist.gov/publications/
- **Content:** Security and privacy controls
- **Focus:** Access control family (AC)

---

## Community Resources

### Forums and Communities

#### Reddit
- **r/netsec** - Network security discussions
- **r/websecurity** - Web security specific
- **r/AskNetsec** - Q&A for security topics
- **r/bugbounty** - Bug bounty community

#### Discord Servers
- **HackerOne Community**
- **Bugcrowd University**
- **PortSwigger Community**
- **OWASP Community**

#### Twitter/X Security Researchers
- **@samwcyo** - Sam Curry (bug bounty)
- **@PortSwiggerRes** - PortSwigger Research
- **@orange_8361** - Orange Tsai
- **@NahamSec** - NahamSec (bug bounty education)
- **@stokfredrik** - Stök (bug bounty videos)
- **@nahamsec** - Ben Sadeghipour

---

### YouTube Channels

#### Educational Channels
- **STÖK** - Bug bounty tutorials
- **NahamSec** - Web security and bug bounty
- **IppSec** - HackTheBox walkthroughs
- **LiveOverflow** - Security research deep dives
- **PwnFunction** - Animated security concepts

#### Conference Talks
- **DEF CON** - Annual security conference
- **Black Hat** - Security research presentations
- **OWASP Global AppSec** - Application security
- **BSides** - Community-driven security events

---

### Podcasts

- **Darknet Diaries** - Security stories and incidents
- **Hacking Humans** - Social engineering focus
- **The Cyber Wire** - Daily security news
- **Risky Business** - Security news and analysis

---

### Blogs and News

#### Security News
- **Krebs on Security** - https://krebsonsecurity.com/
- **The Hacker News** - https://thehackernews.com/
- **Bleeping Computer** - https://www.bleepingcomputer.com/
- **Dark Reading** - https://www.darkreading.com/

#### Research Blogs
- **PortSwigger Research** - https://portswigger.net/research
- **Google Project Zero** - https://googleprojectzero.blogspot.com/
- **Trail of Bits Blog** - https://blog.trailofbits.com/
- **NCC Group Research** - https://research.nccgroup.com/

---

## Summary

This resource guide provides comprehensive references for mastering access control vulnerability testing and exploitation. Key areas covered:

1. **Standards:** OWASP, NIST, PCI DSS, ISO 27001
2. **CVEs:** Recent and historical access control vulnerabilities
3. **Tools:** Burp Suite, ZAP, Nuclei, custom scripts
4. **Research:** Academic papers and industry reports
5. **Secure Coding:** Framework-specific best practices
6. **Training:** PortSwigger, HackTheBox, TryHackMe
7. **Bug Bounty:** HackerOne, Bugcrowd, tips and payouts
8. **Books:** Essential reading for security professionals
9. **Community:** Forums, Discord, Twitter, YouTube

**Recommended Learning Path:**
1. Start with OWASP resources and PortSwigger labs
2. Practice on training platforms (PortSwigger, TryHackMe)
3. Read "The Web Application Hacker's Handbook"
4. Participate in bug bounty programs
5. Join security communities for knowledge sharing
6. Stay updated with security blogs and CVE databases

**Stay Current:**
- Follow security researchers on Twitter
- Subscribe to security newsletters
- Monitor CVE databases
- Participate in CTFs and bug bounties
- Attend security conferences (virtual or in-person)

---

**Last Updated:** 2025
**Maintained By:** Security research community
**License:** Creative Commons - Educational Use
