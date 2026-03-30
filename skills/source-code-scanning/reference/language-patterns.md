# Language-Specific Vulnerability Patterns

## Python

### Dangerous Functions
```python
eval(user_input)                        # CWE-95: arbitrary code
exec(user_input)                        # CWE-78
os.system(f"cmd {user_input}")          # CWE-78: command injection
subprocess.Popen(user_input, shell=True)# CWE-78
pickle.loads(data)                      # CWE-502: deserialization RCE
yaml.load(data)                         # CWE-502: use yaml.safe_load
__import__(user_input)                  # CWE-470: dynamic import
open(user_input)                        # CWE-22: path traversal
```

### Flask/Django Specifics
```python
# Flask: debug mode in production
app.run(debug=True)

# Flask: secret key
app.secret_key = "hardcoded"

# Django: SQL via raw()
User.objects.raw(f"SELECT * WHERE id={uid}")  # SQLi

# Django: mark_safe with user input
mark_safe(user_input)  # XSS
```

## JavaScript / Node.js

### Dangerous Patterns
```javascript
eval(userInput)                     // CWE-95
new Function(userInput)()           // CWE-95
setTimeout(userInput, 0)            // CWE-95 if string
child_process.exec(cmd)             // CWE-78: use execFile
innerHTML = userInput               // CWE-79: XSS
document.write(userInput)           // CWE-79
require(userInput)                  // CWE-706: dynamic require
fs.readFile(userPath)               // CWE-22: path traversal
deserialize(userInput)              // CWE-502: node-serialize RCE
```

### Express Specifics
```javascript
// Missing helmet (security headers)
app.use(helmet())  // should be present

// Regex DoS (ReDoS)
new RegExp(userInput)  // CWE-1333

// Mass assignment
User.create(req.body)  // validate/whitelist fields first

// JWT: none algorithm
jwt.verify(token, secret, { algorithms: ['HS256'] })  // specify algorithm
```

## Java

### Dangerous Patterns
```java
Runtime.exec(userInput)                    // CWE-78
ProcessBuilder(userInput)                  // CWE-78
Statement.executeQuery("SELECT " + input)  // CWE-89: use PreparedStatement
ObjectInputStream.readObject()             // CWE-502: deserialization
Class.forName(userInput).newInstance()     // CWE-470
new File(basePath + userInput)             // CWE-22: path traversal
(T) ois.readObject()                       // CWE-502
```

### Spring Specifics
```java
// SpEL injection
@Value("#{${userInput}}")  // dangerous

// Mass binding
@ModelAttribute User user  // whitelist with @InitBinder

// Open redirect
response.sendRedirect(request.getParameter("url"))
```

## Go

### Dangerous Patterns
```go
exec.Command("sh", "-c", userInput)     // CWE-78
fmt.Sprintf("SELECT * WHERE id=%s", id) // CWE-89: use ?
os.Open(filepath.Join(base, userInput)) // CWE-22
html/template vs text/template          // XSS if wrong pkg
ioutil.ReadFile(userPath)               // CWE-22
```

### Common Go Issues
```go
// Integer overflow in slice index
slice[int32(userValue)]  // CWE-190

// Goroutine data race
go func() { sharedVar = x }()  // no mutex

// Error silently ignored
result, _ := riskyOp()  // CWE-252
```

## PHP

### Dangerous Patterns
```php
eval($userInput);                          // CWE-95
system($userInput);                        // CWE-78
shell_exec($userInput);                    // CWE-78
mysql_query("SELECT " . $input);           // CWE-89 (legacy)
include($userInput);                       // CWE-98: RFI/LFI
require($userInput);                       // CWE-98
unserialize($userInput);                   // CWE-502
echo $userInput;                           // CWE-79: XSS
header("Location: " . $userInput);        // CWE-601: open redirect
$_COOKIE['role'] === 'admin'              // trust client cookie
```

### PHP Specifics
```php
// Type juggling
"0e123" == "0e456"  // both == 0 in PHP (use ===)
strcmp($hash, $input) == 0  // returns null if array passed

// extract() from user input
extract($_POST);  // mass variable injection
```

## Ruby

### Dangerous Patterns
```ruby
eval(user_input)                      # CWE-95
system("cmd #{user_input}")           # CWE-78
`#{user_input}`                       # CWE-78: backtick exec
Open3.popen3(user_input)             # CWE-78
File.read(user_path)                  # CWE-22
YAML.load(user_input)                 # CWE-502: use safe_load
Marshal.load(user_input)              # CWE-502: RCE
redirect_to params[:return_url]       # CWE-601: open redirect
```

### Rails Specifics
```ruby
# SQL injection
User.where("name = '#{params[:name]}'")  # use ? placeholder
User.find_by("id = #{params[:id]}")

# Mass assignment
User.update(params)  # use strong parameters: params.permit(:name)

# XSS
<%= raw user_input %>    # renders without escaping
content_tag :div, user_input, escape: false
```

## Grep Quick-Scan Commands

```bash
# Injection sinks
grep -rn "eval\|exec\|system\|shell_exec\|popen" . --include="*.{py,js,php,rb}"

# Deserialization
grep -rn "pickle.loads\|yaml.load\|unserialize\|readObject\|Marshal.load" .

# SQL string concat
grep -rn '["'"'"'][^"'"'"']*\+.*\(query\|sql\|SELECT\|WHERE\)' .

# Hardcoded creds
grep -rn 'password\s*=\s*["'"'"'][^"'"'"']\{3,\}["'"'"']' .

# Path traversal
grep -rn 'open\s*(\|readFile\s*(\|File.read\s*(' . | grep -i "param\|input\|user\|request"
```
