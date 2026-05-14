# ACME Internal Admin Portal — CTF Challenge

**Category:** Web Exploitation  
**Difficulty:** Beginner / Intermediate  
**Vulnerability:** OS Command Injection (`shell=True`)  
**Educational Purpose:** Demonstrating insecure subprocess usage and secure remediation

---

## Project Overview

This is a purpose-built Capture The Flag (CTF) web challenge for an independent study cybersecurity course. The challenge simulates an accidentally exposed internal IT administration portal for a fictional company, ACME Technologies.

The portal contains a network ping utility that is intentionally vulnerable to OS Command Injection due to insecure use of Python's `subprocess` module with `shell=True` and unsanitized user input.

Players must discover and exploit this vulnerability to retrieve a hidden flag.

---

## Repository Structure

```
acme-admin-portal-ctf/
│
├── author/                  # Full source code (instructor/author view)
│   └── src/                 # Complete annotated application source
│       ├── app.py           # Vulnerable Flask application
│       ├── flag.txt         # Challenge flag
│       ├── requirements.txt
│       ├── Dockerfile
│       ├── templates/       # Jinja2 HTML templates
│       ├── static/          # CSS stylesheet
│       └── fake_data/       # Immersive fake content
│
├── deploy/                  # Deployable challenge environment
│   ├── app.py               # Same vulnerable app
│   ├── Dockerfile
│   ├── requirements.txt
│   ├── templates/
│   ├── static/
│   ├── fake_data/
│   ├── flag.txt
│   └── DEPLOY.md            # Deployment instructions
│
├── solution/                # Solve script + academic writeup
│   ├── solve.py             # Automated exploit script
│   └── WRITEUP.md           # Step-by-step solution and vulnerability analysis
│
└── challenge_description/   # Public-facing challenge prompt
    └── challenge.md
```

---

## Vulnerability Description

### Root Cause

The `/ping` endpoint in `app.py` passes user input directly into a shell command using Python's `subprocess.run()` with `shell=True`:

```python
# VULNERABLE CODE
result = subprocess.run(
    f"ping -c 1 {target}",  # user input concatenated into shell string
    shell=True,             # shell interprets metacharacters
    capture_output=True,
    text=True,
    timeout=10
)
```

With `shell=True`, the command is executed by `/bin/sh`. This means any shell metacharacters (`;`, `&&`, `|`) in the user-supplied `target` parameter will be interpreted by the shell, allowing command injection.

### Example Exploit

Input:
```
8.8.8.8; cat flag.txt
```

Shell executes:
```bash
ping -c 1 8.8.8.8; cat flag.txt
```

Result: the flag is returned in the HTTP response.

---

## Installation & Docker Usage

### Build

```bash
cd deploy/
docker build -t acme-portal .
```

### Run

```bash
docker run -p 5000:5000 acme-portal
```

### Access

```
http://localhost:5000
```

---

## Intended Solution

1. Browse the application and identify the `/tools` page
2. Notice the Ping Utility is the only active tool
3. Test it with a normal IP (`8.8.8.8`) — observe real command output
4. Inject shell metacharacters: `8.8.8.8; cat flag.txt`
5. The flag appears in the output

Full step-by-step walkthrough: [`solution/WRITEUP.md`](solution/WRITEUP.md)  
Automated exploit: [`solution/solve.py`](solution/solve.py)

---

## Security Mitigation

The vulnerability is fixed by:

1. **Removing `shell=True`** and passing arguments as a list
2. **Validating input** against a strict allowlist

```python
# SECURE VERSION
import re

target = request.args.get("target", "")

# Validate: only allow IP/hostname characters
if not re.match(r'^[\d\.a-zA-Z\-]+$', target) or len(target) > 64:
    return render_template("tools.html", ping_result="Error: Invalid target.")

result = subprocess.run(
    ["ping", "-c", "1", target],  # List form — no shell interpretation
    capture_output=True,
    text=True,
    timeout=10
    # shell=True removed entirely
)
```

**Key principles:**
- Never use `shell=True` with user-controlled input
- Validate and allowlist all user input before passing it to system calls
- Use argument arrays instead of string concatenation
- Run applications with minimum required privileges

---

## Learning Objectives

After completing this challenge, students should understand:

- What OS Command Injection is and how it occurs
- Why `shell=True` is dangerous with unsanitized input
- How shell metacharacters (`;`, `&&`, `|`) enable command chaining
- How to identify injection points through reconnaissance
- How to remediate the vulnerability with secure subprocess patterns
- Basic web exploitation methodology

---

## Educational Purpose Disclaimer

This application is **intentionally vulnerable** and was created solely for educational purposes as part of a cybersecurity coursework project. It demonstrates real-world vulnerability patterns in a controlled, isolated environment.

**Do not deploy this application on a public server or in any production environment.**

All company names, characters, and scenarios are fictional and for educational use only.

---

## References

- [OWASP: Command Injection](https://owasp.org/www-community/attacks/Command_Injection)
- [Python subprocess — Security Considerations](https://docs.python.org/3/library/subprocess.html#security-considerations)
- [CWE-78: OS Command Injection](https://cwe.mitre.org/data/definitions/78.html)
- [PortSwigger: OS Command Injection](https://portswigger.net/web-security/os-command-injection)
