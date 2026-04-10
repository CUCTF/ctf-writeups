# power cookie

## Summary

This challenge provides a website simulating an online gradebook. The premise is to exploit an insecure cookie implementation to gain admin access and retrieve the flag.

**Artifacts:**
- Web application hosted at `hhttp://saturn.picoctf.net:61439/`
- `guest.js`: client-side JavaScript that sets cookie values on login
- `check.php`: server-side PHP script that verifies cookie values

---

## Context

The challenge provides a URL to an online gradebook at `http://saturn.picoctf.net:61439/`. When navigating to the site, the only available option is a "Continue as Guest" button. Clicking it redirects to `check.php` and returns the message:

> *"We apologize, we have no guest services at the moment."*

Viewing the page source reveals a reference to `guest.js`, which contains the following logic:
```javascript
function continueAsGuest() {
    window.location = "/check.php";
    document.cookie = "isAdmin=0";
}
```

This shows that clicking the button sets an HTTP cookie `isAdmin` to `0` before redirecting to `check.php`, where the server-side PHP reads and verifies that cookie value.

---

## Vulnerability

HTTP cookies are stored client-side in the browser, meaning they can be freely viewed and modified by the user. The server-side script `check.php` uses the `isAdmin` cookie to determine whether to grant admin access — but it never validates that the cookie value was legitimately set by the server. This means an attacker can simply change `isAdmin` from `0` to `1` to impersonate an administrator.

---

## Exploitation

**Exploit overview:** Modify the `isAdmin` cookie value from `0` to `1` to trick the server into granting admin access and returning the flag.

**Exploit mitigation considerations:**

- **No HttpOnly or server-side session validation:** The cookie is set entirely by client-side JavaScript and is readable/writable by the user. A properly implemented auth system would use server-side session tokens that cannot be tampered with client-side.
- **Boolean trust on a client-controlled value:** The server blindly trusts the `isAdmin` value provided by the client with no cryptographic signing or verification.

### Method 1: Browser Developer Tools

1. Navigate to `http://saturn.picoctf.net:<port>/` and click "Continue as Guest"
2. Open Developer Tools (`F12`) and go to the **Application** tab
3. Under **Storage → Cookies**, find the entry for `isAdmin`
4. Double-click the value field and change it from `0` to `1`
5. Hard refresh the page (`Ctrl+Shift+R`) to send the updated cookie to the server
6. `check.php` reads `isAdmin=1` and returns the flag

### Method 2: `curl` on the Command Line
```bash
# Confirm default behavior — isAdmin=0 returns the guest error
curl --cookie "isAdmin=0" http://saturn.picoctf.net:<port>/check.php

# Set isAdmin=1 to gain admin access and retrieve the flag
curl -s --cookie "isAdmin=1" http://saturn.picoctf.net:<port>/check.php | grep -o "picoCTF{.*}"
```

The `-s` flag suppresses download progress output, and `grep` extracts just the flag from the response.

---

## Flag
```
picoCTF{gr4d3_A_c00k13_0d351e23}
```

---

## Remediation

To patch this vulnerability, cookie-based authentication should never rely on a client-supplied boolean value. Proper mitigations include:

- **Server-side sessions:** Authenticate users server-side and store session state there, issuing only an opaque session token to the client that cannot be forged.
- **HttpOnly and Secure flags:** Set cookies with `HttpOnly` to prevent client-side JavaScript access, and `Secure` to ensure transmission only over HTTPS.
- **Cryptographic signing:** If cookies must carry state, sign them with a secret key (e.g., HMAC) so tampering is detectable.

Written by Tatyana Ilieva 