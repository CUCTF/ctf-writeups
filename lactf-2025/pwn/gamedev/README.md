# gamedev

## Summary

This challenge provides a Linux CLI program ...

**Artifacts:**
* solve.py: exploit script that executes `/bin/sh` shellcode in the vulnerable
  process
* Dockerfile: container image file configured with the vulnerable program and
  debugging environments to analyze the program and develop the exploit
* chall/: all challenge files
* chall/chall: challenge executable
* chall/chall.c: source code of the challenge executable
* chall/Dockerfile: Dockerfile replicating the challenge environment
* chall/libc.so.6: challenge libc
* chall/ld-linux-x86-64.so.2: challenge dynamic loader

## Context

The `gamedev` challenge is running as a remote service to connect to by TCP
to a provided URL and port. The authors provide a copy of the compiled
challenge executable as well as source code and environment, to include libc.

`chall` is a 64-bit x86 Linux userspace program. It runs as a CLI program and
reads input from `stdin` and prints to `stdout`.

The program is a "heap-like game engine" that expects users to create, modify,
and explore "levels" in the game by entering text commands.

```
$ ./chall/chall
Welcome to the heap-like game engine!
A welcome gift: 0x579994d5b662
==================
1. Create level
2. Edit level
3. Test level
4. Explore
5. Reset
6. Exit
Choice:
```

The binary is dynamically compiled, but is missing some standard exploit
mitigations. In particular, stack canaries are disabled.

```
$ file chall/chall
chall/chall: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=2a9ddaa4e9fac0c99d698f62dc7d103c80063f99, for GNU/Linux 3.2.0, not stripped

$ checksec --file=chall/chall
[*] '/ctf/chall/chall'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        PIE enabled
    Stripped:   No
```

## Vulnerability

## Exploitation


**Exploit primitives used**:

## Remediation

## Configuration Notes

Use container for development:

```
docker build -t lactf-gamedev .
docker run --rm -it -p $(pwd):/ctf lactf-gamedev /bin/bash
```

Execute solution script against local target in container:

```
$ python3 solve.py
[*] '/ctf/chall/chall'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        PIE enabled
    Stripped:   No
[*] '/ctf/chall/libc.so.6'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
[*] '/ctf/chall/ld-linux-x86-64.so.2'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        PIE enabled
[+] Starting local process '/ctf/chall/ld-linux-x86-64.so.2': pid 11
[*] &base: 0x7f2ebbbcb000
[*] &atoi: 0x7f2ebba254a0
[!] pwned - enter shell commands
[*] Switching to interactive mode
$ ls
Dockerfile  README.md  chall  solve.py
$ cat chall/flag.txt
THIS_IS_THE_FLAGTHIS_IS_THE_FLAGTHIS_IS_THE_FLAGTHIS_IS_THE_FLAG
```

Execute solution script and start GDB for debugging target locally in
container:

```
# Must start tmux session before script executes.
tmux

python3 solve.py GDB
```

Execute solution script against remote target (ensure that the instance is
running in the picoCTF dashboard and that the URL and port are updated in the
script):

```
python3 solve.py REMOTE
<snip>
$ cat flag.txt
```
