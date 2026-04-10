# bbbloat

## Summary

This challenge provides a stripped ELF 64-bit binary that prompts the user for a "favorite number." The goal is to reverse engineer the binary to find the expected input, which triggers a deobfuscation that decodes and prints the flag. The binary uses obfuscation to prevent the flag from appearing as a plaintext string, but the comparison value and the obfuscated flag data are both recoverable through static analysis in Ghidra.

**Artifacts:**
- `bbbloat`: stripped ELF 64-bit position-independent executable (PIE)

**Category:** Reverse Engineering  

---

## Context

The challenge provides a single binary file called `bbbloat`. Before doing anything else, I wanted to understand the file I was dealing with.

###Identifying the file type with `file`

The `file` command reads the bytes at the start of a file and tells you what it actually is, regardless of the filename or extension.

```
$ file bbbloat
bbbloat: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked,
interpreter /lib64/ld-linux-x86-64.so.2, stripped
```

This means:

- **ELF**: Executable and Linkable Format — the standard binary format for Linux executables. This tells us it's a Linux binary, not a Windows `.exe` or a macOS Mach-O.
- **64-bit**: The binary was compiled for a 64-bit architecture (x86-64), meaning it uses 64-bit registers and memory addresses.
- **LSB**: Least Significant Byte first — i.e., little-endian byte ordering. This is standard for x86/x86-64.
- **pie executable**: Position Independent Executable. The binary is compiled so it can be loaded at any memory address. The OS will randomize the base address each run via ASLR (Address Space Layout Randomization). This makes certain exploit techniques harder but doesn't affect our approach here since we're doing static analysis.
- **dynamically linked**: The binary relies on shared libraries (like `libc`) that are loaded at runtime rather than being compiled into the binary itself. This means calls to functions like `printf` and `scanf` go through the Procedure Linkage Table (PLT).
- **stripped**: Debug symbols have been removed. Normally, a compiled binary keeps a symbol table mapping function names like `main` to their addresses. Stripping removes this, so a disassembler like Ghidra will label functions generically as `FUN_00101249` instead of `main`. This is an obfuscation step.

### Running the binary

Then I ran the binary to understand what it does at face value:

```
$ chmod +x bbbloat    # make sure it's executable
$ ./bbbloat
What's my favorite number?
42
Sorry, that's not it!
```

The program:
1. Prints a prompt asking for a number
2. Reads a number from stdin
3. Checks if it matches some expected value
4. Prints a failure message and exits if wrong

The goal is clear: find the number it expects.

### Checking for plaintext strings with `strings`

I ran the `strings` command scans which scans a binary file and prints any sequence of printable ASCII characters above a minimum length (default 4). 
```
$ strings bbbloat
/lib64/ld-linux-x86-64.so.2
...
__libc_start_main
...
What's my favorite number?
Sorry, that's not it!
...
```

We can see the prompt and failure strings, but no flag and no obvious password or number. This tells us the flag and the expected input are either computed at runtime or stored in a non-obvious form. 

---

## Dynamic Analysis

I then tried `ltrace` and `strace`.

### ltrace — Library Call Tracer

`ltrace` intercepts and logs every call a program makes to shared library functions. This is useful because many programs compare passwords or secrets using library calls like `strcmp("user_input", "secret")` and `ltrace` would show both arguments.

```
$ ltrace ./bbbloat
What's my favorite number?
42
Sorry, that's not it!
+++ exited (status 0) +++
```

`ltrace` produces almost no output here. The program runs and exits, but no library calls with interesting arguments are logged. This tells us the comparison is **not** done through a function like `strcmp`. This means `ltrace` won't yield the answer.

### strace — System Call Tracer

`strace` operates one level lower than `ltrace`. It intercepts raw system calls. Common system calls that I saw include `read` (reading input), `write` (printing output) and `mmap` (mapping memory).

```
$ strace ./bbbloat
execve("./bbbloat", ["./bbbloat"], 0x7ffd... /* 23 vars */) = 0
...
mmap(NULL, 8192, PROT_READ|PROT_WRITE, ...) = 0x7f...
...
write(1, "What's my favorite number?\n", 27) = 27
read(0, 42
"42\n", 1024)                           = 3
write(1, "Sorry, that's not it!\n", 22)  = 22
exit_group(0)                           = ?
```

Breaking down the key lines:

- `write(1, "What's my favorite number?\n", 27)` — writes 27 bytes to file descriptor 1 (stdout), which is the prompt we see
- `read(0, "42\n", 1024)` — reads from file descriptor 0 (stdin); we typed `42` and hit enter
- `write(1, "Sorry, that's not it!\n", 22)` — writes the failure message to stdout
- `exit_group(0)` — program exits with status 0

`strace` confirms the control flow but does not reveal the expected number. The comparison value never touches a system call — it's purely internal to the program's logic. 

---

## Static Analysis with Ghidra

Since dynamic analysis didn't surface the answer, I opened the binary in Ghidra. Ghidra disassembles the binary into assembly instructions and then **decompiles** them into readable C-like pseudocode.

I imported `bbbloat` into Ghidra and viewed it in the **CodeBrowser**.

### Finding main via Defined Strings

Since the binary is stripped, I couldn't just look for a function named `main`. So I looked for **Defined Strings**, where I found:

```
"What's my favorite number?"
```
### Decompiled pseudocode — main

```c
 undefined8 FUN_00101307(void){
    char *__s;
    long in_FS_OFFSET;
    int local_48;
    undefined8 local_38;
    undefined8 local_30;
    undefined8 local_28;
    undefined8 local_20;
    long local_10;

    local_10 = *(long *)(in_FS_OFFSET + 0x28);
    local_38 = 0x4c75257240343a41;
    local_30 = 0x3062396630664634;
    local_28 = 0x65623066635f3d33;
    local_20 = 0x4e326560623535;

    printf("What\'s my favorite number? ");
    __isoc99_scanf();
    if (local_48 == 0x86187) {
        __s = (char *)FUN_00101249(0, &local_38);
        fputs(__s, stdout);
        putchar(10);
        free(__s);
    }
    else {
        puts("Sorry, that\'s not it!");
    }
    if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
        /* WARNING: Subroutine does not return */
        __stack_chk_fail();
    }
    return;
}
```
## Vulnerability ##
In the main code, 

local_10 = *(long *)(in_FS_OFFSET + 0x28) is a compiler-inserted stack canary — a security value read from a special memory region at function entry and checked again before the function returns. If the stack has been tampered with, __stack_chk_fail() is called and the program crashes. This wasn't relevant since this is not a memory exploit.

local_38 through local_20 are hex constants loaded onto the stack. These are the obfuscated flag data that are stored as raw integer values rather than a readable string, which is why strings would not find them.
local_48 is the variable holding the user's input from scanf.

if (local_48 == 0x86187) is the key check; it is a direct integer equality comparison against a hardcoded constant. This is the vulnerability. The expected value is sitting plainly in the binary, readable to anyone with a decompiler.
FUN_00101249 is called if the check passes, taking the obfuscated buffer as an argument and returning a decoded string __s that gets printed with fputs. I double-clicked into this function to understand what it does.
Decompiled pseudocode — FUN_00101249 (decode function): 

```c
char * FUN_00101249(undefined8 param_1, char *param_2)
{
    char cVar1;
    char *__s;
    size_t sVar2;
    ulong local_20;

    __s = strdup(param_2);
    sVar2 = strlen(__s);
    for (local_20 = 0; local_20 < sVar2; local_20 = local_20 + 1) {
        if ((' ' < __s[local_20]) && (__s[local_20] != '\x7f')) {
            cVar1 = (char)(__s[local_20] + 0x2f);
            if (__s[local_20] + 0x2f < 0x7f) {
                __s[local_20] = cVar1;
            }
            else {
                __s[local_20] = cVar1 + -0x5e;
            }
        }
    }
    return __s;
}
```
Breaking down what this function does:

strdup(param_2) makes a copy of the obfuscated flag buffer so the original is not modified.

The for loop iterates over every character in the copied string.
The if condition — ' ' < __s[local_20] and __s[local_20] != '\x7f' — checks that the character is a printable ASCII character (above space, not the DEL character). Characters outside this range are left unchanged.

The transformation adds 0x2f to each qualifying character. If the result is below 0x7f (stays in printable range), it uses that value directly. If it would go above 0x7f, it wraps around by subtracting 0x5e. This is a ROT-style Caesar cipher applied to the printable ASCII range — each character is shifted forward by 47 positions (0x2f) with wrapping, decoding the obfuscated bytes stored in local_38 through local_20. return __s returns the decoded flag string back to main, where it is printed with fputs

---

## Exploitation

### Converting the constant

```
$ python3 -c "print(0x86187)"
549255
```

### Running the binary with the correct input

```
$ ./bbbloat
What's my favorite number?
549255

```
Yielding:
`picoCTF{cu7_7h3_bl047_36dd316a}`

---

## Exploit Primitive Summary

| Primitive | Detail |
|-----------|--------|
| Binary type | Stripped ELF 64-bit PIE — no symbols, base address randomized |
| Comparison mechanism | Direct integer equality: `user_input == 0x86187` (549255 decimal) |
| Flag storage | Bytes packed into stack-allocated integer literals, never a contiguous string |
| Obfuscation method | ROT-style Caesar cipher: each byte shifted by +0x2f with wraparound at 0x7f |
| Deobfuscation trigger | Correct input passes the `if` check, calling the decode loop |
| Relevant mitigations | PIE present but irrelevant; no canary; no anti-debug |

---

## Remediation

The fundamental issue is that both the secret input and the encoded flag are hardcoded into the binary. No matter how the flag is obfuscated, an attacker with Ghidra can always find and reverse it. Mitigations that would raise the bar:

- **Server-side validation**: Send the user's input to a remote server for comparison rather than embedding the expected value locally. The binary would never contain the answer.
- **Cryptographic hash comparison**: Store a hash of the correct answer instead of the answer itself — compare sha256(input) against a stored digest. A hash cannot be reversed, so reading it out of the binary does not reveal the original value.
- **Stronger obfuscation**: A ROT-style Caesar cipher with a fixed shift is trivially reversible once identified in the decompiler. A proper keyed cipher would require knowing the key to reverse. While a more complex or keyed cipher would make analysis more time-consuming, it would not really secure the flag. Because both the encoded data and the decoding logic reside in the binary, a reverse engineer can still recover the original value through static analysis.

Written by Tatyana Ilieva 