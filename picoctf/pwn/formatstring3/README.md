# format string 3

## Summary

This challenge provides a Linux CLI program with a format string
vulnerability that is exploited by overwriting the Global Offset Table (GOT) in order to redirect a function call . 

**Artifacts:**
* chall/format-string-3: vulnerable executable program provided by challenge authors
* chall/format-string-3.c: vulnerable program source code provided by challenge authors
* chall/ld-linux-x86-64.so.2: dynamic linker that ensures the correct library is loaded and used
* chall/libc.so.6: version of the C standard library used to create the executable
* solve.py: exploit script that executes `/bin/sh` shellcode


## Context

The `format string 3` challenge authors provide a domain and port to connect to the
challenge. They also provide a copy of the compiled challenge binary
(`chall/format-string-3`), the source code used to produce the binary (`chall/format-string-3.c`), an interpreter (`ld-linux-x86-64.so.2`), and libc (`chall/libc.so.6`) file. The `format-string-3` must be run in the same directory as the last two files in order for these two files (custom loader and library) to be used on the executable as intended.

`format string 3` is a 64-bit x86 Linux userspace program. It runs as a CLI program and
reads input from `stdin` and prints to `stdout`.

The program prints out a few lines, including the address of setvbuf, waits for user input
and then echoes it, prints /bin/sh, then exits.

Program output when inputting "hi":

```
$ ./format-string-3
Howdy gamers!
Okay I'll be nice. Here's the address of setvbuf in libc: 0x7f9bdcb643f0
hi
hi
/bin/sh

./format-string-3 
Howdy gamers!
Okay I'll be nice. Here's the address of setvbuf in libc: 0x7fae922243f0

/bin/sh
```
```
$ file chall/format-string-3 
chall/format-string-3: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter ./ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=54e1c4048a725df868e9a10dc975a46e8d8e5e92, not stripped

$ checksec format-string-3
[*] '/home/aw3515-picoctf/chall/format-string-3'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x3ff000)
    RUNPATH:    b'.'
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No

$ checksec libc.so.6
[*] '/home/aw3515-picoctf/chall/libc.so.6'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
```

## Vulnerability

The `format-string-3` program contains a format string vulnerability in the `main`
function.

`format-string-3.c` line 26 contains a call to `printf` to print out a buffer containing user input through `stdin`:

```
int main() {
        char *all_strings[MAX_STRINGS] = {NULL};
        char buf[1024] = {'\0'};

        setup();
        hello();

        fgets(buf, 1024, stdin);
        printf(buf);

        puts(normal_string);

        return 0;
}
```

The call `printf(buf)` presents a format string vulnerability. The first argument of a call to `printf` is the format string which specifies to the program how the remaining arguments should be interpreted. For example, a correct call could be `printf("%p", buf)` where `%p` means to treat `buf` as a pointer and print it as an address. This means that for `printf(buf)`, `buf` can contain special format strings that can manipulate the program. 

```
$ ./chall/vuln
How strong is your ROP-fu? Snatch the shell from my hand, grasshopper!
hi%p.%p.%p.
hi0x7fdb2c525963.0xfbad208b.0x7ffd8f5f0560.
/bin/sh
```
In this example run, hi is treated as regular string, and the following `%p`s are treated as format specifiers, specifically pointers. `printf` expects arguments following this to be printed out as pointers, but because there is only one argument, `buf`, it begins to print out values on the stack after `buf` and interpreting those values as arguments. 
## Exploitation

**Exploit overview**: the exploit uses a format string vulnerabiliy with `printf` to overwrite the Global Offset Table so that the a call to `puts` will invoke `system` instead, causing it to execute `\bin\sh` as a command instead of printing it as a string.

**Exploit mitigation considerations**:
* the `format-string-3` program has PIE disabled, so the PLT and GOT entries 
  addresses are fixed across each run.
* `format-string-3` has Partial RELRO, allowing us to write over the Global Offset Table as opposed to with Full RELRO, the GOT would be read only. 
* although `libc.so.6` has PIE enabled, so it's loaded at a random base address for each run of the program, so we can rely on the setvbuf address printed out by the program to calculate offsets to other functions, which remain the same even if addresses change.

**Exploit description**: the `solve.py` exploit sends a single input that both 1)
writes the shellcode into executable process memory and 2) gains control of the
instruction pointer to execute the shellcode.

Because `libc.so.6` has PIE enabled, the address at where it's loaded in is randomized. However, using the address of `setvbuf` that gets printed out by the program, we can find the address of `system` since the difference between the two calls are fixed. 

Using `readelf`, we can find the addresses of `setvbuf` and `system` in `libc`. These two addresses can be used to find the fixed difference between the two:

```
$ readelf -s libc.so.6 | grep system
  1511: 000000000004f760    45 FUNC    WEAK   DEFAULT   16 system@@GLIBC_2.2.5

$ readelf -s libc.so.6 | grep setvbuf
  1300: 000000000007a3f0   608 FUNC    WEAK   DEFAULT   16 setvbuf@@GLIBC_2.2.5
```

From the objdump output, we can find where `puts()` entry is in the Global Offset Table is. In the program, it's at `0x40418`. `solve.py` will replace the contents of this address to be the `system()`address in the `libc` file
```
$ objdump -d format-string-3 
<snip>
Disassembly of section .plt.sec:

0000000000401080 <puts@plt>:
  401080:       f3 0f 1e fa             endbr64 
  401084:       f2 ff 25 8d 2f 00 00    bnd jmp *0x2f8d(%rip)        # 404018 <puts@GLIBC_2.2.5>
  40108b:       0f 1f 44 00 00          nopl   0x0(%rax,%rax,1)
<snip>
```

`solve.py` constructs the payload with this line: `payload = fmtstr_payload(offset, {puts_addr: system_addr}, write_size="byte")` without the us having to manually write each byte and construct the payload. It will will overwrite the `puts` entry in the Global Offset Table with the address of system. `write_size="byte` is equivalent to format specifier `%hhn` which means to write the number of bytes printed so far to memory, specifcally 1 byte at a time. 

The payload it constructs will include both a format string (first argument of `printf`) and a series of addresses starting at 0x404018 (the address of `puts`). The `puts` address will land on the offset specified, in this case `38`, on the stack. The format string will contains a series of expressions like `%Nc%38$hhn`  which will print `N` bytes then write the number of bytes written, `N`, into the 38th argument. Thus if `N` was intentionally set to be a byte of the address of `system` it will get written into `0x404018`, then the next byte into `0x40419`, and so on. Thus, the payload will write `system_addr` (the address of `system`) into the address specified at the offset. This means that the address of `puts` in the Global Offset Table will now hold the address of `system`. So now when the program calls `puts(/bin/sh)` it will go to the Global Offset Table at `0x404018` and then go to the address of `system` at `libc`and invoke `system(/bin/sh)`, dropping us into an interactive shell.

The Global Offset Table will look something like this:
```
Before                                                

        GOT:                    libc.6.so:
        +----------------+      +----------------+
puts -> |    0x404018    | ->   |  puts address  |            
        |                |      +----------------+
        +----------------+      |      ...       |
                                +----------------+
                                | system address |
                                +----------------+

After                                                

        GOT:                    libc.6.so:
        +----------------+      +----------------+
puts -> |    0x404018    | _    |  puts address  |            
        |                |  |   +----------------+
        +----------------+  |   |      ...       |
                            |   +----------------+
                             -> | system address |
                                +----------------+
```


**Exploit primitives used**:
1. Place consecutive address starting from `puts` onto stack
2. Overwrite the `puts` GOT entry with the address of `system`

Note that these primitives are automated for us by `pwn` library's `fmtstr_payload`

## Remediation

To patch the vulnerability, the `printf(buf)` should be replaced with a
proper format string as the first argument so that user input can't be treated as one.
For example, it could instead be `printf("%s", buf)` which will treat and print `buf` as a string:

```
int main() {
	char *all_strings[MAX_STRINGS] = {NULL};
	char buf[1024] = {'\0'};

	setup();
	hello();	

	fgets(buf, 1024, stdin);	
	printf("%s", buf);

	puts(normal_string);

	return 0;
}
```

Compiling the program with standard exploit mitigations would make the
vulnerability more difficult to exploit:
* PIE would have made addresses less predictable and more random
* Full RELRO would make the Global Offset Table read-only, preventing GOT entries from being overwritten.

