# i95-canaveral

## Summary

This challenge provides a Linux CLI program with a stack buffer overflow
vulnerability that is exploited by executing functions within the program different from the original intended execution.

**Artifacts:**
* chall/canaveral.c: vulnerable program source code provided by challenge authors
* solve.py: exploit script that manipulates the program to call `win`
* note: challenge authors provided a `canaveral` executable during the actual time of the competition

## Context

The `canaveral` challenge authors provide a domain and port to connect to the
challenge. They also provide a copy of the compiled challenge binary
(`canaveral`) which is not included here and the source code used to produce the binary (`chall/canaveral.c`).

`canaveral` runs as a CLI program and
reads input from `stdin` and prints to `stdout`.

The program functions only to prompt the user to enter a line of text,
receive that text, and then exit:

```
$ ./chall/vuln
Enter the launch command: 
```

The binary is statically compiled without standard exploit mitigations applied:
the stack is *executable* and position independent executable (PIE) settings
are *disabled*. 

```
$ checksec canaveral
[*] 'canaveral'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX disabled
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No

$ objdump -d chall/canaveral
<snip>
00000000000011c8 <func0>:
    11c8:       f3 0f 1e fa             endbr64 
    11cc:       55                      push   %rbp
    11cd:       48 89 e5                mov    %rsp,%rbp
    11d0:       48 83 c4 80             add    $0xffffffffffffff80,%rsp
    11d4:       64 48 8b 04 25 28 00    mov    %fs:0x28,%rax
    11db:       00 00 
    11dd:       48 89 45 f8             mov    %rax,-0x8(%rbp)
    11e1:       31 c0                   xor    %eax,%eax
    11e3:       48 8d 05 22 0e 00 00    lea    0xe22(%rip),%rax        # 200c <_IO_stdin_used+0xc>
    11ea:       48 89 c7                mov    %rax,%rdi
    11ed:       b8 00 00 00 00          mov    $0x0,%eax
    11f2:       e8 99 fe ff ff          call   1090 <printf@plt>
    11f7:       48 8d 45 80             lea    -0x80(%rbp),%rax
    11fb:       48 89 c7                mov    %rax,%rdi
    11fe:       b8 00 00 00 00          mov    $0x0,%eax
    1203:       e8 98 fe ff ff          call   10a0 <gets@plt>
    1208:       90                      nop
    1209:       48 8b 45 f8             mov    -0x8(%rbp),%rax
    120d:       64 48 2b 04 25 28 00    sub    %fs:0x28,%rax
    1214:       00 00 
    1216:       74 05                   je     121d <func0+0x55>
    1218:       e8 63 fe ff ff          call   1080 <__stack_chk_fail@plt>
    121d:       c9                      leave  
    121e:       c3                      ret    
<snip>
```

## Vulnerability

The `canaveral` program contains a stack buffer overwrite vulnerability in the `func0`
function. By using `gets` to read user input from `stdin`, it allows the user to overflow the buffer and overwrite the return address of the original execution.

`func0`  contains a call to libc `gets` to read user input from `stdin`:

```
void func0() {
	char inp[100];
	printf("Enter the launch command: ");
	gets(inp);
}
```

`gets` will read a line from stdin into the `inp` buffer which is of size 100. However, `gets` has no limit on how many bytes is read into the buffer, and it does not check for buffer ovveruns. 

This means that an attacker can write past the 100 bytes allocated on the stack for the `inp` buffer and overwrite information stored in addresses beyong the buffer.



## Exploitation

**Exploit overview**: the exploit uses a local stack buffer overflow to change the original execution of the program by overwriting the return address in the function call stack to call `win` which is not originally called in `main`

**Exploit mitigation considerations**:
* Stack canary disabled: stack canaries being disabled means that we can overwrite the return addresses on the stack and manipulate program execution flow.
* PIE disabled: the addresses of executable instructions are fixed for every run and can be known before execution which allows the attacker to easily redirect the program to functions with the known addresses.


**Exploit description**: the `solve.py` exploit sends a single input that writes into the `inp` buffer and continues to write past it into the return address to execute the `win` function

```
vuln() stack layout:
low address     +------------+  <--- ebp - 0x50       +------------+
                |            |                        |            |
                |  inp[100]  |                        |            |
                |            |                        |   all 1s   |    
                +------------+                        |            |
                |   padding  |                        |            |         
                +------------+  <--- current ebp      +------------+
                | saved old  |                        |   all 1s   |  
                |     ebp    |                        |            |     
                +------------+                        +------------+
                |   return   |                        |  addr of   |    
                |   address  |                        | ret instr  |    
high address    +------------+                        +------------+  
                                                      |    win     |
                                                      |    addr    |
                                                      +------------+
```

The reason why we can't overwrite the return address to the `win` address directly is bceause `win` calls `system("/bin/sh")` is because `system()` requires `rsp` be aligned to a 16 byte boundary, so before the `win` address, we add a `ret` instruction before it to align `rsp`.


**Exploit primitives used**:
1. Local stack buffer overwrite to overwrite saved return address
2. Overwrite saved return address to control execution flow of program
3. Control instruction pointer to `win` function

## Remediation

To patch the vulnerability, the `gets` function call should be replaced with a
function call that checks the size to prevent arbitrary overwrites like `fgets`.

```
void func0() {
	char inp[100];
	printf("Enter the launch command: ");
	fgets(inp, sizeof inp, stdin);
}
```

Mitigations such as compiler generated stack canaries and PIE would make the exploit more challenging. A stack canary would have made the overwrite of return addresses and manipulating control flow harder with value that changes between each run, and PIE would have made it harder for an attacker to predict the addresses of critical functions.