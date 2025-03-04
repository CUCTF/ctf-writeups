# state-change

## Summary

This challenge provides a Linux CLI program with a stack buffer overflow vulnerability that allows the user to pivot the stack and execute functions within the program.

**Artifacts:**
* chall/chall: vulnerable executable program provided by challenge authors
* chall/chall.c: vulnerable program source code provided by challenge authors
* solve.py: exploit script that interacts with and exploits the vulnerable executable

## Context

The challenge has a provided domain and port, but it can also run locally using the provided chall executable.

When the program is run, it prints out a message and prompts the user to enter text then exits after receiving it.

```
$ ./chall/chall
Hey there, I'm deaddad, Who are you?
hello
```
The binary does not enable stack canaries or position independent executable (PIE) settings, which allows stack overflows to go unchecked and addresses to be predictable.

```
$ file chall/chall
chall/chall: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=e97da1b49704007fe128c866fdae32b24b38fefd, for GNU/Linux 3.2.0, not stripped

$ checksec chall/chall
[*] '/chall/chall'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No

$ cat chall/chall.c
<snip>
void win() {
    char filebuf[64];
    strcpy(filebuf, "./flag.txt");
    FILE* flagfile = fopen("flag.txt", "r");

    /* ********** ********** */
    // Note this condition in win()
    if(state != 0xf1eeee2d) {
        puts("\ntoo ded to gib you the flag");
        exit(1);
    }
    /* ********** ********** */
    
    if (flagfile == NULL) {
        puts(errorMsg);
    } else {
        char buf[256];
        fgets(buf, 256, flagfile);
        buf[strcspn(buf, "\n")] = '\0';
        puts("Here's the flag: ");
        puts(buf);
    }
}
<snip>
...
<snip>
int main(){

    state = 0xdeaddead;
    strcpy(errorMsg, "Couldn't read flag file. Either create a test flag.txt locally and try connecting to the server to run instead.");

    setbuf(stdin, 0);
        setbuf(stdout, 0);

    vuln();
    
    return 0;
}

<snip>
```
In order to get the flag, the `win` function which isn’t called in `main` needs to be called, and the global state variable value needs to be changed from the original initialized value (`0xdeaddead`) to  `0xf1eeee2d`.

## Vulnerability

The chall program contains a stack buffer overflow vulnerability in the vuln function:

```
void vuln(){
    char local_buf[0x20];
    puts("Hey there, I'm deaddead. Who are you?");
    fgets(local_buf, 0x30, stdin);
}
```
While fgets allows the program to limit how much can be written to a buffer, the call to fgets allows the user to write 0x30 bytes into a buffer of size 0x20. This means that an attacker can overwrite 16 bytes into addresses on the stack beyond the allocated local_buf on the stack. 

## Exploitation

**Exploit overview**: the exploit uses a local stack buffer to first pivot the stack to another location and then overwrite the data on the stack. 

**Exploit mitigation considerations:**

Stack canary disabled: stack canaries being disabled means that we can overwrite the return addresses on the stack and manipulate program execution flow.

PIE disabled: the addresses of executable instructions are fixed for every run and can be known before execution which allows the attacker to easily redirect the program to functions with the known addresses.

**Exploit description:**: the `solve.py` exploit sends an input on the first call to `fgets` in `vuln` that overwrites the stack frame base pointer to pivot the stack and the return address to call `vuln` again. On this second call to `vuln` and subsequently `fgets`, it sends an input to overwrite the value of the global state variable and the return address to `win` so that `win` is called and the condition is met to get the flag. 

```
[A]vuln():	   -> [B]first send: ->  [C]second send: 
+------------+    +------------+     +------------+
| local_buf  |    |    0x20    |     | 0xf1eeee2d |
|  [0x20]    |    |random bytes|     |            |
|            |    |            |     |            |
+------------+    +------------+     +------------+
| saved old  |    |   state    |     |     8      |
|     ebp    |    |  address   |     |random bytes|    
|            |    |   + 0x20   |     |            |
+------------+    +------------+     +------------+
|   return   |    |   vuln()   |     |   win()    |
|  address   |    |  address   |     |  address   |
+------------+    +------------+     +------------+
```

Diagram A shows the `vuln` stack call frame. Below the `local_buf` is the saved `$ebp` where after the function is done executing and the stack is cleaned up, the `$ebp` will be restored to this value. Below this is the return address where the instruction pointer will go to in order to resume execution in the caller function. For all functions, local variables are accessed using their offsets from `$ebp`. 

```
<snip>
00000000004012b5 <vuln>:
  4012b5:	f3 0f 1e fa          	endbr64 
  4012b9:	55                   	push   %rbp
  4012ba:	48 89 e5             	mov    %rsp,%rbp
  4012bd:	48 83 ec 20          	sub    $0x20,%rsp
  4012c1:	48 8d 05 80 0d 00 00 	lea    0xd80(%rip),%rax        # 402048 <_IO_stdin_used+0x48>
  4012c8:	48 89 c7             	mov    %rax,%rdi
  4012cb:	e8 c0 fd ff ff       	call   401090 <puts@plt>
  4012d0:	48 8b 15 59 2d 00 00 	mov    0x2d59(%rip),%rdx        # 404030 <stdin@GLIBC_2.2.5>
  4012d7:	48 8d 45 e0          	lea    -0x20(%rbp),%rax
  4012db:	be 30 00 00 00       	mov    $0x30,%esi
  4012e0:	48 89 c7             	mov    %rax,%rdi
  4012e3:	e8 d8 fd ff ff       	call   4010c0 <fgets@plt>
  4012e8:	90                   	nop
  4012e9:	c9                   	leave  
  4012ea:	c3                   	ret    
  <snip>
```

From the obdump assembly output, we can see that in the `vuln` function, the code accesses the `local_buf` variable using `$ebp - 0x20`. In order to pivot the stack and change the state variable value, the saved $ebp value on the `vuln` stack frame needs to be overwritten to the address of the state variable + 0x20 so that in the next call to `vuln`, `$ebp-0x20` is accessing the state variable. The return address also needs to be overwritten to the address if `vuln` so that when the program returns from `vuln`, the instruction pointer goes back to `vuln` instead of `main`, the function that is called `vuln`. These 2 overwrites are both 8 byte addresses which make up the exact space for the overflow since we can write 0x10 bytes past the `local_buf`. This is why we write 0x20 bytes of anything, then the address of state + 0x20, and then the address of `vuln`, more specifically the address in `vuln` that starts to execute `fgets`.

After this overwrite, the instruction pointer is now at `vuln` again and the `$ebp` is 0x20 offset from the address of the global `state` variable. Now when we write to standard in, instead of writing to `local_buf` like before, we will be writing to what’s in the state variable. The `win` function also needs to be called in order to get the flag, so the return address needs to be overwritten to the address of `win`. This means that in the 0x30 bytes that we can write, the first bytes need to be `0xf1eeee2d`, the win condition, and the last 8 bytes need to be the address of `win`. 

**Exploit primitves used:**
1. Local stack buffer overwrite to overwrite stored `$ebp` to pivot the stack and saved return address to control execution flow
2. Overwrite global variable value and return address

## Remediation
To patch the vulnerability, the call to `fgets` should be called with the correct number of bytes so that only the number of bytes allocated for the buffer are how much is read in. 
```
void vuln(){
    char local_buf[0x20];
    puts("Hey there, I'm deaddead. Who are you?");
    fgets(local_buf, 0x20, stdin);
}
```

Mitigations such as stack canaries and PIE would make the exploit more challenging. A stack canary would have prevented the overwrite of return addresses and manipulating control flow, and PIE would have made it harder for an attacker to predict the addresses of critical functions.



