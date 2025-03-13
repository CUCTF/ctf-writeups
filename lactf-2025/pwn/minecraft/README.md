# minecraft
## Summary

This challenge provides a Linux CLI program with a stack buffer overflow
vulnerability that is exploited by building and executing a two-stage ROP chain
which launches a remote shell. 

**Challenge Artifacts:**
* `chall/chall`: vulnerable 64-bit ELF executable provided by challenge authors
* `chall/chall.c`: vulnerable source code provided by challenge authors
* `chall/libc.so.6`: libc binary dynamically linked with `chall`
* `chall/ld-linux-x86-64.so.2`: ld-linux binary used to run and link `chall` 

**Solution Artifacts:**
* `solve.py`: `pwntools` exploit script that executes `/bin/sh` via a ROP chain
* `chall-gadgets.txt`: ROP gadgets in `chall/vuln` found with `ROPgadget`
* `libc-gadgets.txt`: ROP gadgets in `chall/libc.so.6` found with `ROPgadget`
* `Dockerfile`: container image build file configured with vulnerable program
and debugging environment

## Context

The `minecraft` challenge authors provide a domain and port to connect to the 
challenge, a copy of the compiled `chall` binary that is running, the
`libc.so.6` binary it is dynamically linked against, and the binary source code
`chall.c`.

The program is a simple CLI-based 'minecraft' game, where the user inputs
options into a CLI menu. With a certain set of inputs, the game includes a path
which allows the user to input a 'world name' string:
```bash
$ ./chall/chall

M I N C E R A F T

1. Singleplayer
2. Multiplayer
1
Creating new world
Enter world name:
AAAAAAAAAA
```

The binary is a 64-bit x86 ELF executable, which is dynamically linked by
`ld-linux` with the provided `libc`. It is executed in an environment with 
ASLR enabled, so the base address where `libc` is placed at runtime is
randomized. However, position independence (PIE) is disabled, so addresses
from the `chall` binary itself are known. The stack is not executable, so 
shellcode cannot directly be executed from the stack.

```bash
$ file chall/chall
chall/chall: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=85733c251d84d09de2cc21c10b82f13adf2b9878, for GNU/Linux 3.2.0, not stripped

$ checksec chall/chall
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    Stripped:   No
```
  

## Vulnerability 

The source `chall/chall.c` includes a vulnerable stack buffer overflow on line
33, where it makes a call to `gets` which reads user input into a local stack
variable `char world_name[64]`.

The libc `gets` function is inherently insecure, as it reads bytes from `stdin`
to its output buffer in memory unconditionally until it finds a newline.

As a result, with the right sequence of input an attacker controlling `stdin`
can reach the `gets` call and provide a payload line longer than the expected
64 bytes, which will overwrite the stack frame of the `main` function. Without
stack canaries enabled, this allows the attacker to gain control of execution
via a ROP chain. 

## Exploitation

**Exploit overview:** the exploit uses a local stack buffer overflow to launch
a two-stage ROP chain: the first stage leaks the randomized base address of
`libc.so.6` and launches the second stage, which uses ROP gadgets from `libc` to
execute a remote shell.

**Primitives used:**
1. Local stack buffer overflow to overwrite return address and deliver payloads
2. Global Offset Table (GOT) entry leak to discover libc base address

**Input constraints:**
The `gets` function reads payloads until a newline character or EOF, so the
constructed payloads cannot include a newline character (`0x0a`). Since the
second payload is partially random, occasionally it will include `0x0a` and
the exploit must be run again. 

### Detail Exploit Description
The `solve.py` script interacts with the target using pwntools, and performs the
exploit int two stages: The first stage leaks the libc base address, while the
second stage uses the leaked address to construct a payload that launches
`/bin/sh`.

The two-stage design is required because the `chall` binary is small, and does
not have enough ROP gadgets to easily construct a shell execution or file read
payload (see `chall-gadgets.txt`). To construct the final payload, we need
gadgets from the dynamically loaded `libc.so.6` code, which requires first
leaking the runtime-randomized libc base address.  

#### Stage 1: Libc Leak 

To leak libc, `solve.py` first navigates to the vulnerable `gets` call (just
after the "Enter world name:" prompt) in the `main` function, and sends the
initial payload. The stack just before the overflow, when `RIP` points to the vulnerable
`call gets` instruction, looks like this (assuming `RSP=0x7ff000`):
```
<high addresses>

[0xxxxxxx] [-------- previous stack frames -------]
[0x7ff048] [------ saved ret addr (8 bytes) ------]
[0x7ff040] [-------- saved rbp (8 bytes) ---------] <-- rbp
[0x7ff038] [------- char world_name[56:63] -------|
[0x7ff030] |------ char world_name[48:55] --------|
[0x7ffxxx] |-------- char world_name[...] --------| 
[0x7ff000] |------- char world_name[0:7] ---------] <-- rsp, rdi (gets() write location)

<low addresses>
```
At this point, `rdi` points at the same location as `rsp`, since the call to `gets`
is writing into the local variable `world_name` on the top of the stack. However,
`gets` will happily overwrite beyond `world_name` and into the stack frame if an
appropriately sized payload is provided. 

The first payload includes padding 'A' bytes to overrun `world_name`, followed
by a malicious 'saved rbp' value, and then a chain of ROP gadget addresses, the
first of which overwrites the saved return address that `main` will pop and call
when it hits its `ret` instruction. After the first payload overwrite, the 
stack then looks like this:
```
<high addresses>

[0xxxxxxx] [-------- previous stack frames -------]  
[0x7ff050] [--------- main+0x87 inst addr --------] (...  
[0x7ff048] [--------- read_int func addr ---------]  ROP chain
[0x7ff048] [---------- nop gadget addr -----------]  ...)
[0x7ff040] [----- second stack (0x404e00) --------] <-- rbp
[0x7ff038] [--------- padding 'A' bytes  ---------|
[0x7ff030] |--------- padding 'A' bytes  ---------|
[0x7ffxxx] |---------         ...        ---------| 
[0x7ff000] |--------- padding 'A' bytes  ---------] <-- rsp (gets() write location)

<low addresses>
```

Now, the stack frame has been replaced with a malicious payload. 

As `solve.py` sends input to navigate to the `ret` instruction at the end of
`main`, the function cleans up its stack frame by setting `rsp=rbp` (so `rsp`
points to the the fake "saved rbp") and popping the value at the top of the 
stack (the fake "saved rbp") into `rbp`. This value is the address of some unused
but writable 'second stack', where the second payload will later be constructed.

The `rsp` is the left pointing at the address of the first ROP gadget (a 'nop'
gadget), so when the main `ret` instruction finally executes the program will
return to the gadget. The nop gadget does nothing except call `ret` again, which
ensures that `rsp` is 16-byte aligned before the executing next gadget. 

The next gadget is just a pointer to the `read_int` function, which is in the
`chall` binary and reads a number from `stdin`, converts it to an integer, and
returns it by placing it in `eax`. When this function is called during the exploit,
`solve.py` sends the known address of the `puts@libc` entry in the GOT, which is
an address that contains the address of `puts` in `libc.so.6` (which the payload
ultimately leaks). When `read_int` returns, it pops and jumps to the final gadget,
`main+0x87`. 

The gadget `main+0x87` is one instruction before the call to `puts` that
normally displays the "Enter world name" prompt in main, specifically
`mov rdi, eax`. This fills `rdi` (where the subsequent `puts` expects a pointer
to a buffer to display) with `eax`, which the previous gadget filled with the
libc GOT entry. When the `call puts` instruction executes, it sends the address
of `puts` (which is in libc) to the attacker. `solve.py` uses this address
to construct the second payload, described in the next section. 

After leaking a libc address, the program continues executing the `main`
function a second time, starting after `main+0x87`, which hits the vulnerable
`gets` call a second time. This receives the second payload, beginning stage two.

#### Stage 2: Remote Shell

The second stage starts with `solve.py` building the second payload which launches
`/bin/sh`. This payload again uses ROP gadgets, but now can incorporate those
from `libc` (which are much more numerous and complex). To use a `libc` gadget,
`solve.py` uses its constant offset relative to the leaked base address, and then
adds that address to calculate an absolute address. 

After building the payload, `solve.py` sends it to the second `gets` call. This
call writes the payload bytes to `rbp-0x40`, which normally points to the
beginning of the `world_name` local variable. However, since the stage 1 gadget
returned directly to `main+0x87`, the `main` function never set up a stack frame,
and `rbp` still points to our 'second stack' writable location. So, just after
the second `gets` call, the stack 'pivots' from its original location to a new
stack constructed at `0x404e00`: 
```
Original Stack (fully 'rolled up'):
<high addresses>

[0xxxxxxx] [-------- previous stack frames -------]  <-- rsp
[0x7ff050] [--------- main+0x87 inst addr --------] 
[0x7ff048] [--------- read_int func addr ---------] 
[0x7ff048] [---------- nop gadget addr -----------]  
[0x7ff040] [----- second stack (0x404e00) --------] 
[0x7ff038] [--------- padding 'A' bytes  ---------|
[0x7ff030] |--------- padding 'A' bytes  ---------|
[0x7ffxxx] |---------         ...        ---------| 
[0x7ff000] |--------- padding 'A' bytes  ---------]

...

Second stack: 

[0x404e18] [-------- execv "/bin/sh" addr --------]
[0x404e1A] [-------- pop rdi value (NULL) --------]
[0x404e18] [-------- pop_rdi gadget addr ---------]
[0x404e10] [-------- pop r13 value (NULL) --------]
[0x404e0A] [------- pop rbp value (0x404f00) -----]
[0x404e08] [------- pop_rbp_r13 gadget addr ------]  
[0x404e00] [--- unused saved rbp (0xdeadbeef) ----] <-- rbp
[0x404df8] [--------- padding 'A' bytes  ---------|
[0x404dc0] |--------- padding 'A' bytes  ---------|
[0x404dxx] |---------         ...        ---------| 
[0x404dc8] |--------- padding 'A' bytes  ---------] <-- new gets() write location


<low addresses>
```
Once again, after the `gets` call the exploit navigates to the `ret` at the
end of `main`, which "cleans up" the newly constructed stack by resetting
`rsp=rbp` and popping that value (this time, an unused value) into `rbp`. This
leaves `rsp` pointing to the first gadget address (in libc) when `ret` executes.

The first gadget is a `pop rbp; pop r13; ret` gadget that allows us to set the 
values of registers to values required by the final 'one gadget'. Specifically,
we must set `rbp` to a writable region, and `r13` to `NULL`. These values are
popped off the stack, so can just be hardcoded next into the payload.

This gadget returns to the final setup gadget, that pops `NULL` into `rdi`, meeting
the final requirement of the target "one gadget". When the pop_rdi gadget returns,
it jumps to the "one gadget", which calls `execve("/bin/sh", rbp-0x40, r13)`.

Just before this call, the second stack is fully rolled up and `rsp` is 16-byte
aligned. When the call is made, it launches a `/bin/sh` shell and `solve.py`
enters interactive mode, allowing the attacker to display the contents of `flag.txt`. 

### Payload Structures
**Payload 1**
```
---------------------------------------------------------
| Component                     | Value     | Size      |
---------------------------------------------------------
| Padding 'A' bytes             | 'A'*64    | 64 bytes  |
| 'Second stack' address        | 0x404e00  | 8 bytes   |
| NOP gadget address            | 0x4010ef  | 8 bytes   |
| read_int function address     | 0x401176  | 8 bytes   |
| main+087 inst. address        | 0x401234  | 8 bytes   |
---------------------------------------------------------
```
**Payload 2**
```
-------------------------------------------------------------
| Component                     | Value             | Size  |
-------------------------------------------------------------
| Padding 'A' bytes             | 'A'*64        | 64 bytes  |
| Unused saved rbp              | 0xdeadbeef    | 8 bytes   |
| pop rbp pop r13 gadget addr   | libc+0xfea7c  | 8 bytes   |
| rbp address (writable)        | 0x404f00      | 8 bytes   |
| r13 value                     | NULL (0x0)    | 8 bytes   |       
| pop rdi gadget address        | libc+0x277e5  | 8 bytes   |
| rdi value                     | NULL (0x0)    | 8 bytes   | 
| execv "one gadget" address    | libc+0xd511f  | 8 bytes   |
-------------------------------------------------------------
```

## Remediation

To patch the vulnerability, `chall.c` should use an alternative to `gets`, which
is almost always insecure. Using a drop-in replacement like `fgets` with a
correct buffer size argument (i.e. `sizeof(world_name) - 1`) would prevent the
buffer overflow entirely. 

Besides this, adding exploit mitigations would make the ROP chain more difficult
to construct (but likely not impossible):
* Stack canaries would prevent the chain from returning into the first gadget without
find another leak primitive to leak the canary value 
* PIE would prevent hardcoding instructions from the code itself into the ROP chain
without another leak primitive


## Configuration Notes

Use container for development:

```bash
docker build -t lactf-minecraft -f Dockerfile
docker run --rm -it -v $(pwd):/ctf lactf-minecraft /bin/tmux
```

Execute solution script against local target in container:

```bash
$ python3 solve.py
[+] Starting local process '/ctf/chall/ld-linux-x86-64.so.2': pid 16
Press enter to start exploit
Building payload 1...
Payload 1 bytes: 
<snip>
Payload 1 length:  96
Sending first payload...
Navigating to return...
Ret into the payload...
Sending GOT address to leak puts...
Leaked puts address (in libc):  0x7b2386677980
Building payload 2...
Libc base:  0x7b2386600000
pop_rbp_r13_addr:  0x7b23866fea7c
pop_rdi_addr:  0x7b23866277e5
one_gadget_addr:  0x7b23866d511f
Payload 2 bytes: 
<snip>
Payload 2 length:  120
Sending second payload...
Opening shell...
[*] Switching to interactive mode

$ cat chall/flag.txt
THIS_IS_THE_FLAGTHIS_IS_THE_FLAGTHIS_IS_THE_FLAGTHIS_IS_THE_FLAG
$  
```

Execute solution script and start GDB for debugging target locally in
container, writing `pwntools` debugging context to stdout:

```
$ python3 solve.py GDB LOG
```

Execute solution script against remote target (assuming instance running
remotely and `solve.py` includes correct domain/port):

```
python3 solve.py REMOTE
<snip>
$ cat flag.txt
```