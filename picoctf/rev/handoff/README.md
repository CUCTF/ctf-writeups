## Context

Handoff is a binary exploitation challenge centered around shellcode injection with an undersized overflow buffer, forcing us to use a stack pivot to reach a larger buffer elsewhere in memory. The challenge provides a binary and source code, and connecting to the instance gives us gives us the following interactive menu
`1. Add a new entry
2. Update an existing entry
3. Leave feedback and exit`. 
Where the user can select an option and interact with the program as indicated over and over until they exit the program.

## Vulnerability

Looking at the source code,  `handoff.c`, we can see that the key vulnerability is `fgets(feedback, NAME_LEN, stdin)` in the feedback option(3), where 32 bytes are read into an 8 byte buffer. This allows us to overflow past `feedback`, overwrite the saved RBP, and ultimately overwrite the return address, giving us control over where the program executes next. Running `checksec` shows us that the stack is executable, that there is no PIE, and there is no canary protecting the return address. 


## Exploitation

We know that you want to put the payload into the overflow buffer, `feedback`. However, it is only 8 bytes, which is far too small to hold a full `execve("/bin/sh")` payload. So, we redirect execution into a larger buffer elsewhere. The source code shows us that entries are stored in an entries[] array of structs, which gives us 64 byte buffer per entry. So we can use the `feedback` overflow to redirect execution into `entries[1].msg`, which is large enough for the shellcode. However, we also notice in the source code that the program checks for `feedback[7] = '\0'` after the read, which corrupts byte 8 of our payload, so we have to pad with No Operations, or NOPs, so the corruption lands on a NOP rather than something important.

We build the payload in several parts, which can be seen found in `handoff-solve.py`. 

**Step 1: find a `jmp rax` gadget.** When `vuln()` returns from `fgets()`, RAX is the register that holds return values of functions, so it holds the address of the `feedback` buffer, as that is what `fgets` returns. So if we redirect execution to a `jmp rax` instruction at the moment `ret` fires, we land at the start of `feedback`. We find one using ROPgadget:

`ROPgadget --binary ./handoff | grep "jmp rax"`
This gives us `0x000000000040116c`.

**Step 2: calculate the offset to the return address.** From running `objdump`, the disassembly shows us `lea -0xc(%rbp), %rax`, meaning `feedback` is located at `RBP - 12`. Combined with the 8 bytes of saved RBP, the offset from the start of `feedback` to the return address slot is 20 bytes.

**Step 3: calculate the stack pivot distance.** After `ret` fires and `jmp rax` executes, we're running instructions inside `feedback`. From there, we need to reach `entries[1].msg`, where our shellcode lives. We do this with a stack pivot: `sub rsp, 664` followed by `jmp rsp`. The stack grows downward on x86-64, so subtracting 664 from RSP (Stack Pointer, the register that tracks the top of the current stack frame) moves it down in memory to where `entries[1].msg` sits. Then `jmp rsp` transfers execution to that address. We do this instead of a hardcoded `jmp`; stack addresses are randomized on each run, but the distance between `entries[1].msg` and the return address stays constant. To find 664, we set a breakpoint in GDB on the `fgets` for entry 1's message and compute `return_address (RBP+8) - entries[1].msg address = 0x7ffcaa69b178 - 0x7ffcaa69aee0 = 0x298 = 664`. 664 encoded in little endian is `\x98\x02\x00\x00`, which we use for the `sub rsp` instruction.

**Step 4: build the feedback payload.** The 20 bytes from `feedback` to the return address get filled with the pivot bytes (`sub rsp, 664` then `jmp rsp`, 11 bytes total), padded out to 20 bytes with NOPs, followed by the `jmp rax` gadget address, overwriting the return address. The trailing NOPs also handle the `feedback[7] = '\0'` corruption: the null byte lands on a NOP and has no effect since NOPs do nothing.

**Step 5: place shellcode in `entries[1].msg`.** We need x86-64 shellcode that calls `execve("/bin/sh", NULL, NULL)` via `syscall`, which is the 64-bit equivalent of `int 0x80`. We prefix the shellcode with NOPs so that even if RSP lands slightly off after the pivot, execution still ends up at the real instructions.
![stack image](/stackimage.png)

The full flow when the exploit fires can be seen in the diagram above;`ret` jumps to `jmp rax`, which lands us in `feedback`, which runs the NOP sled and pivot to drop RSP by 664 bytes and `jmp rsp` into `entries[1].msg`, which runs the NOP sled into our shellcode and spawns a shell on the picoctf challenge server, giving us access to `flag.txt`! 

## Remediation

The most immediate fix is ensuring the read is bounded to the actual buffer size, for example, `fgets(feedback, sizeof(feedback), stdin)` instead of using the larger `NAME_LEN` constant. This would eliminate the overflow entirely. 

Beyond that, making the stack nonexecutable would reduce the number of primitives, as it would not have allowed us to have shellcode injection. Another security measure would be enabling PIE, which would randomize the addresses of gadgets like `jmp rax`, making it much harder to reliably use ROP gadgets to make a working exploit.

