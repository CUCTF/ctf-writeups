## Context

Format String 2 is a binary exploitation challenge centered around a format string vulnerability. The challenge provide us with the source code, the binary, and allows us to connect to the challenge server. It also give us the following description: "This program is not impressed by cheap parlor tricks like reading arbitrary data off the stack. To impress this program you must change data on the stack!"

## Vulnerability

The vulnerability is `printf(buf)` on line 14, where user input is passed directly as the format string instead of `printf("%s", buf)`. Any format specifiers a user includes in their input is interpreted by `printf`, giving us a write primitive over memory.
The goal is to overwrite the global variable `sus` with `0x67616c66`, which the source code shows us will trigger the release of the flag. Since there is no PIE, `sus` has a fixed address we can grab straight from the binary.

## Exploitation

First we find the format string offset, which tells us which argument number our input is. We find the offset by sending a chain of `%p`s to read from the stack, and then we and look at where the input appears in the output. After some trial and error, we determine this offset to be 14.
Then, we grab the address of `sus`:

```bash
objdump -t ./format-string-2 | grep sus
# 0x404060
```

Then we construct the write. `%n` writes the number of bytes printed so far into a memory address, so to write `0x67616c66`, or 1735943526 in base 10, we would need to print over a billion characters before hitting `%n`, which far exceeds the input limit. Instead, `fmtstr_payload` from pwntools lets us split the write into individual byte writes, each one printing a smaller number of characters and writing a single byte at a time to successive addresses. For example, printing 0x66 to 0x404060, 0x6c to 0x404061, etc.This keeps the payload small enough to fit within the input limit while still achieving the full 4 byte value. The exploit script is in `payload.py`, and running it overwrites `sus`, and prints the flag!

## Remediation

Replace `printf(buf)` with `printf("%s", buf)`. User input should never be passed directly as a format string. Instead, treating it as a plain string eliminates the write primitive entirely.
