# PicoCTF: buffer overflow 1

## Context

In this challenge, we are given a vulnerable Linux binary (`vuln`) along with its source code (`vuln.c`). The goal is to exploit a stack-based buffer overflow to redirect execution to a hidden function (`win`) that prints the flag. The description given is "control the return address".

## Background Information: Buffer Overflows

A buffer overflow occurs when a program writes more data to a memory buffer
than it was allocated to hold. In C programs, this commonly occurs when
unsafe input functions such as `gets`, `scanf`, or improperly used `fgets`
do not enforce bounds checking.

By overflowing a buffer on the stack, it is possible to overwrite adjacent
memory, including control data such as the saved return address. If this
return address is overwritten with a chosen value, program execution can be
redirected to an arbitrary function within the binary.

When a function is called in a C program, the program uses the call stack to
track execution state. Each function call creates a *stack frame*, which
contains local variables and metadata required to return execution to the
caller.

A simplified stack layout for the `vuln()` function is shown below
(addresses increase downward):

+-----------------------------+
| Saved Return Address (EIP) | ← overwritten target
+-----------------------------+
| Saved Base Pointer (EBP) |
+-----------------------------+
| char buf[32] | ← user-controlled input
+-----------------------------+

The *saved return address* is the address that the CPU jumps to when the
function finishes executing. Under normal execution, this points to the
instruction immediately following the function call in `main()`.

Because `gets()` performs no bounds checking, supplying more than 32 bytes
of input allows data to overflow `buf` and overwrite values higher on the
stack, including the saved return address. If an attacker controls this
value, they can redirect execution.

In this challenge, the binary contains a `win()` function that is never
invoked during normal execution. By overflowing `buf` and overwriting the
saved return address with the address of `win()`, execution is redirected
to `win()`, which prints the flag.

## Background Information: Binary Protections (PIE)

Position Independent Executable (PIE) randomizes the base address of a binary
at runtime, causing function addresses to change between executions.

This challenge binary is compiled **without PIE**, meaning function addresses
are static. As a result, the address of the `win()` function can be determined
statically and reliably reused in the exploit.

If PIE were enabled, an additional information leak would be required to
determine the runtime address of `win()` before overwriting the return address.


## Vulnerability

The vulnerability in this challenge is a stack-based buffer overflow.
The program reads user input into a buffer without checking its length,
allowing an attacker to overwrite the saved return address on the stack. Without proper bounds checking, the program is vulnerable to memory corruption.

Examining `vuln.c` reveals the core vulnerability:

```c
#define BUFSIZE 32

void vuln(){
  char buf[BUFSIZE];
  gets(buf);

  printf("Okay, time to return... Fingers Crossed... Jumping to 0x%x\n", get_return_address());
}
```

Here, we see that the buffer buf is only 32 bytes long. The function `gets()` is used to read input, but `gets()` does not perform any bounds checking and will continue reading until a newline is encountered.

This allows user input to overflow buf and overwrite data stored after it on the stack, including the saved return address.

![Alt text]

Also, the program includes a `win()` function as shown below:

```c
void win() {
  char buf[FLAGSIZE];
  FILE *f = fopen("flag.txt","r");
  fgets(buf,FLAGSIZE,f);
  printf(buf);
}
```

The `win()` function reads the flag from `flag.txt` and prints it, but it is never called during normal program execution, which also makes it a target for exploitation. 

## Exploitation

Step 1: Identifying the overflow point

To determine how much input is required to overwrite the return address, I sent increasingly long, predictable strings to the program once prompted for input. Supplying more than 32 bytes caused the program to crash with a segmentation fault, confirming that the buffer overflow was reachable.

By continuing to increase the input length and observing crashes, it became clear that data beyond the buffer was overwriting the saved instruction pointer.

Using repeated characters ("A" * N) made it easy to recognize when the return address was being overwritten. When I noticed that the program attempted to jump to 0x41414141, it confirmed control over the instruction pointer since 0x41 is the ASCII value of 'A'.

Step 2: Locating the win function

Since the binary is not stripped, symbol information is available. The address of the win function was found using:

`readelf -s vuln | grep win`

This revealed the exact address of `win()` within the binary. This address is the value that needs to overwrite the saved return address.

Step 3: Endianness 

On x86 systems, addresses are stored in little-endian format. So, I had to consider that  the bytes of the win function address must be reversed when included in the payload.

For example, if win() is located at:
0x080491f6

It must be written in memory as:
\xF6\x91\x04\x08


Step 4: Developing the payload

The final payload I wrote consists of padding to fill the buffer and reach the return address, and the address of win() in little-endian format.

In Python, the payload was constructed as follows:

```c
import struct

offset = 44
win_addr = struct.pack("<I", 0x080491f6)
payload = b"A" * offset + win_addr + b"\n"
```

The offset was determined experimentally, and struct.pack("<I", ...) ensures proper little-endian encoding. The offset is also apparent from the stack layout: 32 bytes for buf plus the saved base pointer, placing the return address immediately after. Finally, A newline is appended to simulate pressing Enter.

Step 5: Exploiting the remote service

The challenge provides a remote service accessible via nc. I automated interaction with this service via the Python script using the socket module. The script connects to the remote host and port, receives the prompt, sends the crafted payload, and receives the program outputs. After sending the payload, execution returned to the `win()` function, and the flag was printed:

`picoCTF{addr3ss3s_ar3_3asy_b15b081e}`

## Remediation

This vulnerability can be mitigated by multiple solutions:

1. Replacing unsafe functions such as `gets()` with bounded alternatives like `fgets()`
2. Enabling compiler-based protections (e.g. ASLR, PIE)
3. Enforcing strict validation and bounds checking on user input

# Sources/Credits

Written by Tatyana Ilieva

- https://play.picoctf.org/practice/challenge/258?page=1&search=buffer
- https://owasp.org/www-community/vulnerabilities/
- https://www.youtube.com/watch?v=k4hqdVo3cqk
