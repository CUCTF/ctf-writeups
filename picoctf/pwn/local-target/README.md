# local-target

## Summary

`local-target` is a classic "smashing the stack" vulnerability that involves overflowing a stack buffer to overwrite a local variable.

## Context

The local-target challenge authors provide a challenge instance that must be
launched. Upon start, the instance provides a domain and port to connect to the
challenge, as well as a compiled challenge binary `local-target` as well the
corresponding source code `local-target.c`.

```text
$ checksec local-target
[*] '/ctf-writeups/picoctf/crypto/local-target/local-target'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

Since stack canaries are not enabled in this program, it is easier to overwrite stack variables. As well, PIE is not enabled either, which mean variables are located in fixed locations.

From the source code, we see that there is a `win` function located at line , in which the flag is printed. This function is called if `num` is equal to `65`.

## Vulnerability

The vulnerability in the code is at line `15`, where gets() is called on the input
buffer. This is a classic stack buffer overflow vulnerability
[CWE-121](https://cwe.mitre.org/data/definitions/121.html)

`num` is declared at the beginning of the main function on line `11` right under the input buffer:

```text
  char input[16];
  int num = 64;
```

Since `num` is declared directly after `input` on the stack, overflowing the input buffer allows us to overwrite the value of `num`. If the value of `num` is changed to `65`, the following `win` function is triggered.

```text
if( num == 65 ){
    printf("You win!\n");
    fflush(stdout);
    // Open file
    fptr = fopen("flag.txt", "r");
    if (fptr == NULL)
    {
        printf("Cannot open file.\n");
        fflush(stdout);
        exit(0);
    }
```

So, if we are able to overflow input with more than 16 bytes, we can overwrite the value of `num` to be `65`, in order to trigger the `win` function.

Since `input` is a `char` array, but `num` is an integer value, we need to overflow `input` with a `char` value that corresponds to `65` decimal value, which is `A`.

## Exploitation

The exploit involves a stack-based buffer overflow, known coloquially as
"smashing the stack", see [*Smashing the Stack for Fun and Profit*](http://phrack.org/issues/49/14.html).

We should expect that since the buffer is 16 bytes, that overflowing 17 bytes worth of the character `A` will change the value of `num` to `65`. However, this doesn't work, so there must be some padding between the two variables, so we need to calculate the offset between `input` and `num` on the stack. We can use `gdb` to analyse the binary at runtime, or we could also use static analysis techniques.

`num` is located at offset `-0x8` at the start of `main`, and is set to `0x40`, or `64` in decimal. When we overflow the buffer with `17` `A's`, we can see that `A` has successfully landed on the stack at `-0x10` but has not yet changed `num`. Since the offset between `-0x10` and `num` is `-0x18` - `-0x8`, our offset should then be `8` more bytes we have to add to the buffer.

```text
00:0000│ rax rsp 0x7fffffffdbd0 ◂— 'AAAAAAAAAAAAAAAAA'
01:0008│-018     0x7fffffffdbd8 ◂— 'AAAAAAAAA'
02:0010│-010     0x7fffffffdbe0 ◂— 0x41 /* 'A' */
03:0018│-008     0x7fffffffdbe8 ◂— 0x40 /* num */
```

When we fill the buffer with `25` bytes now, we can see that we have successfully overwritten `num` to `0x41` and the payload worked.

```text
00:0000│ rax rsp 0x7fffffffdbe0 ◂— 'AAAAAAAAAAAAAAAAAAAAAAAAA'
... ↓            2 skipped
03:0018│-008     0x7fffffffdbf8 ◂— 0x41 /* num rewritten to 'A' */
```

We can also examine how the memory is laid out in the program and why we need `25` bytes for the payload:

```text
Stack grows down ↓

+----------------------------+
| Return Address            | ← [Higher memory]
+----------------------------+
| Old RBP                   |
+----------------------------+
| num (4 bytes)             | ← Offset -0x8
| padding (4 bytes)         | (To align 16-byte buffer below)
+----------------------------+
| input[16]                 | ← Offset -0x18
+----------------------------+
```

## Remediation

Don't use `gets()`, which does not provide bounds checking and can lead to stack buffer overflows. Instead, use a safer alternative like `fgets()` which performs bounds checking on a specified buffer size.

The program should also be compiled with stack protection compiler flags that mitigate and prevent these types of attacks.

![](https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcSKY0f7c9zwgpX-EwVSzjNX_RbQz4XP-kO7sQ&s)