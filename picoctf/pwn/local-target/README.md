# local-target

## Summary

`local-target` is a classic "smashing the stack" vulnerability. 

## Context

The local-target challenge authors provide a challenge instance that must be
launched. Upon start, the instance provides a domain and port to connect to the
challenge, as well as a compiled challenge binary `local-target` as well the
corresponding source code `local-target.c`.

```text
$ checksec local-target
[*] '/home/cricketwireless/CUCTF/carolinesomers/ctf-writeups/picoctf/crypto/local-target/local-target'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

From the source code, we see that there is a `win` function located at line TODO, in which the flag is printed. This function is called if `num` is equal to `65`. 

## Vulnerability

The vulnerability in the code is at line TODO, where gets() is called on the input
buffer. This is a classic stack buffer overflow vulnerability
[CWE-121](https://cwe.mitre.org/data/definitions/121.html)

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

## Exploitation

The exploit involves a stack-based buffer overflow, known coloquially as
"smashing the stack", see [*Smashing the Stack for Fun and Profit*](http://phrack.org/issues/49/14.html)



## Remediation

Don't use `gets()`, which does not provide bounds checking and can lead to
stack