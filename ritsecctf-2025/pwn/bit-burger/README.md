# bit-burger

## Summary

**Challenge description:**

🍔borger borger borger borg borg borger borger borger borg borg borg borg borg

**Artifacts:**

* bit-burger.bin: compiled binary provided by the challenge

## Context

The bit-burger challenge authors provide a domain and a port that connect to the challenge. They also provide a compiled source binary `bit-burger.bin` that is running on the remote server.

The program asks the user a choice of 24 burger toppings, and then asks if the burger should be grilled or fried.

```text
Welcome to BitBurger, home of the Bit Burger! May I take your order?

What would you like on your Bit Burger?
 - a bun (y/n)? y
 - a patty (y/n)? y
 - cheese (y/n)? y
 - lettuce (y/n)? y
 - tomato (y/n)? y
 - pickles (y/n)? y
 - ketchup packet (y/n)? y
 - mustard packet (y/n)? y
 - mayonnaise packet (y/n)? y
 - debug sauce (y/n)? y
 - pixelated pickles (y/n)? y
 - algorithmic aioli (y/n)? y
 - salted hashes (y/n)? y
 - cracked hashes (y/n)? y
 - array slices (y/n)? y
 - browser cookie crumble (y/n)? y
 - corn kernels (y/n)? y
 - java jam (y/n)? y
 - spam (y/n)? y
 - GNU/gravy (y/n)? y
 - Linux mint (y/n)? y
 - silicon wafers (y/n)? y
 - raspberry pie (y/n)? y
 - wifi pineapples (y/n)? y

Got it! One Bit Burger with a bun, a patty, cheese, lettuce, tomato, pickles, ketchup packet, mustard packet, mayonnaise packet, debug sauce, pixelated pickles, algorithmic aioli, salted hashes, cracked hashes, array slices, browser cookie crumble, corn kernels, java jam, spam, GNU/gravy, Linux mint, silicon wafers, raspberry pie, wifi pineapples, comin' right up!

Would you like that grilled or fried?: grilled

Grilling up your Bit Burger... *sizzle* *sizzle*

Order up!
Thank you, please come again!
```

The program also performs checks on the user input: for burger options, input must be `y`, `n`, or `$`, and for `grilled` or `fried`, any other input gives the following message:

```text
Would you like that grilled or fried?: baked
Sorry, we don't serve baked Bit Burgers here.
Segmentation fault (core dumped)
```

Some part of our memory is invalid when neither `grilled` or `fried` is selected by the user.

```text
$ checksec bit_burger.bin
[*] '/home/cricketwireless/CUCTF/carolinesomers/ctf-writeups/ritsecctf-2025/pwn/bit-burger/bit_burger.bin'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

We observe that this binary has no PIE, so there's a fixed base address (`0x400000`). Stack canaries are present, so we have to be careful. And NX is enabled, so we can't execute the stack directly.

The `main()` function at `0x401628` calls the function to take the order at `0x41069e`(`take_order()`) and the function to choose the style at `0x4016a8` (`choose_style()`)

Let's take a look at `take_order()`:

It runs through each of the ingredient options, with options `y` or `n`, but we can see that there is a secret third option, `$` which calls another function, `0x4` (`manager_control_panel()`).

Inside the `manager_control_panel()` function, it prompts the user for a code, which is obtained by calling srand on the pid bit ORed with the current time, and then taking the last 6 digits. If the correct admin code is entered, then the program executes a `/bin/bash` script which prints the flag.

So we have a function to open up an admin console and brute-forcing the admin code is infeasible.

Now we can check out the `choose_style()` function to figure out the memory errors.

There is a `code *` function pointer that is located at offset `-0x18` that is unintialized at the start of the function. When the user answers, `grilled` or `fried`, then the function pointer is set to `grilled` or `fried` functions. Then the function pointer is called at line `0x40160f`. If `grilled` or `fried` is not selected, then the function is still called, which creates our seg fault issue.

## Vulnerability

The vulnerability lies in the uninitialized function pointer that calls `grilled` or `fried`, creating a control flow issue when neither `grilled` or `fried` are chosen, but the function pointer is still called. This not only causes the program to seg fault, it also means that the data left at the same offset as the variable is what is called next in the program.

 Conveniently, there are a total of 24 burger "options" that are stored in a binary number. Intuitively, we can see that the 24-bit number can become our 6 digit hex address. In the exploitation section, we can see how this works.

## Exploitation

**Exploit overview:**

The exploitation involves choosing the burger options to represent the binary address in the admin function. This binary number is then called in our uninitialized function pointer, giving us the ability to jump wherever in the program we want.

**Exploit mitigation considerations:**

* Function pointers could be avoided all-together, since it is not necessary in this case [Are function pointers evil?](https://stackoverflow.com/questions/19260203/are-function-pointers-evil)
* The manager control panel shouldn't have such elevated privileges
* PIE isn't enables, so we know exactly where in memory everything is located

**Exploit description:**

This attack happens to work because the function pointer used to call `grilled` or `fried` gets set to whatever garbage was left on the stack at offset -018 before `choose_style()` is called.

Let's look back at our `take_order()` function since it is the caller of `choose_style()` to see what's happening on the stack.

The variable that is located at offset `-0x18` in `take_order()` is the binary int that is used to set bits based on the ingredients. So, if we choose the ingredients so that the binary number corresponds to the address `0x401346` in the manager control panel, we should be able to call this address in the `choose_style()` function.

Now, we can choose our ingredients corresponding to the number 010000000001001101000110, but backwords, since it is on the stack, so the responses to the burger options would be `n, y, y, n, n, n, y, n, y, y, n, n, y, n, n, n, n, n, n, n, n, n, y, n`. We can check out the stack in `gdb` right before we return from `take_order`:

```text
───────────────────────────────────────────────────────[ STACK ]────────────────────────────────────────────────────────
00:0000│ rsp 0x7fffffffdc70 ◂— 0x6e00000000000000
01:0008│-018 0x7fffffffdc78 —▸ 0x401346 (manager_control_panel+176) ◂— lea rax, [rip + 0xe3b]
02:0010│-010 0x7fffffffdc80 ◂— 0x18
03:0018│-008 0x7fffffffdc88 ◂— 0xa0aea7ca787b0a00
04:0020│ rbp 0x7fffffffdc90 —▸ 0x7fffffffdca0 ◂— 1
05:0028│+008 0x7fffffffdc98 —▸ 0x4016a3 (main+123) ◂— mov eax, 0
06:0030│+010 0x7fffffffdca0 ◂— 1
07:0038│+018 0x7fffffffdca8 —▸ 0x7ffff7dafd90 (__libc_start_call_main+128) ◂— mov edi, eax
```

and we see that our address 0x401346 has successfully landed on the stack.
Now we want to check if it remains at this location when choose_style() is called.

```text
───────────────────────────────────────────────────────[ STACK ]────────────────────────────────────────────────────────
00:0000│ rsp 0x7fffffffdc70 ◂— 0x6e00000000000000
01:0008│-018 0x7fffffffdc78 —▸ 0x401346 (manager_control_panel+176) ◂— lea rax, [rip + 0xe3b]
02:0010│-010 0x7fffffffdc80 ◂— 0x18
03:0018│-008 0x7fffffffdc88 ◂— 0xa0aea7ca787b0a00
04:0020│ rbp 0x7fffffffdc90 —▸ 0x7fffffffdca0 ◂— 1
05:0028│+008 0x7fffffffdc98 —▸ 0x4016ad (main+133) ◂— lea rax, [rip + 0xce3]
06:0030│+010 0x7fffffffdca0 ◂— 1
07:0038│+018 0x7fffffffdca8 —▸ 0x7ffff7dafd90 (__libc_start_call_main+128) ◂— mov edi, eax
```

boom. uve been pwned.

Now when we choose a style that is not `grilled` or `fried` (a secret third option), the function pointer calls inside the `admin` function and executes the script to print the flag.

Note that while the stack canaries are checked, they are only checked at the end of the function. When we jump to the instruction right before the `/bin/bash` script is run, the flag is printed before the canary is checked.

**Exploit primitives used:**

1. Uninitialized variable
2. Arbitrary Call
3. Authentication Bypass

## Remediation

Enabling position independent execution remediates the issue, but an attacker could still find their way around by guessing the address or leaking an address.

To successfully overcome the specific vulnerability of the uninitialized variable, the code could be rewritten to properly initialize the function pointer to `0`, as well as only calling the function when either `grilled` or `fried` is selected, in order to prevent the program from seg faulting.