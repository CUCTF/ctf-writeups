

# PicoCTF: Some Assembly Required 

This README contains writeups for all levels of Some Assembly Required. Because levels 1 and 2 are quite simple, I've only breifly described those levels and have written more in-depth explanations for levels 3 and 4.
- Level 1: http://mercury.picoctf.net:26318/index.html
- Level 2: http://mercury.picoctf.net:61778/index.html
- Level 3: http://mercury.picoctf.net:47240/index.html

## Context (all levels)

We are provided with a URL that brings us to a very simple site that prompts us to enter a flag. We are given no source code or hints. This is the same for all levels.

<img src="images-sar1234/site.png" width="300" />

## Background Information: WebAssembly (all levels)

WebAssembly (WASM) is a binary format for executable files that aims to make low-level programs in C, C++, and Rust more portable and used in web environments. Web Assembly Text Format (WAT) is the human-readable version of WASM. It is easy to read and resembles the register-by-register format of other assembly languages.

```WAT
export function strcmp(a:int, b:int):int { // func1
  var c:int = g_a;
  var d:int = 32;
  var e:int = c - d;
  e[6]:int = a;
  e[5]:int = b;
  var f:int = e[6]:int;
  e[4]:int = f;
  var g:int = e[5]:int;
  e[3]:int = g;
  ...
```

A useful tool for dealing with WASM and WAT files is [this WASM decompiler by Binaryen](https://github.com/WebAssembly/binaryen). This gives access to a useful WASM to WAT decompiler command:

`wasm-decompile input.wasm -o output.wat`

Another useful tool is the [Web Assembly Toolkit](https://github.com/WebAssembly/wabt). I found this one to be less helpful for this challenge, but it's nice to have on hand!

## Vulnerability (all levels)

To gather more information, I decided to inspect the website. Navigating to the Networks tab, I found a couple of interesting things.

<img src="images-sar1234/level-1-network-analysis.png" width="1000" />

We see an executable file being used by the site, as well as a JavaScript file. 

Note: To see the files for each level, navigate to the level's subdirectory. The JavaScript file can be used for levels 1 and 2, but I was able to solve those levels without it, and therefore they are not included in the level subdirectories.

## Exploitation: Level 1

To try to see what the exectable may do, I decided to `curl` it by doing `curl http://mercury.picoctf.net:26318/JIFxzHyW8W > exec`. To get more information about what kind of executable this is, I did `file exec`:

`exec.wasm: WebAssembly (wasm) binary module version 0x1 (MVP)`

We see the binary is a WebAssembly file, thus I renamed `exec` to `exec.wasm`. I also ran `strings exec.wasm` to try to get more information, and that's where I found the flag:

```text
madalinastoicov@Madalinas-MacBook-Air-2 level-1 % strings exec.wasm
memory
__wasm_call_ctors
strcmp
check_flag
input
copy_char

__dso_handle
__data_end
__global_base
__heap_base
__memory_base

__table_base
 
 j!
  F!!A
!" ! "q!# #
!% $ %q!& 
!( ' (q!) & )k!* 
!+ +
+picoCTF{8857462f9e30faae4d037e5e25fee1ce}
```

## Exploitation: Level 2

I tried doing the same process as level 1: grabbing the executable and running `strings` on it. However, I see that that the flag seems to be encoded this time: 

`xakgK\5cNs((j:l9<mimk?:k;9;8=8?=0?>jnn:j=lu`

Before doing some more advanced decoding, I tried running this string through some basic decoders on CyberChef. After a couple of attempts and different schemes, I found that the flag is XORd:

<img src="images-sar1234/level2-XOR.png" width="600" />

## Exploitation: Level 3

I started solving this level by executing the same steps as levels 1 and 2: grab the executable by using `curl` and running `strings`. For this part, we don't see anything that may resemble a flag:

```text
madalinastoicov@Madalinas-MacBook-Air-2 level-3 % strings exec.wasm
memory
__wasm_call_ctors
strcmp
check_flag
input
copy_char

__dso_handle
__data_end
__global_base
__heap_base
__memory_base

__table_base
 
 j!
  F!!A
!" ! "q!# #
!% $ %q!& 
!( ' (q!) & )k!* 
!+ +
 
 t!
 
 u!
```

We realize we need to get more information to solve this level. Recall that WebAssembly binaries can be decompiled to wat formats.



## Remediation

A vulnerability we see here is that critical information is not secured, and therefore can be easily seen amongst the rest of a binary file. One way to prevent this could be encrypting this data. Or, not making the binary file available to the client is also an option.

# Sources/Credits

Written by Madalina Stoicov

- https://en.wikipedia.org/wiki/WebAssembly
