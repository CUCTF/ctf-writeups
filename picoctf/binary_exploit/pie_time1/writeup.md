# PicoCTF: PIE time 1

## Context

We are provided with a compiled binary and the source code (`vuln` and `vuln.c`), as well as a complimentary server and port to connect to via netcat. We only connect via netcat when we are ready to get the flag. 

When we do `./vuln` we are prompted to enter an address. If the address is not correct, we segfault:
```text
mms2379@spoc:~/ctf/pie_time$ ./vuln
Address of main: 0x58e94163433d
Enter the address to jump to, ex => 0x12345: 0x0
Your input: 0
Segfault Occurred, incorrect address.
```

## Background Information: PIE executables

Executables can come in different forms, notably PIE (position independent executable) and no-PIE. If we compile a PIE executable, it means that that whole chunk of code for the program can be placed anywhere in memory. This enables ASLR (address space layout randomization) which randomizes the memory address of key components of our program, like where its stack, heap, etc. begin. A no-PIE executable's code will be placed at a fixed address. That means that we cannot use ASLR.

Below, I've provided examples of objdumped PIE and no-PIE executables. Note how the no-PIE executable starts at address 0x401000, while the PIE executable starts at 0x1000 so it's able to placed at a random memory address later.

``` text
mms2379@spoc:~/temp/studying/linking2$ objdump -d main-no-pie

main-no-pie:     file format elf64-x86-64


Disassembly of section .init:

0000000000401000 <_init>:
  401000:       f3 0f 1e fa             endbr64 
  401004:       48 83 ec 08             sub    $0x8,%rsp
  401008:       48 8b 05 e9 2f 00 00    mov    0x2fe9(%rip),%rax        # 403ff8 <__gmon_start__@Base>
  40100f:       48 85 c0                test   %rax,%rax
  401012:       74 02                   je     401016 <_init+0x16>
  401014:       ff d0                   call   *%rax
  401016:       48 83 c4 08             add    $0x8,%rsp
  40101a:       c3                      ret
...

```

```text
mms2379@spoc:~/temp/studying/linking2$ objdump -d main-dyn

main-dyn:     file format elf64-x86-64


Disassembly of section .init:

0000000000001000 <_init>:
    1000:       f3 0f 1e fa             endbr64 
    1004:       48 83 ec 08             sub    $0x8,%rsp
    1008:       48 8b 05 d9 2f 00 00    mov    0x2fd9(%rip),%rax        # 3fe8 <__gmon_start__@Base>
    100f:       48 85 c0                test   %rax,%rax
    1012:       74 02                   je     1016 <_init+0x16>
    1014:       ff d0                   call   *%rax
    1016:       48 83 c4 08             add    $0x8,%rsp
    101a:       c3                      ret
  ...

```

## Vulnerability

Recall that we are prompted to enter an address:

```text
mms2379@spoc:~/ctf/pie_time$ ./vuln
Address of main: 0x58e94163433d
Enter the address to jump to, ex => 0x12345: 0x0
Your input: 0
Segfault Occurred, incorrect address.
```

Note that we are given the address of the `main` function. We may take a closer look at the source code. We see that we have a `main()` function and a `win` function that is not called anywhere in the program. We also see that `win` will give us our flag. (Full source code can be found in `pie_time1/vuln.c`)

```C
int win() {
  FILE *fptr;
  char c;

  printf("You won!\n");
  // Open file
  fptr = fopen("flag.txt", "r");
  if (fptr == NULL)
  {
      printf("Cannot open file.\n");
      exit(0);
  }

  // Read contents from file
  c = fgetc(fptr);
  while (c != EOF)
  {
      printf ("%c", c);
      c = fgetc(fptr);
  }

  printf("\n");
  fclose(fptr);
}

int main() {
  signal(SIGSEGV, segfault_handler);
  setvbuf(stdout, NULL, _IONBF, 0); // _IONBF = Unbuffered
  ...
```

Therefore, we conclude that we must somehow call the `win` function in order to get our flag. If this were a no-PIE exectuable, then we could just enter the address of the `win` function. Unfortunatley, `vuln` is a PIE executable:

```
mms2379@spoc:~/ctf/pie_time$ file vuln
vuln: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=0072413e1b5a0613219f45518ded05fc685b680a, for GNU/Linux 3.2.0, not stripped
```

This means that we will have to calculate the address of `win` based on some other address. Recall that we are given the address of `main`. Therefore, we conclude that we must use the address at `main` to call `win`.

## Exploitation 

Taking a look at the disassembly of `vuln`, we can manually calculate the distance in memory between `win` and `main`. (See `pie_time1/vuln_dump.txt` for the full disassembly)

```text
00000000000012a7 <win>:
    12a7:	f3 0f 1e fa          	endbr64 
    12ab:	55                   	push   %rbp
    12ac:	48 89 e5             	mov    %rsp,%rbp
	...

000000000000133d <main>:
    133d:	f3 0f 1e fa          	endbr64 
    1341:	55                   	push   %rbp
    1342:	48 89 e5             	mov    %rsp,%rbp
	...
```

The difference in hex between 0x12a7 and 0x133d is 0x96. So now, every time we execute `vuln` and get our address for `main`, we may simply calculate `main` - 0x96 = address to jump to:

```text
mms2379@spoc:~/ctf/pie_time$ nc rescued-float.picoctf.net 54738
Address of main: 0x5bee3664233d
Enter the address to jump to, ex => 0x12345: 0x5bee366422a7
Your input: 5bee366422a7
You won!
picoCTF{b4s1c_p051t10n_1nd3p3nd3nc3_a267144a}
```

## Remediation

The remediation for this is pretty simple: don't give out addresses in PIE executables! The whole point of PIE is to enable ASLR and make it **harder** to infiltrate, but by providing a reference address and source code, it can be easy to calculate the addresses of other functions and get to whatever function you'd like.

# Sources/Credits

Written by Madalina Stoicov

- https://cs4157.github.io/www/2025-1/lect/17-linking-2.html 
