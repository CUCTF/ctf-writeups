# buffer overflow 3

## Summary

This challenge provides a Linux CLI program with a stack buffer overflow vulnerability that allows the user to execute functions within the program. The premise of this challenge is to brute force a manually placed stack canary placed before the return address in order to make the buffer overflow attack harder.

**Artifacts:**
* chall/vuln: vulnerable executable program provided by challenge authors
* chall/vuln.c: vulnerable program source code provided by challenge authors
* solve.py: exploit script that interacts with and exploits the vulnerable executable

## Context

The challenge has a provided domain and port, but it can also run locally using the provided vuln executable. When running locally, a `canary.txt` file should be provided with your own canary value. The program reads a "canary" value from a file named canary.txt; in order to execute the program, you must create a file named canary.txt that contains a 4 byte string, where the program will then place this value before the return address.

When the program is run, it prints out a message and prompts the user to enter text then exits after receiving it.

```
$ ./chall/vuln 
How Many Bytes will You Write Into the Buffer?
> 3
Input> 123
Ok... Now Where's the Flag?
```
The binary does not enable compiler-generated stack canaries or position independent executable (PIE) settings, which allows stack overflows to go unchecked and addresses to be predictable. However, the premise of this challenge is that there is a manually inserted stack canary right after a buffer, and the program checks if this value is modified in an attempt to prevent malicious buffer overflows.

```
$ file chall/vuln
chall/vuln: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=e97da1b49704007fe128c866fdae32b24b38fefd, for GNU/Linux 3.2.0, not stripped

$ checksec chall/vuln
[*] '/chall/vuln'
    Arch:       i386-32-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x8048000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No

$ cat chall/vuln.c
<snip>
#define BUFSIZE 64
#define FLAGSIZE 64
#define CANARY_SIZE 4
<snip>
void win() {
  char buf[FLAGSIZE];
  FILE *f = fopen("flag.txt","r");
  if (f == NULL) {
    printf("%s %s", "Please create 'flag.txt' in this directory with your",
                    "own debugging flag.\n");
    fflush(stdout);
    exit(0);
  }

  fgets(buf,FLAGSIZE,f); // size bound read
  puts(buf);
  fflush(stdout);
}
<snip>
...
<snip>
void vuln(){
   char canary[CANARY_SIZE];
   char buf[BUFSIZE];
   char length[BUFSIZE];
   int count;
   int x = 0;
   memcpy(canary,global_canary,CANARY_SIZE);
   printf("How Many Bytes will You Write Into the Buffer?\n> ");
   while (x<BUFSIZE) {
      read(0,length+x,1);
      if (length[x]=='\n') break;
      x++;
   }
   sscanf(length,"%d",&count);

   printf("Input> ");
   read(0,buf,count);

   if (memcmp(canary,global_canary,CANARY_SIZE)) {
      printf("***** Stack Smashing Detected ***** : Canary Value Corrupt!\n"); // crash immediately
      fflush(stdout);
      exit(0);
   }
   printf("Ok... Now Where's the Flag?\n");
   fflush(stdout);
}

int main(int argc, char **argv){

  setvbuf(stdout, NULL, _IONBF, 0);
  
  // Set the gid to the effective gid
  // this prevents /bin/sh from dropping the privileges
  gid_t gid = getegid();
  setresgid(gid, gid, gid);
  read_canary();
  vuln();
  return 0;
}
```
In order to get the flag, the `win` function which isn’t called in `main` needs to be called, and the goal is to use the stack buffer overflow to overwrite the saved return address with the win function. However, in order to do that successfully without causing the program to crash, you also need to replace the canary value correctly. For example, if 65 As are sent to the program it will detect an overflow and quit the program. However, if 64 As are sent the program detects no stack smashing since the cannary hasn't been overwritten with a different value. The 65th A is the first byte of the canary with the buffer size being 64 and the canary being right after it.
```
$ chall/vuln.c
How Many Bytes will You Write Into the Buffer?
> 64
Input> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Ok... Now Where's the Flag?

$ chall/vuln.c
How Many Bytes will You Write Into the Buffer?
> 65
Input> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
***** Stack Smashing Detected ***** : Canary Value Corrupt!
```

## Vulnerability

The chall program contains a stack buffer overflow vulnerability in the vuln function:

```
void vuln(){
    ...
    <snip>
    printf("Input> ");
    read(0,buf,count);
    <snip>
    ...
}
```
While `read()` allows the program to limit how much can be written to a buffer, the call to `read()` allows the user to write any number of bytes into a buffer of size 64. This means that an attacker can overwrite bytes into addresses on the stack beyond the allocated 64 `BUFSIZE` on the stack. 

## Exploitation

**Exploit overview**: The exploit uses a local stack buffer overflow to overwrite the saved return address on the stack to call a win function. The exploit overcomes a custom implementation of a stack canary check through leaking the canary by byte-by-byte brute force.

**Exploit mitigation considerations:**

Manual Stack Canary: the program has a manually inserted stack canary. While this does provide some protection, it differs from a compiler generated stack canary in that its value stays the same across all runs. This means that its easier to brute force the value of the canary.

PIE disabled: the addresses of executable instructions are fixed for every run and can be known before execution which allows the attacker to easily redirect the program to functions with the known addresses.

**Exploit description:**: the `solve.py` exploit brute forces the canary value by trying every possible ASCII character starting from the first canary char. Once it is able to overwrite the first character without it detecting a smash, then it knows what first char of the canary is. It then moves on to the next position, and this process repeats until all 4 characters of the canary has been uncovered. Once this canary value has been found, the exploit does one last execution of the vuln program by sending 64 bytes into the buffer, 4 bytes being the canary value, 16 bytes of padding between the canary and the return address, and 8 bytes being the `win` function. 

```
vuln() stack layout:
low address     +------------+  <--- ebp - 0x50
                |   buf[64]  |    
                |            |      
                +------------+  
                |  canary[4] |    
                +------------+  
                |   padding  |    
                +------------+  <--- current ebp 
                | saved old  |   
                |     ebp    |      
                +------------+  
                |   return   |    
                |   address  |    
high address    +------------+   
```

Diagram A shows the `vuln` stack call frame. Below the `buf` is the canary, and below the canary is some padding. Below the padding is the stored ebp and return address so that the program knows where to return to after the `vuln` returns. The objdump of `vuln` shows that the distance between the return address and the `buf` is 0x50 (80 in decimal) bytes because it accesses `buf` through `-0x50(%ebp)`. 

```
<snip>
08049336 <win>:
...
<snip>
08049489 <vuln>:
...
804953e:       8d 45 b0                lea    -0x50(%ebp),%eax
 8049541:       50                      push   %eax
 8049542:       6a 00                   push   $0x0
 8049544:       e8 e7 fb ff ff          call   8049130 <read@plt>  
  <snip>
```

This is why after the overwrite to the canary, `solve.py` also includes 16 bytes of padding before it overwrites the return address. We overwrite the return address to the address of `win` which from the objdump, is `0x8049336`.

**Exploit primitves used:**
1. Brute force the stack canary value
2. Overwrite stack canary with the same value so the overflow goes undetected by the program and overwrite the return address to manipulate the program to call `win`

## Remediation
To patch the vulnerability, the call to `read()` should be called with the correct number of bytes so that only the number of bytes allocated for the buffer are how much can be read in. 
```
void vuln(){
    ...
    char buf[BUFSIZE];
    ...
    printf("Input> ");
    read(0,buf,BUFSIZE);
}
```

Mitigations such as compiler generated stack canaries and PIE would make the exploit more challenging. A stack canary would have made the overwrite of return addresses and manipulating control flow harder with value that changes between each run, and PIE would have made it harder for an attacker to predict the addresses of critical functions.

The program could have also made it harder with the manual stack canary by making the canary value random and dynamically created so that the value changes each time, which would make brute forcing a lot harder since an attacker would have to guess all 4 characters at once per execution. 



