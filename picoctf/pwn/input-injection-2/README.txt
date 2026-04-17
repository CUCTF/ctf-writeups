## Context
This folder contains `source.c`, the C source code for the picoctf challenge `Input Injection 2`, a medium level challenge in the Binary Exploitation category.
Once connected to the challenge instance, a user is told addresses for `username` and `shell`. The user is then prompted to enter a username. Afterwards, the current directory, `/home/ctf-player`, is printed out, and lastly followed by a message that rpints the contetn of username and shell.   

## Vulnerability

Even before looking at the source code, we can recognize that the usage of user input that is reflected back to the user can be dangerous, as it provides a more straightforward potential avenue for unintended data to be reflected to the screen, especially if exploited.

Looking at `source.c` we can notice a few concerning components. Primarily, while not necessarily unsafe by itself, it is generally advisable to not provide the addresses of variables to the user, which is what the program begins by doing.

The key vulnerability in the function is the usage of `scanf` in line 19, with `scanf("%s", username);`. Putting the user input directly into the buffer `username` without ensuring that the input can actually fit into `username` lends itself to buffer overflow vulnerabilities. 

In addition, line 22, `system(shell)`, contains the unsafe `system` system call, which allows for the potential of even further damage to a server because it can allow for RCE.

## Exploitation
Since the program helpfully prints the addresses of both `username` and `shell` at the start, we can calculate the exact offset between them. In this case the offset is 0x30 bytes, which is 48 bytes in decimal. This tells us precisely how many bytes of padding we need to write past username before we start overwriting shell.

With this, the exploit is straightforward: we input 48 bytes of padding followed immediately by our desired command, which overwrites the contents of shell. When `system(shell)` is called, it executes our command instead of `/bin/pwd`.

Because `scanf` stops reading at whitespace, a payload like cat flag.txt would be cut off at cat. To bypass this, we use ${IFS}, the shell variable that expands to a space after scanf is done reading, ultimately giving us `48*Acat${IFS}flag.txt` as our payload to the username field. 

## Remediation
The root cause is that `scanf("%s", username)` places no bound on user input, allowing writes beyond the buffer. Replacing it with fgets and sscanf directly addresses this:
`fgets(username, 28, stdin);`
`sscanf(username, "%27s", username);`
This ensures input is bounded to the size of the buffer, preventing overflow into shell entirely. Additionally, replacing `system(shell)` with a funciton in the exec family, such as `execl` would limit the impact of any future vulnerabilities by removing shell interpretation, reducing the risk of RCE. 
