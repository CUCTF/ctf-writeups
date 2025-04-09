#!/usr/bin/env python3

from pwn import *
from sage.all import *
from sympy import *

bases = list(range(3,257))

sums = []

for base in bases:
    p = process(["python3", "chal.py"])
    p.recvuntil(b'Give me a base! ')
    p.sendline(str(base).encode())
    p.recvuntil(b'Here you go! ')
    sums.append(int(p.recvline().decode().strip()))
    p.close()

# solve chinese remainder theorem for flag = sum % base
crt_soln = int(crt(sums, [b-1 for b in bases]))

flag = crt_soln.to_bytes(45, 'big')
print(flag)