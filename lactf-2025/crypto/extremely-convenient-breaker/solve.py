from pwn import *  # Import pwntools library for easy socket handling

host = 'localhost'  # Target host
port = 5000         # Target port
    
s = remote(host, port)  # Connect to the remote server

# Receive data until the indicator for encrypted flag
s.recvuntil(b'hex: \n')
encrypted_flag = s.recvline().strip()  # Get the encrypted flag from server
print("encrypted flag:", encrypted_flag)  # Print the raw encrypted flag

s.recvuntil(b'hex: ')  # Wait for the next input prompt
# Convert the encrypted flag from hex string to bytes
encrypted_flag = bytes.fromhex(encrypted_flag.decode())
print("encrypted flag:", encrypted_flag)  # Print the converted encrypted flag

# Create first modified version by flipping the last byte's least significant bit
flag1 = encrypted_flag[:-1] + bytes(encrypted_flag[-1] ^ 0x01)
s.sendline(flag1[:64].hex())  # Send first 64 bytes of modified flag to server
decrypt1 = s.recvline()  # Get the first decryption result
print("decrypt1:", decrypt1)  # Print first decrypt result

s.recvuntil(b'hex: ')  # Wait for next input prompt

# Create second modified version by flipping the first byte's least significant bit
flag2 = encrypted_flag
flag2 = bytes([encrypted_flag[0] ^ 0x01]) + encrypted_flag[1:]
s.sendline(flag2.hex())  # Send second modified flag to server
decrypt2 = s.recvline()  # Get the second decryption result
s.recvuntil(b'hex: ')  # Wait for next prompt
print("decrypt2:", decrypt2)  # Print second decrypt result

# Combine parts of both decryptions to get the complete flag
flag = decrypt1[2:34] + decrypt2[-34:]  # Take first part from decrypt1, second part from decrypt2
print("flag:", flag.decode())  # Print the combined flag
