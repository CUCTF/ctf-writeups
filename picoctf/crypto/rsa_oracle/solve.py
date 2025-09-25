#!/usr/bin/env python3

import subprocess
import sys
from pwn import *

def decrypt_with_openssl(encrypted_file, password):
    decrypted_file = "message.dec"
    try:
        subprocess.run(
            ["openssl", "enc", "-aes-256-cbc", "-d", "-in", encrypted_file, "-out", decrypted_file, "-pass", f"pass:{password}"],
            check=True
        )
        with open(decrypted_file, "r") as f:
            decrypted_message = f.read().strip()
        return decrypted_message
    except subprocess.CalledProcessError as e:
        print("Error decrypting file:", e)
        return None

def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <port>")
        sys.exit(1)

    host = "titan.picoctf.net"
    port = sys.argv[1]

    with open("password.enc", "r") as f:
        password = int(f.read().strip())

    # connect to remote host and send request to encrypt "2"
    r = remote(host, port)
    r.recvuntil(b"decrypt.")
    r.sendline(b"E")
    r.recvuntil(b"keysize): ")
    r.sendline(b"\x02")

    # receive first ciphertext (2^e mod n)
    r.recvuntil(b"mod n) ")
    cipher_text = int(r.recvline())

    # compute the chosen ciphertext (2^e * password) and send to oracle to decrypt
    chosen_cipher_text = cipher_text * password
    r.recvuntil(b"decrypt.")
    r.sendline(b"D")
    r.recvuntil(b"decrypt: ")
    r.sendline(str(chosen_cipher_text).encode())

    # extract plain text as int
    r.recvuntil(b"mod n): ")
    plain_text = int(r.recvline(), 16)

    # divide by two (our chosen plaintext) to obtain password
    password = plain_text // 2
    password = p64(password).decode("utf-8", errors="ignore").rstrip("\x00")[::-1]
    print("password:", password)

    # use openssl as in challenge hints
    decrypted_message = decrypt_with_openssl("secret.enc", str(password))
    
    if decrypted_message:
        print("\nflag:", decrypted_message)
    else:
        print("\nfailed to decrypt flag.")

if __name__ == "__main__":
    main()