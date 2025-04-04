from pwn import *
import binascii

printable_chars = b'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}|;:,.<>?'
# Connect to the challenge service
conn = remote('very-serious.chal-kalmarc.tf', 2257)
# to execute against the local python script, uncomment the following line
# conn = process(["python3", "chal.py"])
# Fixed strings in the message
prefix = "Dear ".encode()
suffix = ", as a token of the depth of my feelings, I gift to you that which is most precious to me. A b'".encode()

block_size = 16
extracted_flag = b""
known_chars = 0
def get_name(prefix, suffix, block_size, extracted_flag, guess):
    """Generate the name to send to the server, based on the guessed character, other parts of the message, and the flag extracted so far."""

    #block aligning the name
    name = ("A" * (16 - len(prefix))).encode()

    # calculate the index of the byte we are trying to guess
    index = len(extracted_flag)

    # calculate the 15 bytes that come before the byte in question, in the same block
    before = suffix[-15:]

    # calculate the 16 bytes that came before the block in question. This is not strictly nessary, we could use xor later to deal with this.
    block_before = suffix[-31:-15]

    # calculate the block with the flag guess
    block = before + guess

    # making the name
    name = name + block_before + block

    # aligning the block to the block size, ensuring that the actual flag is in the right place
    pos = (len(suffix) + len(name) + len(prefix))% block_size
    name += b"A" * (block_size-pos-1)
    return name 


    

print_pos = 0
while True:
    # this is the case where we iterated through the whole printable chars array without discovering a match
    if(print_pos >= len(printable_chars)):
        print("no plaintext match for target character found")
        print("flag: ", extracted_flag)
        break

    # Generate the name to send to the server
    name = get_name(prefix, suffix, block_size, extracted_flag, printable_chars[print_pos:print_pos + 1])

    # Send the name to the server, recieve the response
    conn.recvuntil(b"Recipient name: ")
    conn.sendline(name)
    response = conn.recvline()

    # Extract the ciphertext from the response
    ciphertext_hex = response.split(b": ")[1].strip()
    ciphertext = binascii.unhexlify(ciphertext_hex)

    # pull out the third block of the ciphertext. This is the block with our guess for the next flag byte in it.
    guess_block = ciphertext[32:48]

    # pull out the block of the ciphertext with the actual flag in it.
    blocks = len(name) + len(prefix) + len(suffix) + 1
    flag_block = ciphertext[blocks-16:blocks]

    full_ciphertext = prefix + name + suffix 

    # check if they are the same. This means our guess is correct.
    if(guess_block == flag_block):
        print("found a match", printable_chars[print_pos:print_pos + 1])

        # add to extracted_flag and suffix
        extracted_flag += printable_chars[print_pos:print_pos + 1]
        suffix += printable_chars[print_pos:print_pos + 1]

        # print the flag so far
        print_pos = 0
        print("new flag: ", extracted_flag)
        continue
        

    print_pos += 1
