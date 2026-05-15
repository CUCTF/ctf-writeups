#!/usr/bin/env python3

import math
from PIL import Image

BLOCK_SIZE = 16
UMAX = int(math.pow(256, BLOCK_SIZE))


def block_to_int(b):
    return int(b.hex(), 16)


def int_to_block(n):
    return n.to_bytes(BLOCK_SIZE, 'big')


def remove_line(data):
    idx = data.index(b'\n')
    return data[:idx + 1], data[idx + 1:]


def parse_header_ppm(data):
    header = b""
    for _ in range(3):
        line, data = remove_line(data)
        header += line
    return header, data


with open('body.enc.ppm', 'rb') as f:
    raw = f.read()

header, body = parse_header_ppm(raw)
print(f"Header: {header}")
print(f"Body length: {len(body)} bytes, {len(body) // BLOCK_SIZE} blocks")

# body = IV || C[1] || C[2] || ...
# ECB[i] = (C[i] - C[i-1]) % UMAX  (recovers AES-ECB ciphertext, not plaintext)
blocks = [body[i * BLOCK_SIZE:(i + 1) * BLOCK_SIZE] for i in range(len(body) // BLOCK_SIZE)]

ecb_blocks = []
for i in range(1, len(blocks)):
    prev = block_to_int(blocks[i - 1])
    curr = block_to_int(blocks[i])
    ecb = (curr - prev) % UMAX
    ecb_blocks.append(int_to_block(ecb))

ecb_body = b"".join(ecb_blocks)

with open('body_ecb.ppm', 'wb') as f:
    f.write(header)
    f.write(ecb_body)

Image.open('body_ecb.ppm').save('body_ecb.png')
print("Written body_ecb.png")
