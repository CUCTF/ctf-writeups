#!/usr/bin/env python3
"""
Hash length extension exploit for ttyspin.
Server hashes: (SECRET + username + save_code).strip()
We have one valid (username, save_code, checksum). We extend to append a winning save.
"""
import base64
import sys
import os
import time
from pwn import *
from hlextend import sha256
from tmux_process import spawn_in_tmux

SECRET_LEN = 40
block_type_text = ["T", "J", "L", "S", "Z", "O", "I"]

winning_board = [
    [0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [7, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [0, 4, 0, 0, 0, 0, 0, 0, 0, 0],
    [0, 0, 6, 0, 0, 0, 0, 0, 0, 0],
    [0, 0, 0, 3, 0, 0, 0, 0, 0, 0],
    [0, 0, 0, 0, 5, 0, 0, 0, 0, 0],
    [0, 0, 0, 0, 0, 1, 0, 0, 0, 0],
    [0, 0, 0, 0, 0, 0, 2, 0, 0, 0],
    [0, 0, 0, 0, 0, 0, 0, 7, 0, 0],
    [0, 0, 0, 0, 0, 0, 0, 0, 4, 0],
    [0, 0, 0, 0, 0, 0, 0, 0, 0, 6],
    [0, 0, 0, 0, 0, 0, 0, 0, 3, 0],
    [0, 0, 0, 0, 0, 0, 0, 5, 0, 0],
    [0, 0, 0, 0, 0, 0, 1, 0, 0, 0],
    [0, 0, 0, 0, 0, 2, 0, 0, 0, 0],
    [0, 0, 0, 0, 7, 0, 0, 0, 0, 0],
    [0, 0, 0, 4, 0, 0, 0, 0, 0, 0],
    [0, 0, 6, 0, 0, 0, 0, 0, 0, 0],
    [0, 3, 0, 0, 0, 0, 0, 0, 0, 0],
    [5, 0, 0, 0, 0, 0, 0, 0, 0, 0]
]


def build_winning_save():
    """Build save string that loads to winning_board: current|hold|nexts|queue|board"""
    board_str = "".join(
        " " if tile == 0 else block_type_text[tile - 1]
        for row in winning_board for tile in row
    )
    return "T| |ILJZ|TO|" + board_str  # current=T, hold=empty, nexts=empty, queue=empty


def main():
    # Example: you have a valid export with this save and checksum (from a real export)
    save_b64 = sys.argv[1] if len(sys.argv) > 1 else "U3wgfElMSlp8VE98ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICA="
    checksum_hex = sys.argv[2] if len(sys.argv) > 2 else "1f86f6f8044504cd55712eb63ac2d9a778ce64d716347758f52ca4f055acbc73"
    username = sys.argv[3] if len(sys.argv) > 3 else b""

    save_code = base64.b64decode(save_b64)
    # The data that was hashed after SECRET (must match what server hashes)
    known_data = (username + save_code).strip()
    board_data = build_winning_save()
    append_data = board_data.strip().encode()

    sha = sha256()
    # extend(appendData, knownData, secretLength, startHash)
    # Returns the bytestring to use *after SECRET*: knownData + padding + appendData
    extended = sha.extend(append_data, known_data, SECRET_LEN, checksum_hex)
    print(extended)
    new_checksum = sha.hexdigest()
    print(new_checksum)
    new_username = extended[:24]
    new_save_b64 = base64.b64encode(board_data.encode()).decode()
    import hashlib
    from secrets import SECRET
    print(hashlib.sha256((SECRET + new_username + append_data).strip()).hexdigest())

    # Server expects: (SECRET + username + save_code).strip() and checks make_checksum(username, save_code)
    # So we send: username = empty, save_code = extended (so SECRET + extended is the full message)

    script_dir = os.path.dirname(os.path.abspath(__file__))
    try:
        p = spawn_in_tmux(["python3", "game.py"], cwd=script_dir)
    except RuntimeError as e:
        print(e)
        sys.exit(1)

    time.sleep(0.3)
    p.sendline(new_username)
    time.sleep(.3)
    p.sendline(new_save_b64.encode())
    time.sleep(.3)
    p.sendline(new_checksum.encode())
    time.sleep(.3)
    p.interactive()


if __name__ == "__main__":
    main()
