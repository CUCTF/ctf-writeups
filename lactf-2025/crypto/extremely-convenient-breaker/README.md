# Extremely Convenient Breaker 
## Summary
This challenge uses an insecure implementation of AES encryption with an oracle to allow the user to decrypt the flag.

**Artifacts:**
* `chall.py`: vulnerable python process which communicates over a socket
* `solve.py`: Python script to solve the challenge
* `Dockerfile`: Dockerfile to build the challenge
* `flag.txt`: Flag file
* `challenge.yaml`: Challenge metadata file

## Context
The `extremely-convenient-breaker` challenge authors provide a domain and port to connect to the challenge. They also provide a copy of the source code (`chall.py`).

When a user connects to the server, they are greeted with the following message:
```
Here's the encrypted flag in hex:
f0ab46e5aaed7c3583dc07aa0d92ff5d0678dee818e4f8446b97d065689c330469167cc09701d519cc5b1a3d24e44419141b701d53504e2e056f46d65515f8be
Alright, lemme spin up my Extremely Convenient Breaker (trademark copyright all rights reserved).
What ciphertext do you want me to break in an extremely convenient manner? Enter as hex:
```

Digging into the (`chall.py`) source code, we can analyze what is going on. The server first generates a key `key = os.urandom(16)`: 16 random bytes and unique for each user. 
The server then encrypts the flag with the line: `cipher = AES.new(key, AES.MODE_ECB)`. The server then sends the encrypted flag to the user as hex. 

The program then enters a loop, where the server allows the user to input a ciphertext to decrypt. Before decrypting the ciphertext, the server checks to make sure the ciphertext is the same number of bytes (64) and that it is not the same as the encrypted flag. If the ciphertext is valid, the server decrypts the ciphertext and sends the decrypted plaintext back to the user.

## Vurnability
While it is generally bad form to allow an attacker to make arbitrary calls to a decryption function, the real problem here is that the server uses electronic code book (ECB) mode. 

AES is a block cipher, meaning that it encrypts 16 bytes at a time. In most modes, such as cipher block chaining (CBC), the ciphertext is dependent on the previous ciphertext. In other commonly used modes, like counter (CTR) mode, the ciphertext is dependent on a nonce and a counter, which allows for faster computation while ensuring a given block of plaintext will be encrypted to a different ciphertext on successive encryptions.

This implementation uses ECB mode, which is the simplest mode of AES. In ECB mode, the only factors to determine the ciphertext are the key and the plaintext. This means that if the same block of plaintext is encrypted twice, it will produce the same ciphertext. 

We can test this property by sending the server a ciphertext of our own. 

Since we know the length of a block is 16 bytes, we can send the server 64 bytes of 0x00.

Upon sending the server this ciphertext, we get the following response:
```
b'
\x9f\xd9q\xef\xf3\xbc\xd9\x15bZ\xbei\xb7\xe8\xff\xeb
\x9f\xd9q\xef\xf3\xbc\xd9\x15bZ\xbei\xb7\xe8\xff\xeb
\x9f\xd9q\xef\xf3\xbc\xd9\x15bZ\xbei\xb7\xe8\xff\xeb
\x9f\xd9q\xef\xf3\xbc\xd9\x15bZ\xbei\xb7\xe8\xff\xeb'
```
The same block of plaintext, returned 4 times.


## Exploitation
**Exploit overview**: The exploit uses the fact that blocks will always be encrypted the same using to pull out the flag piece by piece.

**Input restrictions**:
The program checks to ensure the flag ciphertext is not being decrypted directly, and that the input is 64 bytes.

**Exploit Description**: The program creates a key, encrypts the flag, and then allows the user to decrypt arbitrary ciphertexts. The user can send any ciphertext they want, as long as it is 64 bytes and not the encrypted flag, but it only checks against the complete ciphertext. Since there are 4 blocks being decrypted each time, we can decrypt the flag 3 blocks at a time.

To construct the attack, we will first read in the encrypted flag. Then we will send the flag with the last byte altered (by xoring with 0x01). This will give us a valid decryption for the first 4 blocks of the flag.
```
|--valid--|--valid--|--valid--|--TRASH--|
```
Next, we will send the encrypted flag with the first byte altered (by xoring with 0x01). This will give us a valid decryption for the last 3 blocks of the flag.
```
|--TRASH--|--valid--|--valid--|--valid--|
```
By stitching these together, we can find the complete flag, and solve the challenge. An automated script has been made to do this in `solve.py`.

**Exploit primitives used**: 
* decrypting arbitrary ciphertexts (decryption oracle)
* AES ECB mode


## Remediation
The first and most pressing step to patch the vurnability is to not provide attackers with an arbitrary decryption oracle. 

The second step is to use a more secure mode of AES, such as CBC or CTR. Even without a decryption oracle, ECB mode will reveal underlying information about repeated sections of the plaintext that could be exploited, whereas these other modes will not.

## Configuration Notes

The challenge is run in a docker container. The Dockerfile is provided in the repository. To build the container, run:
```
docker build -t extremly-convenient-breaker .
```
To run the container, run:
```
docker run -it -p 5000:5000 extremly-convenient-breaker
```
where the first`5000` is the port you want to use locally, and the second `5000` is the port the challenge is running on in the container (don't change this).

To execute the script against the target running in the container, set the port in the file (if you needed to change it when starting the docker container), and run:
```
python3 solve.py
```

To run it against a remote deployment, set the `HOST` and `PORT` variables in `solve.py` to the remote host and port, and run:
```
python3 solve.py
```