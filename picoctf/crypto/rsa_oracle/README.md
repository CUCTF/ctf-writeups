# rsa_oracle

## Summary

**Challenge description:**

```
Can you abuse the oracle?
An attacker was able to intercept communications between a bank and a fintech company. They managed to get the message (ciphertext) and the password that was used to encrypt the message.
Additional details will be available after launching your challenge instance.
```

This challenge provides an instance of an RSA oracle that encrypts and decrypts any input but the intercepted password.
The given ciphertext is encrypted using AES-256 in CBC mode. The exploit abuses the RSA oracle to decode the password in order to decrypt the ciphertext.

**Artifacts:**

* solve.py: solve script that executes the exploit and recovers the flag

## Context

In this challenge we are given an oracle that can encrypt or decrypt messages, other than the password, using RSA.
The challenge authors provide a domain and a port to connect to the challenge, as well as two files, `password.enc` and `secret.enc`.

The challenge also gives us several hints along with this challenge

* Crytography Threat models: chosen plaintext attack.
* OpenSSL can be used to decrypt the message. e.g `openssl enc -aes-256-cbc -d ...`
* The key to getting the flag is by sending a custom message to the server by taking advantage of the RSA encryption algorithm.
* Minimum requirements for a useful cryptosystem is CPA security.

We know that the message, or `secret.enc`, is encrypted with AES, as given in the hints by the challenge authors. In order to decrypt AES, we need a 32-byte key, which is `password.enc` which is encrypted with RSA. Our task is to decode the encrypted password using the oracle into a valid decryption key for AES, so that we can decode the message.

## Vulnerability

The description and hints in the challenge are a bit of a misnomer, as the exploit demonstrates a *chosen ciphertext attack*,
rather than a *chosen plaintext attack*. However, the attack works because we are able to select our own plaintext to produce a ciphertext.
This plaintext exposes the vulnerabilities of this implementation of RSA.

By playing around with the oracle and encrypting the same plaintext several times, we observe the same ciphertext each time.
This tells us that this implementation of RSA doesn't provide semantic security, specifically that there is no padding, so the encryption is deterministic.
Since the RSA is implemented without padding, or as textbook RSA, it makes it vulnerable to certain attacks, such as chosen ciphertext attack.

Now we can perform our chosen ciphertext attack, following the same process as https://crypto.stackexchange.com/questions/2323/how-does-a-chosen-plaintext-attack-on-rsa-work/

Since the oracle is implemented as textbook RSA we encrypt by

*Encryption:* $c \equiv m^e \pmod{n}$

where $m$ is our plaintext message, $e$ is the public key, $n$ is the modulus, and $c$ is our resulting ciphertext.
RSA uses the private key $d$, which is the modular inverse of public key $e$ under $\phi(n)$ in order decrypt a message.

*Decryption:* $c^d \equiv (m^e)^d \equiv m \pmod{n}$

In our attack we first compute the encryption for chosen plaintext $m = 2$ for which the oracle returns the ciphertext $C$

$C \equiv 2^e \pmod{n}$

Next, we compute a chosen ciphertext using our intercepted password $P = p^e$ and our chosen plaintext $C = 2^e$

$C \cdot P = 2^e \cdot p^e \pmod{n}$

The oracle decrypts this ciphertext using the given decryption algorithm, as it is not the intercepted password ciphertext. This returns our recovered plaintext $D$

$D \equiv (2^e \cdot p^e)^d \equiv 2^{ed}\cdot p^{ed} \equiv 2^1 \cdot p^1  \equiv 2 \cdot p \pmod{n}$

We can see that $D$ is equal to the recovered password $p$ multiplied by our chosen plaintext $2$. To recover $p$, we simply multiply the value $D$ by $2^{-1}$.

## Exploitation

**Exploit overview:**

We abuse the oracle by craftily using the chosen ciphertext attack, as described above.

After recovering the password, we use AES to uncover the intercepted message, which reveals the flag.

**Exploit mitigation considerations:**

Access to the oracle could be limited, which can reduce the feasability of chosen ciphertext attacks, however, this doesn't prevent the exploit on textbook RSA.

**Exploit description:**

The exploit involves us abusing the oracle by a series of requests.
First, the script sends a request to encrypt a trvial plaintext.
Next, it computes a chosen ciphertext and sends to the oracle to obtain a decrypted message from which we can
extract the password.
Then, we use the password to decrypt the AES-encrypted message and retrieve the flag.

**Exploit primitives used**:

1. Chosen Ciphertext Attack
2. Chosen Plaintext Attack

## Remediation

Textbook RSA should never be used. Chosen plaintext and chosen ciphertext attacks can be prevented by implementing RSA with a cryptographically secure padding scheme,
such as OAEP (Optimal Asymmetric Encryption Padding). This introduces randomness into the encryption process which provides semantic security
by preventing the deterministic nature of RSA from being exploited.

## Configuration Notes

The provided solution script establishes a remote connection with the server using the Python `pwntools` library (https://docs.pwntools.com/en/stable/).
Before running the script, launch the challenge instance on picoCTF and ensure that the `password.enc` and `secret.enc` files are available in the same directory.
The script takes in one argument: the port number to connect to the running instance