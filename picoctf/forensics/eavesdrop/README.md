## Context

Eavesdrop is a picoctf forensics challenge centered around a vulnerable key exchange, where two parties discuss the encryption key for a file transfer over an unencrypted channel. The challenge provides us with a packet capture file, without much else to go off of. 

## Vulnerability

The first vulnerability lies in the fact that we are able to see the clear-text communication that occurs between the two parties. Despite the fact that they correctly encrypt the sensitive file with 3DES, they share the decryption command and password, in plaintext, over an unencrypted TCP channel. 
So if an attacker conducts a successful MITM on a network, like through ARP spoofing, they end up with a pcap of all the traffic, and any secrets transmitted in cleartext are theirs.

## Exploitation

First we open the pcap in Wireshark, and click to follow one of the TCP streams. Stream 0 holds an interesting conversation between two parties, which gives the instructions to decrypt a file as 
```
openssl des3 -d -salt -in file.des3 -out file.txt -k supersecretpassword123
```
They also mention that the file will be transferred over port 9002. Thus, we follow the TCP stream over port 9002 and find a string of bytes there. 
So now we have the password (`supersecretpassword123`) and the exact command we need to run. They also mention sending the encrypted file over port 9002. Filtering on `tcp.port == 9002` and following that TCP stream shows a payload that starts with `Salted__`, which is the magic number openssl prepends to files encrypted with the `-salt` flag. This is the ciphertext we need to decrypt. In the "Follow TCP Stream" window, the "Show data as" dropdown has to be set to **Raw**. Then, we save it as `file.des3` and run the command from the chat:

```bash
openssl des3 -d -salt -in file.des3 -out file.txt -k supersecretpassword123
```
This leaves an unencrypted `file.txt`, which reveals the flag.

## Remediation

The most immediate fix is to never discuss encryption keys or passwords over an unencrypted channel. They even jokingly reference this in an exchange in the pcap file, right after sharing the password. Sharing the key through a separate trusted channel is one option, but the real fix is using protocols that handle key exchange securely by design.

Most importantly, the chat channel itself should have been encrypted with TLS, which would have prevented an eavesdropper from reading either the chat or the file transfer in the first place. TLS solves the key exchange problem with asymmetric cryptography, establishing a shared secret without ever transmitting the key directly. On top of that, 3DES was deprecated and disallowed for encryption after 2023 as it was deemed insecure and vulnerable to certain attacks, so a more modern cipher alternative should be used.
