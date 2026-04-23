import itertools

f = open("./chall/output.txt", "r")
ciphertext = bytes.fromhex(f.read().strip())

random_strs = [
    b'my encryption method',
    b'is absolutely impenetrable',
    b'and you will never',
    b'ever',
    b'break it'
]

# Taken from the provided ./chall/encrypt.py
# We can use this to decrypt as well
def encrypt(ptxt, key):
    ctxt = b''
    for i in range(len(ptxt)):
        a = ptxt[i]
        b = key[i % len(key)]
        ctxt += bytes([a ^ b])
    return ctxt

for r in range(1, len(random_strs) + 1):
    for c in itertools.combinations(random_strs, r): # generate all possible combinations of random_strs
        ret = ciphertext
        for str in c:
            ret = encrypt(ret, str) # XOR each of str in the combination with the ciphertext

        # print(ret.decode('utf-8'))
        
        potential_key = encrypt(ret, b"picoCTF{")
        # print(potential_key[:len("picoCTF{")].decode('utf-8'))
        
        key = b"Africa!"
        potential_plaintext = encrypt(ret, key)
        if "picoCTF{" in potential_plaintext.decode('utf-8'):
            print(potential_plaintext.decode('utf-8'))