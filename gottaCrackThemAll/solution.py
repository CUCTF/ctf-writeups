cipher = b'oz\xd6\xb9\xdeY\x7f\xc1\xc9\xf4\xc5\x9d\xb9y\xb1j\xe9\xdd`\xe0\xe2\xdf'
password = b'Gastrodon-Water-Ground'
key = b'(\x1b\xa5\xcd\xac6\x1b\xae\xa7\xd9\x92\xfc\xcd\x1c\xc3G\xae\xaf\x0f\x95\x8c\xbb'
l = []
print(len(cipher))
print(len(password))
for (a,b) in zip(cipher,password):
    l.append((a^b).to_bytes(1,'big')) 

print(b''.join(l))
for c in password:
    print(c)
with open('encrypted_passwords.txt', 'rb') as f:
    lines = f.readlines()

def decrypt(c):
	return b''.join((x ^ y).to_bytes(1,'big') for (x,y) in zip(c,key))

for line in lines:
    print(decrypt(line))
