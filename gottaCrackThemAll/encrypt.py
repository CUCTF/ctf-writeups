# with open('key.txt','rb') as f:
# 	key = f.read()

def encrypt(plain):
	return b''.join((ord(x) ^ y).to_bytes(1,'big') for (x,y) in zip(plain,b'(\x1b\xa5\xcd\xac6\x1b\xae\xa7\xd9\x92\xfc\xcd\x1c\xc3G\xae\xaf\x0f'))

print(encrypt('Cacturne-Grass-Dark'))
