# Vendored from https://github.com/stephenbradshaw/hlextend (hash length extension)
from re import match
from math import ceil
from typing import Union

class Hash(object):
    def hash(self, message):
        length = bin(len(message) * 8)[2:].rjust(self._blockSize, "0")
        while len(message) > self._blockSize:
            self._transform(''.join([bin(a)[2:].rjust(8, "0") for a in message[:self._blockSize]]))
            message = message[self._blockSize:]
        message = self._Hash__hashBinaryPad(message, length)
        for a in range(len(message) // self._b2):
            self._transform(message[a * self._b2:a * self._b2 + self._b2])

    def extend(self, appendData, knownData, secretLength, startHash):
        self._Hash__checkInput(secretLength, startHash)
        self._Hash__setStartingHash(startHash)
        extendLength = self._Hash__hashGetExtendLength(secretLength, knownData, appendData)
        message = appendData
        while len(message) > self._blockSize:
            self._transform(''.join([bin(a)[2:].rjust(8, "0") for a in message[:self._blockSize]]))
            message = message[self._blockSize:]
        message = self._Hash__hashBinaryPad(message, extendLength)
        for i in range(len(message) // self._b2):
            self._transform(message[i * self._b2:i * self._b2 + self._b2])
        return self._Hash__hashGetPadData(secretLength, knownData, appendData)

    def hexdigest(self):
        return ''.join([(('%0' + str(self._b1) + 'x') % (a)) for a in self._Hash__digest()])

    def __init__(self):
        self._b1 = self._blockSize//8
        self._b2 = self._blockSize*8

    def _Hash__digest(self):
        return [self.__getattribute__(a) for a in dir(self) if match('^_h\d+$', a)]

    def _Hash__setStartingHash(self, startHash):
        c = 0
        hashVals = [int(startHash[a:a+int(self._b1)], base=16) for a in range(0, len(startHash), int(self._b1))]
        for hv in [a for a in dir(self) if match('^_h\d+$', a)]:
            self.__setattr__(hv, hashVals[c])
            c += 1

    def _Hash__checkInput(self, secretLength, startHash):
        if not isinstance(secretLength, int):
            raise TypeError('secretLength must be a valid integer')
        if secretLength < 1:
            raise ValueError('secretLength must be grater than 0')
        if not match('^[a-fA-F0-9]{' + str(len(self.hexdigest())) + '}$', startHash):
            raise ValueError('startHash must be a string of length ' + str(len(self.hexdigest())) + ' in hexlified format')

    def _Hash__hashGetExtendLength(self, secretLength, knownData, appendData):
        originalHashLength = int(ceil((secretLength+len(knownData)+self._b1+1)/float(self._blockSize)) * self._blockSize)
        newHashLength = originalHashLength + len(appendData)
        return bin(newHashLength * 8)[2:].rjust(self._blockSize, "0")

    def _Hash__hashGetPadData(self, secretLength, knownData, appendData):
        originalHashLength = bin((secretLength+len(knownData)) * 8)[2:].rjust(self._blockSize, "0")
        padData = ''.join(bin(i)[2:].rjust(8, "0") for i in knownData) + "1"
        padData += "0" * (((self._blockSize*7) - (len(padData)+(secretLength*8)) % self._b2) % self._b2) + originalHashLength
        return int(padData, 2).to_bytes(len(padData) // 8, byteorder='big') + appendData

    def _Hash__hashBinaryPad(self, message, length):
        out_msg = ''.join(bin(i)[2:].rjust(8, "0") for i in message)
        out_msg += "1"
        out_msg += "0" * (((self._blockSize*7) - len(out_msg) % self._b2) % self._b2) + length
        return out_msg


class SHA256(Hash):
    _h0, _h1, _h2, _h3, _h4, _h5, _h6, _h7 = (
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19)
    _blockSize = 64

    def _transform(self, chunk):
        def rrot(x, n): return (x >> n) | (x << (32 - n)) & 0xffffffff
        w = []
        k = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]
        for j in range(len(chunk) // 32):
            w.append(int(chunk[j * 32:j * 32 + 32], 2))
        for i in range(16, 64):
            s0 = rrot(w[i - 15], 7) ^ rrot(w[i - 15], 18) ^ (w[i - 15] >> 3)
            s1 = rrot(w[i - 2], 17) ^ rrot(w[i - 2], 19) ^ (w[i - 2] >> 10)
            w.append((w[i - 16] + s0 + w[i - 7] + s1) & 0xffffffff)
        a, b, c, d, e, f, g, h = self._h0, self._h1, self._h2, self._h3, self._h4, self._h5, self._h6, self._h7
        for i in range(64):
            s0 = rrot(a, 2) ^ rrot(a, 13) ^ rrot(a, 22)
            maj = (a & b) ^ (a & c) ^ (b & c)
            t2 = (s0 + maj) & 0xffffffff
            s1 = rrot(e, 6) ^ rrot(e, 11) ^ rrot(e, 25)
            ch = (e & f) ^ ((~e) & g) & 0xffffffff
            t1 = (h + s1 + ch + k[i] + w[i]) & 0xffffffff
            h, g, f, e, d, c, b, a = g, f, e, (d + t1) & 0xffffffff, c, b, a, (t1 + t2) & 0xffffffff
        self._h0 = (self._h0 + a) & 0xffffffff
        self._h1 = (self._h1 + b) & 0xffffffff
        self._h2 = (self._h2 + c) & 0xffffffff
        self._h3 = (self._h3 + d) & 0xffffffff
        self._h4 = (self._h4 + e) & 0xffffffff
        self._h5 = (self._h5 + f) & 0xffffffff
        self._h6 = (self._h6 + g) & 0xffffffff
        self._h7 = (self._h7 + h) & 0xffffffff


def sha256():
    return SHA256()
