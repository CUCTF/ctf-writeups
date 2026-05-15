from sage.all import *
import hashlib
class UOV:
    def __init__(self):
        self.f = GF(2 ** 7)
        self.pk = load('public_key')
        self.sk = load('private_key')
        m = 57
        v = 197
        n = m + v
        self.m = m
        self.v = v
        self.n = n

    def sign(self, msg):
        field = self.f
        m = self.m
        v = self.v
        F, T = self.sk
        t = vector(field, ZZ([x for x in hashlib.shake_128(msg.encode()).digest(m)], 256).digits(2)[:m])
        while True:
            V = random_vector(field, v)
            A = Matrix(self.f, [ov * V for _, ov in F])
            if A.rank() == m:
                break
        b = vector(self.f, [V * vv * V for vv, _ in F])
        O = A.solve_right(t - b)
        signature = ~T * vector(list(V) + list(O))
        return bytes([e.to_integer() for e in signature]).hex()

    def verify(self, msg, sig):
        m = self.m
        t = ZZ([x for x in hashlib.shake_128(msg.encode()).digest(m)], 256).digits(2)[:m]
        sig = vector(self.f, [self.f.from_integer(e) for e in sig])
        result = [sig * f * sig for f in self.pk]
        return t == result
