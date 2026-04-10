#!/usr/bin/env python3

from math import gcd, isqrt
from functools import reduce
from hashlib import md5

try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import unpad
except ImportError:
    raise SystemExit("pycryptodome is required to run this script. Install with: `pip install pycryptodome`")

# public keys provided by output.txt
ALICE_PUB = (
    13109366899209289301676180036151662757744653412475893615415990437597518621948,
    5214723011482927364940019305510447986283757364508376959496938374504175747801,
)
BOB_PUB = (
    1970812974353385315040605739189121087177682987805959975185933521200533840941,
    12973039444480670818762166333866292061530850590498312261363790018126209960024,
)

# encrypted flag provided by output.txt
ENC_FLAG_HEX = "d345a465538e3babd495cd89b43a224ac93614e987dfb4a6d3196e2d0b3b57d9"

# base point from chall.py
BASE = (
    13187661168110324954294058945757101408527953727379258599969622948218380874617,
    5650730937120921351586377003219139165467571376033493483369229779706160055207,
)


def clock_add(P1, P2, p):
    """Add two points on the "clock curve" modulo p."""
    x1, y1 = P1
    x2, y2 = P2
    return ((x1 * y2 + y1 * x2) % p, (y1 * y2 - x1 * x2) % p)


def scalar_mult(P, n, p):
    """Iterative implementation of double-and-add algorithm to avoid hitting python's recursion limit."""
    R = (0, 1)
    Q = P
    while n > 0:
        if n & 1:
            R = clock_add(R, Q, p)
        Q = clock_add(Q, Q, p)
        n >>= 1
    return R


def recover_prime(points):
    """Recover p from the public points by computing gcd of x^2+y^2-1."""
    candidates = [x * x + y * y - 1 for x, y in points]
    return reduce(gcd, candidates)


def factorize_smooth(n):
    """Trial-division factorization. Fast here because p+1 is very smooth."""
    factors = {}
    while n % 2 == 0:
        factors[2] = factors.get(2, 0) + 1
        n //= 2

    d = 3
    lim = isqrt(n)
    while d <= lim and n > 1:
        while n % d == 0:
            factors[d] = factors.get(d, 0) + 1
            n //= d
            lim = isqrt(n)
        d += 2

    if n > 1:
        factors[n] = factors.get(n, 0) + 1
    return factors


def dlog_bsgs(H, G, n, p):
    """Solve x such that H = x*G in subgroup of order n using Baby-step Giant-step algorithm."""
    m = isqrt(n) + 1
    cur = (0, 1)
    baby_steps = {cur: 0}
    for j in range(1, m):
        cur = clock_add(cur, G, p)
        if cur not in baby_steps:
            baby_steps[cur] = j

    neg_mG = scalar_mult(G, n - m, p)

    gamma = H
    for i in range(m):
        j = baby_steps.get(gamma)
        if j is not None:
            return (i * m + j) % n
        gamma = clock_add(gamma, neg_mG, p)
    raise ValueError("No discrete log found.")


def crt_pair(a1, m1, a2, m2):
    """Solve x ≡ a1 (mod m1) and x ≡ a2 (mod m2) for coprime m1, m2 with Chinese Remainder Theorem."""
    inv = pow(m1, -1, m2)
    t = ((a2 - a1) * inv) % m2
    x = a1 + m1 * t
    return x % (m1 * m2), m1 * m2


def crt_all(remainders, moduli):
    """Solve x ≡ a (mod m) for all (a, m) pairs with Chinese Remainder Theorem."""
    x, m = remainders[0], moduli[0]
    for a, mod in zip(remainders[1:], moduli[1:]):
        x, m = crt_pair(x, m, a, mod)
    return x


def pohlig_hellman_two_targets(p_base, p_alice, p_bob, group_order, p):
    """Solve for x1, x2 such that p_alice = x1 * p_base and p_bob = x2 * p_base using Pohlig-Hellman attack."""
    prime_power_factors = factorize_smooth(group_order)
    moduli = []
    remainders_alice = []
    remainders_bob = []

    for prime_factor, exponent in prime_power_factors.items():
        prime_power = prime_factor ** exponent
        p_base_reduced = scalar_mult(p_base, group_order // prime_power, p)
        p_alice_reduced = scalar_mult(p_alice, group_order // prime_power, p)
        p_bob_reduced = scalar_mult(p_bob, group_order // prime_power, p)
        x1 = dlog_bsgs(p_alice_reduced, p_base_reduced, prime_power, p)
        x2 = dlog_bsgs(p_bob_reduced, p_base_reduced, prime_power, p)
        moduli.append(prime_power)
        remainders_alice.append(x1)
        remainders_bob.append(x2)

    return crt_all(remainders_alice, moduli), crt_all(remainders_bob, moduli)

def calculate_norm(P, p):
    """Calculate the norm of a point P = (x, y) as x^2 + y^2 mod p."""
    x, y = P
    return (x * x + y * y) % p


def main():
    p = recover_prime([BASE, ALICE_PUB, BOB_PUB])
    print(f"recovered p: {p}")
    
    for point in [BASE, ALICE_PUB, BOB_PUB]:
        if calculate_norm(point, p) != 1:
            raise ValueError("Point does not lie on the curve defined by x^2 + y^2 ≡ 1 mod p.")

    group_order = p + 1 if p % 4 == 3 else p - 1
    alice_secret, bob_secret = pohlig_hellman_two_targets(BASE, ALICE_PUB, BOB_PUB, group_order, p)
    print(f"alice's secret: {alice_secret}")
    print(f"bob's secret: {bob_secret}")

    shared = shared_alice = scalar_mult(BOB_PUB, alice_secret, p)
    shared_bob = scalar_mult(ALICE_PUB, bob_secret, p)
    if shared_alice != shared_bob:
        raise ValueError("Shared secrets do not match, something went wrong.")
    print(f"shared secret: {shared}")
    
    key = md5(f"{shared[0]},{shared[1]}".encode()).digest()
    print(f"symmetric key: {key.hex()}")

    enc = bytes.fromhex(ENC_FLAG_HEX)
    pt = AES.new(key, AES.MODE_ECB).decrypt(enc)
    flag = unpad(pt, 16).decode()

    print("decrypted flag:", flag)


if __name__ == "__main__":
    main()
