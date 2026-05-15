# Hens and Roosters

## Summary

Please help me buy more Legos! The store has such aggressive rate limiting I can't even get an ID!

The challenge presents a web application where users must accumulate seven "studs" to purchase a Lego set and obtain the flag. Studs are earned by submitting valid signatures for the current stud count. While the server provides free signatures for the first three studs (0, 1, and 2), reaching seven requires bypassing rate limits, exploiting a race condition, and leveraging a cryptographic property of the signature scheme to "clone" valid signatures.

**Artifacts:**

- `backend/app.py`: Flask application handling user progress and signature verification.
- `backend/uov.py`: Implementation of the Unbalanced Oil and Vinegar (UOV) signature scheme.
- `backend/public_key.sobj`: Serialized SageMath object containing the UOV public key matrices.
- `backend/Dockerfile`: Container definition for the Flask backend.
- `proxy/haproxy.cfg`: HAProxy configuration with a vulnerable rate-limiting rule.
- `proxy/Dockerfile`: Container definition for the HAProxy reverse proxy.
- `compose.yaml`: Docker Compose file orchestrating the backend, proxy, and Redis services.
- `solve.py`: Exploit script demonstrating the full attack chain.

## Context

The application uses the **Unbalanced Oil and Vinegar (UOV)** signature scheme over the extension field $\mathbb{F}\_{2^7}$. UOV is a multivariate public-key signature scheme. The signer partitions $n$ variables into $v$ "vinegar" variables (chosen at random) and $m$ "oil" variables (solved for). The public key is a set of $m$ multivariate quadratic polynomials over a finite field; the private key consists of the central maps $F\_i$, which define the quadratic structure over the oil/vinegar partition, and the invertible linear transformation $T$, which masks that structure by mapping internal coordinates to the public variables via $P\_i = T^\top F\_i T$. Verification checks that the signature satisfies all $m$ public polynomial equations. Security relies on the hardness of solving random systems of multivariate quadratic equations (the MQ problem). A user is identified by a `uid`, and their progress (number of studs) is stored in Redis.

To gain a stud, a user must `POST` a valid signature for the payload `str(studs) + '|' + uid` to the `/work` endpoint. The server implements a caching mechanism in Redis to speed up verification of recently seen signatures:

```python
@app.post('/work')
def work():
    # ... read studs and payload ...
    value = r.get(str(sig))
    if value is None:
        r.set(sig, b'-', ex=240)        # Reserve slot; blocks re-submission of same sig
        verified = uov.verify(payload, sig_bytes)  # Slow path (~2.5s)
        if verified:
            r.set(sig, payload, ex=240)
    elif value == b'-':
        return "The signature is still being processed, please send a request later!"
    else:
        verified = value.decode() == payload       # Fast path (cache hit)

    if verified:
        studs = r.incr(uid)
        # ... return next free signature if studs <= 2 ...
```

The server is protected by HAProxy, which enforces a rate limit of one request every 20 seconds.

## Vulnerability

Three distinct vulnerabilities are chained to achieve the exploit.

### 1. HAProxy Rate-Limit Bypass - [CWE-837: Improper Enforcement of a Single, Unique Action](https://cwe.mitre.org/data/definitions/837.html)

The HAProxy configuration tracks request rates based on the full URL, including query parameters:

```haproxy
stick-table type string len 2048 size 100k expire 20s store http_req_rate(20s)
http-request track-sc0 url
http-request deny deny_status 429 if { sc_http_req_rate(0) gt 1 }
```

By appending unique query parameters (e.g., `/work?x=1`, `/work?x=2`), an attacker can force HAProxy to treat each request as a distinct URL, effectively bypassing the rate limit and enabling high-concurrency attacks.

### 2. TOCTOU Race Condition in `/work` - [CWE-367: Time-of-Check Time-of-Use (TOCTOU) Race Condition](https://cwe.mitre.org/data/definitions/367.html)

The `/work` endpoint reads the current stud count from Redis at the beginning of the request and only increments it after a successful (and slow) signature verification.

```python
studs = r.get(uid)                      # (1) Read current count
payload = str(studs) + '|' + uid
# ... slow uov.verify(payload, sig) ... # (2) Large window (~2.5s)
if verified:
    studs = r.incr(uid)                 # (3) Increment count
```

Because verification takes several seconds, multiple concurrent requests can all read the same `studs` value (e.g., `2`), verify their respective signatures for the same payload (`"2|uid"`), and then all trigger the increment. This allows jumping from 2 studs to 8 studs (one increment per successful clone) in a single race window.

### 3. UOV Frobenius Signature Cloning - [CWE-327: Use of a Broken or Risky Cryptographic Algorithm](https://cwe.mitre.org/data/definitions/327.html)

**Verification equation.** The UOV public key consists of $m = 57$ matrices $P\_1, \ldots, P\_m \in \mathbb{F}\_{2^7}^{n \times n}$ (where $n = 254$). To verify a signature $\mathbf{x} \in \mathbb{F}\_{2^7}^n$ against a message, the verifier checks:

$$
\mathbf{x}^\top P\_i \, \mathbf{x} = t\_i \quad \text{for all } i = 1, \ldots, m
$$

where each target $t\_i \in \{0, 1\}$ is a bit extracted from the message hash (via SHAKE-128).

**The weak parameterization.** In this implementation, the public key matrices are constructed such that all entries $(P\_i)\_{jk} \in \mathbb{F}\_2 \subseteq \mathbb{F}\_{2^7}$ — i.e., every coefficient is either 0 or 1. This is the root cause of the vulnerability. To see why, recall that the public key is derived from the private key as $P\_i = T^\top F\_i T$, where $T$ is the secret invertible linear transformation and $F\_i$ are the "central maps." In a secure UOV instantiation, both $T$ and the central maps should have entries drawn uniformly from $\mathbb{F}\_{2^7}$. Here, however, both were generated with entries restricted to $\mathbb{F}\_2$ (i.e., $T \in \mathrm{GL}(n, \mathbb{F}\_2)$ and each $F\_i$ has binary entries). Since the product of matrices with entries in $\mathbb{F}\_2$ remains in $\mathbb{F}\_2$ regardless of the ambient field, the public key matrices $P\_i$ inherit this restriction. This can be confirmed empirically by inspecting the loaded key:

```python
pk = load('public_key')
vals = set(e.to_integer() for P in pk for e in P.list())
print(vals)  # {0, 1}
```

A corner of $P\_1$ illustrates the point — every entry is 0 or 1, even though the ambient field is $\mathbb{F}\_{2^7}$:

```
[1 0 1 1 1 1 0 1 0 1 0 0]
[0 0 1 0 0 1 0 1 0 1 1 1]
[0 0 0 1 0 0 0 0 0 0 0 1]
[1 1 1 0 1 0 1 0 0 0 0 0]
[0 0 0 0 1 0 1 1 0 0 0 1]
[1 1 1 1 0 1 0 1 1 1 1 0]
[0 1 0 1 1 0 1 0 0 0 1 1]
[0 1 1 0 1 0 1 0 0 0 0 0]
```

**The Frobenius automorphism.** The map $\sigma : \mathbb{F}\_{2^7} \to \mathbb{F}\_{2^7}$ defined by $\sigma(a) = a^2$ is a field automorphism (the Frobenius). Being a ring homomorphism, it satisfies $\sigma(a + b) = \sigma(a) + \sigma(b)$ and $\sigma(ab) = \sigma(a)\sigma(b)$. Applied componentwise to a vector, $\sigma(\mathbf{x})\_j = x\_j^2$.

**Why $\sigma(\mathbf{x})$ is also a valid signature.** Expanding the quadratic form for the cloned vector $\sigma(\mathbf{x})$:

$$
\sigma(\mathbf{x})^\top P\_i \, \sigma(\mathbf{x}) = \sum\_{j,k} x\_j^2 \cdot (P\_i)\_{jk} \cdot x\_k^2
$$

Since $(P\_i)\_{jk} \in \mathbb{F}\_2$, it is fixed by $\sigma$, so $(P\_i)\_{jk}^2 = (P\_i)\_{jk}$. Using multiplicativity of $\sigma$:

$$
= \sum\_{j,k} \sigma\!\left(x\_j \cdot (P\_i)\_{jk} \cdot x\_k\right) = \sigma\!\left(\sum\_{j,k} x\_j \cdot (P\_i)\_{jk} \cdot x\_k\right) = \sigma\!\left(\mathbf{x}^\top P\_i \, \mathbf{x}\right) = \sigma(t\_i) = t\_i
$$

The last step holds because $t\_i \in \mathbb{F}\_2$ is also fixed by $\sigma$. Therefore $\sigma(\mathbf{x})$ satisfies all $m$ verification equations for the same message.

**The orbit.** The Frobenius generates the Galois group $\text{Gal}(\mathbb{F}\_{2^7}/\mathbb{F}\_2) \cong \mathbb{Z}/7\mathbb{Z}$, so $\sigma^7 = \text{id}$. For a generic signature $\mathbf{x}$ (one whose components are not all in $\mathbb{F}\_2$), the orbit $\{\mathbf{x},\, \sigma(\mathbf{x}),\, \sigma^2(\mathbf{x}),\, \ldots,\, \sigma^6(\mathbf{x})\}$ has exactly 7 distinct elements, yielding **6 additional valid signatures** from a single observed one.

## Exploitation

The exploit is implemented in `solve.py` and follows these steps:

1. **Preparation**: Create a user session by calling `GET /` (which allocates a fresh `uid` in Redis), then obtain `sig_2` — the server-issued signature for `"2|uid"` — by advancing from 0 to 2 studs.

```python
uid = re.search(r"uid is ([0-9a-f]+)", requests.get(f"{BASE_URL}/?x={time.time()}").text).group(1)

def buy():
    return re.search(r"signature: ([0-9a-f]+)", requests.get(f"{BASE_URL}/buy", params={"uid": uid, "x": time.time()}).text).group(1)

def work(sig):
    return re.search(r"stud is ([0-9a-f]+)", requests.post(f"{BASE_URL}/work?x={time.time()}", json={"uid": uid, "sig": sig}).text).group(1)

sig_2 = work(work(buy()))
```

2. **Signature Cloning**: Compute 6 Frobenius variants of `sig_2` by applying $\sigma$ componentwise — squaring each byte of the signature in $\mathbb{F}\_{2^7}$.

`gf2_7_square` computes $a^2 \bmod (x^7 + x + 1)$ for a single field element $a$, represented as a 7-bit integer. It uses the standard shift-and-accumulate method for polynomial multiplication in $\mathbb{F}\_2[x]$: `b` is initialised to a copy of `a` and serves as the multiplier — the loop iterates over `b`'s 7 bits, and for each set bit XORs the current value of `a` (the multiplicand, being doubled each step) into the accumulator `p`. After each bit, `a` is shifted left by one (equivalent to multiplying by $x$) and reduced modulo $x^7 + x + 1$ if the degree-7 term would overflow — the `hi` bit detects this overflow and the `^= 0x03` applies the reduction $x^7 \equiv x + 1$, i.e., XORs the low two bits.

```python
def gf2_7_square(a: int) -> int:
    p, b = 0, a
    for _ in range(7):
        if b & 1: p ^= a   # if current bit of b is set, accumulate current a into p
        b >>= 1             # advance to next bit
        hi = a >> 6         # detect if next shift will overflow 7 bits
        a = (a << 1) & 0x7F # shift a left (multiply by x), mask to 7 bits
        if hi: a ^= 0x03    # reduce: x^7 ≡ x + 1, so XOR 0b0000011
    return p
```

`frob` applies `gf2_7_square` to every byte of the signature `n` times in succession, collecting each intermediate result. `variants[0]` is $\sigma(\mathbf{x})$, `variants[1]` is $\sigma^2(\mathbf{x})$, and so on up to `variants[6]` = $\sigma^7(\mathbf{x}) = \mathbf{x}$.

```python
def frob(sig_hex: str, n: int) -> list[str]:
    variants, cur = [], bytes.fromhex(sig_hex)
    for _ in range(n):
        cur = bytes(gf2_7_square(b) for b in cur)  # apply σ to every byte
        variants.append(cur.hex())
    return variants[:-1] # skip the last one since σ^7 = σ^0

clones = frob(sig_2, 7)  # 6 Frobenius clones: σ^1(sig_2) … σ^6(sig_2)
```

3. **The Race**: Submit all 6 cloned signatures concurrently. Each request uses a unique `?x=` parameter to bypass HAProxy. Because the clones are not cached, every request enters the slow verification path (~1-2 s). The `b'-'` placeholder in Redis only blocks re-submission of the *same* signature; since all 6 clones are distinct, they race in parallel without blocking each other. All 6 requests read `studs = 2` from Redis before any verification completes.

```python
async def race(uid: str, sigs: list[str]):
    async def post(i, sig):
        async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(force_close=True)) as s:
            async with s.post(f"{BASE_URL}/work?x={i}", json={"uid": uid, "sig": sig}, timeout=TIMEOUT) as r:
                return await r.text()
    await asyncio.gather(*(post(i, sig) for i, sig in enumerate(sigs)))

asyncio.run(race(uid, clones))
```

4. **Completion**: Once all verifications finish, each successful request calls `r.incr(uid)`, advancing the stud count from 2 to at least 7. The attacker then calls `/buy` to retrieve the flag.

## Remediation

1. **Secure Rate Limiting**: Configure HAProxy to track request rates by `path` or `src` (IP address) rather than the full `url` to prevent query-parameter-based bypasses.
2. **Atomic State Updates**: Use atomic Redis operations or Lua scripts to ensure that the "read-verify-increment" cycle is protected against race conditions. For example, use a lock or check that the stud count hasn't changed before incrementing.
3. **Proper UOV Parameterization**: Ensure that the secret linear transformation $T$ (and consequently the public key) is chosen with entries from the full extension field $\mathbb{F}\_{2^7}$ rather than being restricted to the subfield $\mathbb{F}\_2$. This breaks the Frobenius symmetry.
