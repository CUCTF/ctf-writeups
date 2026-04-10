# ClusterRSA

## Summary

Challenge description: A message has been encrypted using RSA, but this time something feels... more crowded than usual.

We find that the modulus is a multi-prime RSA modulus:

$$
n = p_1 \cdot p_2 \cdot \dots \cdot p_n
$$

The key observation is not just that there are more than two prime factors, but that they are all extremely close to one another. For a modulus with $k$ factors, that makes a targeted search around $\sqrt[k]{n}$ more effective than a general-purpose factoring algorithm.

**Artifacts:**

- `message.txt`: provided RSA parameters
- `solve.py`: script to factor the modulus and decrypt the ciphertext

## Context

The challenge provides the usual RSA values:

- `n`: the modulus
- `e`: the public exponent
- `ct`: the ciphertext

## Vulnerability

RSA security depends on the hardness of factoring $n$. In standard RSA, the modulus is:

$$
n = pq
$$

for two large primes. However, the hint about RSA being "more crowded than usual" suggests multi-prime RSA rather than the standard two-prime construction. In fact, we find the modulus instead has four prime factors:

$$
n = p q r s
$$

That already makes factorization easier, because for a modulus of the same overall size, each prime factor is smaller than it would be in ordinary two-prime RSA.

However, there is a second weakness: the four primes are also tightly clustered in value rather than being spread independently across their bit range. Consequentally, they are all very close to $n^{1/4}$.

So instead of treating factorization as a fully generic problem, we can search a narrow interval around the expected factor size and test divisibility directly.

Once the primes are known, the rest is standard RSA math. For two primes:

$$
\varphi(pq) = (p-1)(q-1)
$$

For four primes, we use multiplicativity of Euler's totient over coprime factors. Let:

$$
n_1 = pq, \quad n_2 = rs
$$

Then:

$$
\varphi(n_1) = (p-1)(q-1), \quad \varphi(n_2) = (r-1)(s-1)
$$

and because $n_1$ and $n_2$ are coprime:

$$
\varphi(n_1 n_2) = \varphi(n_1)\varphi(n_2)
$$

So for a 4-prime modulus:

$$
\varphi(n) = (p-1)(q-1)(r-1)(s-1)
$$

and the private exponent is:

$$
d \equiv e^{-1} \pmod{\varphi(n)}
$$

This challenge is vulnerable both because it uses multi-prime RSA and because those factors were generated in an unusually tight cluster. This would fall under [CWE-327: Use of a Broken or Risky Cryptographic Algorithm](https://cwe.mitre.org/data/definitions/327.html).

## Exploitation

The solver in [solve.py](/Users/nassa/Desktop/ctf-writeups/picoctf/crypto/ClusterRSA/solve.py) uses a root-guided clustered-prime search to efficiently factorize the modulus $n$.

### 1. Guess the number of factors and estimate their size

If `n` is the product of $k$ similarly sized primes, each factor should be close to $n^{\frac{1}{k}}$. The script starts with $k=3$ and increases it until the recovered divisors multiply back to $n$.

```python
def factor_modulus(modulus):
    factor_count = 3
    while True:
        try:
            print_progress(CLUSTER_SPAN, factor_count)
            factors = sorted(factor_from_cluster(modulus, factor_count))
            product = 1
            for factor in factors:
                product *= factor
            if product == modulus:
                return factors
        except ValueError:
            pass

        root, _ = gmpy2.iroot(modulus, factor_count)
        if root <= 3:
            break

        factor_count += 1
```

### 2. Search for prime divisors near the kth root

For each candidate $k$, the solver computes the root $\lceil n^{\frac{1}{4}} \rceil$ then scans odd numbers in a window `root - CLUSTER_SPAN` to `root + CLUSTER_SPAN` to find prime divisors of $n$.

```python
def factor_from_cluster(modulus, factor_count):
    root, exact = gmpy2.iroot(modulus, factor_count)
    if not exact:
        root += 1
    start = root - CLUSTER_SPAN
    end = root + CLUSTER_SPAN

    if start < 3:
        start = 3
    if start % 2 == 0:
        start += 1

    factors = []
    candidate = start
    while candidate <= end:
        if gmpy2.is_prime(candidate) and modulus % candidate == 0:
            factors.append(int(candidate))
            if len(factors) == factor_count:
                return factors
        candidate += 2
```

### 3. Expand the window until the full cluster is covered

The search starts at `+/-1000` and doubles the span until it succeeds or reaches the maximum configured bound.

```python
def factor_modulus_with_expanding_span(modulus, initial_span, max_span, growth_factor):
    span = initial_span

    while span <= max_span:
        global CLUSTER_SPAN
        CLUSTER_SPAN = span

        try:
            return factor_modulus(modulus)
        except ValueError:
            if span == max_span:
                break

            next_span = min(max_span, max(span + 1, span * growth_factor))
            span = next_span
```

### 4. Compute the private key and decrypt

Once the factors are known, the script computes the totient, inverts $e$, and decrypts normally.

```python
phi = 1
for prime in factors:
    phi *= prime - 1

d = pow(e, -1, phi)
plaintext = pow(ct, d, n)
```

## Remediation

Do not generate RSA moduli from more than two primes if your modulus size must remain constant, and ensure your randomly generated primes are not unnaturally close to one-another.
