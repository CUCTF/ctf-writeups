# Unfinished Ninjago Game

## Summary

Challenge description: "I'm writing a ninjago game, but apparently there's some crazy cheat codes someone has already found!? And apparently that's supposed to help decrypt hidden secret stuff by the Overlord?"

A 64-bit ELF binary runs as a TCP server. On each connection it seeds a 512-bit xoshiro512\*\* PRNG state with `getrandom`, XORs that state against the flag to produce a public ciphertext, then accepts commands — including an oracle that outputs a single byte `(Σ s[i]) mod 101`. Because the oracle is a linear function of the PRNG state and the ciphertext reveals `state XOR flag`, every connection yields one linear equation over $\mathbb{Z}/101\mathbb{Z}$ in the 512 flag bits. Collecting 512 such equations and solving via Gaussian elimination recovers the flag.

**Artifacts:**

- `main`: ELF 64-bit PIE x86-64 binary; the challenge server
- `PRNG.h`: source for the modified xoshiro512\*\* PRNG embedded in `main`
- `exploit.py`: Python script that implements the attack

## Context

### PRNG

`PRNG.h` implements a modified [xoshiro512\*\*](https://prng.di.unimi.it/) generator. The state is eight 64-bit words `s[0..7]` (512 bits total), seeded fresh by `getrandom` on each TCP connection. The file defines 32 precomputed **jump functions** (`jump0`, `jump16`, …, `jump496`) that advance the state by $2^n$ steps for $n = 0, 16, 32, \ldots, 496$ without iterating through all intermediate `next()` calls. A comment in the file hints at a planned-but-unimplemented feature:

```c
// TODO: write short code to compute pow(x, n, char_poly(next)) for arbitrary n
```

This is a red herring; the intended exploit does not require computing arbitrary jumps.

### Binary Analysis

Reversing `main` with Ghidra reveals five key functions (`main` at `0x0010a440`, `load` at `0x0010a0f8`, `explore_middle` at `0x0010a235`, `explore_right` at `0x0010a711`, `explore_left` at `0x0010a4c3`).

**`main`** seeds the global PRNG state `s[0..7]` with `getrandom`, calls `load()`, then gates `explore_right()` on `errno`. The `remove("flag.txt")` call inside `load()` always fails with `EACCES` — the server runs as an unprivileged `ctf` user and cannot write to the root-owned `/ctf` directory. This non-zero `errno` is what makes `explore_right()` reachable:

```c
int main(void) {
    errno = 0;
    if (getrandom(s, 64, 0) != 64) return -1;  // seed 512-bit state
    load();
    if (errno == 0) return -1;  // remove() always fails → errno always set → explore_right reachable
    explore_right();
    return 0;
}
```

**`load()`** reads `flag.txt` into a stack buffer, XORs each 64-bit word with the seeded PRNG state, and prints the ciphertext. The buffer is pre-filled by a `getrandom` call before being overwritten by the flag contents — the pre-fill is immediately discarded:

```c
void load(void) {
    setbuf(stdout, NULL);
    uint64_t buf[8] = {0};
    if (getrandom(buf, 64, 0) != 64) return;  // pre-fill discarded; only checks syscall success
    int fd = open("flag.txt", O_CREAT|O_RDONLY, 0644);  // 0x40 = O_CREAT; opens existing file read-only
    read(fd, buf, 64);    // overwrites buf with flag bytes
    close(fd);
    for (int i = 0; i < 8; i++) {
        printf("%llu ", buf[i] ^ s[i]);  // ct[i] = flag_word[i] XOR s[i]
        buf[i] = 0;                       // wipe from stack
    }
    putc('\n', stdout);
    remove("flag.txt");  // always fails (EACCES) — sets errno, keeps flag.txt for the next connection
}
```

The flag is treated as eight little-endian `uint64` words. The PRNG state is **never advanced** between the `getrandom` seed and the XOR — `s[i]` in the XOR is exactly the freshly seeded value.

**`explore_middle()`** — the oracle — outputs a single byte. Ghidra shows the compiler emits per-element reductions mod 101 before summing, rather than summing all eight words first; the two forms are algebraically identical:

```c
void explore_middle(void) {
    uint64_t sum = s[0]%101 + s[1]%101 + s[2]%101 + s[3]%101
                 + s[4]%101 + s[5]%101 + s[6]%101 + s[7]%101;
    putc((int)(sum % 101), stdout);
}
```

**`explore_right()`** and **`explore_left()`** are a pair of mutually recursive command loops sharing the same command set:

| Input     | Action                                                                                         |
| --------- | ---------------------------------------------------------------------------------------------- |
| `e`       | exit                                                                                           |
| `m`       | call `explore_middle()` — the oracle                                                           |
| `a`       | advance PRNG with a randomly chosen jump (random nibble from `getrandom`; not user-controlled) |
| `s`       | set global pointer `d` to a local stack address                                                |
| `w`       | write one `getc` byte via `d` (out-of-bounds write, but cannot reach the stack canary)        |
| `r` / `l` | recurse into `explore_right` / `explore_left`                                                  |

The two functions differ only in which jump functions their `'a'` command dispatches. For `'a'`, both functions call `getrandom(&byte, 1, 0)`, mask to the lower nibble, and index into a fixed table: `explore_right` selects from `jump0`–`jump240` (nibble × 16) while `explore_left` selects from `jump256`–`jump496` ((nibble × 16) + 256). Together they cover all 32 jump functions. Nibble 0xf in either function executes the highest jump in its range and loops back to re-read, effectively retrying until a nibble below 0xf is drawn. The jump choice is entirely server-side and uncontrollable by the attacker.

The critical observation: if `'m'` is sent **before** any `'a'` commands, `explore_middle()` sees the original seeded state — the same state used to XOR the flag in `load()`.

## Vulnerability

Because the attacker knows $\text{ct}[i] = s[i] \oplus \text{flag}[i]$ and the oracle $O = \left(\sum_{i=0}^{7} s_i\right) \bmod 101$, all the information needed to recover the flag is present in each connection — it just needs to be extracted algebraically.

### Bit-level decomposition

Index the 512 flag bits as $j = 0, 1, \ldots, 511$, where bit $j$ belongs to word $\lfloor j/64 \rfloor$ at bit position $j \bmod 64$. Let:

- $b_j = \text{bit}_j(\text{ct})$ — the corresponding ciphertext bit (known)
- $x_j = \text{bit}_j(\text{flag})$ — the flag bit (unknown)

Since XOR is bitwise addition mod 2, $\text{bit}_j(s) = b_j \oplus x_j$. As integers:

$$
b_j \oplus x_j = b_j + x_j - 2 b_j x_j
$$

Substituting into the oracle (where bit $j$ contributes weight $2^{j \bmod 64}$ to its word):

$$
O = \sum_{j=0}^{511} 2^{j \bmod 64} \cdot (b_j + x_j - 2 b_j x_j) \pmod{101}
$$

$$
O - \underbrace{\sum_{j=0}^{511} 2^{j \bmod 64} \cdot b_j}_{\displaystyle=\;\sum_{i=0}^{7} \text{ct}_i \pmod{101}} \;\equiv\; \sum_{j=0}^{511} \underbrace{(1 - 2b_j) \cdot 2^{j \bmod 64}}_{\displaystyle H_j} \cdot x_j \pmod{101}
$$

### Linear system

Defining:

$$
h \;=\; \left(O - \sum_{i=0}^{7} \text{ct}_i\right) \bmod 101 \qquad H_j \;=\; (1 - 2b_j) \cdot 2^{j \bmod 64} \bmod 101
$$

every connection yields one linear equation $\sum_j H_j x_j \equiv h \pmod{101}$, with known coefficients determined by that connection's ciphertext and oracle reading. Because 101 is prime, $\mathbb{Z}/101\mathbb{Z}$ is a field. With 512 fresh connections producing linearly independent equations (guaranteed with overwhelming probability because the ciphertexts are independently random), the $512 \times 512$ system has a **unique solution** over $\mathbb{Z}/101\mathbb{Z}$. Since the unknowns $x_j$ are flag bits in $\{0, 1\} \subset \mathbb{Z}/101\mathbb{Z}$, the unique field solution equals the true bit values.

This vulnerability falls under [CWE-338: Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)](https://cwe.mitre.org/data/definitions/338.html). xoshiro512\*\* is a high-quality statistical PRNG, but it is not a CSPRNG — its output is not computationally indistinguishable from random, and the linear structure of its state update is precisely what makes the oracle attack tractable.

## Exploitation

The below steps are implemented in [exploit.py](./exploit.py).

### 1. Collect (ciphertext, oracle) pairs

Open 20 parallel TCP connections. For each connection, read the eight ciphertext words and send `'m'` immediately (before any `'a'` commands, so the PRNG state is still the freshly seeded value), then read the oracle byte.

```python
def query():
    s = socket.socket()
    s.settimeout(15)
    try:
        s.connect((HOST, PORT))
        data = b""
        while b"\n" not in data:
            data += s.recv(4096)
        ct = [int(x) for x in data.split(b"\n")[0].split()]
        s.sendall(b"m")
        oracle = s.recv(1)[0]
        s.sendall(b"e")
        return ct, oracle
    finally:
        s.close()
```

Worker threads run `query()` in a loop and push results onto a shared queue. The main thread reads from the queue until 560 samples are collected (48 extra beyond 512 as a safety margin for rank deficiency).

### 2. Build the linear system

Translate each `(ct, oracle)` pair into a row of the matrix $H$ and the right-hand side vector $h$ over $\mathbb{Z}/101\mathbb{Z}$.

The ciphertext words are unsigned 64-bit integers and can exceed `int64` range, so Python's arbitrary-precision integers handle the modular arithmetic in $h$ rather than NumPy (which would silently overflow):

```python
def build_system(samples):
    n = len(samples)
    H = np.zeros((n, N_BITS), dtype=np.int64)
    h = np.zeros(n, dtype=np.int64)
    for i, (ct, oracle) in enumerate(samples):
        h[i] = (oracle - sum(c % MOD for c in ct)) % MOD  # Python int: safe for uint64
        for j in range(N_BITS):
            ct_bit = (ct[j // 64] >> (j % 64)) & 1
            H[i, j] = (1 - 2 * ct_bit) * POW2[j] % MOD
    return H, h
```

`POW2[j] = pow(2, j % 64, 101)` is precomputed once at module load.

### 3. Solve via RREF over $\mathbb{Z}/101\mathbb{Z}$

Gaussian elimination (reduced row echelon form) is performed on the augmented matrix $[H \mid h]$. For each pivot column the pivot row is scaled so the leading entry becomes 1 (using Fermat's little theorem: $a^{-1} \equiv a^{99} \pmod{101}$), then that column is eliminated from every other row simultaneously using NumPy vectorised operations.

```python
def rref_mod_p(A, b, p):
    M = np.hstack([A % p, (b % p).reshape(-1, 1)]).astype(np.int64)
    pivots, r = [], 0
    for col in range(A.shape[1]):
        nz = np.nonzero(M[r:, col] % p)[0]
        if not len(nz):
            continue
        M[[r, r + nz[0]]] = M[[r + nz[0], r]]
        M[r] = M[r] * pow(int(M[r, col]), p - 2, p) % p
        mask = (M[:, col] % p != 0)
        mask[r] = False
        M[mask] = (M[mask] - M[mask, col:col+1] * M[r]) % p
        pivots.append(col)
        r += 1
        if r >= M.shape[0]:
            break
    return M, pivots
```

After RREF, the solution vector is read from the last column: `x[col] = M[i, 512]` for each pivot `(i, col)`.

### 4. Reconstruct the flag

The 512 recovered bits are packed back into 64 bytes. Bit $j$ lands at byte $\lfloor j/8 \rfloor$ at bit position $j \bmod 8$, following directly from the little-endian layout of the eight `uint64` flag words.

```python
def reconstruct_flag(x):
    flag = bytearray(64)
    for j in range(N_BITS):
        flag[j // 8] |= x[j] << (j % 8)
    return bytes(flag)
```

```
Collecting 560 samples (20 threads)...
    100/560  (616 q/s)
    200/560  (547 q/s)
    300/560  (611 q/s)
    400/560  (638 q/s)
    500/560  (669 q/s)
Collected 560 samples in 0.8s
Building 560×512 matrix over Z/101Z...
Solving via RREF...

Flag: UMASS{sparse_fourier_transforms_are_so_much_fun!fhwtftw!yayayay}
```

## Remediation

The root cause is that the oracle `(Σ s[i]) mod 101` leaks a linear combination of the PRNG state, and because each connection re-seeds the PRNG independently while broadcasting `state XOR flag` as the ciphertext, an attacker accumulates enough linear equations to fully determine the secret state. Two concrete fixes:

1. **Use a larger modulus.** A modulus of 101 means the coefficient field has only 101 elements, keeping the linear system small and tractable. A 64-bit prime modulus (or the full 64-bit sum output) would require far more oracle queries per flag bit.
2. **Do not expose a linear oracle over freshly seeded states alongside a known ciphertext.** The attack requires both a known linear function of the state (`ct[i] = s[i] XOR flag[i]`) and a second independent linear function of the same state (the oracle). Removing either — suppressing the ciphertext, hiding the oracle, or introducing non-linearity such as hashing the state before output — breaks the attack entirely.
