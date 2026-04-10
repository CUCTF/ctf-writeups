#!/usr/bin/env python3
import gmpy2

n = gmpy2.mpz(
    8749002899132047699790752490331099938058737706735201354674975134719667510377522805717156720453193651
)
e = 65537
ct = gmpy2.mpz(
    3021569373773402689513257373362764131880473249842187164838297943840513930619586623604677697191914325
)
INITIAL_CLUSTER_SPAN = 1_000
MAX_CLUSTER_SPAN = 1_000_000
CLUSTER_GROWTH_FACTOR = 2


def decode_int(value):
    byte_len = max(1, (value.bit_length() + 7) // 8)
    return int(value).to_bytes(byte_len, "big").decode()


def print_progress(span, factor_count):
    print(
        f"\rSearching clustered primes within +/-{span} | Trying {factor_count} prime factors...",
        end="",
    )


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

    raise ValueError(
        f"failed to recover {factor_count} clustered primes within +/-{CLUSTER_SPAN}"
    )


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

    raise ValueError(
        f"clustered prime factorization unsuccessful within +/-{CLUSTER_SPAN}"
    )


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

    raise ValueError(
        f"failed to recover clustered primes after expanding to +/-{max_span}"
    )


def main():
    factors = factor_modulus_with_expanding_span(
        n,
        initial_span=INITIAL_CLUSTER_SPAN,
        max_span=MAX_CLUSTER_SPAN,
        growth_factor=CLUSTER_GROWTH_FACTOR,
    )

    phi = 1
    for prime in factors:
        phi *= prime - 1

    d = pow(e, -1, phi)
    plaintext = pow(ct, d, n)

    print(f"\nfactors: {factors}")
    print(f"flag: {decode_int(plaintext)}")


if __name__ == "__main__":
    main()
