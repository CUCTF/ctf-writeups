A = 134775813
13476378
C = 1337
M = 2147483648

def mod_inverse(a, m):
    """Find the modular multiplicative inverse of a under modulo m."""
    m0, x0, x1 = m, 0, 1
    if m == 1:
        return 0
    while a > 1:
        # q is quotient
        q = a // m
        t = m
        # m is remainder now, process same as Euclid's algorithm
        m = a % m
        a = t
        t = x0
        x0 = x1 - q * x0
        x1 = t
    if x1 < 0:
        x1 += m0
    return x1
def find_state_for_lower_200():
    """Find states that map to values <= 1000 using modular arithmetic."""
    states = {}
    A_inv = mod_inverse(A, M)  # Find the modular inverse of A mod M
    for mapped_value in range(1001):  # Only check values <= 1000
        potential_state = (A_inv * (mapped_value - C)) % M
        if mapped_value not in states:
            states[mapped_value] = []
        states[mapped_value] = potential_state
    return states
# states = find_state_for_lower_200()


mask = 2**6 - 1
state = 0
states = find_state_for_lower_200()

def lcg(state):
    """Linear Congruential Generator function."""
    return (A * state + C) % M

# Generate a sequence of numbers using the LCG starting at 0
sequence = []
current_state = state
for _ in range(17):  # Generate 17 numbers
    current_state = lcg(current_state)
    sequence.append(bin(current_state)[2:])  # Convert to binary and remove '0b'

# Print the binary sequence
for i, binary_value in enumerate(sequence):
    padded_value = binary_value.zfill(31)  # Pad binary value to 31 bits
    i_padded = str(i).zfill(2)  # Pad i to 2 digits
    print(f"{i_padded}: {padded_value}")

for i in range(100):
    print(i, states[i])
