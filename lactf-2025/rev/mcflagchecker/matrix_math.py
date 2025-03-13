MOD = 251

# Shoutout to ChatGPT for this one

def mat_inv_mod_251(A):
    """
    Invert matrix A (40x40) over Z/251Z using Gaussian elimination.
    Returns the inverse matrix A_inv if it exists, otherwise raises an exception.
    """
    n = len(A)
    
    # Create an augmented matrix [A|I].
    # We'll store it in a list of lists, working mod 251.
    aug = []
    for i in range(n):
        row = A[i] + [0]*n  # copy A's row + n zeros for the identity
        row[n+i] = 1       # put 1 in the identity portion
        aug.append(row)

    # Perform Gaussian elimination
    for col in range(n):
        # 1. Find a pivot row r for this column (col) such that aug[r][col] != 0
        pivot = col
        while pivot < n and aug[pivot][col] == 0:
            pivot += 1
        if pivot == n:
            raise ValueError("Matrix is singular modulo 251.")

        # 2. Swap pivot row with current row if needed
        if pivot != col:
            aug[col], aug[pivot] = aug[pivot], aug[col]

        # 3. Normalize pivot row so that pivot element becomes 1
        inv_pivot_val = pow(aug[col][col], MOD-2, MOD)  # Fermat's little theorem
        for k in range(2*n):
            aug[col][k] = (aug[col][k] * inv_pivot_val) % MOD

        # 4. Eliminate below and above pivot
        for r in range(n):
            if r != col:
                factor = aug[r][col]
                for c2 in range(2*n):
                    aug[r][c2] = (aug[r][c2] - factor * aug[col][c2]) % MOD

    # Extract the inverse from the augmented matrix
    A_inv = []
    for i in range(n):
        A_inv.append(aug[i][n:2*n])
    return A_inv

def mat_vec_mod_251(A, v):
    """
    Multiply matrix A (nxn) by vector v (length n) modulo 251.
    Returns a vector of length n.
    """
    n = len(A)
    out = []
    for i in range(n):
        s = 0
        for j in range(n):
            s = (s + A[i][j] * v[j]) % MOD
        out.append(s)
    return out
