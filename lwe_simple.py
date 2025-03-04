from fpylll import IntegerMatrix, LLL
import numpy as np

# Define modulus, secret vector, and public key components
q = 19
s = np.array([5, 8, 12])  # Secret vector
a_matrix = np.array([
    [2, 7, 4],
    [6, 3, 5],
    [1, 4, 9],
    [8, 2, 6],
    [7, 1, 3],
    [5, 3, 2]
])

# Generate random noise 0, -1, or 1
noise = np.array([np.random.choice([-1, 0, 1]) for _ in range(a_matrix.shape[0])])
b_vector = ((a_matrix @ s) + noise) % q

print("b_vector:", b_vector)

# Implementing the primal attack using LLL
n = s.size  # Dimension of the secret vector
m = a_matrix.shape[0]  # Number of samples

# Construct the basis matrix B
B = np.zeros((n + m, n + m))
B[0:n, 0:n] = q * np.identity(n)
B[n:, 0:n] = a_matrix
B[n:, n:] = q * np.identity(m)

# Convert B to an integer matrix suitable for LLL
B_lll = IntegerMatrix.from_matrix(B.tolist())

# Apply LLL reduction
LLL.reduction(B_lll)

# Extract the reduced basis
B_reduced = np.array(B_lll)
print("\nReduced Basis:")
print(B_reduced)

# Attempt to find the secret vector from the reduced basis
# Compare the reduced basis vectors to the vector [s, e]
e = noise  # Error vector
se_vector = np.concatenate((s, e))

# Since LLL might return a scalar multiple, check for scaled versions
found = False
for i in range(B_reduced.shape[0]):
    basis_vector = B_reduced[i]
    # Normalize the basis vector for comparison
    gcd = np.gcd.reduce(basis_vector.astype(int))
    normalized_vector = basis_vector / gcd if gcd != 0 else basis_vector
    if np.allclose(normalized_vector, se_vector):
        print("\nSecret vector found in the reduced basis (up to scaling factor):")
        print("Basis vector index:", i)
        print("Basis vector:", basis_vector)
        found = True
        break

if not found:
    print("\nSecret vector not found directly in the reduced basis.")
