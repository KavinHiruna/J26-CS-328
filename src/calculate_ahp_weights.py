
import numpy as np

# Factor order:
# S = Attack severity
# C = Detection confidence
# A = Asset criticality
# F = Attack frequency

factors = [
    "Attack Severity",
    "Detection Confidence",
    "Asset Criticality",
    "Attack Frequency",
]

# PROVISIONAL judgments for testing only.
# These express a proposed preference, not validated expert judgments.
# Replace them with supervisor/expert-supported comparisons before
# reporting the weights as research findings.
pairwise_matrix = np.array([
    [1,   2,   1/2, 2],
    [1/2, 1,   1/3, 1],
    [2,   3,   1,   3],
    [1/2, 1,   1/3, 1],
], dtype=float)

# Calculate the principal eigenvector
eigenvalues, eigenvectors = np.linalg.eig(pairwise_matrix)
max_index = np.argmax(eigenvalues.real)

lambda_max = eigenvalues[max_index].real
weights = eigenvectors[:, max_index].real
weights = np.abs(weights)
weights = weights / weights.sum()

# AHP consistency calculation
n = len(factors)
consistency_index = (lambda_max - n) / (n - 1)

random_index_table = {
    1: 0.00,
    2: 0.00,
    3: 0.58,
    4: 0.90,
    5: 1.12,
    6: 1.24,
    7: 1.32,
    8: 1.41,
    9: 1.45,
    10: 1.49,
}

random_index = random_index_table[n]
consistency_ratio = (
    consistency_index / random_index
    if random_index != 0
    else 0.0
)

print("AHP WEIGHT CALCULATION")
print("=" * 40)

for factor, weight in zip(factors, weights):
    print(f"{factor:25}: {weight:.4f} ({weight * 100:.2f}%)")

print(f"\nMaximum eigenvalue (lambda max): {lambda_max:.4f}")
print(f"Consistency Index (CI):         {consistency_index:.4f}")
print(f"Consistency Ratio (CR):          {consistency_ratio:.4f}")

if consistency_ratio <= 0.10:
    print("Consistency result: ACCEPTABLE for this provisional matrix")
else:
    print("Consistency result: REVIEW pairwise judgments")
