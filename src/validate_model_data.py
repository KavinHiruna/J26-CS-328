
from pathlib import Path
import pandas as pd

from sklearn.model_selection import train_test_split

PROJECT_DIR = Path(__file__).resolve().parent.parent
DATA_FILE = PROJECT_DIR / "data" / "edgeiiot_ml.csv"
FEATURE_FILE = PROJECT_DIR / "outputs" / "selected_ml_features.csv"
OUTPUT_DIR = PROJECT_DIR / "outputs"
OUTPUT_DIR.mkdir(exist_ok=True)

print("Loading dataset and selected features...")

df = pd.read_csv(DATA_FILE, low_memory=False)
features = pd.read_csv(FEATURE_FILE)["feature"].tolist()

X = df[features].apply(pd.to_numeric, errors="coerce")
y = df["Attack_type"].astype(str)

# Reproduce the original experiment's split.
train_idx, test_idx = train_test_split(
    df.index,
    test_size=0.20,
    random_state=42,
    stratify=y,
)

X_train = X.loc[train_idx].copy()
X_test = X.loc[test_idx].copy()
y_train = y.loc[train_idx]
y_test = y.loc[test_idx]

# Hash feature rows to identify identical feature vectors.
train_hash = pd.util.hash_pandas_object(
    X_train, index=False
)
test_hash = pd.util.hash_pandas_object(
    X_test, index=False
)

train_hashes = set(train_hash.tolist())
test_hashes = set(test_hash.tolist())

overlap_hashes = train_hashes.intersection(test_hashes)

# Exact feature duplicates anywhere in the dataset.
feature_duplicate_rows = int(X.duplicated().sum())

# Exact feature duplicates with different attack labels.
label_check = pd.DataFrame({
    "feature_hash": pd.util.hash_pandas_object(
        X, index=False
    ).values,
    "attack_type": y.values,
})

labels_per_vector = label_check.groupby(
    "feature_hash"
)["attack_type"].nunique()

conflicting_vectors = int(
    (labels_per_vector > 1).sum()
)

results = {
    "total_records": len(df),
    "training_records": len(train_idx),
    "testing_records": len(test_idx),
    "duplicate_feature_rows_full_dataset": feature_duplicate_rows,
    "unique_feature_hashes_training": len(train_hashes),
    "unique_feature_hashes_testing": len(test_hashes),
    "overlapping_feature_hashes_train_test": len(overlap_hashes),
    "feature_vectors_with_conflicting_labels": conflicting_vectors,
}

report_file = OUTPUT_DIR / "model_data_validation.txt"

with open(report_file, "w", encoding="utf-8") as file:
    for name, value in results.items():
        file.write(f"{name}: {value}\n")

print("\nDATA VALIDATION RESULTS")
print("=" * 50)

for name, value in results.items():
    print(f"{name}: {value}")

print("\nSaved evidence:")
print(report_file)

print(
    "\nNote: hash matches identify candidate identical feature "
    "vectors. They are a diagnostic, not proof of leakage."
)
