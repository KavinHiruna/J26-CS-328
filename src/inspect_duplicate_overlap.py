
from pathlib import Path
import pandas as pd
from sklearn.model_selection import train_test_split

PROJECT_DIR = Path(__file__).resolve().parent.parent
DATA_FILE = PROJECT_DIR / "data" / "edgeiiot_ml.csv"
FEATURE_FILE = PROJECT_DIR / "outputs" / "selected_ml_features.csv"
OUTPUT_DIR = PROJECT_DIR / "outputs"

df = pd.read_csv(DATA_FILE, low_memory=False)
features = pd.read_csv(FEATURE_FILE)["feature"].tolist()

X = df[features].apply(pd.to_numeric, errors="coerce")
y = df["Attack_type"].astype(str)

train_idx, test_idx = train_test_split(
    df.index,
    test_size=0.20,
    random_state=42,
    stratify=y,
)

train = X.loc[train_idx].copy()
test = X.loc[test_idx].copy()

train["label"] = y.loc[train_idx]
test["label"] = y.loc[test_idx]

# Hash features only, excluding the label.
train_hash = pd.util.hash_pandas_object(
    train[features], index=False
)
test_hash = pd.util.hash_pandas_object(
    test[features], index=False
)

train["feature_hash"] = train_hash.values
test["feature_hash"] = test_hash.values

overlap = set(train["feature_hash"]) & set(test["feature_hash"])

train_overlap = train[train["feature_hash"].isin(overlap)]
test_overlap = test[test["feature_hash"].isin(overlap)]

train_labels = train_overlap.groupby(
    "feature_hash"
)["label"].agg(lambda values: sorted(set(values)))

test_labels = test_overlap.groupby(
    "feature_hash"
)["label"].agg(lambda values: sorted(set(values)))

comparison = pd.concat(
    [
        train_labels.rename("train_labels"),
        test_labels.rename("test_labels"),
    ],
    axis=1,
).dropna()

comparison["labels_match"] = comparison.apply(
    lambda row: row["train_labels"] == row["test_labels"],
    axis=1,
)

comparison.to_csv(
    OUTPUT_DIR / "duplicate_overlap_analysis.csv"
)

print("DUPLICATE OVERLAP ANALYSIS")
print("=" * 45)
print("Overlapping feature hashes:", len(overlap))
print(
    "Hashes with matching label sets:",
    int(comparison["labels_match"].sum()),
)
print(
    "Hashes with different label sets:",
    int((~comparison["labels_match"]).sum()),
)
print("\nSaved evidence:")
print(OUTPUT_DIR / "duplicate_overlap_analysis.csv")
