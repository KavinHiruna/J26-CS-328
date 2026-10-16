
from pathlib import Path
import json
import time

import numpy as np
import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import GroupShuffleSplit
from sklearn.pipeline import Pipeline

PROJECT_DIR = Path(__file__).resolve().parent.parent
DATA_FILE = PROJECT_DIR / "data" / "edgeiiot_ml.csv"
FEATURE_FILE = PROJECT_DIR / "outputs" / "selected_ml_features.csv"
OUTPUT_DIR = PROJECT_DIR / "outputs"

SEED = 42
OUTPUT_DIR.mkdir(exist_ok=True)

print("STEP 1: Loading dataset and selected features")

df = pd.read_csv(DATA_FILE, low_memory=False)
features = pd.read_csv(FEATURE_FILE)["feature"].tolist()

X = df[features].apply(pd.to_numeric, errors="coerce")
y = df["Attack_type"].astype(str)

# Use identical feature vectors as groups.
# Missing values are filled with a common marker for grouping only.
group_frame = X.fillna("__MISSING__")
groups = pd.util.hash_pandas_object(
    group_frame, index=False
).to_numpy()

print("Records:", len(df))
print("Features:", len(features))
print("Attack classes:", y.nunique())
print("Unique feature groups:", len(np.unique(groups)))

print("\nSTEP 2: Creating grouped train/test split")

splitter = GroupShuffleSplit(
    n_splits=1,
    test_size=0.20,
    random_state=SEED,
)

train_idx, test_idx = next(
    splitter.split(X, y, groups=groups)
)

X_train, X_test = X.iloc[train_idx], X.iloc[test_idx]
y_train, y_test = y.iloc[train_idx], y.iloc[test_idx]

print("Training records:", len(train_idx))
print("Testing records:", len(test_idx))
print("Training classes:", y_train.nunique())
print("Testing classes:", y_test.nunique())

train_classes = set(y_train)
test_classes = set(y_test)
all_classes = set(y)

print("Classes missing from test:", sorted(all_classes - test_classes))
print("Classes missing from train:", sorted(all_classes - train_classes))

print("\nSTEP 3: Training model")

model = Pipeline([
    ("imputer", SimpleImputer(strategy="median")),
    ("classifier", RandomForestClassifier(
        n_estimators=100,
        random_state=SEED,
        n_jobs=-1,
        class_weight="balanced",
    )),
])

start = time.perf_counter()
model.fit(X_train, y_train)
training_seconds = time.perf_counter() - start

print(f"Training time: {training_seconds:.2f} seconds")

print("\nSTEP 4: Evaluating grouped hold-out")

predictions = model.predict(X_test)

metrics = {
    "validation": "GroupShuffleSplit by identical feature vector",
    "random_seed": SEED,
    "dataset_records": int(len(df)),
    "training_records": int(len(train_idx)),
    "testing_records": int(len(test_idx)),
    "feature_count": int(len(features)),
    "all_classes": sorted(all_classes),
    "test_classes": sorted(test_classes),
    "classes_missing_from_test": sorted(all_classes - test_classes),
    "classes_missing_from_train": sorted(all_classes - train_classes),
    "accuracy": float(accuracy_score(y_test, predictions)),
    "macro_precision": float(
        precision_score(y_test, predictions, average="macro",
                        zero_division=0)
    ),
    "macro_recall": float(
        recall_score(y_test, predictions, average="macro",
                     zero_division=0)
    ),
    "macro_f1": float(
        f1_score(y_test, predictions, average="macro",
                 zero_division=0)
    ),
    "weighted_f1": float(
        f1_score(y_test, predictions, average="weighted",
                 zero_division=0)
    ),
    "training_seconds": float(training_seconds),
}

report = classification_report(
    y_test,
    predictions,
    labels=sorted(all_classes),
    output_dict=True,
    zero_division=0,
)

metrics_path = OUTPUT_DIR / "grouped_model_metrics.json"
report_path = OUTPUT_DIR / "grouped_classification_report.csv"

with open(metrics_path, "w", encoding="utf-8") as file:
    json.dump(metrics, file, indent=4)

pd.DataFrame(report).transpose().to_csv(report_path)

print("\nGROUPED VALIDATION RESULTS")
print("=" * 45)
for key, value in metrics.items():
    print(f"{key}: {value}")

print("\nPER-CLASS REPORT")
print(classification_report(
    y_test, predictions, zero_division=0
))

print("\nSaved evidence:")
print(metrics_path)
print(report_path)
