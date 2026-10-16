
from pathlib import Path
import json
import time

import joblib
import numpy as np
import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline

PROJECT_DIR = Path(__file__).resolve().parent.parent
DATA_FILE = PROJECT_DIR / "data" / "edgeiiot_ml.csv"
AUDIT_FILE = PROJECT_DIR / "outputs" / "ml_feature_audit.csv"
OUTPUT_DIR = PROJECT_DIR / "outputs"
MODEL_DIR = PROJECT_DIR / "models"

OUTPUT_DIR.mkdir(exist_ok=True)
MODEL_DIR.mkdir(exist_ok=True)

SEED = 42

print("STEP 1: Loading dataset and feature audit")

df = pd.read_csv(DATA_FILE, low_memory=False)
audit = pd.read_csv(AUDIT_FILE)

# Select numeric candidates with at least 95% convertible values.
# Exclude targets, timestamps and host identifiers.
excluded = {
    "Attack_label",
    "Attack_type",
    "frame.time",
    "ip.src_host",
    "ip.dst_host",
}

feature_columns = audit.loc[
    (audit["usable_numeric_candidate"])
    & (audit["numeric_values"] >= 0.95 * len(df)),
    "column",
].tolist()

feature_columns = [
    col for col in feature_columns
    if col not in excluded
]

if not feature_columns:
    raise ValueError("No suitable numeric feature candidates found.")

X = df[feature_columns].apply(
    pd.to_numeric, errors="coerce"
)

# Remove constant or entirely missing features.
feature_columns = [
    col for col in X.columns
    if X[col].notna().any() and X[col].nunique(dropna=True) > 1
]
X = X[feature_columns]

y = df["Attack_type"].astype(str)

if y.isna().any():
    raise ValueError("Target contains missing values.")

print(f"Dataset rows: {len(df):,}")
print(f"Selected features: {len(feature_columns)}")
print(f"Attack classes: {y.nunique()}")
print("Selected columns:", feature_columns)

# Reproducible stratified hold-out evaluation.
print("\nSTEP 2: Creating stratified train/test split")

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=SEED,
    stratify=y,
)

print(f"Training records: {len(X_train):,}")
print(f"Testing records: {len(X_test):,}")
print(f"Random seed: {SEED}")

# Median imputation is fitted on training data only.
model = Pipeline([
    ("imputer", SimpleImputer(strategy="median")),
    ("classifier", RandomForestClassifier(
        n_estimators=100,
        random_state=SEED,
        n_jobs=-1,
        class_weight="balanced",
    )),
])

print("\nSTEP 3: Training Random Forest")

start = time.perf_counter()
model.fit(X_train, y_train)
training_seconds = time.perf_counter() - start

print(f"Training time: {training_seconds:.2f} seconds")

print("\nSTEP 4: Evaluating on held-out test data")

start = time.perf_counter()
predictions = model.predict(X_test)
prediction_seconds = time.perf_counter() - start

metrics = {
    "model": "RandomForestClassifier",
    "target": "Attack_type",
    "dataset_rows": int(len(df)),
    "training_rows": int(len(X_train)),
    "testing_rows": int(len(X_test)),
    "feature_count": int(len(feature_columns)),
    "class_count": int(y.nunique()),
    "random_seed": SEED,
    "test_size": 0.20,
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
    "prediction_seconds": float(prediction_seconds),
}

report = classification_report(
    y_test,
    predictions,
    labels=sorted(y.unique()),
    output_dict=True,
    zero_division=0,
)

metrics_file = OUTPUT_DIR / "attack_model_metrics.json"
report_file = OUTPUT_DIR / "attack_classification_report.csv"
matrix_file = OUTPUT_DIR / "attack_confusion_matrix.csv"
features_file = OUTPUT_DIR / "selected_ml_features.csv"
model_file = MODEL_DIR / "attack_classifier.joblib"

with open(metrics_file, "w", encoding="utf-8") as file:
    json.dump(metrics, file, indent=4)

pd.DataFrame(report).transpose().to_csv(report_file)

labels = sorted(y.unique())
matrix = confusion_matrix(y_test, predictions, labels=labels)

pd.DataFrame(
    matrix,
    index=labels,
    columns=labels,
).to_csv(matrix_file)

pd.DataFrame({"feature": feature_columns}).to_csv(
    features_file, index=False
)

joblib.dump(model, model_file)

print("\nEVALUATION RESULTS")
print("=" * 45)
for key, value in metrics.items():
    print(f"{key}: {value}")

print("\nPER-CLASS RESULTS")
print(classification_report(
    y_test, predictions, zero_division=0
))

print("\nSAVED EVIDENCE")
for path in [
    metrics_file,
    report_file,
    matrix_file,
    features_file,
    model_file,
]:
    print(path)
