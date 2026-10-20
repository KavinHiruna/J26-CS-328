"""
Train a Decision Tree classifier for SOC Component 3.

Run from the project root:
    python src/train_decision_tree.py

Uses Edge-IIoTset, Attack_type as target, and the feature list from the
existing Random Forest experiment. Uses the same 80/20 stratified split and
random_state=42 for comparability with the existing Logistic Regression script.
"""

from pathlib import Path
import json
import time
import warnings

import numpy as np
import pandas as pd
from sklearn.tree import DecisionTreeClassifier
from sklearn.impute import SimpleImputer
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    precision_score,
    recall_score,
    f1_score,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from joblib import dump

warnings.filterwarnings("ignore", category=FutureWarning)

ROOT = Path(__file__).resolve().parents[1]
DATA_PATH = ROOT / "data" / "edgeiiot_ml.csv"
FEATURES_PATH = ROOT / "outputs" / "selected_ml_features.csv"
OUTPUT_DIR = ROOT / "outputs"
MODEL_DIR = ROOT / "models"
TARGET = "Attack_type"
RANDOM_STATE = 42
TEST_SIZE = 0.20


def load_feature_names(dataset_columns):
    if not FEATURES_PATH.exists():
        raise FileNotFoundError(
            f"Cannot find {FEATURES_PATH}. Run the existing Random Forest "
            "training script first so both models can use the same feature list."
        )

    feature_df = pd.read_csv(FEATURES_PATH)
    columns = set(dataset_columns)

    for col in feature_df.columns:
        values = feature_df[col].dropna().astype(str).str.strip().tolist()
        matches = [v for v in values if v in columns]
        if matches:
            return list(dict.fromkeys(matches))

    raise ValueError(
        "Could not identify feature names in outputs/selected_ml_features.csv. "
        f"Columns found: {list(feature_df.columns)}"
    )


def main():
    if not DATA_PATH.exists():
        raise FileNotFoundError(f"Dataset not found: {DATA_PATH}")

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    MODEL_DIR.mkdir(parents=True, exist_ok=True)

    print(f"Loading dataset: {DATA_PATH}")
    df = pd.read_csv(DATA_PATH, low_memory=False)
    if TARGET not in df.columns:
        raise KeyError(f"Target column '{TARGET}' is not in the dataset.")

    df = df.dropna(subset=[TARGET]).copy()
    features = [
        c for c in load_feature_names(df.columns)
        if c != TARGET and c in df.columns
    ]
    X = df[features].copy()

    for col in X.columns:
        X[col] = pd.to_numeric(X[col], errors="coerce")
    X = X.replace([np.inf, -np.inf], np.nan)

    usable_columns = X.columns[X.notna().any(axis=0)].tolist()
    removed_columns = [c for c in X.columns if c not in usable_columns]
    X = X[usable_columns]
    if not usable_columns:
        raise ValueError("No usable numeric features were found.")

    y = df[TARGET].astype(str)

    print(f"Rows: {len(df):,}")
    print(f"Target classes: {y.nunique()}")
    print(f"Features used: {len(usable_columns)}")
    if removed_columns:
        print(f"Removed all-missing features: {removed_columns}")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=TEST_SIZE, random_state=RANDOM_STATE, stratify=y
    )

    # Median imputation is fitted on training data only.
    model = Pipeline(
        steps=[
            ("imputer", SimpleImputer(strategy="median")),
            (
                "classifier",
                DecisionTreeClassifier(
                    random_state=RANDOM_STATE,
                    class_weight=None,
                ),
            ),
        ]
    )

    print("Training Decision Tree...")
    start_train = time.perf_counter()
    model.fit(X_train, y_train)
    training_seconds = time.perf_counter() - start_train

    start_predict = time.perf_counter()
    y_pred = model.predict(X_test)
    prediction_seconds = time.perf_counter() - start_predict

    metrics = {
        "model": "DecisionTreeClassifier",
        "target": TARGET,
        "dataset": str(DATA_PATH.relative_to(ROOT)),
        "rows_used": int(len(df)),
        "feature_count": int(len(usable_columns)),
        "features": usable_columns,
        "test_size": TEST_SIZE,
        "random_state": RANDOM_STATE,
        "accuracy": float(accuracy_score(y_test, y_pred)),
        "macro_precision": float(precision_score(y_test, y_pred, average="macro", zero_division=0)),
        "macro_recall": float(recall_score(y_test, y_pred, average="macro", zero_division=0)),
        "macro_f1": float(f1_score(y_test, y_pred, average="macro", zero_division=0)),
        "weighted_f1": float(f1_score(y_test, y_pred, average="weighted", zero_division=0)),
        "training_seconds": float(training_seconds),
        "prediction_seconds": float(prediction_seconds),
        "notes": (
            "Attack-type classification only; does not directly predict "
            "Critical/High/Medium/Low SOC priority. Default tree settings used; "
            "consider tuning max_depth using training-only cross-validation "
            "before final model selection."
        ),
    }

    report = classification_report(y_test, y_pred, output_dict=True, zero_division=0)
    pd.DataFrame(report).transpose().to_csv(
        OUTPUT_DIR / "decision_tree_classification_report.csv"
    )

    labels = sorted(y.unique())
    cm = confusion_matrix(y_test, y_pred, labels=labels)
    pd.DataFrame(cm, index=labels, columns=labels).to_csv(
        OUTPUT_DIR / "decision_tree_confusion_matrix.csv",
        index_label="actual_class",
    )

    with open(OUTPUT_DIR / "decision_tree_metrics.json", "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)

    pd.DataFrame({"feature": usable_columns}).to_csv(
        OUTPUT_DIR / "decision_tree_features.csv", index=False
    )
    dump(model, MODEL_DIR / "decision_tree_pipeline.joblib")

    print("\n=== Decision Tree Results ===")
    print(f"Accuracy:          {metrics['accuracy']:.4f} ({metrics['accuracy']*100:.2f}%)")
    print(f"Macro precision:   {metrics['macro_precision']:.4f}")
    print(f"Macro recall:      {metrics['macro_recall']:.4f}")
    print(f"Macro F1-score:    {metrics['macro_f1']:.4f}")
    print(f"Weighted F1-score: {metrics['weighted_f1']:.4f}")
    print(f"Training time:     {training_seconds:.2f} seconds")
    print(f"Prediction time:   {prediction_seconds:.2f} seconds")
    print("\nSaved outputs:")
    print("  outputs/decision_tree_metrics.json")
    print("  outputs/decision_tree_classification_report.csv")
    print("  outputs/decision_tree_confusion_matrix.csv")
    print("  outputs/decision_tree_features.csv")
    print("  models/decision_tree_pipeline.joblib")


if __name__ == "__main__":
    main()
