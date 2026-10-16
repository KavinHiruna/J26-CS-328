"""
Train a Logistic Regression baseline for the SOC Component 3 project.

Run from the project root:
    python src/train_logistic_regression.py

Expected project files:
    data/edgeiiot_ml.csv
    outputs/selected_ml_features.csv

The script uses Attack_type as the target and reuses the feature list saved by
the existing Random Forest experiment, where possible, to support a fair
comparison. It saves metrics, a classification report, a confusion matrix,
selected feature names, and the trained pipeline.
"""

from pathlib import Path
import json
import time
import warnings

import numpy as np
import pandas as pd
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
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
from sklearn.preprocessing import StandardScaler
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
    """Read the feature list saved by the existing Random Forest experiment."""
    if not FEATURES_PATH.exists():
        raise FileNotFoundError(
            f"Cannot find {FEATURES_PATH}. Run the existing Random Forest "
            "training script first so both models can use the same features."
        )

    feature_df = pd.read_csv(FEATURES_PATH)
    dataset_columns = set(dataset_columns)

    # First preference: any column that contains dataset column names.
    for col in feature_df.columns:
        values = feature_df[col].dropna().astype(str).str.strip().tolist()
        matches = [value for value in values if value in dataset_columns]
        if matches:
            # Keep order and remove duplicates.
            return list(dict.fromkeys(matches))

    # Handle a one-column file where the header itself is a feature name.
    for col in feature_df.columns:
        if col in dataset_columns:
            values = feature_df[col].dropna().astype(str).str.strip().tolist()
            matches = [value for value in values if value in dataset_columns]
            if matches:
                return list(dict.fromkeys(matches))

    raise ValueError(
        "Could not identify feature names in outputs/selected_ml_features.csv. "
        f"Columns found: {list(feature_df.columns)}. Open this file and check "
        "which column contains the 36 selected dataset feature names."
    )


def main():
    if not DATA_PATH.exists():
        raise FileNotFoundError(
            f"Dataset not found: {DATA_PATH}\n"
            "Check that data/edgeiiot_ml.csv exists in the project folder."
        )

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    MODEL_DIR.mkdir(parents=True, exist_ok=True)

    print(f"Loading dataset: {DATA_PATH}")
    df = pd.read_csv(DATA_PATH, low_memory=False)
    if TARGET not in df.columns:
        raise KeyError(f"Target column '{TARGET}' is not in the dataset.")

    df = df.dropna(subset=[TARGET]).copy()
    feature_names = load_feature_names(df.columns)

    # Exclude the target and any accidental non-feature columns.
    feature_names = [
        col for col in feature_names
        if col != TARGET and col in df.columns
    ]
    if not feature_names:
        raise ValueError("No usable features were found in the saved feature list.")

    X = df[feature_names].copy()
    # Force numeric values; invalid values become missing and are median-imputed
    # inside the training pipeline. Replace infinite values before imputation.
    for col in X.columns:
        X[col] = pd.to_numeric(X[col], errors="coerce")
    X = X.replace([np.inf, -np.inf], np.nan)
    y = df[TARGET].astype(str)

    # Remove columns that are entirely missing, as median imputation cannot
    # learn a value for them.
    usable_columns = X.columns[X.notna().any(axis=0)].tolist()
    removed_columns = [col for col in X.columns if col not in usable_columns]
    X = X[usable_columns]
    if not usable_columns:
        raise ValueError("All selected features are empty or non-numeric.")

    print(f"Rows: {len(df):,}")
    print(f"Target classes: {y.nunique()}")
    print(f"Features used: {len(usable_columns)}")
    if removed_columns:
        print(f"Removed all-missing features: {removed_columns}")

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=TEST_SIZE,
        random_state=RANDOM_STATE,
        stratify=y,
    )

    # Scaling is important for Logistic Regression. The pipeline ensures that
    # medians and scaling values are learned only from training data.
    model = Pipeline(
        steps=[
            ("imputer", SimpleImputer(strategy="median")),
            ("scaler", StandardScaler()),
            (
                "classifier",
                LogisticRegression(
                    max_iter=2000,
                    solver="lbfgs",
                    random_state=RANDOM_STATE,
                ),
            ),
        ]
    )

    print("Training Logistic Regression...")
    start_train = time.perf_counter()
    model.fit(X_train, y_train)
    training_seconds = time.perf_counter() - start_train

    start_predict = time.perf_counter()
    y_pred = model.predict(X_test)
    prediction_seconds = time.perf_counter() - start_predict

    metrics = {
        "model": "LogisticRegression",
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
            "Attack-type classification only; this model does not directly "
            "predict Critical/High/Medium/Low SOC priority."
        ),
    }

    report = classification_report(y_test, y_pred, output_dict=True, zero_division=0)
    report_df = pd.DataFrame(report).transpose()
    report_df.to_csv(OUTPUT_DIR / "logistic_regression_classification_report.csv")

    labels = sorted(y.unique())
    cm = confusion_matrix(y_test, y_pred, labels=labels)
    pd.DataFrame(cm, index=labels, columns=labels).to_csv(
        OUTPUT_DIR / "logistic_regression_confusion_matrix.csv",
        index_label="actual_class",
    )

    with open(OUTPUT_DIR / "logistic_regression_metrics.json", "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)

    pd.DataFrame({"feature": usable_columns}).to_csv(
        OUTPUT_DIR / "logistic_regression_features.csv", index=False
    )
    dump(model, MODEL_DIR / "logistic_regression_pipeline.joblib")

    print("\n=== Logistic Regression Results ===")
    print(f"Accuracy:          {metrics['accuracy']:.4f} ({metrics['accuracy']*100:.2f}%)")
    print(f"Macro precision:   {metrics['macro_precision']:.4f}")
    print(f"Macro recall:      {metrics['macro_recall']:.4f}")
    print(f"Macro F1-score:    {metrics['macro_f1']:.4f}")
    print(f"Weighted F1-score: {metrics['weighted_f1']:.4f}")
    print(f"Training time:     {training_seconds:.2f} seconds")
    print(f"Prediction time:   {prediction_seconds:.2f} seconds")
    print("\nSaved outputs:")
    print("  outputs/logistic_regression_metrics.json")
    print("  outputs/logistic_regression_classification_report.csv")
    print("  outputs/logistic_regression_confusion_matrix.csv")
    print("  outputs/logistic_regression_features.csv")
    print("  models/logistic_regression_pipeline.joblib")
    print("\nReminder: compare these results with Random Forest using the same split "
          "and features. Do not select a winner using accuracy alone.")


if __name__ == "__main__":
    main()
