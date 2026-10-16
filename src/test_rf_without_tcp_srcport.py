from pathlib import Path
import json
import time
import pandas as pd
from sklearn.impute import SimpleImputer
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, classification_report
from sklearn.pipeline import Pipeline

ROOT = Path(__file__).resolve().parents[1]
DATA_PATH = ROOT / "data" / "edgeiiot_ml.csv"
FEATURE_PATH = ROOT / "outputs" / "selected_ml_features.csv"
SPLIT_DIR = ROOT / "outputs" / "fair_comparison"
OUT_DIR = SPLIT_DIR / "ablation_tcp_srcport"

def read_indices(path):
    frame = pd.read_csv(path)
    # Split files may store indices as a named column or as the first column.
    candidates = [c for c in frame.columns if c.lower() in {"row_index", "index", "indices", "row_indices"}]
    col = candidates[0] if candidates else frame.columns[0]
    return pd.to_numeric(frame[col], errors="raise").astype(int).to_numpy()

def main():
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    df = pd.read_csv(DATA_PATH, low_memory=False)
    feature_names = pd.read_csv(FEATURE_PATH)["feature"].astype(str).tolist()

    if "tcp.srcport" not in feature_names:
        raise ValueError("tcp.srcport is not in selected_ml_features.csv; cannot run this ablation.")

    target_col = "Attack_type"
    df = df.loc[df[target_col].notna()].reset_index(drop=True)

    # Use exactly the saved row split from the original fair comparison.
    train_idx = read_indices(SPLIT_DIR / "train_row_indices.csv")
    test_idx = read_indices(SPLIT_DIR / "test_row_indices.csv")

    # Confirm split indices correspond to current target-filtered dataset.
    if max(train_idx.max(), test_idx.max()) >= len(df):
        raise ValueError(
            "Saved split indices do not match the current target-filtered dataset. "
            "Stop rather than silently creating a different split."
        )

    features = [f for f in feature_names if f != "tcp.srcport"]
    X = df[features].apply(pd.to_numeric, errors="coerce")
    X = X.replace([float("inf"), float("-inf")], float("nan"))
    y = df[target_col].astype(str)

    X_train, X_test = X.iloc[train_idx], X.iloc[test_idx]
    y_train, y_test = y.iloc[train_idx], y.iloc[test_idx]

    model = Pipeline([
        ("imputer", SimpleImputer(strategy="median")),
        ("classifier", RandomForestClassifier(
            n_estimators=100,
            random_state=42,
            n_jobs=-1,
            class_weight=None
        ))
    ])

    print("Training Random Forest WITHOUT tcp.srcport...")
    start = time.perf_counter()
    model.fit(X_train, y_train)
    train_seconds = time.perf_counter() - start

    start = time.perf_counter()
    predictions = model.predict(X_test)
    prediction_seconds = time.perf_counter() - start

    metrics = {
        "experiment": "Random Forest without tcp.srcport",
        "dataset_rows": int(len(df)),
        "training_rows": int(len(train_idx)),
        "testing_rows": int(len(test_idx)),
        "feature_count": int(len(features)),
        "removed_feature": "tcp.srcport",
        "accuracy": float(accuracy_score(y_test, predictions)),
        "macro_precision": float(precision_score(y_test, predictions, average="macro", zero_division=0)),
        "macro_recall": float(recall_score(y_test, predictions, average="macro", zero_division=0)),
        "macro_f1": float(f1_score(y_test, predictions, average="macro", zero_division=0)),
        "weighted_f1": float(f1_score(y_test, predictions, average="weighted", zero_division=0)),
        "training_seconds": float(train_seconds),
        "prediction_seconds": float(prediction_seconds)
    }

    report = pd.DataFrame(classification_report(
        y_test, predictions, output_dict=True, zero_division=0
    )).transpose()
    report.to_csv(OUT_DIR / "random_forest_without_tcp_srcport_report.csv", index_label="class")

    with open(OUT_DIR / "random_forest_without_tcp_srcport_metrics.json", "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)

    # Compare with baseline Random Forest from the same fair-comparison run.
    baseline_path = SPLIT_DIR / "random_forest_metrics.json"
    if baseline_path.exists():
        with open(baseline_path, "r", encoding="utf-8") as f:
            baseline = json.load(f)
        comparison = pd.DataFrame([
            {
                "experiment": "Baseline Random Forest (36 features)",
                "accuracy": baseline.get("accuracy"),
                "macro_precision": baseline.get("macro_precision"),
                "macro_recall": baseline.get("macro_recall"),
                "macro_f1": baseline.get("macro_f1"),
                "weighted_f1": baseline.get("weighted_f1"),
                "feature_count": 36
            },
            {
                "experiment": "Random Forest without tcp.srcport",
                "accuracy": metrics["accuracy"],
                "macro_precision": metrics["macro_precision"],
                "macro_recall": metrics["macro_recall"],
                "macro_f1": metrics["macro_f1"],
                "weighted_f1": metrics["weighted_f1"],
                "feature_count": len(features)
            }
        ])
        comparison.to_csv(OUT_DIR / "tcp_srcport_ablation_comparison.csv", index=False)
        print("\n=== BASELINE VS WITHOUT tcp.srcport ===")
        print(comparison.to_string(index=False))
    else:
        print("\nBaseline metrics file not found at:", baseline_path)
        print("Please compare the metrics below with the baseline values already recorded.")

    print("\n=== MITM METRICS WITHOUT tcp.srcport ===")
    mitm_row = report.loc[report.index.astype(str) == "MITM"]
    if not mitm_row.empty:
        print(mitm_row[["precision", "recall", "f1-score", "support"]].to_string())
    else:
        print("MITM row not found in report.")

    print("\n=== OVERALL METRICS WITHOUT tcp.srcport ===")
    for key in ["accuracy", "macro_precision", "macro_recall", "macro_f1", "weighted_f1"]:
        print(f"{key}: {metrics[key]:.4f} ({metrics[key] * 100:.2f}%)")

    print("\nSaved outputs to:", OUT_DIR)
    print("This is a feature-ablation experiment, not proof of causation.")

if __name__ == "__main__":
    main()
