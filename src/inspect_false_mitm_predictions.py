from pathlib import Path
import pandas as pd
import joblib

ROOT = Path(__file__).resolve().parents[1]
DATA_PATH = ROOT / "data" / "edgeiiot_ml.csv"
FEATURE_PATH = ROOT / "outputs" / "selected_ml_features.csv"
TEST_INDEX_PATH = ROOT / "outputs" / "fair_comparison" / "test_row_indices.csv"
MODEL_PATH = ROOT / "models" / "fair_comparison" / "random_forest_pipeline.joblib"
OUT_DIR = ROOT / "outputs" / "fair_comparison"

def read_indices(path):
    frame = pd.read_csv(path)
    preferred = [c for c in frame.columns if c.lower() in {
        "row_index", "index", "indices", "row_indices"
    }]
    col = preferred[0] if preferred else frame.columns[0]
    return pd.to_numeric(frame[col], errors="raise").astype(int).to_numpy()

def main():
    print("Loading dataset, feature list, saved test split, and Random Forest...")
    df = pd.read_csv(DATA_PATH, low_memory=False)
    df = df.loc[df["Attack_type"].notna()].reset_index(drop=True)
    features = pd.read_csv(FEATURE_PATH)["feature"].astype(str).tolist()
    test_indices = read_indices(TEST_INDEX_PATH)
    model = joblib.load(MODEL_PATH)

    if len(test_indices) == 0 or test_indices.max() >= len(df):
        raise ValueError("Saved test indices do not match the current dataset. Stop and check the split files.")

    X = df.loc[:, features].apply(pd.to_numeric, errors="coerce")
    X = X.replace([float("inf"), float("-inf")], float("nan"))
    test_df = df.iloc[test_indices].copy()
    X_test = X.iloc[test_indices]

    predictions = model.predict(X_test)
    test_df["predicted_attack_type"] = predictions
    test_df["test_row_index"] = test_indices

    # False MITM predictions: predicted MITM, but the true label is not MITM.
    false_mitm = test_df[
        (test_df["predicted_attack_type"].astype(str) == "MITM")
        & (test_df["Attack_type"].astype(str) != "MITM")
    ].copy()

    # Add only the model's selected features, plus labels/index, for traceable inspection.
    keep_cols = [
        "test_row_index", "Attack_type", "predicted_attack_type",
        "Attack_label"
    ] + features
    keep_cols = [c for c in keep_cols if c in false_mitm.columns]
    false_mitm = false_mitm[keep_cols]

    out_path = OUT_DIR / "false_mitm_predictions_with_features.csv"
    false_mitm.to_csv(out_path, index=False)

    # Summary of true classes wrongly predicted as MITM.
    summary = (
        false_mitm["Attack_type"]
        .value_counts()
        .rename_axis("actual_attack_type")
        .reset_index(name="predicted_as_MITM_count")
    )
    summary_path = OUT_DIR / "false_mitm_prediction_summary.csv"
    summary.to_csv(summary_path, index=False)

    print("\n=== FALSE MITM PREDICTIONS ===")
    print(f"Test records predicted as MITM but actually another class: {len(false_mitm):,}")
    print("\nActual classes wrongly predicted as MITM:")
    print(summary.to_string(index=False))

    print("\n=== SAMPLE FALSE MITM RECORDS (first 10) ===")
    display_cols = [
        c for c in [
            "test_row_index", "Attack_type", "predicted_attack_type",
            "tcp.srcport", "tcp.dstport", "tcp.flags", "tcp.len",
            "tcp.ack", "tcp.seq", "udp.port", "udp.stream"
        ] if c in false_mitm.columns
    ]
    print(false_mitm[display_cols].head(10).to_string(index=False))

    print("\nSaved evidence:")
    print(out_path)
    print(summary_path)
    print("\nThis script only inspects predictions; it does not change data or retrain the model.")

if __name__ == "__main__":
    main()
