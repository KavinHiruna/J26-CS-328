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
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    df = pd.read_csv(DATA_PATH, low_memory=False)
    df = df.loc[df["Attack_type"].notna()].reset_index(drop=True)
    features = pd.read_csv(FEATURE_PATH)["feature"].astype(str).tolist()
    test_indices = read_indices(TEST_INDEX_PATH)
    model = joblib.load(MODEL_PATH)

    if len(test_indices) == 0 or test_indices.max() >= len(df):
        raise ValueError("Saved test indices do not match the current dataset.")

    X = df.loc[:, features].apply(pd.to_numeric, errors="coerce")
    X = X.replace([float("inf"), float("-inf")], float("nan"))
    test = df.iloc[test_indices].copy()
    test["test_row_index"] = test_indices
    test["predicted_attack_type"] = model.predict(X.iloc[test_indices])

    # Compare actual MITM cases with false MITM predictions, using same selected features.
    actual_mitm = test[test["Attack_type"].astype(str) == "MITM"].copy()
    false_mitm = test[
        (test["predicted_attack_type"].astype(str) == "MITM")
        & (test["Attack_type"].astype(str) != "MITM")
    ].copy()

    groups = {
        "Actual_MITM_correctly_predicted": actual_mitm,
        "Other_classes_falsely_predicted_MITM": false_mitm
    }

    summary_rows = []
    detail_rows = []
    for feature in features:
        for group_name, group_df in groups.items():
            values = pd.to_numeric(group_df[feature], errors="coerce")
            summary_rows.append({
                "group": group_name,
                "feature": feature,
                "rows": len(group_df),
                "missing_count": int(values.isna().sum()),
                "missing_percent": float(values.isna().mean() * 100),
                "zero_count": int((values == 0).sum()),
                "zero_percent": float((values == 0).mean() * 100),
                "unique_non_missing_values": int(values.nunique(dropna=True)),
                "mean": float(values.mean()) if values.notna().any() else None,
                "median": float(values.median()) if values.notna().any() else None
            })

    summary = pd.DataFrame(summary_rows)
    summary.to_csv(OUT_DIR / "mitm_feature_pattern_comparison.csv", index=False)

    wide = summary.pivot(index="feature", columns="group", values="zero_percent")
    wide = wide.reset_index()
    a = "Actual_MITM_correctly_predicted"
    b = "Other_classes_falsely_predicted_MITM"
    wide["absolute_zero_percent_difference"] = (wide[a] - wide[b]).abs()
    wide = wide.sort_values("absolute_zero_percent_difference", ascending=False)
    wide.to_csv(OUT_DIR / "mitm_feature_zero_difference.csv", index=False)

    print("\n=== TEST GROUP SIZES ===")
    print(f"Correctly predicted actual MITM records: {len(actual_mitm):,}")
    print(f"False MITM predictions from other classes: {len(false_mitm):,}")

    print("\n=== FEATURES WITH LARGEST DIFFERENCE IN ZERO RATE ===")
    print(wide.head(15).round(3).to_string(index=False))

    print("\n=== COMPARISON FOR KEY TCP FEATURES ===")
    key_features = [f for f in [
        "tcp.srcport", "tcp.dstport", "tcp.flags", "tcp.len",
        "tcp.ack", "tcp.seq", "tcp.ack_raw", "tcp.checksum",
        "tcp.connection.fin", "tcp.connection.rst",
        "tcp.connection.syn", "tcp.connection.synack"
    ] if f in features]
    print(summary[summary["feature"].isin(key_features)].round(3).to_string(index=False))

    print("\nSaved:")
    print(OUT_DIR / "mitm_feature_pattern_comparison.csv")
    print(OUT_DIR / "mitm_feature_zero_difference.csv")
    print("\nInspection only: no rows/features were changed and no model was retrained.")

if __name__ == "__main__":
    main()
