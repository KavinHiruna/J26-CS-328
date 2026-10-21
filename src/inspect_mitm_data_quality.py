
import pandas as pd
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATA_PATH = ROOT / "data" / "edgeiiot_ml.csv"
OUT_DIR = ROOT / "outputs" / "fair_comparison"

print("Loading dataset...")
df = pd.read_csv(DATA_PATH, low_memory=False)

# Select actual MITM records
mitm = df[df["Attack_type"].astype(str).str.strip() == "MITM"].copy()
other = df[df["Attack_type"].astype(str).str.strip() != "MITM"].copy()

print("\n=== MITM DATASET SUMMARY ===")
print(f"MITM rows: {len(mitm):,}")
print(f"Other rows: {len(other):,}")

# Check missing values
print("\n=== MISSING VALUES: MITM VS OTHER ATTACKS ===")
missing = pd.DataFrame({
    "MITM_missing_count": mitm.isna().sum(),
    "MITM_missing_percent": mitm.isna().mean() * 100,
    "Other_missing_percent": other.isna().mean() * 100
})
missing = missing.sort_values(
    "MITM_missing_percent", ascending=False
)
print(missing.head(20).round(3).to_string())

# Check frame.time parsing
print("\n=== FRAME.TIME QUALITY ===")
mitm_time = pd.to_datetime(mitm["frame.time"], errors="coerce")
other_time = pd.to_datetime(other["frame.time"], errors="coerce")

print(f"MITM unparseable timestamps: {mitm_time.isna().sum():,} "
      f"({mitm_time.isna().mean() * 100:.2f}%)")
print(f"Other unparseable timestamps: {other_time.isna().sum():,} "
      f"({other_time.isna().mean() * 100:.2f}%)")

print("\nExamples of MITM frame.time values:")
print(mitm["frame.time"].astype(str).head(10).to_string(index=False))

# Check constant values and feature distributions
excluded = {"Attack_type", "Attack_label"}
feature_cols = [c for c in df.columns if c not in excluded]

numeric_cols = []
for col in feature_cols:
    converted = pd.to_numeric(df[col], errors="coerce")
    if converted.notna().sum() > 0:
        numeric_cols.append(col)

rows = []
for col in numeric_cols:
    m = pd.to_numeric(mitm[col], errors="coerce")
    o = pd.to_numeric(other[col], errors="coerce")
    rows.append({
        "feature": col,
        "MITM_missing_percent": m.isna().mean() * 100,
        "Other_missing_percent": o.isna().mean() * 100,
        "MITM_unique_values": m.nunique(dropna=True),
        "Other_unique_values": o.nunique(dropna=True),
        "MITM_mean": m.mean(),
        "Other_mean": o.mean()
    })

feature_summary = pd.DataFrame(rows)
feature_summary.to_csv(
    OUT_DIR / "mitm_numeric_feature_summary.csv", index=False
)

missing.to_csv(OUT_DIR / "mitm_missing_value_summary.csv")

print("\n=== NUMERIC FEATURES WITH DIFFERENT MISSINGNESS ===")
if not feature_summary.empty:
    feature_summary["missingness_difference"] = (
        feature_summary["MITM_missing_percent"]
        - feature_summary["Other_missing_percent"]
    ).abs()
    print(
        feature_summary.sort_values(
            "missingness_difference", ascending=False
        ).head(15).round(3).to_string(index=False)
    )

print("\nSaved:")
print(OUT_DIR / "mitm_missing_value_summary.csv")
print(OUT_DIR / "mitm_numeric_feature_summary.csv")
print("\nInspection complete. No dataset values were changed.")
