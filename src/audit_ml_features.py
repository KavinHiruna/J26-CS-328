
from pathlib import Path
import pandas as pd

PROJECT_DIR = Path(__file__).resolve().parent.parent
DATA_FILE = PROJECT_DIR / "data" / "edgeiiot_ml.csv"
OUTPUT_DIR = PROJECT_DIR / "outputs"
OUTPUT_DIR.mkdir(exist_ok=True)

print("Auditing dataset features...")

df = pd.read_csv(DATA_FILE, low_memory=False)

target_columns = ["Attack_label", "Attack_type"]

# These columns are identifiers or potentially unreliable metadata,
# so they are excluded from the initial feature candidate list.
excluded_columns = [
    "Attack_label",
    "Attack_type",
    "frame.time",
    "ip.src_host",
    "ip.dst_host",
]

candidate_columns = [
    col for col in df.columns
    if col not in excluded_columns
]

report = []

for col in candidate_columns:
    converted = pd.to_numeric(df[col], errors="coerce")
    valid_count = int(converted.notna().sum())

    report.append({
        "column": col,
        "original_dtype": str(df[col].dtype),
        "numeric_values": valid_count,
        "missing_after_numeric_conversion": len(df) - valid_count,
        "unique_numeric_values": int(converted.nunique()),
        "usable_numeric_candidate": (
            valid_count > 0 and converted.nunique() > 1
        ),
    })

audit = pd.DataFrame(report)
audit = audit.sort_values(
    ["usable_numeric_candidate", "numeric_values"],
    ascending=[False, False],
)

audit.to_csv(
    OUTPUT_DIR / "ml_feature_audit.csv",
    index=False,
)

print("\nAUDIT RESULTS")
print("=" * 45)
print("Total rows:", len(df))
print("Total columns:", len(df.columns))
print("Target columns found:", [
    col for col in target_columns if col in df.columns
])
print("Candidate input columns:", len(candidate_columns))
print(
    "Usable numeric candidates:",
    int(audit["usable_numeric_candidate"].sum()),
)

print("\nTop 15 feature candidates:")
print(audit.head(15).to_string(index=False))

print("\nSaved evidence:")
print(OUTPUT_DIR / "ml_feature_audit.csv")
