
import pandas as pd
from pathlib import Path

DATA_PATH = Path("data/edgeiiot_ml.csv")

print("Loading dataset...")
df = pd.read_csv(DATA_PATH)

print("\n=== DATASET SIZE ===")
print(f"Total rows: {len(df):,}")
print(f"Total columns: {len(df.columns)}")

print("\n=== ATTACK LABEL DISTRIBUTION ===")
print(df["Attack_label"].value_counts(dropna=False).sort_index())

print("\n=== ATTACK TYPE DISTRIBUTION ===")
print(df["Attack_type"].value_counts(dropna=False))

print("\n=== FRAME TIME SUMMARY ===")
print(df["frame.time"].describe())

print("\n=== MISSING VALUES IN IMPORTANT COLUMNS ===")
for col in ["frame.time", "ip.src_host", "ip.dst_host",
            "Attack_label", "Attack_type"]:
    print(f"{col}: {df[col].isna().sum():,}")

print("\n=== EXACT DUPLICATE ROWS ===")
print(df.duplicated().sum())
