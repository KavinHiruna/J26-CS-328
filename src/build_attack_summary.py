
from pathlib import Path
import pandas as pd

# Project paths
PROJECT_DIR = Path(__file__).resolve().parent.parent
DATA_FILE = PROJECT_DIR / "data" / "edgeiiot_ml.csv"
OUTPUT_DIR = PROJECT_DIR / "outputs"

OUTPUT_DIR.mkdir(exist_ok=True)

print("Loading Edge-IIoTset dataset...")

df = pd.read_csv(
    DATA_FILE,
    usecols=["ip.src_host", "Attack_label", "Attack_type"],
    low_memory=False
)

# Clean column values
df["ip.src_host"] = (
    df["ip.src_host"]
    .astype("string")
    .str.strip()
)

df["Attack_type"] = (
    df["Attack_type"]
    .astype("string")
    .str.strip()
)

# Keep confirmed attack records from the dataset label
attacks = df[df["Attack_label"] == 1].copy()

# Summary by attack type
attack_summary = (
    attacks.groupby("Attack_type", dropna=False)
    .size()
    .reset_index(name="record_count")
    .sort_values("record_count", ascending=False)
)

# Summary by source host and attack type
host_summary = (
    attacks.groupby(
        ["ip.src_host", "Attack_type"],
        dropna=False
    )
    .size()
    .reset_index(name="record_count")
    .sort_values("record_count", ascending=False)
)

# Save outputs
attack_summary.to_csv(
    OUTPUT_DIR / "attack_type_summary.csv",
    index=False
)

host_summary.to_csv(
    OUTPUT_DIR / "source_host_attack_summary.csv",
    index=False
)

print("\nDataset summary")
print("-------------------------")
print(f"Total dataset rows: {len(df):,}")
print(f"Attack records: {len(attacks):,}")
print(f"Attack types: {attacks['Attack_type'].nunique()}")
print(f"Source hosts: {attacks['ip.src_host'].nunique()}")

print("\nTop 10 attack types:")
print(attack_summary.head(10).to_string(index=False))

print("\nSaved files:")
print(OUTPUT_DIR / "attack_type_summary.csv")
print(OUTPUT_DIR / "source_host_attack_summary.csv")
