
from pathlib import Path
import pandas as pd

from attack_severity_mapping import ATTACK_SEVERITY

PROJECT_DIR = Path(__file__).resolve().parent.parent
DATA_FILE = PROJECT_DIR / "data" / "edgeiiot_ml.csv"
OUTPUT_DIR = PROJECT_DIR / "outputs"

OUTPUT_DIR.mkdir(exist_ok=True)

print("Loading dataset...")

df = pd.read_csv(
    DATA_FILE,
    usecols=[
        "ip.src_host",
        "Attack_label",
        "Attack_type",
    ],
    low_memory=False,
)

# Keep attack records only
attacks = df[df["Attack_label"] == 1].copy()

# Map attack types to provisional severity scores
attacks["attack_severity"] = attacks["Attack_type"].map(
    ATTACK_SEVERITY
)

# Keep unmapped attack types visible for investigation
attacks["severity_mapping_status"] = attacks[
    "attack_severity"
].apply(
    lambda value: "mapped" if pd.notna(value) else "unmapped"
)

# Count records for each source-host and attack-type combination.
# This is a record-count proxy, NOT a time-window attack rate.
host_type_counts = (
    attacks.groupby(
        ["ip.src_host", "Attack_type"],
        dropna=False,
    )
    .size()
    .rename("attack_record_count")
    .reset_index()
)

attacks = attacks.merge(
    host_type_counts,
    on=["ip.src_host", "Attack_type"],
    how="left",
)

# Missing inputs remain explicitly unavailable.
# Do not invent detection confidence or asset criticality.
attacks["detection_confidence"] = pd.NA
attacks["asset_criticality"] = pd.NA

attacks["context_status"] = (
    "Requires IDS confidence and OT asset registry"
)

output_file = OUTPUT_DIR / "risk_dataset_prepared.csv"
attacks.to_csv(output_file, index=False)

print("\nPreparation results")
print("----------------------------")
print(f"Attack records: {len(attacks):,}")
print(
    "Mapped severity records:",
    int(attacks["attack_severity"].notna().sum()),
)
print(
    "Unmapped severity records:",
    int(attacks["attack_severity"].isna().sum()),
)
print(
    "Records requiring additional context:",
    int(attacks["context_status"].notna().sum()),
)
print(f"\nSaved: {output_file}")
