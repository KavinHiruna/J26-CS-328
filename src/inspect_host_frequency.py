
import pandas as pd
from pathlib import Path

DATA_PATH = Path("data/edgeiiot_ml.csv")

df = pd.read_csv(
    DATA_PATH,
    usecols=["ip.src_host", "Attack_label", "Attack_type"],
    low_memory=False
)

print("=== SOURCE HOSTS WITH MOST ATTACK RECORDS ===")

attacks = df[df["Attack_label"] == 1].copy()

host_counts = (
    attacks.groupby("ip.src_host")
    .agg(
        attack_records=("Attack_label", "size"),
        attack_types=("Attack_type", "nunique")
    )
    .sort_values("attack_records", ascending=False)
)

print(host_counts.head(15).to_string())

print("\n=== RECORDS WITHOUT A USABLE SOURCE HOST ===")

source = attacks["ip.src_host"].astype("string").str.strip()

invalid_source = (
    source.isna()
    | source.eq("")
    | source.eq("0")
    | source.eq("0.0")
)

print("Attack records:", len(attacks))
print("Missing or placeholder source hosts:", int(invalid_source.sum()))

print("\n=== ATTACK TYPES PER SOURCE HOST ===")
print(attacks.groupby("Attack_type")["ip.src_host"].nunique())
