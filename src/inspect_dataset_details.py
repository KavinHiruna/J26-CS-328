
import pandas as pd
from pathlib import Path

DATA_PATH = Path("data/edgeiiot_ml.csv")

print("Reading selected columns...")
df = pd.read_csv(
    DATA_PATH,
    usecols=["frame.time", "ip.src_host", "ip.dst_host",
             "Attack_label", "Attack_type"],
    dtype={"frame.time": "string"},
    low_memory=False
)

print("\n=== FIRST 15 FRAME.TIME VALUES ===")
print(df["frame.time"].head(15).to_string(index=False))

print("\n=== LAST 10 FRAME.TIME VALUES ===")
print(df["frame.time"].tail(10).to_string(index=False))

print("\n=== ATTACK LABEL BY ATTACK TYPE ===")
print(pd.crosstab(df["Attack_type"], df["Attack_label"]))

print("\n=== SOURCE HOST COUNT ===")
print("Unique source hosts:", df["ip.src_host"].nunique())

print("\n=== DESTINATION HOST COUNT ===")
print("Unique destination hosts:", df["ip.dst_host"].nunique())

print("\n=== SAMPLE SOURCE AND DESTINATION HOSTS ===")
print(df[["ip.src_host", "ip.dst_host"]].head(10).to_string(index=False))
