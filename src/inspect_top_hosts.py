
import pandas as pd
from pathlib import Path

DATA_PATH = Path("data/edgeiiot_ml.csv")

df = pd.read_csv(
    DATA_PATH,
    usecols=["ip.src_host", "Attack_type", "Attack_label"],
    low_memory=False
)

attacks = df[df["Attack_label"] == 1]

top_hosts = ["192.168.0.128", "192.168.0.170"]

for host in top_hosts:
    host_rows = attacks[attacks["ip.src_host"].astype(str) == host]

    print(f"\n=== SOURCE HOST: {host} ===")
    print("Total attack records:", len(host_rows))
    print("\nAttack types:")
    print(host_rows["Attack_type"].value_counts().to_string())

print("\n=== ATTACK RECORDS BY CATEGORY ===")
print(attacks["Attack_type"].value_counts().to_string())
