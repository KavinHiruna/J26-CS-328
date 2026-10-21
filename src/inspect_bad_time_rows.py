
import pandas as pd
from pathlib import Path

DATA_PATH = Path("data/edgeiiot_ml.csv")

df = pd.read_csv(
    DATA_PATH,
    usecols=[
        "frame.time",
        "ip.src_host",
        "ip.dst_host",
        "Attack_label",
        "Attack_type"
    ],
    dtype="string",
    low_memory=False
)

time_col = df["frame.time"].str.strip()

# Recognize timestamps in the observed format: 2021 23:12:11.894359000
timestamp_pattern = r"^\d{4}\s+\d{2}:\d{2}:\d{2}\.\d+$"
valid_timestamp = time_col.str.match(timestamp_pattern, na=False)

bad_rows = df.loc[~valid_timestamp]

print("=== ROWS WITHOUT THE EXPECTED TIMESTAMP FORMAT ===")
print("Total:", len(bad_rows))

print("\n=== ATTACK LABEL DISTRIBUTION ===")
print(bad_rows["Attack_label"].value_counts(dropna=False))

print("\n=== ATTACK TYPE DISTRIBUTION ===")
print(bad_rows["Attack_type"].value_counts(dropna=False))

print("\n=== MOST COMMON INVALID TIME VALUES ===")
print(time_col[~valid_timestamp].value_counts().head(15))

print("\n=== FIRST 10 AFFECTED ROWS ===")
print(bad_rows.head(10).to_string(index=False))
