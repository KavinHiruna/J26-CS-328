
import pandas as pd
from pathlib import Path

DATA_PATH = Path("data/edgeiiot_ml.csv")

df = pd.read_csv(
    DATA_PATH,
    usecols=["frame.time"],
    dtype={"frame.time": "string"},
    low_memory=False
)

time_col = df["frame.time"].str.strip()

print("=== TOTAL ROWS ===")
print(len(time_col))

print("\n=== MOST COMMON VALUES ===")
print(time_col.value_counts(dropna=False).head(20))

print("\n=== VALUES THAT LOOK LIKE TIMESTAMPS ===")
timestamp_pattern = r"\d{4}.*\d{2}:\d{2}:\d{2}"
looks_like_timestamp = time_col.str.contains(
    timestamp_pattern, na=False
)
print("Timestamp-like rows:", int(looks_like_timestamp.sum()))

print("\n=== VALUES THAT LOOK NUMERIC ===")
numeric_values = pd.to_numeric(time_col, errors="coerce")
print("Numeric rows:", int(numeric_values.notna().sum()))

print("\n=== FIRST 10 NON-NUMERIC VALUES ===")
print(time_col[numeric_values.isna()].head(10).to_string(index=False))

print("\n=== LAST 10 NON-NUMERIC VALUES ===")
print(time_col[numeric_values.isna()].tail(10).to_string(index=False))
