
import pandas as pd
from pathlib import Path

DATA_PATH = Path("data/edgeiiot_ml.csv")

print("Reading dataset...")

df = pd.read_csv(DATA_PATH, nrows=5)

print("\n=== COLUMN NAMES ===")
for column in df.columns:
    print(column)

print("\n=== FIRST 5 ROWS ===")
print(df.to_string(index=False))

print("\n=== DATA TYPES ===")
print(df.dtypes.to_string())

print("\n=== TOTAL COLUMNS ===")
print(len(df.columns))
