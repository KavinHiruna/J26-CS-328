
import pandas as pd
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data" / "edgeiiot_ml.csv"
OUT = ROOT / "outputs" / "fair_comparison"

df = pd.read_csv(DATA, low_memory=False)

df["tcp.srcport"] = pd.to_numeric(
    df["tcp.srcport"], errors="coerce"
)

mitm = df[df["Attack_type"].astype(str).str.strip() == "MITM"]
other = df[df["Attack_type"].astype(str).str.strip() != "MITM"]

for name, subset in [("MITM", mitm), ("OTHER", other)]:
    ports = subset["tcp.srcport"]

    print(f"\n=== {name} SOURCE PORTS ===")
    print(f"Rows: {len(subset):,}")
    print(f"Missing: {ports.isna().sum():,} "
          f"({ports.isna().mean() * 100:.2f}%)")
    print(f"Unique non-missing values: {ports.nunique():,}")
    print("Most frequent values:")
    print(ports.value_counts(dropna=False).head(15).to_string())

# Save a summary for project evidence.
summary = []
for name, subset in [("MITM", mitm), ("OTHER", other)]:
    ports = subset["tcp.srcport"]
    summary.append({
        "group": name,
        "rows": len(subset),
        "missing_count": int(ports.isna().sum()),
        "missing_percent": ports.isna().mean() * 100,
        "unique_non_missing_values": ports.nunique()
    })

OUT.mkdir(parents=True, exist_ok=True)
output_path = OUT / "mitm_source_port_summary.csv"
pd.DataFrame(summary).to_csv(output_path, index=False)

print(f"\nSaved: {output_path}")
