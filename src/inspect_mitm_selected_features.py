
import pandas as pd
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FEATURES = ROOT / "outputs" / "selected_ml_features.csv"

features = pd.read_csv(FEATURES)["feature"].tolist()

print(f"Total selected features: {len(features)}")

print("\n=== RELEVANT FEATURES ===")
for col in ["frame.time", "tcp.options", "tcp.srcport",
            "tcp.payload", "ip.src_host", "ip.dst_host"]:
    print(f"{col}: {'SELECTED' if col in features else 'NOT SELECTED'}")

print("\n=== ALL SELECTED FEATURES ===")
for i, feature in enumerate(features, start=1):
    print(f"{i:02d}. {feature}")
