
from pathlib import Path
import pandas as pd

PROJECT_DIR = Path(__file__).resolve().parent.parent
REGISTRY_FILE = PROJECT_DIR / "data" / "ot_asset_registry.csv"
OUTPUT_DIR = PROJECT_DIR / "outputs"
OUTPUT_DIR.mkdir(exist_ok=True)

assets = pd.read_csv(REGISTRY_FILE)

required_columns = [
    "asset_id",
    "asset_name",
    "scenario",
    "asset_role",
    "criticality",
    "criticality_reason",
    "data_source",
]

missing_columns = [
    col for col in required_columns
    if col not in assets.columns
]

if missing_columns:
    raise ValueError(f"Missing columns: {missing_columns}")

if assets["asset_id"].isna().any():
    raise ValueError("Asset IDs cannot be empty.")

if assets["asset_id"].duplicated().any():
    raise ValueError("Duplicate asset IDs found.")

if not assets["criticality"].between(1, 5).all():
    raise ValueError("Criticality must be between 1 and 5.")

if assets["criticality_reason"].isna().any():
    raise ValueError("Every asset needs a criticality reason.")

if assets["data_source"].isna().any():
    raise ValueError("Every asset needs a data-source description.")

print("OT ASSET REGISTRY VERIFICATION")
print("=" * 40)
print("Asset count:", len(assets))
print("Unique asset IDs:", assets["asset_id"].nunique())
print("Scenarios:", assets["scenario"].nunique())
print("Criticality range:",
      assets["criticality"].min(), "to",
      assets["criticality"].max())

print("\nAssets by scenario:")
print(assets.groupby("scenario").size().to_string())

print("\nCriticality distribution:")
print(assets["criticality"].value_counts().sort_index().to_string())

print("\nRegistry validation: PASSED")
print("Note: validation checks structure and ranges,")
print("not the real-world correctness of assumptions.")

report = OUTPUT_DIR / "ot_asset_registry_verification.txt"
report.write_text(
    "OT asset registry structural validation: PASSED\n"
    f"Asset count: {len(assets)}\n"
    f"Unique asset IDs: {assets['asset_id'].nunique()}\n"
    f"Scenario count: {assets['scenario'].nunique()}\n"
    "Criticality values are provisional scenario assumptions.\n",
    encoding="utf-8",
)

print("\nSaved evidence:", report)
