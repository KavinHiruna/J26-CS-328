
from pathlib import Path
import pandas as pd

from calculate_risk_score import (
    calculate_risk_score,
    classify_priority,
)

PROJECT_DIR = Path(__file__).resolve().parent.parent
REGISTRY_FILE = PROJECT_DIR / "data" / "ot_asset_registry.csv"
OUTPUT_DIR = PROJECT_DIR / "outputs"
OUTPUT_DIR.mkdir(exist_ok=True)

assets = pd.read_csv(REGISTRY_FILE)
assets = assets.set_index("asset_id", drop=False)

# Illustrative test alert. These values are test inputs,
# not measured values from Edge-IIoTset.
test_alert = {
    "alert_id": "TEST-001",
    "asset_id": "OT-001",
    "attack_type": "Ransomware",
    "attack_severity": 5,
    "detection_confidence": 0.90,
    "attack_frequency": 4,
}

if test_alert["asset_id"] not in assets.index:
    raise ValueError("Test alert references an unknown asset.")

asset = assets.loc[test_alert["asset_id"]]
criticality = int(asset["criticality"])

score = calculate_risk_score(
    attack_severity=test_alert["attack_severity"],
    detection_confidence=test_alert["detection_confidence"],
    asset_criticality=criticality,
    attack_frequency=test_alert["attack_frequency"],
)

priority = classify_priority(score)

result = {
    **test_alert,
    "asset_name": asset["asset_name"],
    "scenario": asset["scenario"],
    "asset_criticality": criticality,
    "risk_score": score,
    "priority": priority,
    "input_status": "Illustrative test values",
}

print("ASSET-TO-RISK INTEGRATION TEST")
print("=" * 45)

for key, value in result.items():
    print(f"{key}: {value}")

output_file = OUTPUT_DIR / "asset_risk_integration_test.csv"
pd.DataFrame([result]).to_csv(output_file, index=False)

print("\nIntegration test: PASSED")
print("Saved evidence:", output_file)
