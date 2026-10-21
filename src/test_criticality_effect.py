
from pathlib import Path
import pandas as pd

from calculate_risk_score import (
    calculate_risk_score,
    classify_priority,
)

PROJECT_DIR = Path(__file__).resolve().parent.parent
OUTPUT_DIR = PROJECT_DIR / "outputs"
OUTPUT_DIR.mkdir(exist_ok=True)

# Fixed illustrative alert inputs.
# Only asset criticality changes between test cases.
fixed_inputs = {
    "attack_severity": 5,
    "detection_confidence": 0.90,
    "attack_frequency": 4,
}

results = []

for criticality in [1, 2, 3, 4, 5]:
    score = calculate_risk_score(
        **fixed_inputs,
        asset_criticality=criticality,
    )

    results.append({
        "test_case": f"CRIT-{criticality}",
        "asset_criticality": criticality,
        "attack_severity": fixed_inputs["attack_severity"],
        "detection_confidence": fixed_inputs["detection_confidence"],
        "attack_frequency": fixed_inputs["attack_frequency"],
        "risk_score": score,
        "priority": classify_priority(score),
    })

results_df = pd.DataFrame(results)

print("ASSET CRITICALITY EFFECT TEST")
print("=" * 45)
print(results_df.to_string(index=False))

scores = results_df["risk_score"].tolist()

if not all(
    scores[i] < scores[i + 1]
    for i in range(len(scores) - 1)
):
    raise AssertionError(
        "Risk scores did not increase strictly with criticality."
    )

output_file = OUTPUT_DIR / "criticality_effect_test.csv"
results_df.to_csv(output_file, index=False)

print("\nVerification: PASSED")
print("Risk scores increase as criticality increases.")
print("Saved evidence:", output_file)
