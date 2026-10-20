
import json
from pathlib import Path
import pandas as pd

output_dir = Path("outputs")

files = {
    "Logistic Regression": "logistic_regression_metrics.json",
    "Decision Tree": "decision_tree_metrics.json",
    "Random Forest": "attack_model_metrics.json",
    "HistGradientBoosting": "hist_gradient_boosting_metrics.json",
}

for model_name, filename in files.items():
    path = output_dir / filename

    print("\n" + "=" * 45)
    print(model_name)

    if not path.exists():
        print("Metrics file not found:", path)
        continue

    with open(path, "r", encoding="utf-8") as file:
        data = json.load(file)

    rows = data.get("rows_used", data.get("dataset_rows", "Not recorded"))
    seed = data.get("random_state", data.get("random_seed", "Not recorded"))

    print("Dataset rows:", rows)
    print("Training rows:", data.get("training_rows", "Not recorded"))
    print("Testing rows:", data.get("testing_rows", "Not recorded"))
    print("Feature count:", data.get("feature_count", "Not recorded"))
    print("Test size:", data.get("test_size", "Not recorded"))
    print("Random seed:", seed)

    feature_file = output_dir / (
        "selected_ml_features.csv"
        if model_name == "Random Forest"
        else filename.replace("_metrics.json", "_features.csv")
    )

    if feature_file.exists():
        features = pd.read_csv(feature_file)
        print("Feature file:", feature_file.name)
        print("Feature file columns:", list(features.columns))
        print("Feature rows:", len(features))
    else:
        print("Feature file missing:", feature_file.name)

print("\nVerification complete. No models were retrained.")
