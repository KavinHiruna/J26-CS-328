
from pathlib import Path
import pandas as pd

output_dir = Path("outputs")

feature_files = {
    "Logistic Regression": "logistic_regression_features.csv",
    "Decision Tree": "decision_tree_features.csv",
    "Random Forest": "selected_ml_features.csv",
    "HistGradientBoosting": "hist_gradient_boosting_features.csv",
}

feature_sets = {}

for model_name, filename in feature_files.items():
    path = output_dir / filename

    if not path.exists():
        print(f"Missing file: {path}")
        continue

    df = pd.read_csv(path)

    if "feature" not in df.columns:
        print(f"Unexpected format in: {filename}")
        continue

    features = set(df["feature"].dropna().astype(str))
    feature_sets[model_name] = features

    print(f"{model_name}: {len(features)} unique features")

if len(feature_sets) == len(feature_files):
    reference_name = "Random Forest"
    reference = feature_sets[reference_name]

    print("\nFEATURE COMPARISON")
    print("=" * 40)

    for name, features in feature_sets.items():
        missing = sorted(reference - features)
        extra = sorted(features - reference)

        print(f"\n{name}")
        print("Matches Random Forest:", features == reference)
        print("Missing compared with Random Forest:", missing)
        print("Extra compared with Random Forest:", extra)
else:
    print("\nCould not compare all four models.")
