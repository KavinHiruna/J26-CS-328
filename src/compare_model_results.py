"""
Create a consolidated comparison table from saved Component 3 model metrics.

Run from project root:
    python src/compare_model_results.py

Creates outputs/model_comparison.csv and outputs/model_comparison.txt.
This summarizes reported metrics and checks saved metadata; it cannot by itself
prove that all models used identical test rows or eliminate data leakage.
"""
from pathlib import Path
import json
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "outputs"
FILES = {
    "Logistic Regression": OUT / "logistic_regression_metrics.json",
    "Decision Tree": OUT / "decision_tree_metrics.json",
    "Random Forest": OUT / "attack_model_metrics.json",
    "HistGradientBoosting": OUT / "hist_gradient_boosting_metrics.json",
}
METRICS = [
    ("Accuracy (%)", "accuracy", 100),
    ("Macro precision (%)", "macro_precision", 100),
    ("Macro recall (%)", "macro_recall", 100),
    ("Macro F1 (%)", "macro_f1", 100),
    ("Weighted F1 (%)", "weighted_f1", 100),
    ("Training time (s)", "training_seconds", 1),
    ("Prediction time (s)", "prediction_seconds", 1),
]

def read_json(path):
    if not path.exists():
        return None
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def main():
    OUT.mkdir(parents=True, exist_ok=True)
    rows, loaded, missing = [], {}, []
    for name, path in FILES.items():
        data = read_json(path)
        if data is None:
            missing.append(f"{name}: {path.relative_to(ROOT)} not found")
            continue
        loaded[name] = data
        row = {
            "Model": name,
            "Target": data.get("target", "not recorded"),
            "Rows": data.get("rows_used", "not recorded"),
            "Feature count": data.get("feature_count", "not recorded"),
            "Test size": data.get("test_size", "not recorded"),
            "Random state": data.get("random_state", "not recorded"),
        }
        for label, key, multiplier in METRICS:
            value = data.get(key)
            row[label] = round(float(value) * multiplier, 4) if value is not None else None
        rows.append(row)

    if not rows:
        print("No model metric files were found. Check the outputs folder.")
        for item in missing:
            print("-", item)
        return

    table = pd.DataFrame(rows)
    table.to_csv(OUT / "model_comparison.csv", index=False)

    notes = []
    feature_lists = {
        name: tuple(data["features"])
        for name, data in loaded.items()
        if isinstance(data.get("features"), list)
    }
    if len(feature_lists) == len(loaded) and len(set(feature_lists.values())) == 1:
        notes.append("Saved feature lists match across all loaded models.")
    else:
        notes.append("Feature lists are not verified as identical; inspect each model's metadata.")

    splits = {(data.get("test_size"), data.get("random_state")) for data in loaded.values()}
    if len(splits) == 1:
        notes.append("Saved test_size and random_state metadata match.")
        notes.append("Matching split settings alone do not prove identical test records.")
    else:
        notes.append("Split metadata differs or is missing; comparison is not fully controlled.")

    if missing:
        notes.append("Missing metric files:")
        notes.extend("- " + item for item in missing)

    if table["Accuracy (%)"].notna().any():
        notes.append("Highest reported accuracy: " + str(table.loc[table["Accuracy (%)"].idxmax(), "Model"]))
    if table["Macro F1 (%)"].notna().any():
        notes.append("Highest reported macro F1: " + str(table.loc[table["Macro F1 (%)"].idxmax(), "Model"]))
    if table["Training time (s)"].notna().any():
        notes.append("Fastest reported training: " + str(table.loc[table["Training time (s)"].idxmin(), "Model"]))

    notes.append(
        "These models predict Attack_type, not Critical/High/Medium/Low SOC priority. "
        "Check test-set leakage and per-class results before selecting a final model."
    )

    with open(OUT / "model_comparison.txt", "w", encoding="utf-8") as f:
        f.write("COMPONENT 3 — MODEL COMPARISON\n")
        f.write("=" * 34 + "\n\n")
        f.write(table.to_string(index=False))
        f.write("\n\nCOMPARABILITY CHECKS AND NOTES\n")
        f.write("-" * 32 + "\n")
        f.write("\n".join(notes) + "\n")

    print("\n=== Component 3 Model Comparison ===")
    print(table.to_string(index=False))
    print("\n=== Checks and notes ===")
    for note in notes:
        print("-", note)
    print("\nSaved:")
    print("  outputs/model_comparison.csv")
    print("  outputs/model_comparison.txt")

if __name__ == "__main__":
    main()
