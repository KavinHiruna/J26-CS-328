from pathlib import Path
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
REPORT_PATH = ROOT / "outputs" / "fair_comparison" / "random_forest_classification_report.csv"
MATRIX_PATH = ROOT / "outputs" / "fair_comparison" / "random_forest_confusion_matrix.csv"
OUT_DIR = ROOT / "outputs" / "fair_comparison"

def main():
    if not REPORT_PATH.exists():
        raise FileNotFoundError(
            f"Cannot find: {REPORT_PATH}\n"
            "Run src\\fair_model_comparison.py first and confirm its output files exist."
        )
    if not MATRIX_PATH.exists():
        raise FileNotFoundError(
            f"Cannot find: {MATRIX_PATH}\n"
            "Check the exact confusion-matrix filename in outputs\\fair_comparison."
        )

    report = pd.read_csv(REPORT_PATH, index_col=0)
    required = {"precision", "recall", "f1-score", "support"}
    if not required.issubset(set(report.columns)):
        raise ValueError(
            f"Unexpected report columns: {list(report.columns)}. "
            "Open the classification report CSV and check its format."
        )

    # Keep only individual class rows; summary rows such as accuracy/macro avg are not classes.
    summary_names = {"accuracy", "macro avg", "weighted avg", "micro avg", "samples avg"}
    class_report = report.loc[~report.index.astype(str).str.lower().isin(summary_names)].copy()
    class_report = class_report[pd.to_numeric(class_report["support"], errors="coerce").notna()]
    for col in ["precision", "recall", "f1-score", "support"]:
        class_report[col] = pd.to_numeric(class_report[col], errors="coerce")

    class_report = class_report.sort_values(["f1-score", "support"], ascending=[True, True])
    weak = class_report.head(5).copy()
    weak_path = OUT_DIR / "random_forest_weak_classes.csv"
    weak.to_csv(weak_path, index_label="attack_type")

    matrix = pd.read_csv(MATRIX_PATH, index_col=0)
    matrix.index = matrix.index.astype(str)
    matrix.columns = matrix.columns.astype(str)
    # The matrix has actual classes as rows and predicted classes as columns.
    # Clear the diagonal so only errors remain.
    for label in matrix.index:
        if label in matrix.columns:
            matrix.loc[label, label] = 0
    confusions = (
        matrix.stack()
        .rename("count")
        .reset_index()
        .rename(columns={"level_0": "actual_attack_type", "level_1": "predicted_attack_type"})
    )
    confusions["count"] = pd.to_numeric(confusions["count"], errors="coerce").fillna(0)
    confusions = confusions[confusions["count"] > 0].sort_values("count", ascending=False).head(10)
    confusion_path = OUT_DIR / "random_forest_top_confusions.csv"
    confusions.to_csv(confusion_path, index=False)

    print("\n=== RANDOM FOREST: FIVE WEAKEST ATTACK CLASSES (by F1-score) ===")
    print(weak.reset_index().to_string(index=False, formatters={
        "precision": "{:.3f}".format,
        "recall": "{:.3f}".format,
        "f1-score": "{:.3f}".format,
        "support": "{:.0f}".format,
    }))
    print("\n=== RANDOM FOREST: TEN MOST COMMON MISCLASSIFICATIONS ===")
    if confusions.empty:
        print("No off-diagonal errors found in the confusion matrix.")
    else:
        print(confusions.to_string(index=False))
    print("\nSaved evidence:")
    print(f" - {weak_path}")
    print(f" - {confusion_path}")
    print("\nReminder: these metrics measure attack-type classification, not SOC priority accuracy.")

if __name__ == "__main__":
    main()
