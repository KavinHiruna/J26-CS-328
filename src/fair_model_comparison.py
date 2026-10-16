"""Fair shared-split comparison of four Component 3 attack classifiers.
Run from project root: python src/fair_model_comparison.py
Outputs go to outputs/fair_comparison/ and models/fair_comparison/.
All models share rows, 36 features, stratified split, and class_weight=None.
This is a new controlled experiment; it does not overwrite earlier evidence.
"""
from pathlib import Path
import json, time, warnings
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, HistGradientBoostingClassifier
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.tree import DecisionTreeClassifier

warnings.filterwarnings("ignore", category=FutureWarning)
ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data" / "edgeiiot_ml.csv"
FEATURE_FILE = ROOT / "outputs" / "selected_ml_features.csv"
OUT = ROOT / "outputs" / "fair_comparison"
MODELS_OUT = ROOT / "models" / "fair_comparison"
TARGET, SEED, TEST_SIZE = "Attack_type", 42, 0.20

def main():
    if not DATA.exists(): raise FileNotFoundError(f"Dataset not found: {DATA}")
    if not FEATURE_FILE.exists(): raise FileNotFoundError(f"Feature list not found: {FEATURE_FILE}")
    OUT.mkdir(parents=True, exist_ok=True)
    MODELS_OUT.mkdir(parents=True, exist_ok=True)

    print("STEP 1: Loading data and shared features")
    df = pd.read_csv(DATA, low_memory=False).dropna(subset=[TARGET]).reset_index(drop=True)
    features = pd.read_csv(FEATURE_FILE)["feature"].dropna().astype(str).tolist()
    if len(features) != 36 or len(set(features)) != 36:
        raise ValueError(f"Expected 36 unique features, got {len(features)} entries / {len(set(features))} unique.")
    missing = [c for c in features if c not in df.columns]
    if missing: raise ValueError(f"Features missing from dataset: {missing}")

    X = df[features].copy()
    for c in X.columns: X[c] = pd.to_numeric(X[c], errors="coerce")
    X = X.replace([np.inf, -np.inf], np.nan)
    all_missing = X.columns[X.isna().all()].tolist()
    if all_missing: raise ValueError(f"Selected features entirely missing: {all_missing}")
    y = df[TARGET].astype(str)
    print(f"Rows: {len(df):,} | Features: {len(features)} | Classes: {y.nunique()}")

    print("\nSTEP 2: Creating one shared stratified split")
    idx = np.arange(len(df))
    train_idx, test_idx = train_test_split(idx, test_size=TEST_SIZE, random_state=SEED, stratify=y)
    X_train, X_test = X.iloc[train_idx], X.iloc[test_idx]
    y_train, y_test = y.iloc[train_idx], y.iloc[test_idx]
    pd.DataFrame({"row_index": train_idx}).to_csv(OUT / "train_row_indices.csv", index=False)
    pd.DataFrame({"row_index": test_idx}).to_csv(OUT / "test_row_indices.csv", index=False)
    meta = {
        "dataset": "data/edgeiiot_ml.csv", "target": TARGET, "rows": len(df),
        "features": features, "feature_count": len(features),
        "training_rows": len(train_idx), "testing_rows": len(test_idx),
        "test_size": TEST_SIZE, "random_state": SEED, "stratified": True,
        "class_weight_policy": "none for all four models",
        "note": "Same row indices/features/preprocessing protocol. Row-level split does not rule out near-duplicate leakage."
    }
    (OUT / "split_metadata.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")

    models = {
        "Logistic Regression": Pipeline([("imputer", SimpleImputer(strategy="median")), ("scaler", StandardScaler()), ("classifier", LogisticRegression(max_iter=2000, solver="lbfgs", random_state=SEED, class_weight=None))]),
        "Decision Tree": Pipeline([("imputer", SimpleImputer(strategy="median")), ("classifier", DecisionTreeClassifier(random_state=SEED, class_weight=None))]),
        "Random Forest": Pipeline([("imputer", SimpleImputer(strategy="median")), ("classifier", RandomForestClassifier(n_estimators=100, random_state=SEED, n_jobs=-1, class_weight=None))]),
        "HistGradientBoosting": Pipeline([("imputer", SimpleImputer(strategy="median")), ("classifier", HistGradientBoostingClassifier(max_iter=100, learning_rate=0.1, max_leaf_nodes=31, random_state=SEED))]),
    }
    names = {"Logistic Regression":"logistic_regression", "Decision Tree":"decision_tree", "Random Forest":"random_forest", "HistGradientBoosting":"hist_gradient_boosting"}
    labels = sorted(y.unique())
    result_rows = []
    print(f"Train: {len(train_idx):,} | Test: {len(test_idx):,} | Split seed: {SEED}")
    for name, model in models.items():
        print(f"\nTraining {name}...")
        t = time.perf_counter(); model.fit(X_train, y_train); train_sec = time.perf_counter()-t
        t = time.perf_counter(); pred = model.predict(X_test); pred_sec = time.perf_counter()-t
        m = {
            "model": name, "target": TARGET, "rows_used": len(df),
            "training_rows": len(train_idx), "testing_rows": len(test_idx),
            "feature_count": len(features), "features": features,
            "test_size": TEST_SIZE, "random_state": SEED, "shared_split": True,
            "class_weight_policy": "none",
            "accuracy": float(accuracy_score(y_test,pred)),
            "macro_precision": float(precision_score(y_test,pred,average="macro",zero_division=0)),
            "macro_recall": float(recall_score(y_test,pred,average="macro",zero_division=0)),
            "macro_f1": float(f1_score(y_test,pred,average="macro",zero_division=0)),
            "weighted_f1": float(f1_score(y_test,pred,average="weighted",zero_division=0)),
            "training_seconds": train_sec, "prediction_seconds": pred_sec
        }
        stem = names[name]
        (OUT / f"{stem}_metrics.json").write_text(json.dumps(m, indent=2), encoding="utf-8")
        pd.DataFrame(classification_report(y_test,pred,labels=labels,output_dict=True,zero_division=0)).transpose().to_csv(OUT / f"{stem}_classification_report.csv")
        pd.DataFrame(confusion_matrix(y_test,pred,labels=labels),index=labels,columns=labels).to_csv(OUT / f"{stem}_confusion_matrix.csv",index_label="actual_class")
        joblib.dump(model, MODELS_OUT / f"{stem}_pipeline.joblib")
        result_rows.append({
            "Model":name, "Accuracy (%)":round(m["accuracy"]*100,2),
            "Macro precision (%)":round(m["macro_precision"]*100,2),
            "Macro recall (%)":round(m["macro_recall"]*100,2),
            "Macro F1 (%)":round(m["macro_f1"]*100,2),
            "Weighted F1 (%)":round(m["weighted_f1"]*100,2),
            "Training time (s)":round(train_sec,2), "Prediction time (s)":round(pred_sec,4)
        })
        print(f"Accuracy={m['accuracy']*100:.2f}% | Macro F1={m['macro_f1']*100:.2f}% | Weighted F1={m['weighted_f1']*100:.2f}% | Train={train_sec:.2f}s")
    table = pd.DataFrame(result_rows)
    table.to_csv(OUT / "model_comparison.csv", index=False)
    report = (
        "FAIR MODEL COMPARISON — SHARED TEST SPLIT\n" + "="*44 + "\n\n" +
        table.to_string(index=False) + "\n\n" +
        f"Dataset rows: {len(df)}; features: {len(features)}; classes: {y.nunique()}\n" +
        f"Training rows: {len(train_idx)}; testing rows: {len(test_idx)}\n" +
        "Split: stratified 80/20, random_state=42\n" +
        "Class weighting: none for all four models in this controlled experiment\n\n" +
        "Caution: row-level split does not rule out near-duplicate leakage or prove performance on unseen sessions/environments.\n" +
        "These models classify Attack_type, not final Critical/High/Medium/Low SOC priority.\n"
    )
    (OUT / "model_comparison.txt").write_text(report, encoding="utf-8")
    print("\n=== FAIR COMPARISON ===")
    print(table.to_string(index=False))
    print(f"\nSaved comparison: {OUT / 'model_comparison.csv'}")
    print(f"Saved text report: {OUT / 'model_comparison.txt'}")
    print(f"Saved models: {MODELS_OUT}")

if __name__ == "__main__":
    main()
