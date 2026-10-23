"""
Build web_injection_rf.pkl and web_feature_columns.pkl for the Web Injection XAI dashboard.

WHAT THIS MODEL IS (read before citing it):
  * A multi-class Random Forest stand-in/baseline: Other / SQL_injection / XSS / Uploading,
    trained so the dashboard's SHAP/LIME/PSS panels have a real fitted model to explain.
  * Labels: EdgeIIoT_train_80 has only a binary Attack_label. web_injection_xai.web_labels()
    derives the class from the request (SQLi: URI targets /vulnerabilities/sqli; XSS: script /
    event-handler / javascript: payload; Uploading: request to DVWA's upload directory).
    The SQLi label uses the URL path, which is not a model feature; the XSS and upload labels
    are payload/path rules that overlap with some features, so treat their scores as optimistic.
  * Features: the 54 SQLi features + XSS + upload features (web_injection_xai.WEB_FEATURES),
    built by the same code the dashboard uses.

Usage (from dev/):
    python backend/component2_xai/model/train_web_injection_rf.py
"""
from __future__ import annotations

import argparse
import json
import pickle
import sys
from pathlib import Path

import pandas as pd
import sklearn
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))       # dev/backend/component2_xai
import sqli_xai_config as C  # noqa: E402
import web_injection_xai as W  # noqa: E402


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default=str(C.first_existing(C.DATASET_PATHS) or C.DATASET_PATHS[0]))
    ap.add_argument("--out", default=str(C.MODEL_DIR))
    args = ap.parse_args()

    df = pd.read_csv(args.data, low_memory=False)
    print(f"Loaded {len(df):,} rows")
    y = W.web_labels(df)
    print("Class counts:", y.value_counts().to_dict())

    print("Building features ...")
    X_ = W.build_matrix(df)
    X_tr, X_te, y_tr, y_te = train_test_split(X_, y, test_size=0.2, stratify=y, random_state=42)
    model = RandomForestClassifier(n_estimators=200, max_depth=14, min_samples_leaf=2,
                                   class_weight="balanced", n_jobs=-1, random_state=42)
    model.fit(X_tr, y_tr)
    pred = model.predict(X_te)
    labels = list(model.classes_)
    report = classification_report(y_te, pred, labels=labels, digits=4, output_dict=True, zero_division=0)
    print(classification_report(y_te, pred, labels=labels, digits=4, zero_division=0))
    cm = confusion_matrix(y_te, pred, labels=labels)
    print("Confusion matrix (rows = true", labels, "):", cm.tolist())

    model.fit(X_, y)                                   # refit on all rows for the delivered artifact
    model.model_source_ = "Stand-in baseline multi-class RF (web injection)"
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    with open(out / "web_injection_rf.pkl", "wb") as f:
        pickle.dump(model, f, protocol=4)
    with open(out / "web_feature_columns.pkl", "wb") as f:
        pickle.dump(list(W.WEB_FEATURES), f, protocol=4)

    imp = sorted(zip(W.WEB_FEATURES, model.feature_importances_), key=lambda t: -t[1])[:12]
    card = {
        "model": "RandomForestClassifier (multi-class stand-in baseline, web injection)",
        "classes": {c: W.DISPLAY[c] for c in labels},
        "label_rules": {"SQL_injection": f"Attack_label == 1 AND full_uri matches {W.LABEL_SQLI}",
                        "XSS": f"Attack_label == 1 AND request text matches {W.LABEL_XSS}",
                        "Uploading": f"Attack_label == 1 AND full_uri matches {W.LABEL_UPLOAD}"},
        "n_rows": int(len(df)), "class_counts": {k: int(v) for k, v in y.value_counts().items()},
        "n_features": len(W.WEB_FEATURES),
        "holdout_20pct": {c: {"precision": round(report[c]["precision"], 4), "recall": round(report[c]["recall"], 4),
                              "f1": round(report[c]["f1-score"], 4), "support": int(report[c]["support"])}
                          for c in labels},
        "holdout_confusion_matrix": {"labels": labels, "matrix": cm.tolist()},
        "top_feature_importances": {k: round(float(v), 4) for k, v in imp},
        "trained_with": {"scikit-learn": sklearn.__version__, "pickle_protocol": 4},
    }
    (out / "web_injection_model_card.json").write_text(json.dumps(card, indent=2))
    print(json.dumps(card["holdout_20pct"], indent=2))


if __name__ == "__main__":
    main()
