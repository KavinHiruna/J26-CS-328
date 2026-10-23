"""
Train the DDoS TCP SYN Flood detector and pre-compute global explanations.

Usage (from dev/backend):

    python -m component2_xai.DDoS_tcp.train ^
        --data "D:/datasets/Edge-IIoTset/Normal traffic" ^
               "D:/datasets/Edge-IIoTset/Attack traffic/DDoS_ICMP_Flood_attack.csv"

`--data` accepts files and/or folders (searched recursively for *.csv).
Rows that are not Normal, DDoS_TCP, DDoS_UDP or DDoS_ICMP are ignored, so the combined
DNN-EdgeIIoT-dataset.csv also works on its own.

Outputs go to component2_xai/DDoS_tcp/artifacts/.
"""
from __future__ import annotations

import argparse
import json
import time
from datetime import datetime, timezone

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.inspection import permutation_importance
from sklearn.metrics import (accuracy_score, average_precision_score,
                             classification_report, confusion_matrix,
                             f1_score, precision_recall_curve, precision_score,
                             recall_score, roc_auc_score, roc_curve)
from sklearn.model_selection import train_test_split

from . import config
from .data_loader import build_dataset
from .features import FeatureEncoder
from .xai_methods import fit_surrogate, local_attributions, surrogate_rule_list


def _downsample_curve(x, y, n=200):
    if len(x) <= n:
        return list(map(float, x)), list(map(float, y))
    idx = np.linspace(0, len(x) - 1, n).astype(int)
    return [float(x[i]) for i in idx], [float(y[i]) for i in idx]


def train(data_paths: list[str], verbose: bool = True) -> dict:
    t0 = time.time()
    config.ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)

    print("[1/6] Loading Edge-IIoTset CSVs")
    raw, y = build_dataset(data_paths, verbose=verbose)
    print(f"      dataset: {len(raw):,} rows  (attack={int(y.sum()):,}, normal={int((y == 0).sum()):,})")

    print("[2/6] Splitting + encoding features")
    raw_tr, raw_te, y_tr, y_te = train_test_split(
        raw, y, test_size=config.TEST_SIZE, stratify=y, random_state=config.RANDOM_STATE)
    enc = FeatureEncoder().fit(raw_tr)
    X_tr, X_te = enc.transform(raw_tr), enc.transform(raw_te)
    print(f"      {len(enc.feature_names)} features "
          f"({len(enc.categorical_cols)} categorical, dropped constant: {len(enc.dropped_constant)})")

    print("[3/6] Training Random Forest")
    model = RandomForestClassifier(**config.RF_PARAMS)
    t_fit = time.time()
    model.fit(X_tr, y_tr)
    fit_seconds = time.time() - t_fit

    print("[4/6] Evaluating")
    t_pred = time.time()
    proba = model.predict_proba(X_te)[:, 1]
    pred_ms_per_row = (time.time() - t_pred) / max(len(X_te), 1) * 1000
    pred = (proba >= 0.5).astype(int)
    fpr, tpr, _ = roc_curve(y_te, proba)
    prec, rec, _ = precision_recall_curve(y_te, proba)
    fpr_s, tpr_s = _downsample_curve(fpr, tpr)
    rec_s, prec_s = _downsample_curve(rec[::-1], prec[::-1])
    cm = confusion_matrix(y_te, pred, labels=[0, 1])

    metrics = {
        "trained_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "model": "RandomForestClassifier",
        "params": {k: v for k, v in config.RF_PARAMS.items() if k != "n_jobs"},
        "data_sources": sorted(raw["__source"].unique().tolist()),
        "n_train": int(len(X_tr)), "n_test": int(len(X_te)),
        "class_counts": {"Normal": int((y == 0).sum()), config.CLASS_NAMES[1]: int(y.sum())},
        "source_counts": raw.groupby("__source").size().astype(int).to_dict(),
        "accuracy": float(accuracy_score(y_te, pred)),
        "precision": float(precision_score(y_te, pred, zero_division=0)),
        "recall": float(recall_score(y_te, pred, zero_division=0)),
        "f1": float(f1_score(y_te, pred, zero_division=0)),
        "roc_auc": float(roc_auc_score(y_te, proba)),
        "pr_auc": float(average_precision_score(y_te, proba)),
        "false_positive_rate": float(cm[0, 1] / max(cm[0].sum(), 1)),
        "confusion_matrix": cm.tolist(),
        "roc_curve": {"fpr": fpr_s, "tpr": tpr_s},
        "pr_curve": {"recall": rec_s, "precision": prec_s},
        "classification_report": classification_report(
            y_te, pred, target_names=config.CLASS_NAMES, output_dict=True, zero_division=0),
        "fit_seconds": round(fit_seconds, 2),
        "inference_ms_per_packet": round(pred_ms_per_row, 4),
        "features": enc.feature_names,
        "categorical_features": enc.categorical_cols,
        "dropped_columns": config.DROP_COLUMNS,
        "dropped_constant_columns": enc.dropped_constant,
    }
    print(f"      accuracy={metrics['accuracy']:.4f}  f1={metrics['f1']:.4f}  roc_auc={metrics['roc_auc']:.4f}")

    print("[5/6] Global explanations")
    rng = np.random.default_rng(config.RANDOM_STATE)
    n_s = min(config.SHAP_SAMPLE_SIZE, len(X_te))
    idx = rng.choice(len(X_te), n_s, replace=False)
    X_s, y_s = X_te.iloc[idx], y_te.iloc[idx].to_numpy()
    attr, base, method = local_attributions(model, X_s)
    mean_abs = np.abs(attr).mean(axis=0)
    mean_attack = attr[y_s == 1].mean(axis=0) if (y_s == 1).any() else np.zeros(attr.shape[1])

    n_perm = min(3000, len(X_te))
    perm = permutation_importance(model, X_te.iloc[:n_perm], y_te.iloc[:n_perm],
                                  n_repeats=config.PERMUTATION_REPEATS,
                                  random_state=config.RANDOM_STATE, n_jobs=-1, scoring="f1")
    sur, fidelity, rules_text = fit_surrogate(model, X_tr, config.SURROGATE_MAX_DEPTH)
    rules = surrogate_rule_list(sur, enc.feature_names, config.CLASS_NAMES, enc.vocab)

    feats = enc.feature_names
    global_xai = {
        "attribution_method": method,
        "base_value": float(base),
        "feature_importance": sorted([
            {"feature": f,
             "description": config.FEATURE_DESCRIPTIONS.get(f, f),
             "mean_abs_attribution": float(mean_abs[i]),
             "mean_attack_attribution": float(mean_attack[i]),
             "gini_importance": float(model.feature_importances_[i]),
             "permutation_importance": float(perm.importances_mean[i]),
             "permutation_std": float(perm.importances_std[i])}
            for i, f in enumerate(feats)], key=lambda d: -d["mean_abs_attribution"]),
        "surrogate": {"max_depth": config.SURROGATE_MAX_DEPTH, "fidelity": fidelity,
                      "rules_text": rules_text, "rules": rules},
    }
    np.savez_compressed(config.SHAP_SAMPLE_PATH, X=X_s.to_numpy(), values=attr, y=y_s,
                        features=np.array(feats), base=np.array([base]), method=np.array([method]))

    # Per-class typical values for "this packet vs. typical traffic" comparisons.
    baselines = {}
    for label, name in [(0, config.CLASS_NAMES[0]), (1, config.CLASS_NAMES[1])]:
        part = X_tr[y_tr.to_numpy() == label]
        baselines[name] = {f: {"median": float(part[f].median()), "mean": float(part[f].mean())} for f in feats}

    print("[6/6] Saving artifacts ->", config.ARTIFACTS_DIR)
    joblib.dump(model, config.MODEL_PATH, compress=3)
    joblib.dump(enc, config.ENCODER_PATH)
    joblib.dump(sur, config.SURROGATE_PATH)
    bg_idx = rng.choice(len(X_tr), min(config.BACKGROUND_SIZE, len(X_tr)), replace=False)
    joblib.dump(X_tr.iloc[bg_idx].reset_index(drop=True), config.BACKGROUND_PATH)

    # A labelled raw sample from the *test* split for the dashboard demo.
    demo = raw_te.copy()
    demo["__y"] = y_te.to_numpy()
    per = 500
    demo = pd.concat([demo[demo["__y"] == c].sample(min(per, int((demo["__y"] == c).sum())),
                                                     random_state=config.RANDOM_STATE)
                      for c in (0, 1)]).sample(frac=1, random_state=config.RANDOM_STATE)
    demo.drop(columns=["__y", "__source"]).to_csv(config.SAMPLE_TRAFFIC_PATH, index=False)

    metrics["total_seconds"] = round(time.time() - t0, 1)
    config.METRICS_PATH.write_text(json.dumps(metrics, indent=2))
    config.GLOBAL_XAI_PATH.write_text(json.dumps(global_xai, indent=2))
    config.BASELINE_PATH.write_text(json.dumps(baselines, indent=2))
    print(f"Done in {metrics['total_seconds']}s")
    return metrics


def main():
    ap = argparse.ArgumentParser(description="Train DDoS TCP SYN Flood XAI model (Edge-IIoTset)")
    ap.add_argument("--data", nargs="+", required=True,
                    help="CSV files and/or folders with Normal and DDoS_TCP / DDoS_UDP / DDoS_ICMP rows")
    args = ap.parse_args()
    train(args.data)


if __name__ == "__main__":
    main()
