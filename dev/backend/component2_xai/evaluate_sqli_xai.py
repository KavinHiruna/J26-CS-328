"""
Batch evaluation of the Component 2 SQLi XAI engine (results for the thesis/report).

For a sample of incidents it measures:
  * Shapley efficiency error (sanity check - should be ~0)
  * deletion fidelity: probability drop when the top evidence is removed vs random characters
  * agreement: rules <-> PSS, PSS <-> SHAP, PSS <-> LIME
  * Explanation Trust Score distribution
  * how often a minimal sanitisation counterfactual exists, and its size
  * payload share (how much of the decision comes from payload text vs network/size features)
  * technique frequency and explanation time

FILE LOCATION : dev/backend/component2_xai/evaluate_sqli_xai.py
Default paths come from sqli_xai_config.py:
  dataset  -> dev/data/EdgeIIoT_train_80_with_incident_id.csv
  model    -> dev/backend/component2_xai/model/sql_injection_rf.pkl
  features -> dev/backend/component2_xai/model/sql_feature_columns.pkl
  results  -> dev/outputs/component2_xai_eval/

Run (from the dev folder):
  python backend\component2_xai\evaluate_sqli_xai.py --n 300 --candidates
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from collections import Counter
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
import sqli_xai_config as C  # noqa: E402
import sqli_xai_engine as X  # noqa: E402

CANDIDATE_PATTERN = X.CANDIDATE_PATTERN


def _default(paths):
    found = C.first_existing(paths)
    return str(found) if found else str(paths[0])


def describe(series: pd.Series) -> dict:
    s = pd.to_numeric(series, errors="coerce").dropna()
    if s.empty:
        return {"n": 0}
    return {"n": int(len(s)), "mean": round(float(s.mean()), 4), "median": round(float(s.median()), 4),
            "std": round(float(s.std(ddof=0)), 4), "min": round(float(s.min()), 4), "max": round(float(s.max()), 4)}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--data", default=_default(C.DATASET_PATHS), help="CSV with Incident_ID and HTTP/TCP columns")
    ap.add_argument("--model", default=_default(C.MODEL_PATHS), help="trained model (joblib/pickle) with predict_proba")
    ap.add_argument("--features", default=C.first_existing(C.FEATURE_PATHS),
                    help="training feature-name list (optional if the model has feature_names_in_)")
    ap.add_argument("--attack-class", help="class label meaning SQL injection / attack (inferred if omitted)")
    ap.add_argument("--n", type=int, default=200, help="number of incidents to explain")
    ap.add_argument("--background", type=int, default=300, help="background rows for SHAP/LIME/random baseline")
    ap.add_argument("--candidates", action="store_true", help="sample only rows containing SQL-like text")
    ap.add_argument("--no-shap", action="store_true")
    ap.add_argument("--no-lime", action="store_true")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--out", default=str(C.OUTPUT_DIR), help="output folder")
    args = ap.parse_args(argv)

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    df = pd.read_csv(args.data, low_memory=False)
    for label, path in (("dataset", args.data), ("model", args.model)):
        if not Path(path).is_file():
            sys.exit(f"{label} not found: {path}")
    model = C.load_artifact(args.model)
    feats = C.load_artifact(args.features) if args.features else None

    probe = X.SQLiXAIEngine(model, feature_names=feats, attack_class=args.attack_class)
    background = probe.build_feature_matrix(df.sample(min(args.background, len(df)), random_state=args.seed))
    engine = X.SQLiXAIEngine(model, feature_names=feats, background=background,
                             attack_class=args.attack_class, random_state=args.seed)
    res = engine.resolver(df.columns)
    if not res.id_col:
        sys.exit("No Incident ID column found.")

    pool = df
    if args.candidates:
        cols = [c for c in dict.fromkeys(res.target + res.body + [res.query, res.referer]) if c]
        mask = pd.Series(False, index=df.index)
        for c in cols:
            mask |= df[c].astype("string").str.contains(CANDIDATE_PATTERN, regex=True, na=False)
        pool = df[mask]
    sample = pool.sample(min(args.n, len(pool)), random_state=args.seed)
    print(f"Explaining {len(sample)} incidents (pool {len(pool):,} of {len(df):,}); attack class = {engine.attack_class}")

    rows, techniques, eff_errors = [], Counter(), []
    for i, (_, record) in enumerate(sample.iterrows(), 1):
        t0 = time.perf_counter()
        e = engine.explain(record, use_shap=not args.no_shap, use_lime=not args.no_lime)
        row = e.summary_row()
        row["explain_seconds"] = round(time.perf_counter() - t0, 4)
        row["shapley_efficiency_error"] = abs(sum(e.pss.values()) - (e.attack_probability - e.pss_base))
        eff_errors.append(row["shapley_efficiency_error"])
        techniques.update(t["technique"] for t in e.techniques)
        rows.append(row)
        if i % 25 == 0:
            print(f"  {i}/{len(sample)}")

    per = pd.DataFrame(rows)
    per.to_csv(out / "per_incident_metrics.csv", index=False)
    attacks = per[per["is_attack"]]
    summary = {
        "dataset": str(args.data), "model": str(args.model), "attack_class": str(engine.attack_class),
        "incidents_explained": int(len(per)), "predicted_attacks": int(len(attacks)),
        "shapley_efficiency_max_error": float(max(eff_errors) if eff_errors else 0.0),
        "trust_score": describe(per["trust_score"]),
        "trust_levels": per["trust_level"].value_counts().to_dict(),
        "rule_pss_agreement": describe(per["rule_pss_agreement"]),
        "pss_shap_agreement": describe(per["pss_shap_agreement"]),
        "pss_lime_agreement": describe(per["pss_lime_agreement"]),
        "deletion_drop_top": describe(attacks["deletion_drop_top"]),
        "deletion_drop_random": describe(attacks["deletion_drop_random"]),
        "fidelity_gain": describe(attacks["fidelity_gain"]),
        "fidelity_gain_positive_rate": (round(float((pd.to_numeric(attacks["fidelity_gain"], errors="coerce") > 0).mean()), 4)
                                        if len(attacks) else None),
        "counterfactual_found_rate": (round(float(attacks["counterfactual_found"].astype(bool).mean()), 4)
                                      if len(attacks) else None),
        "counterfactual_size": describe(attacks.loc[attacks["counterfactual_found"].astype(bool), "counterfactual_size"]),
        "payload_share_attacks": describe(attacks["pss_payload_share"]),
        "technique_frequency": dict(techniques.most_common()),
        "explain_seconds": describe(per["explain_seconds"]),
        "notes": [
            "deletion_drop_top uses the same removal operator as PSS, so compare it with "
            "deletion_drop_random (same character budget) rather than reading it alone.",
            "payload_share near 0 for many attacks means the model relies on network/size features, "
            "not on the SQL payload - report this as a model-behaviour finding.",
        ],
    }
    (out / "summary.json").write_text(json.dumps(summary, indent=2, default=str))
    print(json.dumps(summary, indent=2, default=str))
    print(f"\nSaved: {out / 'per_incident_metrics.csv'} and {out / 'summary.json'}")


if __name__ == "__main__":
    main()
