"""
Train the DDoS ICMP Flood detector on Edge-IIoTset CSVs.

Run from  dev/backend :

    # real data (recommended)
    python -m component2_xai.DDoS_icmp.train ^
        --csv "D:/data/Edge-IIoTset/Attack traffic/DDoS_ICMP_Flood_attack.csv" ^
        --csv "D:/data/Edge-IIoTset/Normal traffic/Distance/Distance.csv" ^
        --csv "D:/data/Edge-IIoTset/Normal traffic/Flame_Sensor/Flame_Sensor.csv"

    # demo only (synthetic ICMP floods injected into a normal capture)
    python -m component2_xai.DDoS_icmp.train --demo --csv path/to/Distance_15MB.csv

The model bundle is written to component2_xai/DDoS_icmp/models/ddos_icmp_model.joblib
(the dashboard loads it automatically when no model is uploaded).
"""
from __future__ import annotations

import argparse
import json

import pandas as pd

from .config import DEFAULT_MODEL_PATH
from .demo_data import make_demo_dataset
from .features import build_features_many
from .model import save_bundle, train_model


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--csv", action="append", default=[], help="Edge-IIoTset CSV (repeatable)")
    ap.add_argument("--demo", action="store_true", help="inject synthetic ICMP floods (demo only)")
    ap.add_argument("--max-rows", type=int, default=200_000, help="rows sampled per CSV (contiguous head)")
    ap.add_argument("--out", default=str(DEFAULT_MODEL_PATH))
    ap.add_argument("--trees", type=int, default=200)
    args = ap.parse_args(argv)

    frames = [pd.read_csv(p, low_memory=False, nrows=args.max_rows) for p in args.csv]
    if args.demo:
        frames = [make_demo_dataset(frames[0] if frames else None)]
    if not frames:
        ap.error("give at least one --csv or use --demo")

    feats, report = build_features_many(frames)
    print(f"rows: {len(feats):,}  labels: {report.attack_types}")
    for n in report.notes:
        print("note:", n)
    bundle, metrics = train_model(feats, n_estimators=args.trees)
    if args.demo:
        bundle["meta"]["model_name"] += " (DEMO - synthetic ICMP floods)"
    path = save_bundle(bundle, args.out)
    print(json.dumps({k: v for k, v in metrics.items()}, indent=2))
    print(f"saved -> {path}")


if __name__ == "__main__":
    main()
