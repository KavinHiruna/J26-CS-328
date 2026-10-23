"""
pipeline.py - BATCH run: take Component 1's alerts, score and rank every one, save the queue.

Run from the dev folder:      python -m backend.component3_soc.pipeline

Steps (each one is a small function you can read and test on its own):
  1. read the alerts Component 1 produced              (data/c1_alerts_test20.csv, format of docs/interfaces.md)
  2. calibrate the detector's confidence               (calibrate.py)
  3. drop flows predicted Normal: they are not alerts
  4. severity, asset, frequency for each alert         (factors.py)
  5. risk score and priority level                     (scoring.py)
  6. save outputs/scored_alerts.csv, best-to-worst, and print a summary
"""
import pandas as pd

from . import factors, scoring
from .calibrate import calibrate
from .config import ALERTS_FILE, LEVELS, NOT_AN_ALERT, OUTPUT_DIR, SCORED_FILE, WINDOW_SECONDS


def load_alerts(path=ALERTS_FILE):
    alerts = pd.read_csv(path, dtype={"src_ip": str, "dst_ip": str})
    needed = {"flow_id", "src_ip", "dst_ip", "predicted_type", "confidence_raw", "event_time"}
    if not needed.issubset(alerts.columns):
        raise ValueError(f"Alert file must have columns {sorted(needed)}")
    return alerts


def add_factors(alerts):
    """Add severity, asset and frequency columns to the alert table."""
    alerts = alerts.copy()
    alerts["attack_severity"] = alerts["predicted_type"].map(factors.get_severity)

    asset = alerts["dst_ip"].map(factors.get_asset)                       # (id, name, criticality, status)
    alerts["asset_id"] = asset.str[0]
    alerts["asset_name"] = asset.str[1]
    alerts["asset_criticality"] = asset.str[2].astype(float)
    alerts["asset_status"] = asset.str[3]

    window = factors.window_counts(alerts)                                # NaN when there is no timestamp
    has_time = window.notna()
    count = window.where(has_time, factors.capture_counts(alerts))
    alerts["window_count"] = window
    alerts["frequency_count"] = count
    alerts["attack_frequency"] = count.map(factors.log_frequency).astype(float)
    alerts["frequency_basis"] = has_time.map({True: f"time window ({WINDOW_SECONDS} s)",
                                              False: "fallback: no timestamp, capture-wide count"})
    return alerts


def add_scores(alerts):
    """Add risk score, priority level and advice."""
    alerts = alerts.copy()
    alerts["risk_score"] = [
        scoring.risk_score(r.attack_severity, r.detection_confidence, r.asset_criticality, r.attack_frequency)
        for r in alerts.itertuples()]
    alerts["priority"] = alerts["risk_score"].map(scoring.priority_level)
    alerts["recommendations"] = [" | ".join(scoring.recommend(p, t))
                                 for p, t in zip(alerts["priority"], alerts["predicted_type"])]
    return alerts


def run(save=True):
    raw = load_alerts()
    raw["detection_confidence"] = calibrate(raw)                           # step 2
    alerts = raw[raw["predicted_type"] != NOT_AN_ALERT].copy()             # step 3
    alerts = add_scores(add_factors(alerts))                               # steps 4-5
    alerts["alert_id"] = "FLOW-" + alerts["flow_id"].astype(str)
    alerts["detection_correct"] = alerts["predicted_type"] == alerts["true_type"]
    columns = ["alert_id", "flow_id", "src_ip", "dst_ip", "true_type", "predicted_type", "detection_correct",
               "attack_severity", "detection_confidence", "asset_id", "asset_name", "asset_criticality",
               "asset_status", "window_count", "frequency_basis", "attack_frequency", "risk_score", "priority",
               "recommendations"]
    queue = alerts[columns].sort_values("risk_score", ascending=False, kind="stable").reset_index(drop=True)
    if save:
        OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        queue.to_csv(SCORED_FILE, index=False)
    return raw, queue


def summary(raw, queue):
    lines = [f"Flows read: {len(raw):,} | alerts (not Normal): {len(queue):,} | dropped as Normal: {len(raw) - len(queue):,}",
             "", "Alerts per priority level:"]
    counts = queue["priority"].value_counts()
    for level in LEVELS:
        n = int(counts.get(level, 0))
        lines.append(f"  {level:<9}{n:>7,}  {n / len(queue):6.1%}")
    lines += ["", f"Score: min {queue.risk_score.min():.1f}, median {queue.risk_score.median():.1f}, max {queue.risk_score.max():.1f}",
              f"Frequency basis: {(queue.frequency_basis.str.startswith('time')).mean():.1%} time window, "
              f"rest capture-wide fallback ({', '.join(sorted(queue.loc[queue.frequency_basis.str.startswith('fallback'), 'predicted_type'].unique()))})",
              f"Target not in registry (fallback asset): {(queue.asset_status.str.startswith('fallback')).mean():.1%}",
              "", "Top 5 alerts:"]
    lines.append(queue.head(5)[["alert_id", "predicted_type", "asset_id", "detection_confidence",
                                "attack_frequency", "risk_score", "priority"]].to_string(index=False))
    return "\n".join(lines)


if __name__ == "__main__":
    raw_table, queue_table = run()
    print(summary(raw_table, queue_table))
    print(f"\nSaved {SCORED_FILE}")
